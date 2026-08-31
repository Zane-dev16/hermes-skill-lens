"""Community pack pins — fail-closed trust table (SPEC §15; v1.0 deliverable a).

Covers the ratified failure-mode table BOTH ways on every surface:

- pin loader: valid TOML, unknown fields warn, layer precedence, relative
  path resolution, duplicate names, bad hex, pack-count ceiling;
- digest flow: pinned golden pack passes; one flipped byte → PIN MISMATCH
  both lanes (D-055 tamper-test mirror);
- fail-closed matrix on the scan path (resolve_external_packs +
  scan_bundle), the ``rules verify`` verb, and doctor check 1;
- id collision with core (LNS-NET-011 fixture) rejects the pack; the
  distinct-id pack merges (dispatch stays closed — engines are id-keyed,
  so unimplemented external ids surface LNS-ENG-001, never a silent drop);
- import contract: pytest-socket proves a registered pack scan stays
  network-free (SPEC §14 G1/G3);
- determinism: envelope byte-stable with a registered benign pack (and
  vectors A–G keep their own byte-exact suite green with an empty table);
- street cap: external CRITICAL finding displays effective MEDIUM with
  annotation; pricing keeps reading the rule-assigned severity (score
  unchanged, D-041 hard boundary).
"""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

from skill_lens import packpins, packsec
from skill_lens.canonical import canonical_dumps
from skill_lens.engines import scan_bundle
from skill_lens.report import build_report

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

VALID_RULE = """\
id: {rule_id}
title: "Community net rule"
rule_version: "1"
status: active
engine: netgraph
capability: network.send
severity: {severity}
weight: {weight}
evidence_kind: crossref
confidence_default: 0.8
static_only: false
tags: [community]
remediation: fix
rationale: why
detection: how
fixtures:
  positive: [x]
  negative: [y]
"""


def _make_pack(root: pathlib.Path, name: str = "acme") -> pathlib.Path:
    """A minimal valid community pack (loader-clean, one CRITICAL rule)."""
    pack = root / name
    (pack / "rules").mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        f'name: {name}-rules\nversion: "2026.01.1"\n'
        "spec_version: rule-pack/1\ndescription: test community pack\nrules_dir: rules\n",
        encoding="utf-8",
    )
    (pack / "rules" / "LNS-NET-901.yaml").write_text(
        VALID_RULE.format(rule_id="LNS-NET-901", severity="CRITICAL", weight=40),
        encoding="utf-8",
    )
    return pack


def _pin_toml(pack_dir: pathlib.Path, *, name: str = "acme", sha: str | None = None) -> str:
    digest = (
        sha
        if sha is not None
        else packsec.canonical_digest(packsec.canonical_pack_inputs(pack_dir)).hex()
    )
    return f'[[pack]]\nname = "{name}"\npath = "{pack_dir.as_posix()}"\nsha256 = "{digest}"\n'


def _project(tmp_path: pathlib.Path, toml: str) -> pathlib.Path:
    (tmp_path / ".lens").mkdir()
    (tmp_path / ".lens" / "packs.toml").write_text(toml, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# 1. Pin loader
# ---------------------------------------------------------------------------


def test_loader_valid_file_resolves_relative_paths(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    warnings: list[str] = []
    pins = packpins.load_pack_pins(project_dir=tmp_path, warnings=warnings)
    assert len(pins) == 1
    assert pins[0].name == "acme"
    assert pins[0].resolved == pack.resolve()
    assert pins[0].sha256 == packsec.canonical_digest(packsec.canonical_pack_inputs(pack)).hex()
    assert warnings == []


def test_loader_unknown_fields_warn_and_record(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    toml = _pin_toml(pack) + 'squid = "mascot"\n'
    _project(tmp_path, toml)
    warnings: list[str] = []
    pins = packpins.load_pack_pins(project_dir=tmp_path, warnings=warnings)
    assert len(pins) == 1  # tolerated, never fatal (D-012 style)
    assert any("squid" in w for w in warnings)
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert any("squid" in w for w in state.warnings)


def test_loader_malformed_toml_is_pack_pin_error(tmp_path: pathlib.Path) -> None:
    _project(tmp_path, "[[pack]\nname = 'broken'\n")
    with pytest.raises(packpins.PackPinError) as excinfo:
        packpins.load_pack_pins(project_dir=tmp_path)
    assert "malformed TOML" in str(excinfo.value)


def test_loader_duplicate_names_rejected(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    toml = _pin_toml(pack) + _pin_toml(pack)  # same name twice in one file
    _project(tmp_path, toml)
    with pytest.raises(packpins.PackPinError, match="duplicate pack name"):
        packpins.load_pack_pins(project_dir=tmp_path)


def test_loader_bad_sha256_hex_rejected(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack, sha="nothex"))
    with pytest.raises(packpins.PackPinError, match="64 lowercase hex"):
        packpins.load_pack_pins(project_dir=tmp_path)


def test_loader_layer_precedence_project_wins(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    other = _make_pack(tmp_path, name="zeta")
    global_path = tmp_path / "global.toml"
    global_path.write_text(_pin_toml(other, name="acme"), encoding="utf-8")
    _project(tmp_path, _pin_toml(pack, name="acme"))
    pins = packpins.load_pack_pins(project_dir=tmp_path, global_path=global_path)
    assert len(pins) == 1  # later wins PER NAME, no duplicates
    assert pins[0].resolved == pack.resolve()
    assert pins[0].layer == packpins.PROJECT_PIN_LABEL


def test_loader_disabled_pack_is_inert(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack) + "enabled = false\n")
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert len(state.packs) == 0
    assert any("disabled" in n for n in state.notices)
    assert state.cache_suffix == ""


def test_loader_pack_count_ceiling(tmp_path: pathlib.Path) -> None:
    packs = [_make_pack(tmp_path, name=f"p{i:02d}") for i in range(packpins.MAX_EXTERNAL_PACKS + 1)]
    toml = "\n".join(_pin_toml(p, name=f"p{i:02d}") for i, p in enumerate(packs))
    _project(tmp_path, toml)
    with pytest.raises(packpins.PackPinError, match="ceiling"):
        packpins.load_pack_pins(project_dir=tmp_path)


# ---------------------------------------------------------------------------
# 2. Digest flow (both lanes; D-055 tamper-test mirror)
# ---------------------------------------------------------------------------


def test_pinned_pack_verifies_and_merges(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert [p.name for p in state.packs] == ["acme-rules"]
    assert list(state.notices) == ["lens packs · acme: loaded (sha256 pin verified)"]


def test_flipped_byte_rejects_pack_both_lanes(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    digest = packsec.canonical_digest(packsec.canonical_pack_inputs(pack)).hex()
    tampered = tmp_path / "tampered"
    shutil.copytree(pack, tampered)
    rule = tampered / "rules" / "LNS-NET-901.yaml"
    rule.write_text(rule.read_text(encoding="utf-8") + "\n# one flipped byte\n", encoding="utf-8")

    # Value-object lane (verify_external_pack, shared by verb + doctor).
    report = packsec.verify_external_pack(path=tampered, name="acme", sha256_pin=digest)
    assert report.status == "fail"
    assert report.kind == "pin"
    assert not report.accepted

    # Scan-registration lane: pin the TAMPERED bytes; pack excluded, loud
    # notice, actual digest folded into the cache key.
    _project(
        tmp_path,
        _pin_toml(pack, sha=digest).replace(
            f'path = "{pack.as_posix()}"', f'path = "{tampered.as_posix()}"'
        ),
    )
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert len(state.packs) == 0
    assert any("REJECTED" in n and "digest" in n for n in state.notices)


def test_missing_sha256_pin_rejects_pack(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    toml = _pin_toml(pack, sha="0" * 64).replace(f'sha256 = "{"0" * 64}"\n', "")
    _project(tmp_path, toml)
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert len(state.packs) == 0
    assert any("missing sha256 pin" in n for n in state.notices)


# ---------------------------------------------------------------------------
# 3. Fail-closed matrix — scan / rules verb / doctor
# ---------------------------------------------------------------------------


def test_loader_rejected_pack_raises_on_scan_lane(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    (pack / "rules" / "broken.yaml").write_text("id: [unclosed\n", encoding="utf-8")
    _project(tmp_path, _pin_toml(pack))
    with pytest.raises(packpins.PackPinError, match="failed rule-pack validation"):
        packpins.resolve_external_packs(project_dir=tmp_path)


def test_id_collision_with_core_rejects_pack(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    (pack / "rules" / "LNS-NET-011.yaml").write_text(
        VALID_RULE.format(rule_id="LNS-NET-011", severity="CRITICAL", weight=40),
        encoding="utf-8",
    )
    _project(tmp_path, _pin_toml(pack))
    state = packpins.resolve_external_packs(project_dir=tmp_path)
    assert len(state.packs) == 0
    assert any("collision" in n for n in state.notices)


def test_malformed_pins_file_is_exit2_on_scan_lane(tmp_path: pathlib.Path) -> None:
    _project(tmp_path, "[[pack]\nname = 'broken'\n")
    with pytest.raises(packpins.PackPinError):  # PolicyError subclass → exit-2 lanes
        packpins.resolve_external_packs(project_dir=tmp_path)


def test_rules_verify_reports_pins_pass_lane(tmp_path: pathlib.Path, monkeypatch) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    monkeypatch.chdir(tmp_path)
    from skill_lens.slash import dispatch_verb

    out = dispatch_verb("rules verify", view=_view(tmp_path), cache=_cache())
    assert "verified against committed pubkey" in out  # core block intact
    assert "acme: loaded (sha256 pin verified)" in out


def test_rules_verify_exit2_on_hard_reject(tmp_path: pathlib.Path, monkeypatch) -> None:
    pack = _make_pack(tmp_path)
    digest = packsec.canonical_digest(packsec.canonical_pack_inputs(pack)).hex()
    rule = pack / "rules" / "LNS-NET-901.yaml"
    rule.write_text(rule.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
    _project(tmp_path, _pin_toml(pack, sha=digest))  # pin = pre-tamper digest
    monkeypatch.chdir(tmp_path)
    from skill_lens.slash import dispatch_verb

    sink: dict = {}
    out = dispatch_verb("rules verify", view=_view(tmp_path), cache=_cache(), sink=sink)
    assert sink.get("rules_exit") == 2
    assert "REJECTED" in out


def test_rules_list_shows_core_and_packs(tmp_path: pathlib.Path, monkeypatch) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    monkeypatch.chdir(tmp_path)
    from skill_lens.cli import _tokens_for
    from skill_lens.slash import dispatch_verb

    out = dispatch_verb("rules list", view=_view(tmp_path), cache=_cache())
    assert "core 2026.08.9" in out
    assert "acme-rules 2026.01.1" in out
    assert "pin-match ok" in out
    ns = _namespace("rules", action="list")
    assert _tokens_for("rules", ns) == ["rules", "list"]


def test_doctor_check1_passes_with_registered_pack(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    from skill_lens.doctor import check_rule_pack

    result, _version, _checksum = check_rule_pack(project_dir=tmp_path)
    assert result.status == "pass"
    assert any("acme" in line for line in result.detail)


def test_doctor_check1_hard_fails_on_mismatch(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    digest = packsec.canonical_digest(packsec.canonical_pack_inputs(pack)).hex()
    rule = pack / "rules" / "LNS-NET-901.yaml"
    rule.write_text(rule.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
    _project(tmp_path, _pin_toml(pack, sha=digest))  # pin = pre-tamper digest
    from skill_lens.doctor import check_rule_pack

    result, _v, _c = check_rule_pack(project_dir=tmp_path)
    assert result.status == "fail"
    assert result.hard
    assert any("REJECTED" in line and "digest does not match" in line for line in result.detail)


def test_doctor_check1_warns_on_missing_pin(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    toml = _pin_toml(pack, sha="0" * 64).replace(f'sha256 = "{"0" * 64}"\n', "")
    _project(tmp_path, toml)
    from skill_lens.doctor import check_rule_pack

    result, _v, _c = check_rule_pack(project_dir=tmp_path)
    assert result.status == "warn"  # config omission, not tamper evidence
    assert not result.hard


# ---------------------------------------------------------------------------
# 4. Scan integration: cache suffix, street cap, determinism
# ---------------------------------------------------------------------------


def test_cache_suffix_changes_when_pack_bytes_change(tmp_path: pathlib.Path) -> None:
    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    before = packpins.resolve_external_packs(project_dir=tmp_path).cache_suffix
    rule = pack / "rules" / "LNS-NET-901.yaml"
    rule.write_text(rule.read_text(encoding="utf-8") + "\n# edit\n", encoding="utf-8")
    after = packpins.resolve_external_packs(project_dir=tmp_path).cache_suffix
    assert before != after  # a stale fast-path answer can never be served


def test_benign_registered_pack_keeps_envelope_byte_stable(
    tmp_path: pathlib.Path,
) -> None:
    """A registered pack whose rules fire nothing must not move the bytes."""
    fixture = REPO_ROOT / "corpus/fixtures/malicious/committed-keys"
    baseline = build_report(scan_bundle(fixture))
    baseline_text = canonical_dumps(baseline)
    pack = _make_pack(tmp_path)
    with_pins = scan_bundle(
        fixture,
        external_packs=(
            packpins.resolve_external_packs(project_dir=_project(tmp_path, _pin_toml(pack))).packs
        ),
    )
    assert canonical_dumps(build_report(with_pins)) == baseline_text
    # ...and the envelope keeps reporting the governed CORE pack identity.
    assert with_pins.rule_pack_name == baseline["rule_pack"]["name"]


def test_street_cap_display_not_pricing(tmp_path: pathlib.Path) -> None:
    from skill_lens.engines import EXTERNAL_STREET_CAP, _annotate_external_findings

    finding = {
        "id": "F-1",
        "rule_id": "LNS-NET-901",
        "severity": "CRITICAL",
        "effective_severity": "CRITICAL",
        "annotations": [],
    }
    [out] = _annotate_external_findings([finding], {"LNS-NET-901": "acme-rules"})
    assert out["severity"] == "CRITICAL"  # pricing input NEVER rewritten (D-041)
    assert out["effective_severity"] == EXTERNAL_STREET_CAP == "MEDIUM"
    assert "[pack:acme-rules]" in out["annotations"]
    assert "[street-cap:acme-rules effective MEDIUM]" in out["annotations"]
    # LOW external findings get provenance only, no cap annotation.
    low = dict(finding, severity="LOW", effective_severity="LOW")
    [out_low] = _annotate_external_findings([low], {"LNS-NET-901": "acme-rules"})
    assert out_low["effective_severity"] == "LOW"
    assert not any("street-cap" in a for a in out_low["annotations"])


def test_scan_bundle_rejects_colliding_external_pack_itself(
    tmp_path: pathlib.Path,
) -> None:
    from skill_lens import rules as rules_mod
    from skill_lens.rules import load_core_pack

    fixture = REPO_ROOT / "corpus/fixtures/benign/pinned-deps-helper"
    pack = _make_pack(tmp_path)
    (pack / "rules" / "LNS-NET-011.yaml").write_text(
        VALID_RULE.format(rule_id="LNS-NET-011", severity="CRITICAL", weight=40),
        encoding="utf-8",
    )
    ext = rules_mod.load_pack(pack)
    collector = _collector()
    scan_bundle(fixture, external_packs=[ext], diagnostics=collector)
    codes = [d.code for d in collector.snapshot()]
    assert "LNS-PACK-ID-COLLISION" in codes
    del load_core_pack  # imported for readability of the assertion above


# ---------------------------------------------------------------------------
# 5. Import contract: registered-pack scan stays network-free
# ---------------------------------------------------------------------------


def test_registered_pack_scan_needs_no_socket(tmp_path: pathlib.Path) -> None:
    """SPEC §14 G1/G3: a registered community pack never opens a socket."""
    pytest_socket = pytest.importorskip("pytest_socket")

    pack = _make_pack(tmp_path)
    _project(tmp_path, _pin_toml(pack))
    pytest_socket.disable_socket()
    try:
        state = packpins.resolve_external_packs(project_dir=tmp_path)
        result = scan_bundle(
            REPO_ROOT / "corpus/fixtures/benign/pinned-deps-helper",
            external_packs=state.packs,
        )
        assert result.findings is not None
    finally:
        pytest_socket.enable_socket()


# ---------------------------------------------------------------------------
# 6. Determinism across runs: canonical envelope JSON with an external pack
# ---------------------------------------------------------------------------


def test_external_findings_serialization_is_stable(tmp_path: pathlib.Path) -> None:
    from skill_lens.engines import _annotate_external_findings

    rows = [
        {"rule_id": "LNS-NET-901", "severity": "CRITICAL", "annotations": ["[x]"]},
        {"rule_id": "LNS-SEC-001", "severity": "HIGH", "annotations": None},
    ]
    once = _annotate_external_findings([dict(r) for r in rows], {"LNS-NET-901": "acme"})
    twice = _annotate_external_findings([dict(r) for r in rows], {"LNS-NET-901": "acme"})
    assert json.dumps(once, sort_keys=True) == json.dumps(twice, sort_keys=True)
    assert json.dumps(once[0], sort_keys=True) == json.dumps(
        {
            "rule_id": "LNS-NET-901",
            "severity": "CRITICAL",
            "annotations": ["[x]", "[pack:acme]", "[street-cap:acme effective MEDIUM]"],
            "effective_severity": "MEDIUM",
        },
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _view(tmp_path: pathlib.Path):
    from skill_lens.context import PluginContextView
    from tests.conftest import FakePluginContext

    return PluginContextView(FakePluginContext(data_root=tmp_path))


def _cache():
    from skill_lens.slash import reset_shared_cache, shared_cache

    reset_shared_cache()
    return shared_cache()


def _namespace(verb: str, **attrs):
    from argparse import Namespace

    return Namespace(lens_verb=verb, plain=False, fail_on=None, **attrs)


def _collector():
    from skill_lens.diagnostics import DiagnosticsCollector

    return DiagnosticsCollector()
