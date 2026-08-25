"""Loader tests for skill_lens.rules (strict validation, D-012 schema).

Covers the task-mandated trio — bad YAML, duplicate ids, unknown engine
refs — plus enum/weight/capability drift, unknown-field tolerance, pack
version format, embedded-pack offline load, and fixture verification.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.rules import (
    CODE_RULE_FIXTURE_MISSING,
    CODE_RULE_UNKNOWN_FIELD,
    RulePackError,
    load_core_pack,
    load_pack,
    rule_lookup,
    verify_rule_fixtures,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

VALID_RULE = """\
id: LNS-TST-001
title: "Test rule"
rule_version: "1"
status: active
engine: shellscan
capability: execute.shell
severity: HIGH
weight: 18
evidence_kind: regex
confidence_default: 0.85
static_only: false
tags:
  - test
remediation: "Fix it."
rationale: "Because."
detection: "Matches the thing."
fixtures:
  positive:
    - corpus/fixtures/malicious/reverse-dropper
  negative:
    - corpus/fixtures/benign/pinned-tarball-installer
"""


def write_pack(tmp_path: Path, *rule_texts: str, pack_yaml: str | None = None) -> Path:
    root = tmp_path / "pack"
    (root / "rules").mkdir(parents=True)
    (root / "pack.yaml").write_text(
        pack_yaml
        if pack_yaml is not None
        else (
            'name: test-pack\nversion: "2026.08.1"\nspec_version: rule-pack/1\n'
            'description: "test"\nchangelog:\n  - version: "2026.08.1"\n'
            '    notes:\n      - "init"\n'
        ),
        encoding="utf-8",
    )
    for idx, text in enumerate(rule_texts):
        (root / "rules" / f"rule-{idx:03d}.yaml").write_text(text, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Embedded core pack (offline, package data)
# ---------------------------------------------------------------------------


def test_core_pack_loads_offline_with_expected_shape() -> None:
    pack = load_core_pack()
    assert pack.name == "core"
    assert pack.version == "2026.08.2"  # YYYY.MM.N semver (SPEC §15); patch bump = new rule
    assert len(pack.rules) >= 16  # core v0.1 ships 16 rules + MAN-004
    ids = [rule.id for rule in pack.rules]
    assert ids == sorted(ids), "rules must be id-sorted"
    assert len(set(ids)) == len(ids), "duplicate ids in shipped pack"
    for rule in pack.rules:
        assert rule.engine in {
            "manifest",
            "shellscan",
            "netgraph",
            "secretscan",
        }, f"{rule.id} bound to engine outside Phase-1 set"
        assert rule.status == "active"
        assert rule.fixtures_positive and rule.fixtures_negative


def test_core_pack_reservations_hold() -> None:
    """LNS-MAN-004 shipped with the claims step (SPEC §9.2, DECISIONS D-020)."""
    pack = load_core_pack()
    man004 = pack.rule_by_id("LNS-MAN-004")
    assert man004 is not None
    assert man004.status == "active"
    assert man004.engine == "manifest"
    assert man004.severity == "LOW"
    assert man004.weight == 2
    assert man004.fixtures_positive and man004.fixtures_negative
    # Still-reserved deferred ids must not appear under other meanings.
    assert pack.rule_by_id("LNS-MAN-006") is None
    assert pack.rule_by_id("LNS-MAN-008") is None
    # §7 anchor: NET-011 title/capability conform to the worked finding.
    net011 = pack.rule_by_id("LNS-NET-011")
    assert net011 is not None
    assert net011.title == "Posts locally collected data to external host"
    assert net011.capability == "network.send"
    assert net011.severity == "CRITICAL"


def test_core_pack_checksum_is_stable() -> None:
    assert load_core_pack().content_checksum() == load_core_pack().content_checksum()


def test_core_pack_declared_fixtures_exist_on_disk() -> None:
    """§15 merge blocker: declared TP/FP fixtures must exist (CI gate)."""
    diags = DiagnosticsCollector()
    verify_rule_fixtures(load_core_pack(), REPO_ROOT, diagnostics=diags)
    missing = [d for d in diags.snapshot() if d.code == CODE_RULE_FIXTURE_MISSING]
    assert not missing, [d.message for d in missing]


def test_rule_lookup_helper() -> None:
    lookup = rule_lookup(load_core_pack())
    assert lookup("LNS-SHL-001") is not None
    assert lookup("LNS-XXX-999") is None


# ---------------------------------------------------------------------------
# Structural faults raise RulePackError
# ---------------------------------------------------------------------------


def test_bad_yaml_raises(tmp_path: Path) -> None:
    root = write_pack(tmp_path, "id: [unclosed\n  bad yaml: :::\n")
    with pytest.raises(RulePackError, match="YAML parse failed"):
        load_pack(root)


def test_duplicate_ids_raise(tmp_path: Path) -> None:
    second = VALID_RULE.replace("LNS-TST-001", "LNS-TST-002")
    root = write_pack(tmp_path, VALID_RULE, second.replace("TST-002", "TST-001"))
    with pytest.raises(RulePackError, match="duplicate rule id 'LNS-TST-001'"):
        load_pack(root)


def test_unknown_engine_ref_raises(tmp_path: Path) -> None:
    root = write_pack(tmp_path, VALID_RULE.replace("engine: shellscan", "engine: shellzapper"))
    with pytest.raises(RulePackError, match="unknown engine 'shellzapper'"):
        load_pack(root)


@pytest.mark.parametrize(
    ("field_snippet", "match"),
    [
        ("severity: EXTREME", "unknown severity"),
        ("evidence_kind: vibes", "unknown evidence_kind"),
        ("status: archived", "unknown status"),
        ("capability: wallet.drain", "unknown capability family"),
        ("weight: 12", "does not equal the HIGH tier"),
        ("weight: 18.5", "must declare integer 'weight'"),
        ("confidence_default: 1.4", "outside \\(0, 1\\]"),
        ("id: SHL-1", "does not match LNS-XXX-nnn"),
    ],
)
def test_field_drift_raises(tmp_path: Path, field_snippet: str, match: str) -> None:
    # Drop the original line carrying this key, then append the drifted
    # variant at top level (flat YAML mapping; position is irrelevant).
    key = field_snippet.split(":")[0].strip()
    kept = [line for line in VALID_RULE.splitlines() if not line.startswith(f"{key}:")]
    root = write_pack(tmp_path, "\n".join(kept) + f"\n{field_snippet}\n")
    with pytest.raises(RulePackError, match=match):
        load_pack(root)


def test_missing_required_fields_raise(tmp_path: Path) -> None:
    stripped = "\n".join(
        line for line in VALID_RULE.splitlines() if not line.startswith("remediation:")
    )
    root = write_pack(tmp_path, stripped)
    with pytest.raises(RulePackError, match="'remediation' is required"):
        load_pack(root)


def test_active_rule_without_negative_fixture_raises(tmp_path: Path) -> None:
    stripped = "\n".join(
        line
        for line in VALID_RULE.splitlines()
        if "negative:" not in line and "benign/pinned" not in line
    )
    root = write_pack(tmp_path, stripped)
    with pytest.raises(RulePackError, match="lacks a benign negative fixture"):
        load_pack(root)


@pytest.mark.parametrize("version", ["1.2.3", "2026.13.1", "26.08.1", "2026.08"])
def test_bad_pack_versions_raise(tmp_path: Path, version: str) -> None:
    pack_yaml = (
        f'name: test-pack\nversion: "{version}"\nspec_version: rule-pack/1\n'
        'description: "t"\nchangelog:\n  - version: "x"\n    notes: ["n"]\n'
    )
    root = write_pack(tmp_path, VALID_RULE, pack_yaml=pack_yaml)
    with pytest.raises(RulePackError, match="version"):
        load_pack(root)


def test_unsupported_spec_version_raises(tmp_path: Path) -> None:
    pack_yaml = (
        'name: test-pack\nversion: "2026.08.1"\nspec_version: rule-pack/9\n'
        'description: "t"\nchangelog:\n  - version: "x"\n    notes: ["n"]\n'
    )
    root = write_pack(tmp_path, VALID_RULE, pack_yaml=pack_yaml)
    with pytest.raises(RulePackError, match="unsupported spec_version"):
        load_pack(root)


def test_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(RulePackError, match="not found"):
        load_pack(tmp_path / "nowhere")


# ---------------------------------------------------------------------------
# Tolerant paths (warn-and-record)
# ---------------------------------------------------------------------------


def test_unknown_fields_warn_but_load(tmp_path: Path) -> None:
    mutated = VALID_RULE.replace(
        "tags:",
        "author_hunch: probably-fine\ntags:",
        1,
    )
    root = write_pack(tmp_path, mutated)
    diags = DiagnosticsCollector()
    pack = load_pack(root, diagnostics=diags)
    assert len(pack.rules) == 1
    codes = {d.code for d in diags.snapshot()}
    assert CODE_RULE_UNKNOWN_FIELD in codes
    detail_keys = {
        d.detail.get("key") for d in diags.snapshot() if d.code == CODE_RULE_UNKNOWN_FIELD
    }
    assert "author_hunch" in detail_keys


def test_unknown_capability_subpath_warns_but_loads(tmp_path: Path) -> None:
    mutated = VALID_RULE.replace(
        "capability: execute.shell", "capability: execute.shell:fancy_mode"
    )
    root = write_pack(tmp_path, mutated)
    diags = DiagnosticsCollector()
    pack = load_pack(root, diagnostics=diags)
    assert pack.rules[0].capability == "execute.shell:fancy_mode"
    assert any(d.code == "LNS-RULE-UNKNOWN-SUBPATH" for d in diags)


def test_known_subpath_is_accepted_silently(tmp_path: Path) -> None:
    mutated = (
        VALID_RULE.replace("capability: execute.shell", "capability: persistence:cron_json")
        .replace("engine: shellscan", "engine: manifest")
        .replace("severity: HIGH", "severity: MEDIUM")
        .replace("weight: 18", "weight: 7")
    )
    root = write_pack(tmp_path, mutated)
    diags = DiagnosticsCollector()
    pack = load_pack(root, diagnostics=diags)
    subpath_warnings = [d for d in diags.snapshot() if d.code == "LNS-RULE-UNKNOWN-SUBPATH"]
    assert not subpath_warnings
    assert pack.rules[0].capability_family == "persistence"


def test_draft_rules_may_omit_fixtures(tmp_path: Path) -> None:
    stripped = "\n".join(line for line in VALID_RULE.splitlines()).replace(
        "status: active", "status: draft"
    )
    stripped = "\n".join(
        line
        for line in stripped.splitlines()
        if "fixtures:" not in line
        and "positive:" not in line
        and "negative:" not in line
        and "corpus/fixtures" not in line
    )
    root = write_pack(tmp_path, stripped)
    pack = load_pack(root)
    assert not pack.rules[0].fixtures_positive
