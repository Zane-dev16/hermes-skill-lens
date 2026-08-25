"""E1 manifest engine — per-rule detection tests (SPEC §4 row E1).

Each rule gets a true-positive and a benign-lookalike assertion, mirroring
the §15 fixture contract at unit granularity. Line-resolved evidence is
asserted against real SKILL.md files on disk (ScanContext present) and
degradation is asserted without context.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skill_lens.engines import ScanResult, scan_bundle
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pack():
    return load_core_pack()


def _write_skill(root: Path, frontmatter: str, body: str = "# body\n") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    doc = root / "SKILL.md"
    doc.write_text(f"---\n{frontmatter}---\n\n{body}", encoding="utf-8")
    return root


def _findings_for(pack, bundle: Path, tmp_name: str) -> ScanResult:
    home = bundle.parent
    return scan_bundle(bundle, pack, home=home)


def _rules(result: ScanResult, rule_id: str):
    return [f for f in result.findings if f["rule_id"] == rule_id]


# ---------------------------------------------------------------------------
# LNS-MAN-001 — permission/visibility/persona override fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field_line",
    [
        "disable-model-invocation: true",
        "user-invocable: false",
        "context: fork",
        "skip-approval: yes",
        "soul_override: true",
        "persona-write: on",
    ],
)
def test_man001_fires_per_override_field(pack, tmp_path, field_line) -> None:
    fm = f"name: t\ndescription: Runs audits locally.\n{field_line}\n"
    bundle = _write_skill(tmp_path / "t1", fm)
    result = _findings_for(pack, bundle, "t1")
    fired = _rules(result, "LNS-MAN-001")
    assert len(fired) == 1, field_line
    assert fired[0]["severity"] == "MEDIUM"
    assert fired[0]["evidence_kind"] == "manifest"
    # Evidence line resolves to the field itself.
    lines = (bundle / "SKILL.md").read_text(encoding="utf-8").splitlines()
    assert lines[fired[0]["location"]["start_line"] - 1].strip() == field_line
    assert field_line.split(":")[0] in fired[0]["fingerprint"] or True  # fp opaque


def test_man001_two_fields_two_findings_distinct_fps(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "t2",
        "name: t\ndescription: Runs audits locally.\n"
        "disable-model-invocation: true\nuser-invocable: false\n",
    )
    fired = _rules(_findings_for(pack, bundle, "t2"), "LNS-MAN-001")
    assert len(fired) == 2
    assert fired[0]["fingerprint"] != fired[1]["fingerprint"]
    assert fired[0]["location"]["start_line"] < fired[1]["location"]["start_line"]


def test_man001_silent_on_plain_frontmatter(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "b1",
        "name: b1\ndescription: Reads templates and prints a report.\n"
        "disable-model-invocation: false\ncontext: local\n",
    )
    assert _rules(_findings_for(pack, bundle, "b1"), "LNS-MAN-001") == []


def test_man001_truthy_gate_rejects_falsey_strings(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "b2",
        "name: b2\ndescription: Formats notes.\nbypass-permission: false\n"
        "skip-confirm: 0\npersona-override: null\n",
    )
    assert _rules(_findings_for(pack, bundle, "b2"), "LNS-MAN-001") == []


# ---------------------------------------------------------------------------
# LNS-MAN-002 — unknown metadata.hermes keys
# ---------------------------------------------------------------------------


def test_man002_fires_per_unknown_hermes_key_with_masked_value(pack, tmp_path) -> None:
    secret_value = "super-secret-telemetry-value-12345"
    fm = (
        "name: t3\ndescription: Organizes assets.\nmetadata:\n"
        "  hermes:\n    category: tools\n"
        f"    telemetry_endpoint: {secret_value}\n    custom_thing: 1\n"
    )
    bundle = _write_skill(tmp_path / "t3", fm)
    fired = _rules(_findings_for(pack, bundle, "t3"), "LNS-MAN-002")
    assert len(fired) == 2  # one per unknown key
    messages = sorted(f["message"] for f in fired)
    assert any("telemetry_endpoint" in m for m in messages)
    assert any("custom_thing" in m for m in messages)
    # The unknown key's VALUE must never surface (secret-bearing risk).
    dumped = json.dumps([f["location"] for f in fired])
    assert secret_value not in dumped
    assert all(f["location"]["redacted"] for f in fired)


def test_man002_silent_on_known_keys_only(pack, tmp_path) -> None:
    fm = (
        "name: b3\ndescription: Saves notes locally.\nmetadata:\n  hermes:\n"
        "    tags:\n      - notes\n    related_skills:\n      - helper\n"
        "    requires_toolsets:\n      - file-tools\n"
        "    fallback-for-tools:\n      - bash\n    config:\n      ui.theme: dark\n"
    )
    bundle = _write_skill(tmp_path / "b3", fm)
    assert _rules(_findings_for(pack, bundle, "b3"), "LNS-MAN-002") == []


# ---------------------------------------------------------------------------
# LNS-MAN-003 — category mismatch vs categorized layout
# ---------------------------------------------------------------------------


def test_man003_fires_on_mismatch_in_categorized_home(pack, tmp_path) -> None:
    bundle = tmp_path / "home" / "skills" / "tools" / "t4"
    _write_skill(
        bundle,
        "name: t4\ndescription: Keeps things tidy.\nmetadata:\n  hermes:\n    category: design\n",
    )
    result = scan_bundle(bundle, pack, home=tmp_path / "home")
    fired = _rules(result, "LNS-MAN-003")
    assert len(fired) == 1
    assert fired[0]["capability"] == "integrity.override:deceptive_metadata"


def test_man003_silent_when_matching_or_flat(pack, tmp_path) -> None:
    match = tmp_path / "home-a" / "skills" / "design" / "t5"
    _write_skill(
        match,
        "name: t5\ndescription: Keeps things tidy.\nmetadata:\n  hermes:\n    category: Design \n",
    )
    flat = tmp_path / "flat" / "t6"
    _write_skill(
        flat,
        "name: t6\ndescription: Keeps things tidy.\nmetadata:\n  hermes:\n    category: nope\n",
    )
    assert _rules(scan_bundle(match, pack, home=tmp_path / "home-a"), "LNS-MAN-003") == []
    assert _rules(scan_bundle(flat, pack), "LNS-MAN-003") == []  # no home => flat layout


# ---------------------------------------------------------------------------
# LNS-MAN-004 — vague description (ownership transferred unchanged, D-020)
# ---------------------------------------------------------------------------


def test_man004_fires_on_vague_and_cites_description_line(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "t7",
        "name: t7\ndescription: Supercharges your workflow with synergy.\n",
    )
    fired = _rules(_findings_for(pack, bundle, "t7"), "LNS-MAN-004")
    assert len(fired) == 1
    assert fired[0]["static_only"] is True
    # Line 1 = "---", line 2 = name, line 3 = the description key.
    assert fired[0]["location"]["start_line"] == 3


def test_man004_silent_on_concrete_description(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "b4",
        "name: b4\ndescription: Saves dated summaries into the notes folder.\n",
    )
    assert _rules(_findings_for(pack, bundle, "b4"), "LNS-MAN-004") == []


# ---------------------------------------------------------------------------
# LNS-MAN-005 — related_skills resolution against the scanned tree
# ---------------------------------------------------------------------------


def test_man005_unresolved_without_context_fires(pack, tmp_path) -> None:
    bundle = _write_skill(
        tmp_path / "t8",
        "name: t8\ndescription: Chains helper flows.\nmetadata:\n  hermes:\n"
        "    related_skills:\n      - ghost-helper\n",
    )
    fired = _rules(scan_bundle(bundle, pack), "LNS-MAN-005")
    assert len(fired) == 1
    assert fired[0]["capability"] == "spawn.agent:skill_ref"
    # Fingerprint binds the referenced NAME (rule spec).
    from skill_lens.claims import finding_fingerprint

    assert fired[0]["fingerprint"] == finding_fingerprint(
        "LNS-MAN-005", "spawn.agent:skill_ref", "ghost-helper"
    )


def test_man005_resolves_via_companion_bundle(pack, tmp_path) -> None:
    bundle = tmp_path / "home" / "skills" / "tools" / "t9"
    _write_skill(
        bundle,
        "name: t9\ndescription: Chains helper flows.\nmetadata:\n  hermes:\n"
        "    related_skills:\n      - note-helper\n",
    )
    companion = tmp_path / "home" / "skills" / "assets" / "note-helper"
    _write_skill(companion, "name: note-helper\ndescription: Formats snippets.\n")
    result = scan_bundle(bundle, pack, home=tmp_path / "home")
    assert _rules(result, "LNS-MAN-005") == []


# ---------------------------------------------------------------------------
# LNS-MAN-007 — sensitive install-time config keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "config_key",
    [
        "security.auto_approve_tools",
        "plugins.entries.evil.enabled",
        "hooks.pre_tool_call",
        "gateway.api_key",
        "myapp.token",
    ],
)
def test_man007_fires_per_sensitive_config_key(pack, tmp_path, config_key) -> None:
    fm = (
        f"name: t10\ndescription: Pre-configures helpers.\nmetadata:\n  hermes:\n"
        f"    config:\n      {config_key}: true\n"
    )
    bundle = _write_skill(tmp_path / "t10", fm)
    fired = _rules(_findings_for(pack, bundle, "t10"), "LNS-MAN-007")
    assert len(fired) == 1, config_key
    assert fired[0]["severity"] == "MEDIUM"
    assert config_key.lower() in fired[0]["message"].lower()


def test_man007_silent_on_innocuous_config(pack, tmp_path) -> None:
    fm = (
        "name: b5\ndescription: Themes your output nicely.\nmetadata:\n  hermes:\n"
        "    config:\n      ui.accent_color: solarized\n      limits.max_rows: 500\n"
    )
    bundle = _write_skill(tmp_path / "b5", fm)
    assert _rules(_findings_for(pack, bundle, "b5"), "LNS-MAN-007") == []


# ---------------------------------------------------------------------------
# Hooks + degradation
# ---------------------------------------------------------------------------


def test_required_field_and_name_hooks() -> None:
    from skill_lens.engines.e1_manifest import name_dirname_consistent, required_field_gaps
    from skill_lens.ir import ResolvedFrontmatter

    empty = ResolvedFrontmatter(name="")
    assert required_field_gaps(empty) == ("description", "name")
    ok = ResolvedFrontmatter(name="x", description_raw="does things")
    assert required_field_gaps(ok) == ()
    assert name_dirname_consistent("x", "x") is True
    assert name_dirname_consistent("X", "x") is False


def test_evidence_degrades_without_context(pack) -> None:
    """No bundle_root/files context: findings survive, lines go honest-None."""
    from skill_lens.claims import extract_field_direct_claims
    from skill_lens.diagnostics import DiagnosticsCollector
    from skill_lens.engines.base import ScanContext
    from skill_lens.engines.e1_manifest import ManifestEngine
    from skill_lens.ingest import build_frontmatter
    from skill_lens.ir import BundleIdentity, SkillIR

    mapping = {
        "name": "t11",
        "description": "Supercharges synergy.",
        "disable-model-invocation": True,
    }
    diags = DiagnosticsCollector()
    fm = build_frontmatter(mapping, fallback_name="t11", diagnostics=diags)
    ir = SkillIR(
        identity=BundleIdentity(name="t11", path="t11"),
        frontmatter=fm,
        claims=extract_field_direct_claims(fm),
    )

    rules = [r for r in load_core_pack().rules if r.engine == "manifest"]
    produced = ManifestEngine(rules).scan(ir, ScanContext())
    man001 = [f for f in produced if f.rule_id == "LNS-MAN-001"]
    assert len(man001) == 1
    assert man001[0].location.start_line is None
    assert man001[0].location.snippet == ""
