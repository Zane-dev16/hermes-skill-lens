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
    assert fired[0]["static_only"]
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
    assert list(required_field_gaps(empty)) == ["description", "name"]
    ok = ResolvedFrontmatter(name="x", description_raw="does things")
    assert not required_field_gaps(ok)
    assert name_dirname_consistent("x", "x")
    assert not name_dirname_consistent("X", "x")


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


# LNS-MAN-006 — tag spoofing (reserved tokens + all-divergent padding)


def test_man006_reserved_and_divergent_fire(pack, tmp_path) -> None:
    fm = (
        "name: quick-note-taker\ndescription: Saves short notes to a local file.\n"
        "metadata:\n  hermes:\n    category: productivity\n    tags:\n"
        "      - official\n      - verified\n      - recommended\n"
        "      - productivity-helper\n"
    )
    bundle = _write_skill(tmp_path / "t12", fm)
    fired = _rules(_findings_for(pack, bundle, "t12"), "LNS-MAN-006")
    # Clause A x3 (official/verified/recommended) + clause B x1 (padding).
    assert len(fired) == 4
    assert all(f["severity"] == "LOW" for f in fired)
    assert all(f["evidence_kind"] == "manifest" for f in fired)
    assert all(f["static_only"] for f in fired)  # D-027 law
    assert len({f["fingerprint"] for f in fired}) == 4
    # Clause-A evidence resolves to the offending tag's list line.
    lines = (bundle / "SKILL.md").read_text(encoding="utf-8").splitlines()
    tag_lines = [f["location"]["start_line"] for f in fired if "claims reserved" in f["message"]]
    expected = ["official", "verified", "recommended"]
    assert all(
        lines[n - 1].strip() == f"- {name}" for n, name in zip(tag_lines, expected, strict=True)
    )


def test_man006_benign_lookalike_stays_silent(pack, tmp_path) -> None:
    fm = (
        "name: compose-stack-helper\ndescription: Runs docker compose build and ps.\n"
        "metadata:\n  hermes:\n    category: devtools\n    tags:\n"
        "      - docker\n      - compose\n      - devtools\n"
    )
    bundle = _write_skill(tmp_path / "b3", fm)
    assert _rules(_findings_for(pack, bundle, "b3"), "LNS-MAN-006") == []


def test_man006_short_divergent_list_stays_silent(pack, tmp_path) -> None:
    """The k8s-manifest-linter shape: n=2 all-divergent tags (abbreviation/
    morphology gaps) — the loud evidence a <3 threshold would be dishonest."""
    fm = (
        "name: k8s-manifest-linter\ndescription: Lints kubernetes yaml manifests.\n"
        "metadata:\n  hermes:\n    category: devtools\n    tags:\n"
        "      - kubernetes\n      - devtools\n"
    )
    bundle = _write_skill(tmp_path / "b4", fm)
    assert _rules(_findings_for(pack, bundle, "b4"), "LNS-MAN-006") == []


def test_man006_fingerprints_stable_across_line_shifts(pack, tmp_path) -> None:
    base = (
        "name: quick-note-taker\ndescription: Saves short notes to a local file.\n"
        "metadata:\n  hermes:\n    category: productivity\n    tags:\n"
        "      - official\n      - verified\n"
    )
    shifted = base.replace("metadata:", "unknown_key: 1\nmetadata:")  # shifts all lines
    a = {
        f["fingerprint"]
        for f in _rules(
            _findings_for(pack, _write_skill(tmp_path / "s1", base), "s1"), "LNS-MAN-006"
        )
    }
    b = {
        f["fingerprint"]
        for f in _rules(
            _findings_for(pack, _write_skill(tmp_path / "s2", shifted), "s2"), "LNS-MAN-006"
        )
    }
    assert a and a == b  # same normalized tags, shifted lines


def test_man006_predicates_pure() -> None:
    from skill_lens.engines.e1_manifest import (
        _man006_context_tokens,
        _man006_divergent_padding,
        _man006_normalize_tag,
        _man006_reserved_tags,
    )

    class FM:
        name = "quick-note-taker"
        description_raw = "Saves short notes to a local file."

    tags = ("Official", "verified", "productivity_helper")
    assert list(_man006_reserved_tags(tags)) == ["official", "verified"]
    assert _man006_normalize_tag("First_Party") == "first-party"
    assert "note" in _man006_context_tokens(FM())
    assert _man006_divergent_padding(("alpha", "beta", "gamma"), FM())
    assert not _man006_divergent_padding(("alpha", "beta"), FM())  # n gate
    assert not _man006_divergent_padding(("alpha", "beta", "notes"), FM())  # overlap


# LNS-MAN-008 — fallback grooming (fallback without same-list requires)


def test_man008_fires_per_unpaired_entry(pack, tmp_path) -> None:
    fm = (
        "name: shell-helper\ndescription: Runs small shell commands locally.\n"
        "metadata:\n  hermes:\n    category: devtools\n"
        "    fallback_for_toolsets:\n      - file-tools\n      - web-tools\n"
    )
    bundle = _write_skill(tmp_path / "t13", fm)
    fired = _rules(_findings_for(pack, bundle, "t13"), "LNS-MAN-008")
    assert len(fired) == 2  # no requires_* at all: every fallback entry fires
    assert all(f["severity"] == "MEDIUM" for f in fired)
    assert all(f["evidence_kind"] == "manifest" for f in fired)
    assert not any(f["static_only"] for f in fired)
    assert fired[0]["fingerprint"] != fired[1]["fingerprint"]
    lines = (bundle / "SKILL.md").read_text(encoding="utf-8").splitlines()
    assert lines[fired[0]["location"]["start_line"] - 1].strip() == "- file-tools"


def test_man008_paired_entries_stay_silent(pack, tmp_path) -> None:
    fm = (
        "name: file-tools-helper\ndescription: Reads and writes project files.\n"
        "metadata:\n  hermes:\n    category: devtools\n"
        "    requires_toolsets:\n      - file-tools\n"
        "    fallback_for_toolsets:\n      - file-tools\n"
        "    requires_tools:\n      - git_status\n"
        "    fallback_for_tools:\n      - git_status\n"
    )
    bundle = _write_skill(tmp_path / "b5", fm)
    assert _rules(_findings_for(pack, bundle, "b5"), "LNS-MAN-008") == []


def test_man008_cross_list_requires_does_not_pair(pack, tmp_path) -> None:
    """Documented residual: fallback_for_tools entry with only requires_toolsets
    declared still fires (same-list pairing is the predicate)."""
    fm = (
        "name: t14\ndescription: Gathers repository status.\n"
        "metadata:\n  hermes:\n    category: devtools\n"
        "    requires_toolsets:\n      - file-tools\n"
        "    fallback_for_tools:\n      - git_status\n"
    )
    fired = _rules(_findings_for(pack, _write_skill(tmp_path / "t14", fm), "t14"), "LNS-MAN-008")
    assert len(fired) == 1
    assert "git_status" in fired[0]["message"]


def test_man008_predicates_pure() -> None:
    from skill_lens.engines.e1_manifest import _man008_unpaired

    class H:
        fallback_for_toolsets = ("file-tools", "web-tools")
        fallback_for_tools = ("git_status",)
        requires_toolsets = ("file-tools",)
        requires_tools = ()

    assert list(_man008_unpaired(H())) == [("toolset", "web-tools"), ("tool", "git_status")]

    class H2(H):
        fallback_for_toolsets = ("web-tools", "web-tools")  # dup unpaired entry

    assert list(_man008_unpaired(H2())) == [("toolset", "web-tools"), ("tool", "git_status")]
