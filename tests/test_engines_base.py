"""Engine foundations — protocol, D-CRASH isolation, dedup, fingerprints.

Covers the PLAN Phase-1 exit clause verbatim: "a deliberately raising test
engine changes neither results nor UX", plus SPEC §7's fingerprint law
(stable across line shifts) and dedup law (collapse on fingerprint,
max-5 attached locations, remainder counted).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import skill_lens.engines as engines_pkg
from skill_lens.engines import REGISTRY, available_engines, scan_bundle
from skill_lens.engines.base import (
    CODE_ENGINE_FAILURE,
    Engine,
    ScanContext,
    TestEngine,
    dedup_findings,
    run_engine,
)
from skill_lens.ir import BundleIdentity, SkillIR
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "corpus" / "fixtures"


@pytest.fixture(scope="module")
def pack():
    return load_core_pack()


# ---------------------------------------------------------------------------
# Protocol + registry shape
# ---------------------------------------------------------------------------


def test_registered_engines_satisfy_protocol(pack) -> None:
    assert available_engines() == {"manifest", "netgraph", "secretscan", "shellscan"}
    for name in sorted(available_engines()):
        impl_class = engines_pkg.ENGINE_IMPLEMENTATIONS[name][0]
        engine = impl_class(pack.rules_by_engine()[name])
        assert isinstance(engine, Engine), f"{name} violates the Engine protocol"
        assert isinstance(engine.name, str) and engine.name == name
        assert isinstance(engine.RULE_IDS, tuple) and engine.RULE_IDS


def test_engine_rule_bindings_cover_pack_bindings(pack) -> None:
    """Every pack rule bound to a registered engine has an implementation."""
    for engine_name, rules in pack.rules_by_engine().items():
        if engine_name not in available_engines():
            continue
        _, implemented = engines_pkg.ENGINE_IMPLEMENTATIONS[engine_name]
        unimplemented = [rule.id for rule in rules if rule.id not in implemented]
        assert not unimplemented, (
            f"pack rules bound to '{engine_name}' lack implementations: {unimplemented}"
        )


# ---------------------------------------------------------------------------
# Exception isolation (D-CRASH / PLAN §0 engine model)
# ---------------------------------------------------------------------------


def test_run_engine_isolates_any_exception() -> None:
    ir = SkillIR(identity=BundleIdentity(name="whatever"))
    boom = TestEngine(message="kaboom")
    produced = run_engine(boom, ir, ScanContext())
    assert len(produced) == 1
    failure = produced[0]
    assert failure.rule_id == CODE_ENGINE_FAILURE
    assert failure.engine == "test_boom"
    assert failure.severity == "LOW"
    assert failure.message == "engine 'test_boom' failed: RuntimeError"
    # Fingerprint binds (engine, exception class) — stable across retries.
    again = run_engine(TestEngine(message="different message"), ir, ScanContext())
    assert again[0].fingerprint == failure.fingerprint


def test_isolation_changes_neither_results_nor_ux(pack, tmp_path) -> None:
    """With one engine replaced by TestEngine: others' output is IDENTICAL
    and scanning completes normally (no exception reaches the caller)."""
    spec_dir = FIXTURES / "malicious" / "stealth-invocation"
    baseline = scan_bundle(spec_dir, pack, home=tmp_path)

    patched = {name: entry for name, entry in engines_pkg.ENGINE_IMPLEMENTATIONS.items()}
    engines_pkg.ENGINE_IMPLEMENTATIONS["manifest"] = (
        TestEngine,
        frozenset(),
    )
    try:
        disrupted = scan_bundle(spec_dir, pack, home=tmp_path)
    finally:
        engines_pkg.ENGINE_IMPLEMENTATIONS.clear()
        engines_pkg.ENGINE_IMPLEMENTATIONS.update(patched)

    # UX: no crash, same result object shape, findings still sorted tuples.
    assert isinstance(disrupted.findings, tuple)
    # Results: every non-manifest finding survives byte-identically.
    isolated = {"LNS-MAN-001", CODE_ENGINE_FAILURE}

    def by_rule(result):
        return [
            json.dumps(f, sort_keys=True) for f in result.findings if f["rule_id"] not in isolated
        ]

    assert by_rule(disrupted) == by_rule(baseline)
    # The isolated engine surfaces exactly one synthetic INFO-tier finding.
    failures = [f for f in disrupted.findings if f["rule_id"] == CODE_ENGINE_FAILURE]
    assert len(failures) == 1
    assert "engine 'manifest' failed: RuntimeError" in failures[0]["message"]


# ---------------------------------------------------------------------------
# Fingerprint stability (SPEC §7 / D-HASH): line shifts never re-key
# ---------------------------------------------------------------------------


def _copy_fixture(src: Path, dest: Path) -> Path:
    import shutil

    shutil.copytree(src, dest)
    return dest


def _fingerprints_by_rule(result) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    for finding in result.findings:
        table.setdefault(str(finding["rule_id"]), []).append(str(finding["fingerprint"]))
    return table


def test_fingerprints_stable_under_ten_blank_lines(pack, tmp_path) -> None:
    src = FIXTURES / "malicious" / "stealth-invocation"
    first = _copy_fixture(src, tmp_path / "before")
    shifted = _copy_fixture(src, tmp_path / "after")
    doc = shifted / "SKILL.md"
    lines = doc.read_text(encoding="utf-8").splitlines(keepends=True)
    doc.write_text("".join(lines[:3]) + "\n" * 10 + "".join(lines[3:]), encoding="utf-8")

    before = scan_bundle(first, pack, home=tmp_path / "home-a")
    after = scan_bundle(shifted, pack, home=tmp_path / "home-b")

    assert _fingerprints_by_rule(before) == _fingerprints_by_rule(after)
    # And the shifted scan actually resolves DIFFERENT line numbers — the
    # stability comes from normalization, not from coincidence.
    before_lines = {
        f["rule_id"]: f["location"]["start_line"]
        for f in before.findings
        if f["location"]["start_line"]
    }
    after_lines = {
        f["rule_id"]: f["location"]["start_line"]
        for f in after.findings
        if f["location"]["start_line"]
    }
    assert before_lines != after_lines


# ---------------------------------------------------------------------------
# Dedup (SPEC §7): collapse on fingerprint, max-5 listed, remainder counted
# ---------------------------------------------------------------------------


def _finding(rule_id: str, fingerprint: str, path: str, line: int):
    from skill_lens.claims import finding_fingerprint
    from skill_lens.engines.base import Finding, Location

    return Finding(
        fingerprint=fingerprint or finding_fingerprint(rule_id, "x", path),
        rule_id=rule_id,
        rule_version="1",
        engine="secretscan",
        title="t",
        capability="credentials.read",
        severity="LOW",
        effective_severity="LOW",
        confidence=0.5,
        evidence_kind="regex",
        static_only=True,
        location=Location(path=path, start_line=line),
    )


def test_dedup_collapses_and_counts_overflow_locations() -> None:
    # One shared fingerprint across 8 sites = exactly the multi-location
    # evidence shape SPEC §7 dedup exists for.
    findings = [_finding("LNS-SEC-002", "shared-fp", "scripts/a.sh", i) for i in range(1, 8)]
    findings.append(_finding("LNS-SEC-002", "shared-fp", "scripts/b.sh", 1))
    ordered = sorted(findings, key=lambda f: (f.rule_id, f.location.path, f.location.start_line))
    merged = dedup_findings(ordered)
    assert len(merged) == 1
    survivor = merged[0]
    assert len(survivor.locations) == 5
    assert survivor.additional_location_count == 3
    paths = [loc.path for loc in survivor.locations]
    assert paths == ["scripts/a.sh"] * 5  # deterministic survivor ordering


def test_dedup_keeps_distinct_fingerprints_separate() -> None:
    findings = [
        _finding("LNS-SEC-001", "", "one.md", 1),
        _finding("LNS-SEC-002", "", "two.md", 2),
    ]
    assert len(dedup_findings(findings)) == 2


# ---------------------------------------------------------------------------
# REGISTRY seam compatibility (D-015 three-arg shape)
# ---------------------------------------------------------------------------


def test_registry_entries_are_three_arg_callables(tmp_path) -> None:
    ir = SkillIR(identity=BundleIdentity(name="empty"))
    diags = type(ir.diagnostics)()
    for name in sorted(REGISTRY):
        produced = REGISTRY[name](ir, (), diags)
        assert produced == []
