"""Golden vectors A-G (SPEC §8.3) — the exact Phase-1 exit oracle.

Eight real fixture bundles under ``corpus/vectors/`` run through the LIVE
pipeline (``scan_bundle`` → ``build_report`` — ingest, claims, engines,
fingerprint dedup, scoring) must reproduce the §8.3 outcomes EXACTLY:

    A=100/A·clean · B=91/A·notice · C=25/F·alert · C′=40/D·warn·needs_review
    D(lab)=85/B·notice · E=80/C·warn · F=83/B·notice · G=70/C·warn

No ±1 tolerance. The expected tuples live in the committed machine-readable
oracle ``corpus/vectors/expected.toml`` (DECISIONS D-028); this suite also
pins the fired rule-id sets and applied ceilings so fixture drift fails
loudly. Further deliverables proven here: engine-registration isolation
(a deliberately-raising engine changes neither vector outcomes nor UX),
and ``/lens scan --json`` byte-stability across repeated runs.
"""

from __future__ import annotations

import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

import pytest

from skill_lens.canonical import canonical_dumps
from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.engines import (
    ENGINE_IMPLEMENTATIONS,
    ScanContext,
    infer_skills_root,
    reset_scan_context,
    run_all,
    scan_bundle,
    set_scan_context,
)
from skill_lens.engines.base import CODE_ENGINE_FAILURE, TestEngine
from skill_lens.render import render_chat_compact
from skill_lens.report import build_report
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = REPO_ROOT / "corpus" / "vectors"
EXPECTED_TOML = VECTORS_DIR / "expected.toml"

#: The eight §8.3 vectors, canonical order.
VECTOR_NAMES: tuple[str, ...] = ("A", "B", "C", "C-prime", "D", "E", "F", "G")


#: Directory slug for a vector name (vector ids may carry "-prime").
def _slug(name: str) -> str:
    return name.lower().replace("-", "")


# ---------------------------------------------------------------------------
# Oracle loading + pipeline runner
# ---------------------------------------------------------------------------


def _load_oracle() -> dict[str, dict[str, Any]]:
    raw = tomllib.loads(EXPECTED_TOML.read_text(encoding="utf-8"))
    vectors = raw.get("vectors")
    assert isinstance(vectors, dict), "expected.toml must carry a [vectors] table"
    assert all(isinstance(key, str) and isinstance(value, dict) for key, value in vectors.items())
    return {str(key): dict(value) for key, value in vectors.items()}


@pytest.fixture(scope="module")
def oracle() -> dict[str, dict[str, Any]]:
    return _load_oracle()


def run_vector(
    name: str,
    tmp_root: Path,
) -> tuple[dict[str, Any], Path]:
    """Copy vector *name* into a categorized home and scan it live."""
    src = VECTORS_DIR / name
    assert (src / "SKILL.md").is_file(), f"vector {name} lacks SKILL.md"
    home = tmp_root / f"home-{_slug(name)}"
    bundle = home / "skills" / "testing" / _slug(name)
    shutil.copytree(src, bundle, dirs_exist_ok=True)
    result = scan_bundle(bundle, home=home)
    profile = str(_load_oracle().get(name, {}).get("profile", "street"))
    envelope = build_report(result, profile=profile)
    return envelope, bundle


# ---------------------------------------------------------------------------
# Deliverable 2 — exact tuples against the live pipeline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", VECTOR_NAMES)
def test_golden_vector_exact_outcome(
    name: str,
    tmp_path: Path,
    oracle: dict[str, dict[str, Any]],
) -> None:
    """(score, grade, verdict, needs_review) — byte-exact, no tolerance."""
    exp = oracle[name]
    envelope, _bundle = run_vector(name, tmp_path)
    score = envelope["score"]

    got = (
        int(score["value"]),
        str(score["grade"]),
        str(score["verdict"]),
        bool(score["needs_review"]),
    )
    want = (int(exp["score"]), str(exp["grade"]), str(exp["verdict"]), bool(exp["needs_review"]))
    assert got == want, f"vector {name}: {got} != §8.3 oracle {want}"

    fired = sorted({str(f["rule_id"]) for f in envelope["findings"]})
    assert fired == sorted(str(r) for r in exp["rules"]), f"vector {name}: fired rules drifted"

    ceilings = sorted(str(c) for c in score["ceilings_applied"])
    assert ceilings == sorted(str(c) for c in exp["ceilings"]), (
        f"vector {name}: applied ceilings drifted"
    )


def test_oracle_covers_exactly_the_eight_vectors(oracle: dict[str, dict[str, Any]]) -> None:
    """The committed oracle and the fixture tree agree on the vector set."""
    on_disk = sorted(p.name for p in VECTORS_DIR.iterdir() if p.is_dir())
    assert on_disk == sorted(VECTOR_NAMES)
    assert sorted(oracle) == sorted(VECTOR_NAMES)


def test_vector_dirs_are_ingestible_bundles(oracle: dict[str, dict[str, Any]]) -> None:
    """Every vector is a categorized-layout-compatible bundle on its own."""
    for name in VECTOR_NAMES:
        src = VECTORS_DIR / name
        text = (src / "SKILL.md").read_text(encoding="utf-8")
        assert text.startswith("---"), f"vector {name} lacks frontmatter block"


# ---------------------------------------------------------------------------
# Deliverable 3 — isolation clause: a raising engine changes nothing
# ---------------------------------------------------------------------------


def test_registered_raising_engine_changes_neither_outcomes_nor_ux(tmp_path: Path) -> None:
    """Registering TestEngine ALONGSIDE the real engines is inert.

    Registration alone binds no pack rules to the new slot, so every
    vector's canonical envelope stays byte-identical and the scan UX is
    untouched — registration can never perturb results by itself.
    """
    baseline: dict[str, str] = {}
    for name in VECTOR_NAMES:
        envelope, _bundle = run_vector(name, tmp_path)
        baseline[name] = canonical_dumps(envelope)

    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(ENGINE_IMPLEMENTATIONS, "test_boom", (TestEngine, frozenset()))
        for name in VECTOR_NAMES:
            envelope, _bundle = run_vector(name, tmp_path)
            assert canonical_dumps(envelope) == baseline[name], (
                f"vector {name} changed when a raising engine was registered"
            )


def test_raising_engine_with_bound_rules_is_contained(tmp_path: Path) -> None:
    """Even when the pack BINDS rules to a crashing engine: contained.

    The crash collapses to exactly one synthetic ``LNS-ENG-000`` finding;
    every other engine's findings survive byte-identically; the report
    still builds and still renders compact chat output (UX intact).
    """
    home = tmp_path / "home-boom"
    bundle = home / "skills" / "testing" / "boom_target"
    shutil.copytree(VECTORS_DIR / "C", bundle)
    ir_bundle = scan_bundle(bundle, home=home).ir

    pack = load_core_pack()
    grouped = pack.rules_by_engine()
    ctx = ScanContext(bundle_root=bundle, skills_root=infer_skills_root(bundle))

    token = set_scan_context(ctx)
    try:
        baseline = run_all(ir_bundle, grouped, DiagnosticsCollector(), ctx=ctx)
        bound = {"test_boom": (grouped.get("manifest", ()) or ())}
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(ENGINE_IMPLEMENTATIONS, "test_boom", (TestEngine, frozenset("*")))
            disrupted = run_all(ir_bundle, {**grouped, **bound}, DiagnosticsCollector(), ctx=ctx)
    finally:
        reset_scan_context(token)

    failures = [f for f in disrupted if f["rule_id"] == CODE_ENGINE_FAILURE]
    assert len(failures) == 1, "a crashing engine yields exactly one synthetic finding"
    assert "engine 'test_boom' failed: RuntimeError" in str(failures[0]["message"])

    def others(findings: list[dict[str, Any]]) -> list[str]:
        return [
            json.dumps(f, sort_keys=True) for f in findings if f["rule_id"] != CODE_ENGINE_FAILURE
        ]

    assert others(disrupted) == others(baseline), "real-engine evidence must survive verbatim"

    # UX: the disrupted scan STILL produces a full report and a render.
    from skill_lens.engines import ScanResult as RealScanResult

    result = RealScanResult(
        ir=ir_bundle,
        findings=tuple(disrupted),
        diagnostics=DiagnosticsCollector(),
        rule_pack_name=pack.name,
        rule_pack_version=pack.version,
        rule_pack_checksum=pack.content_checksum(),
    )
    envelope = build_report(result)
    assert isinstance(envelope["score"], dict)
    text = render_chat_compact(envelope, plugin_data_dir=tmp_path)
    assert text.strip(), "compact render must survive an isolated engine crash"


# ---------------------------------------------------------------------------
# Deliverable 4 — /lens scan --json byte-stability (envelope only)
# ---------------------------------------------------------------------------


def test_slash_scan_json_byte_stable_across_runs(tmp_path: Path) -> None:
    """/lens scan --json twice ⇒ identical bytes; no _meta inside."""
    from skill_lens.cache import FastPathCache
    from skill_lens.context import PluginContextView
    from skill_lens.slash import make_handler

    _envelope, bundle = run_vector("C", tmp_path)

    view = PluginContextView(FakeCtxForSlash(tmp_path))
    handler = make_handler(view, FastPathCache())

    first = handler(f"scan {bundle} --json --no-cache")
    second = handler(f"scan {bundle} --json --no-cache")
    assert isinstance(first, str) and first.startswith("```json")
    assert first == second, "--json output must be byte-stable across runs"
    body = first.removeprefix("```json\n").removesuffix("\n```")
    assert "_meta" not in body and "generated_at" not in body


class FakeCtxForSlash:
    """Minimal host-context double: only plugin-data state is needed here."""

    def __init__(self, data_root: Path) -> None:
        self.manifest = type("M", (), {"key": "lens", "name": "lens", "version": "0.9.0a0"})()
        self.plugin_id = "lens"
        self._state_dir = data_root / "plugin-data" / "lens"
        self._state_dir.mkdir(parents=True, exist_ok=True)

    @property
    def state(self):  # pragma: no cover - attribute shape only
        return type("S", (), {"data_dir": self._state_dir})()


# ---------------------------------------------------------------------------
# Cross-checks against the scoring-phase reference table
# ---------------------------------------------------------------------------


def test_expected_toml_agrees_with_scoring_v2_reference() -> None:
    """The oracle matches corpus/vectors/scoring-v2.json (scoring phase)."""
    ref = json.loads((VECTORS_DIR / "scoring-v2.json").read_text(encoding="utf-8"))
    oracle = _load_oracle()
    for name in VECTOR_NAMES:
        entry = ref[name]
        exp = oracle[name]
        assert entry["score"] == exp["score"], name
        assert entry["grade"] == exp["grade"], name
        assert entry["verdict"] == exp["verdict"], name
        assert entry["needs_review"] == exp["needs_review"], name
