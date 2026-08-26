"""Golden-fixture corpus harness (SPEC §15 / PLAN §3 testing strategy).

The corpus lives at ``<repo>/corpus/fixtures/<malicious|benign>/<name>/``.
Each fixture is a REAL skill bundle (SKILL.md + payload files) ingested
through the production path — never a hand-built IR — dogfooding
:mod:`skill_lens.ingest` per PLAN Phase 1/3.

Harness flow per fixture (:func:`run_case`):

1. Build a throwaway Hermes home ``<tmp>/skills/<category>/<name>/`` from
   the fixture (categorized layout; ``category`` comes from expected.toml,
   default ``testing``). Optional ``companions/<bundle>`` subdirectories are
   copied in as sibling bundles so rules about cross-bundle resolution
   (e.g. LNS-MAN-005 related_skills) test both ways.
2. Discover + load through :func:`skill_lens.ingest.discover_bundles` /
   :func:`load_bundle` with that home.
3. Dispatch engines over the immutable IR via the engine seam and collect
   findings sorted by ``(rule_id, path, start_line)`` (DETERMINISM LAW).

Engine seam contract (filled by later Phase-1 implementers; DECISIONS
D-015): a module ``skill_lens.engines`` exposing either

- ``REGISTRY: dict[str, Callable[[SkillIR, tuple[Rule, ...],
  DiagnosticsCollector], list[dict]]]`` keyed by engine name, or
- ``run_all(ir, rules_by_engine, diagnostics) -> list[dict]`` performing the
  orchestrated, exception-isolated dispatch (D-CRASH) itself.

Findings are plain §7-shaped mappings carrying at least ``rule_id``,
``severity``, and ``location`` (``path``/``start_line``). Until that module
exists, scans simply yield zero findings and corpus tests xfail per rule
with reason "engine not implemented yet" — nothing else changes shape.

expected.toml keys (DECISIONS D-013; SPEC does not pin them)::

    category         = "tools"        # optional; install-dir placement
    expect_verdict   = "alert"        # FUTURE: checked once scoring lands
    expect_grade     = "F"            # FUTURE
    expect_score_max = 25             # FUTURE

    [[expect_rules]]                  # malicious only: MUST fire
    rule_id        = "LNS-NET-011"
    severity_band  = ["CRITICAL"]     # optional accepted tiers

Benign fixtures declare no ``[[expect_rules]]`` and must fire NOTHING from
the core pack. Authoring convention (D-013): benign descriptions state
concrete capabilities so the future LNS-MAN-004 vague-description finding
never fires on them.

DETERMINISM LAW: fixture discovery is sorted; no wall-clock anywhere; the
harness adds no timestamps to results.
"""

from __future__ import annotations

import importlib
import shutil
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from .diagnostics import (
    SEVERITY_INFO,
    DiagnosticsCollector,
)
from .engines.base import (
    ScanContext,
    infer_skills_root,
    reset_scan_context,
    set_scan_context,
)
from .ingest import discover_bundles, load_bundle
from .ir import SkillIR
from .rules import SEVERITY_TIERS, Rule, RulePack, load_core_pack

#: Stable diagnostic codes for the corpus subsystem.
CODE_CORPUS_MANIFEST = "LNS-CORPUS-MANIFEST"  # expected.toml problems
CODE_CORPUS_ENGINE_FAIL = "LNS-CORPUS-ENGINE-FAIL"  # engine raised (isolated)

FIXTURES_DIRNAME = "fixtures"
CLASS_MALICIOUS = "malicious"
CLASS_BENIGN = "benign"
CLASSES: tuple[str, ...] = (CLASS_MALICIOUS, CLASS_BENIGN)

EXPECTED_TOML = "expected.toml"
COMPANIONS_DIRNAME = "companions"
DEFAULT_CATEGORY = "testing"

# expected.toml vocabulary: current keys + reserved future keys (parsed,
# stored, unchecked until the scoring phase lands).
_FUTURE_KEYS = ("expect_verdict", "expect_grade", "expect_score_max")


@dataclass(frozen=True)
class Expectation:
    """One ``[[expect_rules]]`` entry."""

    rule_id: str
    severity_band: tuple[str, ...] = ()  # empty = any tier accepted


@dataclass(frozen=True)
class FixtureSpec:
    """One discovered fixture case, ready to run."""

    name: str
    klass: str  # CLASS_MALICIOUS | CLASS_BENIGN
    path: Path
    category: str
    expects: tuple[Expectation, ...]
    companions: tuple[str, ...]
    future: dict[str, Any] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        return self.klass == CLASS_MALICIOUS


@dataclass(frozen=True)
class CaseResult:
    """Outcome of scanning one fixture through the full pipeline."""

    spec: FixtureSpec
    ir: SkillIR
    findings: tuple[dict[str, Any], ...]
    diagnostics: DiagnosticsCollector

    def fired_rule_ids(self) -> set[str]:
        return {str(f.get("rule_id")) for f in self.findings if f.get("rule_id")}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def find_corpus_root(start: Path | str | None = None) -> Path | None:
    """Walk up from *start* (default cwd) looking for ``corpus/fixtures``.

    Keeps tests and tools honest about repo layout without hardcoding an
    absolute path. Returns ``None`` when nothing matches.
    """
    probe = Path(start) if start is not None else Path.cwd()
    probe = probe.resolve()
    for candidate in (probe, *probe.parents):
        root = candidate / "corpus" / FIXTURES_DIRNAME
        if root.is_dir():
            return root
    return None


def discover_fixtures(corpus_root: Path | str) -> tuple[FixtureSpec, ...]:
    """Parse every ``<class>/<name>/expected.toml`` into specs (sorted).

    Missing or malformed expected.toml yields a warning diagnostic on the
    returned collector wrapper rather than an exception — but fixtures
    WITHOUT a parsable manifest are still returned so CI can demand one
    (see :func:`evaluate_case` failing closed).
    """
    root = Path(corpus_root)
    specs: list[FixtureSpec] = []
    for klass in CLASSES:
        class_dir = root / klass
        if not class_dir.is_dir():
            continue
        for fixture_dir in sorted(p for p in class_dir.iterdir() if p.is_dir()):
            diags = DiagnosticsCollector()
            manifest_path = fixture_dir / EXPECTED_TOML
            raw = _read_expected_toml(manifest_path, diags=diags)
            category = DEFAULT_CATEGORY
            if isinstance(raw.get("category"), str) and raw["category"].strip():
                category = raw["category"].strip()
            future = {key: raw[key] for key in _FUTURE_KEYS if key in raw}
            companions_dir = fixture_dir / COMPANIONS_DIRNAME
            companions: tuple[str, ...] = ()
            if companions_dir.is_dir():
                companions = tuple(sorted(p.name for p in companions_dir.iterdir() if p.is_dir()))
            expects: list[Expectation] = []
            for entry in raw.get("expect_rules", []):
                band_raw = entry.get("severity_band", [])
                band = (
                    tuple(str(t) for t in band_raw if str(t) in SEVERITY_TIERS)
                    if isinstance(band_raw, list)
                    else ()
                )
                expects.append(
                    Expectation(
                        rule_id=str(entry.get("rule_id", "")),
                        severity_band=band,
                    )
                )
            specs.append(
                FixtureSpec(
                    name=fixture_dir.name,
                    klass=klass,
                    path=fixture_dir,
                    category=category,
                    expects=tuple(expects),
                    companions=companions,
                    future=dict(future),
                )
            )
            del diags  # discovery-time problems resurface at evaluate time
    return tuple(sorted(specs, key=lambda s: (s.klass, s.name)))


def _read_expected_toml(
    path: Path,
    *,
    diags: DiagnosticsCollector,
) -> dict[str, Any]:
    """Read expected.toml tolerantly; unknown keys warn (forward compat)."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        diags.warning(CODE_CORPUS_MANIFEST, "fixture lacks expected.toml", path=str(path))
        return {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as exc:
        diags.warning(
            CODE_CORPUS_MANIFEST,
            f"expected.toml unparsable: {exc}",
            path=str(path),
        )
        return {}
    known = {"category", "expect_rules", *_FUTURE_KEYS}
    for key in sorted(set(data) - known):
        diags.warning(
            CODE_CORPUS_MANIFEST,
            f"unknown expected.toml key tolerated: {key}",
            path=str(path),
            detail={"key": key},
        )
    rules = data.get("expect_rules", [])
    if not isinstance(rules, list):
        diags.warning(
            CODE_CORPUS_MANIFEST,
            "'expect_rules' must be an array of tables",
            path=str(path),
        )
        data["expect_rules"] = []
    else:
        cleaned = []
        for entry in rules:
            if not isinstance(entry, dict) or not entry.get("rule_id"):
                diags.warning(
                    CODE_CORPUS_MANIFEST,
                    "expect_rules entry missing 'rule_id'",
                    path=str(path),
                )
                continue
            cleaned.append(entry)
        data["expect_rules"] = cleaned
    return data


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def prepare_home(spec: FixtureSpec, tmp_root: Path | str) -> Path:
    """Materialize the categorized-layout Hermes home for *spec*.

    Layout::

        <tmp>/skills/<category>/<name>/        <- fixture payload
        <tmp>/skills/<category>/<companion>/   <- resolution siblings

    ``expected.toml``, ``companions/``, and dot-entries are excluded from the
    bundle payload itself. Purely additive; safe to call repeatedly.
    """
    tmp_root = Path(tmp_root)
    bundle_dir = tmp_root / "skills" / spec.category / spec.name
    bundle_dir.mkdir(parents=True, exist_ok=True)
    excluded = {EXPECTED_TOML, COMPANIONS_DIRNAME}
    for entry in sorted(spec.path.iterdir()):
        if entry.name.startswith(".") or entry.name in excluded:
            continue
        dest = bundle_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, dest)
    companions_dir = spec.path / COMPANIONS_DIRNAME
    if companions_dir.is_dir():
        for companion in sorted(p for p in companions_dir.iterdir() if p.is_dir()):
            dest = tmp_root / "skills" / spec.category / companion.name
            shutil.copytree(companion, dest, dirs_exist_ok=True)
    return tmp_root


def _load_engines_module() -> ModuleType | None:
    """Dynamically probe the optional ``skill_lens.engines`` seam.

    Dynamic import (not a static ``from`` import) is deliberate: the module
    does not exist until a later Phase-1 implementer lands it, and optional
    seams must never hard-fail analysis or runtime.
    """
    try:
        return importlib.import_module(f"{__package__ or 'skill_lens'}.engines")
    except ImportError:
        return None


def _load_claims_module() -> ModuleType | None:
    """Probe the claims module (same dynamic-probe discipline as engines)."""
    try:
        return importlib.import_module(f"{__package__ or 'skill_lens'}.claims")
    except ImportError:  # pragma: no cover - ships with the package
        return None


def claim_stage_rule_ids() -> frozenset[str]:
    """Rule ids hosted by the claims stage right now (DECISIONS D-020).

    Until the bound engine registers in ``skill_lens.engines``, these rules
    are detected by the claims stage, so corpus expectations for them are
    live gates rather than engine-absence xfails.
    """
    module = _load_claims_module()
    ids = getattr(module, "CLAIM_STAGE_RULE_IDS", None)
    if isinstance(ids, (frozenset, set)):
        return frozenset(str(rule_id) for rule_id in ids)
    return frozenset()


def available_engines() -> frozenset[str]:
    """Names of engine implementations present right now (probe seam).

    Probing is deliberately lazy and failure-tolerant: until some Phase-1
    implementer creates ``skill_lens.engines``, this returns the empty set
    and every dependent corpus assertion xfails instead of erroring.
    """
    engines_module = _load_engines_module()
    if engines_module is None:
        return frozenset()
    registry = getattr(engines_module, "REGISTRY", None)
    if isinstance(registry, dict):
        return frozenset(str(key) for key in registry)
    return frozenset()


@dataclass(frozen=True)
class _DispatchEntry:
    """One seam callable: a per-engine fn or the ``__all__`` orchestrator.

    The two shapes take different second arguments (rules tuple vs the full
    rules-by-engine mapping), so they share a dynamically-checked alias and
    the dispatch site branches on ``engine_name``. Contract enforcement lives
    in tests/test_corpus.py seam-simulation tests, which is where shape bugs
    actually bite.
    """

    engine_name: str  # "__all__" marks an orchestrator (run_all)
    fn: Callable[..., list[dict]]


def _resolve_engine_fns(
    rules_by_engine: dict[str, tuple[Rule, ...]],
) -> list[_DispatchEntry]:
    """Deterministic dispatch plan from the optional engines seam."""
    engines_module = _load_engines_module()
    if engines_module is None:
        return []

    runner = getattr(engines_module, "run_all", None)
    if callable(runner):
        return [_DispatchEntry("__all__", cast(Callable[..., list[dict]], runner))]

    registry = getattr(engines_module, "REGISTRY", None)
    if isinstance(registry, dict):
        plan: list[_DispatchEntry] = []
        for engine_name in sorted(rules_by_engine):
            fn = registry.get(engine_name)
            if callable(fn):
                plan.append(_DispatchEntry(engine_name, cast(Callable[..., list[dict]], fn)))
        return plan
    return []


def run_case(
    spec: FixtureSpec,
    *,
    tmp_root: Path | str,
    pack: RulePack | None = None,
) -> CaseResult:
    """Ingest + engine-dispatch one fixture. Never raises into callers.

    Engine faults are exception-isolated per engine call (D-CRASH spirit):
    they become ``LNS-CORPUS-ENGINE-FAIL`` diagnostics and the remaining
    engines continue.
    """
    active_pack = pack if pack is not None else load_core_pack()
    home = prepare_home(spec, tmp_root)

    refs = discover_bundles(home)
    target_ref = next((ref for ref in refs if ref.name == spec.name), None)
    if target_ref is None:  # defensive: prepare_home guarantees placement
        target_ref = next(iter(refs), None)

    diags = DiagnosticsCollector()
    if target_ref is None:
        ir = load_bundle(home / "skills" / spec.category / spec.name, home=home, diagnostics=diags)
    else:
        ir = load_bundle(target_ref.path, home=target_ref.path.parents[2], diagnostics=diags)

    findings: list[dict[str, Any]] = []
    grouped = active_pack.rules_by_engine()
    plan = _resolve_engine_fns(grouped)
    covered_engines = {entry.engine_name for entry in plan}
    has_orchestrator = "__all__" in covered_engines
    # Real-world seams for engines (line-resolved evidence, related_skills
    # resolution): bundle dir + enclosing skills tree when they exist.
    context_token = set_scan_context(
        ScanContext(
            bundle_root=target_ref.path if target_ref is not None else None,
            skills_root=(infer_skills_root(target_ref.path) if target_ref is not None else None),
        )
    )
    try:
        for entry in plan:
            try:
                if entry.engine_name == "__all__":
                    # Orchestrated dispatch: run_all owns the full mapping
                    # (contract D-015) and performs per-engine isolation itself.
                    produced = entry.fn(ir, grouped, diags)
                else:
                    produced = entry.fn(ir, grouped.get(entry.engine_name, ()), diags)
            except Exception as exc:  # noqa: BLE001 — isolation IS the contract
                diags.record(
                    CODE_CORPUS_ENGINE_FAIL,
                    f"engine {entry.engine_name!r} failed: {exc.__class__.__name__}: {exc}",
                    severity=SEVERITY_INFO,
                    path=f"{spec.klass}/{spec.name}",
                )
                continue
            if produced:
                findings.extend(dict(item) for item in produced)
    finally:
        reset_scan_context(context_token)
    if not has_orchestrator:
        findings.extend(_run_claim_stage_fallback(ir, active_pack, covered_engines, spec, diags))
    findings.sort(key=_finding_sort_key)
    return CaseResult(spec=spec, ir=ir, findings=tuple(findings), diagnostics=diags)


def _run_claim_stage_fallback(
    ir: SkillIR,
    pack: RulePack,
    covered_engines: set[str],
    spec: FixtureSpec,
    diags: DiagnosticsCollector,
) -> list[dict[str, Any]]:
    """Interim hosting: rules whose engine is absent run via the claims stage.

    Once an engine registers for a rule, the stage stops routing it here —
    ownership transfers with zero double emission and no test edits
    (DECISIONS D-020). Faults are isolated exactly like engine faults.
    """
    pending = tuple(rule for rule in pack.rules if rule.engine not in covered_engines)
    if not pending:
        return []
    claims_module = _load_claims_module()
    runner = getattr(claims_module, "run_claim_stage", None) if claims_module else None
    if not callable(runner):
        return []
    stage_fn = cast(Callable[..., Any], runner)
    try:
        produced = [dict(item) for item in stage_fn(ir, pending, diags) or ()]
    except Exception as exc:  # noqa: BLE001 — isolation IS the contract
        diags.record(
            CODE_CORPUS_ENGINE_FAIL,
            f"claims stage failed: {exc.__class__.__name__}: {exc}",
            severity=SEVERITY_INFO,
            path=f"{spec.klass}/{spec.name}",
        )
        return []
    return [dict(item) for item in produced]


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = finding.get("location") or {}
    return (
        str(finding.get("rule_id", "")),
        str(location.get("path", "")),
        location.get("start_line", 0) if isinstance(location.get("start_line", 0), int) else 0,
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_case(result: CaseResult) -> tuple[str, ...]:
    """Return human-readable problems for a finished case (empty = pass).

    Malicious: every expected rule_id must be present; when a severity band
    is declared, the finding's rule-assigned severity must be inside it.
    Benign: NO core-pack finding may appear at all. The fixture manifest is
    re-read STRICTLY here so missing/malformed expected.toml fails the case
    closed (merge blocker, never a silent pass).
    """
    problems: list[str] = []
    label = f"{result.spec.klass}/{result.spec.name}"
    manifest_diags = DiagnosticsCollector()
    _read_expected_toml(result.spec.path / EXPECTED_TOML, diags=manifest_diags)
    for diag in manifest_diags.snapshot():
        if diag.severity in ("warning", "error"):
            problems.append(f"{label}: {diag.message}")
    fired = result.fired_rule_ids()
    if result.spec.is_malicious:
        if not result.spec.expects:
            problems.append(f"{label}: malicious fixture declares no expect_rules")
        for expectation in result.spec.expects:
            if expectation.rule_id not in fired:
                problems.append(f"{label}: expected {expectation.rule_id} did not fire")
                continue
            if expectation.severity_band:
                severities = {
                    str(f.get("severity"))
                    for f in result.findings
                    if f.get("rule_id") == expectation.rule_id
                }
                if not severities & set(expectation.severity_band):
                    problems.append(
                        f"{label}: {expectation.rule_id} severity "
                        f"{sorted(severities)} outside band "
                        f"{sorted(expectation.severity_band)}"
                    )
    else:
        unexpected = sorted(fired)
        if unexpected:
            problems.append(f"{label}: benign fixture fired core-pack rules: {unexpected}")
    return tuple(problems)


__all__ = [
    "CASE_RESULT_DOC",
    "CaseResult",
    "Expectation",
    "FixtureSpec",
    "available_engines",
    "claim_stage_rule_ids",
    "discover_fixtures",
    "evaluate_case",
    "find_corpus_root",
    "prepare_home",
    "run_case",
]


#: Re-exported doc anchor so help() shows the seam contract alongside code.
CASE_RESULT_DOC = CaseResult.__doc__
