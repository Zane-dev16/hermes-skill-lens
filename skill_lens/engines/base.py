"""Engine foundations — protocol, isolation, context, findings (SPEC §4/§6/§7).

Every detection engine is an in-process object behind one protocol
(D-PROC/D-CRASH):

- ``name`` — the §4 catalog binding (must match ``Rule.engine`` tokens);
- ``RULE_IDS`` — the rule ids this implementation owns (bindings are data;
  a pack rule bound to this engine but absent from ``RULE_IDS`` is reported
  as an unimplemented-binding diagnostic rather than silently silent);
- ``scan(bundle_ir, ctx) -> list[Finding]`` — pure static analysis over the
  immutable IR. Engines NEVER execute bundle content, open sockets, or read
  wall-clock time.

Exception isolation (:func:`run_engine`): ANY exception escaping
``engine.scan`` collapses to ONE synthetic INFO finding ``LNS-ENG-000``
naming the engine ("engine '<id>' failed: <class>") — one crashing engine
cannot fail a scan, and the honest caveat stands: this covers Python
exceptions only, not native crashes (SPEC §6 D-PROC caveat).

:class:`ScanContext` carries the optional real-filesystem seams engines may
need (bundle directory, sibling skills tree, in-memory zip members). It is
threaded through a :mod:`contextvars` slot so the corpus harness's 3-arg
seam contract (DECISIONS D-015) stays byte-compatible while orchestrated
callers (:func:`skill_lens.engines.scan_bundle`) can supply richer context.

DETERMINISM LAW honored throughout: findings sort by
``(rule_id, path, start_line)``; fingerprints exclude line numbers and
absolute paths; no timestamps anywhere (they belong to the ``_meta``
sidecar only).
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ..claims import finding_fingerprint
from ..diagnostics import SEVERITY_INFO, DiagnosticsCollector
from ..ir import FileRecord, SkillIR

if TYPE_CHECKING:  # import cycle safety: rules is data-only but heavy to load
    from ..rules import Rule

#: Stable codes/names for the engine sub-system.
CODE_ENGINE_FAILURE = "LNS-ENG-000"  # synthetic isolation finding (D-CRASH)
CODE_ENGINE_UNIMPLEMENTED = "LNS-ENG-001"  # pack rule bound to an engine that lacks it

#: Synthetic-failure findings ride the lowest scoring tier so an isolated
#: crash is VISIBLE without inventing an off-rubric severity (DECISIONS
#: D-021: "INFO" semantics live in the message + diagnostic; the severity
#: enum stays CRITICAL|HIGH|MEDIUM|LOW per SPEC §7).
FAILURE_SEVERITY = "LOW"

FAILURE_CAPABILITY = "integrity.override"
FAILURE_EVIDENCE_KIND = "manifest"

#: Mirrors the ingest single-file projection ceiling: engines never re-read
#: more of a file than ingest recorded (partial files stay partial).
_MAX_FILE_READ_BYTES = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Scan context (threaded via contextvars; explicit passing preferred)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanContext:
    """Optional real-world seams engines MAY consult, never require.

    ``bundle_root`` — real directory of the bundle (dir scans only); lets
    engines quote exact frontmatter lines. ``skills_root`` — the scanned
    ``<home>/skills`` tree enabling cross-bundle resolution (LNS-MAN-005
    related_skills lookups). ``files`` — in-memory member bytes for zip
    scans keyed by IR rel-path. Every field degrades to ``None``: engines
    must produce their best evidence without context (line numbers become
    ``None``, references count as unresolved per the rule detections).
    """

    bundle_root: Path | None = None
    skills_root: Path | None = None
    files: Mapping[str, bytes] | None = None


_CURRENT_CONTEXT: contextvars.ContextVar[ScanContext | None] = contextvars.ContextVar(
    "skill-lens-scan-context", default=None
)


def set_scan_context(ctx: ScanContext) -> contextvars.Token[ScanContext | None]:
    """Install *ctx* for the current thread/task; returns a reset token."""
    return _CURRENT_CONTEXT.set(ctx)


def reset_scan_context(token: contextvars.Token[ScanContext | None]) -> None:
    """Restore the previous context slot (always called in ``finally``)."""
    _CURRENT_CONTEXT.reset(token)


def current_context() -> ScanContext:
    """The ambient context, or an empty one when nobody installed any."""
    ctx = _CURRENT_CONTEXT.get()
    return ctx if ctx is not None else ScanContext()


def infer_skills_root(path: Path | str) -> Path | None:
    """Nearest enclosing directory literally named ``skills`` (heuristic).

    Works for categorized homes (``<home>/skills/<category>/<name>``), flat
    placements, and quarantine corridors alike. Returns ``None`` when no
    ancestor qualifies — engines then treat chains as unresolved (the rule
    detections' stated fallback).
    """
    probe = Path(path).expanduser()
    try:
        probe = probe.resolve()
    except OSError:  # pragma: no cover — pathological filesystems only
        probe = probe.absolute()
    for ancestor in probe.parents:
        if ancestor.name == "skills":
            return ancestor
    return None


# ---------------------------------------------------------------------------
# Content access (IR-driven; context supplies bytes, never discovery)
# ---------------------------------------------------------------------------


def read_bundle_file(ir: SkillIR, ctx: ScanContext, rel_path: str) -> bytes | None:
    """Bytes for one IR-recorded file, or ``None`` when unavailable.

    In-memory ``ctx.files`` wins (zip scans); otherwise the file is read
    from ``ctx.bundle_root`` capped at the ingest projection ceiling. Never
    raises; never discovers files the IR does not record.
    """
    del ir  # symmetry: callers pass the scan's IR; discovery stays IR-driven
    if ctx.files is not None:
        data = ctx.files.get(rel_path)
        return data[:_MAX_FILE_READ_BYTES] if data is not None else None
    if ctx.bundle_root is None:
        return None
    candidate = ctx.bundle_root / rel_path
    try:
        if not candidate.is_file():
            return None
        with open(candidate, "rb") as fh:
            return fh.read(_MAX_FILE_READ_BYTES + 1)[:_MAX_FILE_READ_BYTES]
    except OSError:
        return None


def iter_text_files(ir: SkillIR, ctx: ScanContext) -> Iterator[tuple[FileRecord, str]]:
    """Yield ``(record, text)`` for every decodable IR file, in IR order.

    ``ir.files`` is already sorted by path (ingest law), keeping engine
    iteration byte-stable. Binary records are skipped (hash-only per the
    decode ladder); undecodable bytes decode lossily so structural scanning
    still proceeds, mirroring ingest tolerance.
    """
    for record in ir.files:
        if record.encoding == "binary":
            continue
        data = read_bundle_file(ir, ctx, record.path)
        if data is None:
            continue
        yield record, data.decode("utf-8", errors="replace")


def manifest_rel_path(ir: SkillIR) -> str:
    """Shallowest SKILL.md rel-path (same resolution rule as ingest)."""
    best: tuple[int, str] | None = None
    for record in ir.files:
        if record.path.rsplit("/", 1)[-1] == "SKILL.md":
            depth_key = (record.path.count("/"), record.path)
            if best is None or depth_key < best:
                best = depth_key
    return best[1] if best is not None else "SKILL.md"


def read_skill_md_text(ir: SkillIR, ctx: ScanContext) -> str | None:
    """Raw SKILL.md text for line-resolved evidence (``None`` tolerated)."""
    data = read_bundle_file(ir, ctx, manifest_rel_path(ir))
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Finding model (SPEC §7 schema, normative key set)
# ---------------------------------------------------------------------------


def claimed_capability_paths(bundle_ir: SkillIR) -> list[str]:
    """Declared capability paths on the IR (empty when nothing is claimed).

    Shared input for the §8.2 ``declared`` ×0.5 modifier: engines flag
    findings whose capability a field-direct claim already covers
    (:func:`skill_lens.claims.is_declared` semantics, D-018). Deterministic:
    claims are IR-ordered.
    """
    return [claim.capability for claim in bundle_ir.claims]


@dataclass(frozen=True)
class Location:
    """One evidence location; ``snippet`` is already surface-safe."""

    path: str
    start_line: int | None
    end_line: int | None = None
    snippet: str = ""
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "redacted": self.redacted,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Location:
        start = raw.get("start_line")
        end = raw.get("end_line")
        return cls(
            path=str(raw.get("path", "")),
            start_line=start if isinstance(start, int) else None,
            end_line=end if isinstance(end, int) else None,
            snippet=str(raw.get("snippet", "")),
            redacted=bool(raw.get("redacted", False)),
        )


@dataclass(frozen=True)
class Finding:
    """§7-shaped finding (typed core; :meth:`to_dict` is the wire form).

    ``id`` stays empty until the report layer numbers findings ``F-N``
    sequentially (scan pipeline duty — engines never number). ``locations``
    carries dedup-attached evidence sites (max 5 listed per SPEC §7);
    ``additional_location_count`` counts the remainder.
    """

    fingerprint: str
    rule_id: str
    rule_version: str
    engine: str
    title: str
    capability: str
    severity: str
    effective_severity: str
    confidence: float
    evidence_kind: str
    static_only: bool
    declared: bool = False
    overreach: bool = False
    location: Location = field(default_factory=lambda: Location(path="", start_line=None))
    claim_ref: str | None = None
    message: str = ""
    remediation: str = ""
    tags: tuple[str, ...] = ()
    suppressed: bool = False
    suppressed_by: str | None = None
    llm_touched: bool = False
    id: str = ""
    locations: tuple[Location, ...] = ()
    additional_location_count: int = 0
    #: Additive engine-supplied machine detail (E8 depintel package refs).
    #: Serialized ONLY when non-empty so every other finding keeps its
    #: historical §7 wire shape byte-exact (report/1 additive-growth law).
    detail: tuple[dict[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "engine": self.engine,
            "title": self.title,
            "capability": self.capability,
            "severity": self.severity,
            "effective_severity": self.effective_severity,
            "confidence": self.confidence,
            "evidence_kind": self.evidence_kind,
            "static_only": self.static_only,
            "declared": self.declared,
            "overreach": self.overreach,
            "location": self.location.to_dict(),
            "locations": [loc.to_dict() for loc in self.locations] or [self.location.to_dict()],
            "additional_location_count": self.additional_location_count,
            "claim_ref": self.claim_ref,
            "message": self.message,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "suppressed": self.suppressed,
            "suppressed_by": self.suppressed_by,
            "llm_touched": self.llm_touched,
        }
        if self.detail:  # additive key only when set — wire shape stays byte-exact
            payload["detail"] = [dict(item) for item in self.detail]
        return payload

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Finding:
        """Tolerant import of a §7-shaped mapping (claims-stage handoffs)."""
        loc_raw = raw.get("location") or {}
        locations_raw = raw.get("locations") or []
        locations = tuple(Location.from_dict(item) for item in locations_raw)
        return cls(
            fingerprint=str(raw.get("fingerprint", "")),
            rule_id=str(raw.get("rule_id", "")),
            rule_version=str(raw.get("rule_version", "")),
            engine=str(raw.get("engine", "")),
            title=str(raw.get("title", "")),
            capability=str(raw.get("capability", "")),
            severity=str(raw.get("severity", "")),
            effective_severity=str(raw.get("effective_severity", raw.get("severity", ""))),
            confidence=float(raw.get("confidence", 0.0)),
            evidence_kind=str(raw.get("evidence_kind", "")),
            static_only=bool(raw.get("static_only", False)),
            declared=bool(raw.get("declared", False)),
            overreach=bool(raw.get("overreach", False)),
            location=Location.from_dict(loc_raw),
            claim_ref=raw.get("claim_ref") if isinstance(raw.get("claim_ref"), str) else None,
            message=str(raw.get("message", "")),
            remediation=str(raw.get("remediation", "")),
            tags=tuple(str(t) for t in raw.get("tags", ())),
            suppressed=bool(raw.get("suppressed", False)),
            suppressed_by=(
                raw.get("suppressed_by") if isinstance(raw.get("suppressed_by"), str) else None
            ),
            llm_touched=bool(raw.get("llm_touched", False)),
            id=str(raw.get("id", "")),
            locations=locations,
            additional_location_count=int(raw.get("additional_location_count", 0) or 0),
            detail=tuple(dict(item) for item in raw.get("detail", ()) if isinstance(item, Mapping)),
        )


def finding_sort_key(finding: Finding) -> tuple[Any, ...]:
    """DETERMINISM LAW ordering: ``(rule_id, path, start_line)``."""
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


def dict_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """Same ordering for plain §7 dicts (corpus-harness compatible)."""
    location = finding.get("location") or {}
    start = location.get("start_line")
    return (
        str(finding.get("rule_id", "")),
        str(location.get("path", "")),
        start if isinstance(start, int) else 0,
    )


# ---------------------------------------------------------------------------
# Dedup (SPEC §7): within a report, collapse on fingerprint
# ---------------------------------------------------------------------------

MAX_ATTACHED_LOCATIONS = 5


def dedup_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates on ``fingerprint``; attach locations (max 5).

    Survivor = the first finding in *already-sorted* input order (callers
    sort before dedup so survivor choice is input-deterministic). Attached
    locations list at most :data:`MAX_ATTACHED_LOCATIONS` sites; the
    remainder is COUNTED in ``additional_location_count``, never dropped
    silently.
    """
    order: list[str] = []
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        # Unfingerprinted findings never collapse with anything (string key
        # keeps the group mapping str-keyed and JSON-mental-model clean).
        key = finding.fingerprint or f"<unfingerprinted:{id(finding)}>"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    merged: list[Finding] = []
    for key in order:
        members = groups[key]
        survivor = members[0]
        if len(members) == 1:
            merged.append(survivor)
            continue
        listed = [member.location for member in members[:MAX_ATTACHED_LOCATIONS]]
        additional = max(0, len(members) - MAX_ATTACHED_LOCATIONS)
        merged.append(
            Finding(
                fingerprint=survivor.fingerprint,
                rule_id=survivor.rule_id,
                rule_version=survivor.rule_version,
                engine=survivor.engine,
                title=survivor.title,
                capability=survivor.capability,
                severity=survivor.severity,
                effective_severity=survivor.effective_severity,
                confidence=survivor.confidence,
                evidence_kind=survivor.evidence_kind,
                static_only=survivor.static_only,
                declared=survivor.declared,
                overreach=survivor.overreach,
                location=survivor.location,
                claim_ref=survivor.claim_ref,
                message=survivor.message,
                remediation=survivor.remediation,
                tags=survivor.tags,
                suppressed=survivor.suppressed,
                suppressed_by=survivor.suppressed_by,
                llm_touched=survivor.llm_touched,
                id=survivor.id,
                locations=tuple(listed),
                additional_location_count=additional,
                detail=survivor.detail,
            )
        )
    return merged


# ---------------------------------------------------------------------------
# Engine protocol + exception isolation (D-PROC / D-CRASH)
# ---------------------------------------------------------------------------


@runtime_checkable
class Engine(Protocol):
    """The single §4 protocol every engine implements."""

    name: str
    RULE_IDS: tuple[str, ...]

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        """Pure static analysis; must never raise past :func:`run_engine`."""
        ...


class TestEngine:
    """Deliberately raising engine — proves isolation changes NOTHING else.

    Used by the test-suite (PLAN Phase-1 exit: "a deliberately raising test
    engine changes neither results nor UX"). NOT registered in the shipped
    REGISTRY; instantiable directly in tests.
    """

    name = "test_boom"
    RULE_IDS: tuple[str, ...] = ()

    #: Never collect this as a test class despite the ``Test`` prefix.
    __test__ = False

    def __init__(self, rules: Iterable[Rule] = (), message: str = "deliberate crash") -> None:
        self._rules = tuple(rules)
        self._message = message

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError(self._message)


def engine_failure_finding(engine_name: str, exc: BaseException) -> Finding:
    """The D-CRASH synthetic: ``LNS-ENG-000 engine '<id>' failed: <class>``.

    Deterministic per (engine, exception class): the fingerprint binds only
    those tokens, so retrying a flaky engine cannot fork identities.
    """
    message = f"engine '{engine_name}' failed: {exc.__class__.__name__}"
    return Finding(
        fingerprint=finding_fingerprint(
            CODE_ENGINE_FAILURE, FAILURE_CAPABILITY, f"{engine_name}\x00{exc.__class__.__name__}"
        ),
        rule_id=CODE_ENGINE_FAILURE,
        rule_version="1",
        engine=engine_name,
        title="Engine failure isolated",
        capability=FAILURE_CAPABILITY,
        severity=FAILURE_SEVERITY,
        effective_severity=FAILURE_SEVERITY,
        confidence=1.0,
        evidence_kind=FAILURE_EVIDENCE_KIND,
        static_only=True,
        declared=False,
        overreach=False,
        location=Location(path="", start_line=None, end_line=None, snippet="", redacted=False),
        claim_ref=None,
        message=message,
        remediation="Re-run the scan; persistent engine failures belong in doctor output.",
        tags=("engine-failure", "isolation"),
        suppressed=False,
        suppressed_by=None,
        llm_touched=False,
    )


def run_engine(
    engine: Engine,
    bundle_ir: SkillIR,
    ctx: ScanContext | None = None,
    diagnostics: DiagnosticsCollector | None = None,
    *,
    slot_name: str | None = None,
) -> list[Finding]:
    """Run one engine behind the isolation boundary (never raises).

    Any exception from ``engine.scan`` becomes exactly one synthetic
    ``LNS-ENG-000`` finding (plus an INFO diagnostic when a collector is
    supplied); every other outcome is returned verbatim. Results of OTHER
    engines are untouched by construction — callers run engines separately.
    ``slot_name`` overrides failure attribution so orchestrators can name
    the §4 catalog slot even when a substitute/test implementation sits in
    it (D-CRASH wording: "engine '<id>' failed").
    """
    context = ctx if ctx is not None else current_context()
    try:
        produced = engine.scan(bundle_ir, context)
    except Exception as exc:  # noqa: BLE001 — isolation IS the contract (D-CRASH)
        attributed = slot_name or getattr(engine, "name", "<unnamed>")
        failure = engine_failure_finding(attributed, exc)
        if diagnostics is not None:
            diagnostics.record(
                CODE_ENGINE_FAILURE,
                failure.message,
                severity=SEVERITY_INFO,
                path=bundle_ir.identity.path,
                detail={"engine": attributed},
            )
        return [failure]
    normalized: list[Finding] = []
    for item in produced:
        normalized.append(item if isinstance(item, Finding) else Finding.from_dict(item))
    return normalized
