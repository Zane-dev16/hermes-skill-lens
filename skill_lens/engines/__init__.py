"""Engine dispatch + scan pipeline (DECISIONS D-015 / D-CRASH / SPEC §7).

Seam contract (D-015), honored for the corpus harness:

- ``REGISTRY`` maps engine names to 3-arg callables
  ``(ir, rules_tuple, diagnostics) -> list[dict]``;
- ``run_all(ir, rules_by_engine, diagnostics, ctx=None)`` is the preferred
  orchestrator: per-engine exception isolation (each crash collapses to ONE
  synthetic ``LNS-ENG-000`` finding — D-CRASH), fingerprint dedup with
  max-5 attached locations (SPEC §7), and the determinism-law ordering
  ``(rule_id, path, start_line)``.

:func:`scan_bundle` is the spine later phases consume: ingest one target,
run every engine behind the isolation boundary, dedup + sort, number the
report's findings ``F-1..N``, and return a :class:`ScanResult`. Zip
targets are supported by re-reading members into an in-memory context map;
dir targets hand engines the real bundle directory so evidence lines
resolve exactly.

Shipped today: E1 manifest, E2 textinject (pure-Python Unicode/ghost-stream
scanner — grammar-free, so its degraded mode IS the primary mode), E3
shellscan, E4 pyscan + E5 jsscan (AST + golden-tested line-scanner fallback),
E6 netgraph, E7 secretscan, and E8 depintel — all eight §4 engines.
"""

from __future__ import annotations

import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..diagnostics import SEVERITY_ERROR, SEVERITY_INFO, DiagnosticsCollector
from ..ingest import (
    DEFAULT_CEILINGS,
    Ceilings,
    load_bundle,
)
from ..ir import SkillIR
from ..rules import Rule, RulePack, load_core_pack
from .base import (
    CODE_ENGINE_UNIMPLEMENTED,
    MAX_ATTACHED_LOCATIONS,
    Finding,  # re-exported convenience
    ScanContext,
    dict_sort_key,
    infer_skills_root,
    reset_scan_context,
    run_engine,
    set_scan_context,
)
from .e1_manifest import ENGINE_NAME as MANIFEST_ENGINE_NAME
from .e1_manifest import RULE_IDS as MANIFEST_RULE_IDS
from .e1_manifest import ManifestEngine
from .e2_textinject import ENGINE_NAME as TEXTINJECT_ENGINE_NAME
from .e2_textinject import RULE_IDS as TEXTINJECT_RULE_IDS
from .e2_textinject import TextInjectEngine
from .e3_shellscan import ENGINE_NAME as SHELLSCAN_ENGINE_NAME
from .e3_shellscan import RULE_IDS as SHELLSCAN_RULE_IDS
from .e3_shellscan import ShellScanEngine
from .e4_pyscan import ENGINE_NAME as PYSCAN_ENGINE_NAME
from .e4_pyscan import RULE_IDS as PYSCAN_RULE_IDS
from .e4_pyscan import PyScanEngine
from .e5_jsscan import ENGINE_NAME as JSSCAN_ENGINE_NAME
from .e5_jsscan import RULE_IDS as JSSCAN_RULE_IDS
from .e5_jsscan import JsScanEngine
from .e6_netgraph import ENGINE_NAME as NETGRAPH_ENGINE_NAME
from .e6_netgraph import RULE_IDS as NETGRAPH_RULE_IDS
from .e6_netgraph import NetgraphEngine
from .e7_secretscan import ENGINE_NAME as SECRETSCAN_ENGINE_NAME
from .e7_secretscan import RULE_IDS as SECRETSCAN_RULE_IDS
from .e7_secretscan import SecretScanEngine
from .e8_depintel import ENGINE_NAME as DEPINTEL_ENGINE_NAME
from .e8_depintel import RULE_IDS as DEPINTEL_RULE_IDS
from .e8_depintel import DepIntelEngine

__all__ = [
    "ENGINE_IMPLEMENTATIONS",
    "MAX_ATTACHED_LOCATIONS",
    "REGISTRY",
    "DeadlineCallback",
    "Finding",
    "ScanContext",
    "ScanDeadlineBreach",
    "ScanResult",
    "available_engines",
    "dedup_finding_dicts",
    "run_all",
    "scan_bundle",
]

#: Mirrors base.MAX_ATTACHED_LOCATIONS for callers importing from here.
MAX_ATTACHED_LOCATIONS = MAX_ATTACHED_LOCATIONS


# ---------------------------------------------------------------------------
# Internal deadline (slash interim inline scans; SPEC §11.5 gateway note)
# ---------------------------------------------------------------------------


class ScanDeadlineBreach(RuntimeError):
    """Raised ONLY when a caller-supplied deadline callback fires.

    The default (``deadline=None``) keeps :func:`run_all` and
    :func:`scan_bundle` byte-identical and never-raising-this; interactive
    surfaces pass a monotonic-callback so a pathological target cannot wedge
    a synchronous reply path past the internal ceiling.
    """


#: Zero-arg callback shape; True means "deadline exceeded, abort".
DeadlineCallback = Callable[[], bool]


def _check_deadline(deadline: DeadlineCallback | None, stage: str) -> None:
    if deadline is not None and deadline():
        raise ScanDeadlineBreach(f"internal scan deadline exceeded at stage '{stage}'")


# ---------------------------------------------------------------------------
# Registry (3-arg seam shape, D-015) + orchestrated dispatch
# ---------------------------------------------------------------------------


def _manifest_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(ManifestEngine(rules), ir, diagnostics, slot_name=MANIFEST_ENGINE_NAME)


def _textinject_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(TextInjectEngine(rules), ir, diagnostics, slot_name=TEXTINJECT_ENGINE_NAME)


def _secretscan_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(SecretScanEngine(rules), ir, diagnostics, slot_name=SECRETSCAN_ENGINE_NAME)


def _netgraph_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(NetgraphEngine(rules), ir, diagnostics, slot_name=NETGRAPH_ENGINE_NAME)


def _shellscan_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(ShellScanEngine(rules), ir, diagnostics, slot_name=SHELLSCAN_ENGINE_NAME)


def _pyscan_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(PyScanEngine(rules), ir, diagnostics, slot_name=PYSCAN_ENGINE_NAME)


def _jsscan_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(JsScanEngine(rules), ir, diagnostics, slot_name=JSSCAN_ENGINE_NAME)


def _depintel_entry(ir: SkillIR, rules: tuple, diagnostics: DiagnosticsCollector) -> list[dict]:
    return _dispatch_one(DepIntelEngine(rules), ir, diagnostics, slot_name=DEPINTEL_ENGINE_NAME)


def _dispatch_one(
    engine: Any,
    ir: SkillIR,
    diagnostics: DiagnosticsCollector,
    *,
    slot_name: str | None = None,
) -> list[dict[str, Any]]:
    """One engine through the isolation boundary; dicts out, sorted."""
    produced = run_engine(engine, ir, current_context(), diagnostics, slot_name=slot_name)
    dicts = [finding.to_dict() for finding in produced]
    dicts.sort(key=dict_sort_key)
    return dedup_finding_dicts(dicts)


#: The D-015 probe surface: engine names present RIGHT NOW.
REGISTRY: dict[str, Any] = {
    MANIFEST_ENGINE_NAME: _manifest_entry,
    NETGRAPH_ENGINE_NAME: _netgraph_entry,
    PYSCAN_ENGINE_NAME: _pyscan_entry,
    SECRETSCAN_ENGINE_NAME: _secretscan_entry,
    SHELLSCAN_ENGINE_NAME: _shellscan_entry,
    JSSCAN_ENGINE_NAME: _jsscan_entry,
    TEXTINJECT_ENGINE_NAME: _textinject_entry,
    DEPINTEL_ENGINE_NAME: _depintel_entry,
}

#: Engine name -> (implementation class, implemented rule ids).
ENGINE_IMPLEMENTATIONS: dict[str, tuple[type, frozenset[str]]] = {
    MANIFEST_ENGINE_NAME: (ManifestEngine, frozenset(MANIFEST_RULE_IDS)),
    NETGRAPH_ENGINE_NAME: (NetgraphEngine, frozenset(NETGRAPH_RULE_IDS)),
    PYSCAN_ENGINE_NAME: (PyScanEngine, frozenset(PYSCAN_RULE_IDS)),
    SECRETSCAN_ENGINE_NAME: (SecretScanEngine, frozenset(SECRETSCAN_RULE_IDS)),
    SHELLSCAN_ENGINE_NAME: (ShellScanEngine, frozenset(SHELLSCAN_RULE_IDS)),
    JSSCAN_ENGINE_NAME: (JsScanEngine, frozenset(JSSCAN_RULE_IDS)),
    TEXTINJECT_ENGINE_NAME: (TextInjectEngine, frozenset(TEXTINJECT_RULE_IDS)),
    DEPINTEL_ENGINE_NAME: (DepIntelEngine, frozenset(DEPINTEL_RULE_IDS)),
}


def available_engines() -> frozenset[str]:
    """Names of shipped engine implementations (tests/doctor surface)."""
    return frozenset(ENGINE_IMPLEMENTATIONS)


def run_all(
    ir: SkillIR,
    rules_by_engine: dict[str, tuple],
    diagnostics: DiagnosticsCollector | None = None,
    ctx: ScanContext | None = None,
    deadline: DeadlineCallback | None = None,
) -> list[dict[str, Any]]:
    """Orchestrated, exception-isolated dispatch over every registered engine.

    Only engines with implementations run here; unimplemented §4 engines
    stay the corpus harness's sanctioned-absent state. Rules bound to a
    REGISTERED engine but not in that engine's ``RULE_IDS`` produce one
    ``LNS-ENG-001`` info diagnostic each (visibility over silence).
    Output is deduped on fingerprint and sorted by
    ``(rule_id, path, start_line)`` — the exact contract the corpus
    harness and :func:`scan_bundle` build on.
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    context = ctx if ctx is not None else current_context()

    findings: list[Finding] = []
    for engine_name in sorted(ENGINE_IMPLEMENTATIONS):
        _check_deadline(deadline, f"engine:{engine_name}")
        impl_class, implemented_ids = ENGINE_IMPLEMENTATIONS[engine_name]
        rules = rules_by_engine.get(engine_name, ())
        for rule in rules:
            if rule.id not in implemented_ids:
                diags.record(
                    CODE_ENGINE_UNIMPLEMENTED,
                    f"rule {rule.id} is bound to engine '{engine_name}' "
                    "but no implementation carries it",
                    severity=SEVERITY_INFO,
                    path=ir.identity.path,
                    detail={"engine": engine_name, "rule_id": rule.id},
                )
        if not rules:
            continue
        findings.extend(run_engine(impl_class(rules), ir, context, diags, slot_name=engine_name))

    dicts = [finding.to_dict() for finding in sorted(findings, key=_typed_sort)]
    dicts = dedup_finding_dicts(dicts)
    dicts.sort(key=dict_sort_key)
    return dicts


def _typed_sort(finding: Finding) -> tuple[Any, ...]:
    from .base import finding_sort_key

    return finding_sort_key(finding)


def dedup_finding_dicts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dict-level SPEC §7 dedup: collapse on fingerprint, attach locations.

    Input MUST already be sorted (survivor = first member). The survivor
    keeps up to :data:`MAX_ATTACHED_LOCATIONS` locations; the remainder is
    counted in ``additional_location_count`` — never silently dropped.
    """
    order: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        key = str(finding.get("fingerprint") or f"<unfingerprinted:{id(finding)}>")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    merged: list[dict[str, Any]] = []
    for key in order:
        members = groups[key]
        survivor = dict(members[0])
        if len(members) == 1:
            survivor["locations"] = [dict(survivor["location"])]
            survivor["additional_location_count"] = 0
            merged.append(survivor)
            continue
        listed = [dict(member.get("location") or {}) for member in members[:MAX_ATTACHED_LOCATIONS]]
        survivor["locations"] = listed
        survivor["additional_location_count"] = max(0, len(members) - MAX_ATTACHED_LOCATIONS)
        merged.append(survivor)
    return merged


def current_context() -> ScanContext:
    """Ambient context accessor re-exported for seam symmetry."""
    from .base import current_context as _current

    return _current()


# ---------------------------------------------------------------------------
# Community-pack merge (SPEC §15; fail-closed, street-capped)
# ---------------------------------------------------------------------------

#: Street-profile cap for community rules (ratified): external findings
#: DISPLAY at effective MEDIUM until a pack is promoted; pricing keeps
#: reading the rule-assigned severity (D-041 hard boundary — scores stay
#: recomputable, the cap is annotation + display only).
EXTERNAL_STREET_CAP = "MEDIUM"


_EXTERNAL_ANNOTATION = "[pack:{}"


def _merge_external_packs(
    pack: RulePack,
    external_packs: Sequence[RulePack],
    diags: DiagnosticsCollector,
) -> tuple[RulePack, dict[str, str]]:
    """Merge accepted community packs into the dispatch set, fail-closed.

    Any external rule id equal to a CORE rule id (or to a rule of an
    already-accepted pack) rejects THAT pack with an error diagnostic
    (LNS-PACK-ID-COLLISION) — community rules share the LNS- space and
    must never shadow core. Returns the merged pack (CORE identity
    preserved: name/version/checksum keep reporting the governed core so
    envelopes stay byte-stable) and the accepted rule-id→pack-name map.
    """
    from ..packpins import CODE_PACK_ID_COLLISION

    taken = {rule.id for rule in pack.rules}
    extra_rules: list[Rule] = []
    names: dict[str, str] = {}
    for ext in external_packs:
        collide = sorted({rule.id for rule in ext.rules if rule.id in taken})
        if collide:
            diags.record(
                CODE_PACK_ID_COLLISION,
                f"pack {ext.name} rejected: rule id collision ({', '.join(collide)}) — "
                "community rules share the LNS- space with core and must not shadow it",
                severity=SEVERITY_ERROR,
                path=ext.source_label,
                detail={"pack": ext.name, "ids": collide},
            )
            continue
        taken.update(rule.id for rule in ext.rules)
        extra_rules.extend(ext.rules)
        names.update({rule.id: ext.name for rule in ext.rules})
    if not extra_rules:
        return pack, names
    merged = RulePack(
        name=pack.name,
        version=pack.version,
        spec_version=pack.spec_version,
        description=pack.description,
        changelog=pack.changelog,
        rules=tuple(sorted(tuple(pack.rules) + tuple(extra_rules), key=lambda rule: rule.id)),
        source_label=pack.source_label,
        _file_inputs=pack._file_inputs,
    )
    return merged, names


def _annotate_external_findings(
    findings: list[dict[str, Any]],
    external_names: dict[str, str],
) -> list[dict[str, Any]]:
    """Provenance-annotate external-rule findings; apply the street cap.

    Pure: input dicts are copied, never mutated. Every external finding
    gains ``[pack:<name>]``; CRITICAL/HIGH ones additionally gain the cap
    annotation and ``effective_severity`` = MEDIUM (display only — the
    ``severity`` field that prices the score is never rewritten, D-041).
    """
    annotated: list[dict[str, Any]] = []
    for row in findings:
        pack_name = external_names.get(str(row.get("rule_id", "")))
        if pack_name is None:
            annotated.append(row)
            continue
        out = dict(row)
        notes = [str(item) for item in (out.get("annotations") or [])]
        notes.append(f"[pack:{pack_name}]")
        if str(out.get("severity")) in ("CRITICAL", "HIGH"):
            notes.append(f"[street-cap:{pack_name} effective {EXTERNAL_STREET_CAP}]")
            out["effective_severity"] = EXTERNAL_STREET_CAP
        out["annotations"] = notes
        annotated.append(out)
    return annotated


# ---------------------------------------------------------------------------
# The scan pipeline spine (scorer-facing, Phase 1+)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """Everything a report layer needs after one full bundle scan."""

    ir: SkillIR
    findings: tuple[dict[str, Any], ...]
    diagnostics: DiagnosticsCollector
    rule_pack_name: str
    rule_pack_version: str
    rule_pack_checksum: str

    def fired_rule_ids(self) -> set[str]:
        return {str(f.get("rule_id")) for f in self.findings if f.get("rule_id")}


def scan_bundle(
    path_or_dir: str | Path,
    rules_pack: RulePack | None = None,
    *,
    external_packs: Sequence[RulePack] = (),
    home: str | Path | None = None,
    ceilings: Ceilings = DEFAULT_CEILINGS,
    diagnostics: DiagnosticsCollector | None = None,
    deadline: DeadlineCallback | None = None,
) -> ScanResult:
    """Ingest + engine-dispatch + dedup one bundle (never raises).

    ``rules_pack=None`` loads the embedded core pack. ``external_packs``
    (community packs, SPEC §15) are merged INTO the dispatch set after a
    fail-closed id-collision check (any external id shadowing a core id —
    or another accepted pack — rejects THAT pack with an error
    diagnostic; advisor-safest); the envelope's ``rule_pack`` block keeps
    reporting the CORE pack identity so vectors and downstream consumers
    stay byte-stable. External-rule findings carry a ``[pack:<name>]``
    provenance annotation and, under the street profile cap, an
    ``effective_severity`` ceiling at MEDIUM — pricing keeps reading the
    rule-assigned severity (D-041 hard boundary, scores recomputable).
    Findings carry sequential report ids ``F-1..N`` assigned AFTER sort +
    dedup, so ids are input-deterministic and stable across line shifts
    that preserve detection content. When *deadline* is supplied it is
    consulted after ingest and between engines; breach raises
    :class:`ScanDeadlineBreach` (default ``None`` preserves the old
    contract exactly).
    """
    pack = rules_pack if rules_pack is not None else load_core_pack()
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    target = Path(path_or_dir).expanduser()

    merged = pack
    external_names: dict[str, str] = {}  # rule id -> pack name (accepted only)
    if external_packs:
        merged, external_names = _merge_external_packs(pack, external_packs, diags)

    _check_deadline(deadline, "start")
    ir = load_bundle(target, home=home, ceilings=ceilings, diagnostics=diags)
    _check_deadline(deadline, "ingest")
    ctx = _build_context(target, ir)

    token = set_scan_context(ctx)
    try:
        findings = run_all(ir, merged.rules_by_engine(), diags, ctx=ctx, deadline=deadline)
    finally:
        reset_scan_context(token)

    findings.sort(key=dict_sort_key)
    numbered: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        row = dict(finding)
        row["id"] = f"F-{index}"
        numbered.append(row)
    if external_names:
        numbered = _annotate_external_findings(numbered, external_names)

    return ScanResult(
        ir=ir,
        findings=tuple(numbered),
        diagnostics=diags,
        rule_pack_name=pack.name,
        rule_pack_version=pack.version,
        rule_pack_checksum=pack.content_checksum(),
    )


def _build_context(target: Path, ir: SkillIR) -> ScanContext:
    """Resolve whatever real-world seams this target can offer engines."""
    if ir.source_kind == "zip" and target.is_file():
        return ScanContext(
            bundle_root=None,
            skills_root=infer_skills_root(target),
            files=_zip_member_map(target),
        )
    if target.is_dir():
        return ScanContext(
            bundle_root=target,
            skills_root=infer_skills_root(target),
            files=None,
        )
    # Lone SKILL.md or exotic target: parent dir may still resolve lines.
    parent = target.parent if target.is_file() else None
    return ScanContext(bundle_root=parent, skills_root=infer_skills_root(target), files=None)


def _zip_member_map(zip_path: Path) -> dict[str, bytes]:
    """Re-read zip members into memory (mirrors ingest caps/skip policy)."""
    from ..ingest import MAX_SINGLE_FILE_BYTES, MAX_TOTAL_BYTES

    members: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in sorted(zf.infolist(), key=lambda item: item.filename):
                if info.is_dir():
                    continue
                parts = info.filename.split("/")
                if any(part.startswith(".") for part in parts[:-1]):
                    continue
                if not parts[-1] or parts[-1].startswith("."):
                    continue
                read_n = min(max(info.file_size, 0), MAX_SINGLE_FILE_BYTES)
                try:
                    with zf.open(info) as fh:
                        data = fh.read(read_n)[:MAX_SINGLE_FILE_BYTES]
                except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
                    continue
                if total + len(data) > MAX_TOTAL_BYTES:
                    break
                members[info.filename] = data
                total += len(data)
    except (zipfile.BadZipFile, OSError):
        return {}
    return members
