"""Canonical ``report/1`` envelope assembly (SPEC §12.3).

The envelope is the deterministic, byte-stable machine view of one scan:
``{schema, tool, target, provenance, policy, rule_pack, score, findings,
suppressed_count, claims, notes}``. ``score`` carries the rubric-v2 block
including per-finding ``score_math`` so T3 stays machine-checkable.

DETERMINISM LAW (§12.3 normative): no key in this mapping may contain
wall-clock, path-prefix-, locale-, or environment-dependent values.
Volatile observations belong to the ``_meta`` sidecar
(:mod:`skill_lens.canonical`) and never here. Serializing with
:func:`skill_lens.canonical.canonical_dumps` yields byte-identical text for
identical inputs across runs and machines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from skill_lens.baseline import apply_baselines
from skill_lens.engines import ScanResult
from skill_lens.ir import TOOL_NAME, tool_version
from skill_lens.scoring import score_findings

#: Envelope schema token (SPEC §12.3; additive growth stays inside report/1).
REPORT_SCHEMA = "report/1"

#: Default policy profile until the Phase-2 policy loader lands (SPEC §10).
DEFAULT_PROFILE = "street"
DEFAULT_POLICY_SOURCES: tuple[str, ...] = ("built-in",)


def build_report(
    result: ScanResult,
    *,
    profile: str = DEFAULT_PROFILE,
    policy_sources: tuple[str, ...] | None = None,
    baseline_entries: Sequence[Any] = (),
    report_date: date | None = None,
) -> dict[str, Any]:
    """Assemble the ``report/1`` envelope from a :class:`ScanResult`.

    Pure function of the scan output + policy labels; scoring is computed
    here via :func:`skill_lens.scoring.score_findings`. Never raises on
    finding-shape drift — the scorer tolerates junk buckets by design.

    Baseline stage (Phase 2): when *baseline_entries* is non-empty, the
    suppression pass runs AFTER dedup (``scan_bundle`` output is already
    deduped) and BEFORE scoring — suppressed findings keep their full §7
    record in the envelope but price nothing, so scores stay a deterministic
    function of (bundle bytes, policy, baseline set, report date). Default
    arguments preserve byte-identical historical behavior (golden vectors).
    """
    findings: list[dict[str, Any]] = list(result.findings)
    if baseline_entries:
        findings, _stats = apply_baselines(findings, baseline_entries, report_date=report_date)
    score = score_findings(findings)
    ir = result.ir

    return {
        "schema": REPORT_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "target": {
            "bundle_hash": ir.bundle_hash,
            "name": ir.identity.name,
            "category": ir.identity.category,
            "path_as_given": ir.identity.path,
            "layout": ir.identity.layout,
            "source_kind": ir.source_kind,
            "file_count": ir.file_count,
            "total_bytes": ir.total_bytes,
        },
        "provenance": _provenance_annotation(ir.provenance.to_dict() if ir.provenance else None),
        "policy": {
            "profile": profile,
            "sources": list(
                policy_sources if policy_sources is not None else DEFAULT_POLICY_SOURCES
            ),
        },
        "rule_pack": {
            "name": result.rule_pack_name,
            "version": result.rule_pack_version,
            "checksum": result.rule_pack_checksum,
        },
        "score": score.to_dict(),
        "findings": findings,
        "suppressed_count": sum(1 for f in findings if f.get("suppressed")),
        "claims": [claim.to_dict() for claim in ir.claims],
        "notes": list(ir.notes),
    }


def _provenance_annotation(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Annotation-only provenance passthrough (D-PROV: never read by math)."""
    return dict(raw) if raw is not None else None


def report_hash8(envelope: Mapping[str, Any]) -> str:
    """Stable 8-hex display shard of the target bundle hash ("9f2ca41e").

    Falls back to hashing the envelope itself for targets whose ingest
    could not produce a content hash, keeping overflow filenames stable.
    """
    bundle_hash = str((envelope.get("target") or {}).get("bundle_hash") or "")
    if bundle_hash.startswith("sha256:") and len(bundle_hash) >= len("sha256:") + 8:
        return bundle_hash[len("sha256:") :][:8]
    from skill_lens.claims import finding_fingerprint

    return finding_fingerprint("report", "", repr(sorted(envelope))[:512])[len("sha256:") :][:8]


__all__ = ["DEFAULT_PROFILE", "REPORT_SCHEMA", "build_report", "report_hash8"]
