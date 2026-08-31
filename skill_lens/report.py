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
from pathlib import Path
from typing import Any

from .baseline import apply_baselines
from .engines import ScanResult
from .ir import TOOL_NAME, tool_version
from .scoring import score_findings

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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 rendering (SPEC §12.4 --sarif; mapping table normative)
# ---------------------------------------------------------------------------

SARIF_VERSION = "2.1.0"

#: Official SARIF 2.1.0 JSON schema (vendored at
#: tests/fixtures/schema/sarif-schema-2.1.0.json — source URL recorded in
#: DECISIONS D-045); every suite-rendered SARIF validates against it.
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

#: Tool identity (SPEC §12.4 driver row).
SARIF_DRIVER_NAME = "Skill Lens"
TOOL_INFORMATION_URI = "https://github.com/Zane-dev16/hermes-skill-lens"

#: Severity -> level mapping (§12.4): alert-band severities are errors,
#: warn-band warnings, notice/clean findings notes. effective_severity is
#: read so policy downgrades surface honestly to automation consumers.
_SARIF_LEVELS: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def render_sarif(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Render one ``report/1`` envelope as a SARIF 2.1.0 log (pure function).

    Mapping per SPEC §12.4 (normative table):

    - tool → ``runs[0].tool.driver`` with name/version/informationUri and a
      ``rules[]`` array carrying id, shortDescription/fullDescription,
      helpUri and ``properties.{capability,defaultSeverity,weight}``;
    - severity → ``level`` via :data:`_SARIF_LEVELS` on EFFECTIVE severity;
    - score block → ``invocations[0].executionSuccessful`` plus
      ``properties.lens.{score,grade,verdict,needs_review}``;
    - fingerprint → ``result.partialFingerprints.lensPrimaryFingerprint``
      (GitHub code-scanning compatible key);
    - location/snippet → standard ``physicalLocation.region`` with the
      already-redacted snippet text;
    - suppressed → ``result.suppressions[]`` with justification;
    - enriched → result ``properties.enriched/osv_vulns`` property bags plus
      run-level ``properties.lens.enrichment`` when present.

    Rule metadata resolves from the embedded core pack (offline); unknown
    rule ids degrade to bare-id descriptors rather than inventing data.
    Deterministic: stable sorts everywhere, no wall-clock anywhere.
    """
    from .rules import load_core_pack

    pack = load_core_pack()
    findings = list(envelope.get("findings") or [])

    rule_ids = sorted({str(f.get("rule_id")) for f in findings if f.get("rule_id")})
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    for position, rule_id in enumerate(rule_ids):
        rule_index[rule_id] = position
        rule = pack.rule_by_id(rule_id)
        descriptor: dict[str, Any] = {"id": rule_id}
        if rule is not None:
            descriptor.update(
                {
                    "name": rule.id,
                    "shortDescription": {"text": rule.title},
                    "fullDescription": {"text": rule.detection},
                    "helpUri": f"{TOOL_INFORMATION_URI}#{rule.id}",
                    "properties": {
                        "capability": rule.capability,
                        "defaultSeverity": rule.severity,
                        "weight": rule.weight,
                    },
                }
            )
        else:  # community-pack rule: honest bare descriptor, never invented data
            descriptor["shortDescription"] = {"text": rule_id}
        rules.append(descriptor)

    results: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("effective_severity") or finding.get("severity") or "LOW")
        result: dict[str, Any] = {
            "ruleId": str(finding.get("rule_id", "")),
            "ruleIndex": rule_index.get(str(finding.get("rule_id", "")), 0),
            "level": _SARIF_LEVELS.get(severity, "note"),
            "message": {"text": str(finding.get("message") or finding.get("title") or "finding")},
            "partialFingerprints": {"lensPrimaryFingerprint": str(finding.get("fingerprint", ""))},
        }
        location = finding.get("location") or {}
        artifact: dict[str, Any] = {"uri": str(location.get("path", ""))}
        physical: dict[str, Any] = {"artifactLocation": artifact}
        start_line = location.get("start_line")
        if isinstance(start_line, int) and start_line > 0:
            region: dict[str, Any] = {"startLine": start_line}
            end_line = location.get("end_line")
            if isinstance(end_line, int) and end_line >= start_line:
                region["endLine"] = end_line
            snippet = str(location.get("snippet") or "")
            if snippet:
                region["snippet"] = {"text": snippet}
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
        if finding.get("suppressed"):
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": str(finding.get("suppressed_by") or "suppressed"),
                }
            ]
        properties: dict[str, Any] = {
            "severity": str(finding.get("severity", "")),
            "effectiveSeverity": severity,
            "confidence": finding.get("confidence"),
            "staticOnly": bool(finding.get("static_only", False)),
            "tags": list(finding.get("tags") or ()),
        }
        if finding.get("enriched") is not None and "enriched" in finding:
            properties["enriched"] = bool(finding.get("enriched"))
        if "osv_vulns" in finding:
            properties["osv_vulns"] = list(finding.get("osv_vulns") or ())
        result["properties"] = properties
        results.append(result)

    score = envelope.get("score") or {}
    lens_invocation: dict[str, Any] = {
        "score": score.get("value"),
        "grade": score.get("grade"),
        "verdict": score.get("verdict"),
        "needs_review": bool(score.get("needs_review", False)),
    }
    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "properties": {"lens": lens_invocation},
    }

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": SARIF_DRIVER_NAME,
                "version": str((envelope.get("tool") or {}).get("version", "")),
                "informationUri": TOOL_INFORMATION_URI,
                "rules": rules,
            }
        },
        "invocations": [invocation],
        "results": results,
    }
    enrichment = envelope.get("enrichment")
    if enrichment:
        run["properties"] = {"lens": {"enrichment": dict(enrichment)}}

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif_file(envelope: Mapping[str, Any], path: str | Path) -> Path:
    """Write canonical SARIF for *envelope* to *path* (atomic replace).

    The bytes are exactly :func:`canonical_dumps` over
    :func:`render_sarif` — the same text the ``--sarif`` fence wraps, so
    machine consumers (the GitHub Action's ``upload-sarif`` step) read
    byte-identical output across surfaces. Writes land via a temp file in
    the target directory + :func:`os.replace`, so a crashed scan can never
    leave a truncated artifact behind.
    """
    import os
    import tempfile

    from .canonical import canonical_dumps

    target = Path(path).expanduser()
    text = canonical_dumps(render_sarif(envelope))
    parent = target.parent if str(target.parent) else Path(".")
    # No parent auto-creation: an unwritable/missing target directory must
    # FAIL the request loudly (the artifact is the point of the flag), not
    # silently fabricate directories.
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=".lens-sarif-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def report_hash8(envelope: Mapping[str, Any]) -> str:
    """Stable 8-hex display shard of the target bundle hash ("9f2ca41e").

    Falls back to hashing the envelope itself for targets whose ingest
    could not produce a content hash, keeping overflow filenames stable.
    """
    bundle_hash = str((envelope.get("target") or {}).get("bundle_hash") or "")
    if bundle_hash.startswith("sha256:") and len(bundle_hash) >= len("sha256:") + 8:
        return bundle_hash[len("sha256:") :][:8]
    from .claims import finding_fingerprint

    return finding_fingerprint("report", "", repr(sorted(envelope))[:512])[len("sha256:") :][:8]


__all__ = [
    "DEFAULT_PROFILE",
    "REPORT_SCHEMA",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "build_report",
    "render_sarif",
    "report_hash8",
    "write_sarif_file",
]
