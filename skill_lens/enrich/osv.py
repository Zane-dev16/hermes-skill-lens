"""OSV.dev opt-in enrichment — the ONLY sanctioned network surface (SPEC §4 E8).

LAW OF THIS MODULE (§14 G1/G2/G3): it is NEVER imported by the default
pipeline. The lazy import happens exclusively inside the flagged codepath
(``--osv`` on the CLI scan verb / ``osv:true`` on ``/lens scan``), and the
import-contract test proves both halves: no network module loads in the
default closure, and this module is imported only when the flag routes here.

Behavior: dependency findings produced by E8 depintel carry additive
``detail`` package refs (``{"ecosystem", "package"}``). For each unique
(ecosystem, package) pair this adapter queries the OSV.dev batch API
(https://api.osv.dev/v1/query, POST JSON) and attaches to the originating
findings:

- ``enriched: true``  — G2's in-report marker: this finding WAS looked up;
- ``osv_vulns: [...]`` — sorted advisory ids (empty = queried, none known).

The envelope gains a top-level additive ``enrichment`` summary block; the
coverage footer renders the enriched marker whenever that block is present
(:func:`skill_lens.render.envelope_enriched`).

HONEST LIMITS (recorded in DECISIONS D-045):
- Enriched output is a RUNTIME NETWORK OBSERVATION. Like ``llm_touched``
  objects it sits OUTSIDE the §12.3 determinism guarantees — golden tests
  never enable ``--osv``, so vectors stay byte-exact.
- Directory targets only: zip/single-file targets have no manifest tree to
  re-read for dep identities; they get an honest ``skipped`` status.
- Every failure mode (network down, timeout, bad payload) DEGRADES: errors
  are counted in the summary, never raised into the host (advisor law).
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

#: OSV.dev batch query endpoint (public, keyless, no telemetry beyond the
#: query itself — one POST per unique package).
OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"

#: Ecosystem names OSV.dev expects (ours are lowercase internal tokens).
_OSV_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}

#: Per-request socket timeout (seconds). The worker thread runs enrichment,
#: never the reply path, but unbounded waits are still unacceptable.
DEFAULT_TIMEOUT_SECONDS = 10.0

EnrichFetch = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _default_fetch(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Real transport: one POST to api.osv.dev. Injected away in tests."""
    request = urllib.request.Request(
        OSV_QUERY_ENDPOINT,
        data=json.dumps(dict(payload)).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def query_osv(
    name: str,
    ecosystem: str,
    *,
    fetch: EnrichFetch | None = None,
) -> list[str]:
    """Sorted advisory ids for one package; raises on transport failure.

    Callers that must never raise go through :func:`enrich_envelope`, which
    counts failures into its summary instead.
    """
    osv_ecosystem = _OSV_ECOSYSTEMS.get(ecosystem)
    if osv_ecosystem is None:
        return []
    response = (fetch or _default_fetch)({"package": {"name": name, "ecosystem": osv_ecosystem}})
    vulns = response.get("vulns") if isinstance(response, Mapping) else None
    if not isinstance(vulns, list):
        return []
    ids = {str(vuln.get("id")) for vuln in vulns if isinstance(vuln, Mapping) and vuln.get("id")}
    return sorted(ids)


def enrich_envelope(
    envelope: dict[str, Any],
    *,
    root: Path | str | None = None,
    fetch: EnrichFetch | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Opt-in OSV pass over one report/1 envelope; NEVER raises.

    Returns a NEW envelope mapping (input untouched) with:

    - per-finding ``enriched=true`` (+ ``osv_vulns``) on every depintel
      finding that carried machine-readable package detail;
    - top-level ``enrichment`` summary: provider, opt-in name, query/error
      counts, advisory totals — or an honest skipped/error status.

    ``root`` is the scanned bundle directory (dir targets only; other target
    kinds report ``skipped`` because their manifests are not re-readable at
    this layer). ``fetch``/``timeout_seconds`` are test seams and bounds.
    """
    del timeout_seconds  # reserved: per-request bound rides _default_fetch today
    findings = envelope.get("findings")
    if not isinstance(findings, list):
        return envelope

    enriched_findings = [dict(finding) for finding in findings]
    pairs: set[tuple[str, str]] = set()
    for finding in enriched_findings:
        if str(finding.get("engine")) != "depintel":
            continue
        for item in finding.get("detail") or ():
            ecosystem = str(item.get("ecosystem", ""))
            package = str(item.get("package", ""))
            if ecosystem and package:
                pairs.add((ecosystem, package))

    summary: dict[str, Any]
    if not root or not Path(root).is_dir():
        summary = {
            "provider": "api.osv.dev",
            "opt_in": "--osv",
            "status": "skipped",
            "reason": "enrichment supports directory bundles only",
            "queried": 0,
            "errors": 0,
            "advisories": 0,
        }
    else:
        errors = 0
        advisories = 0
        lookup: dict[tuple[str, str], list[str]] = {}
        for ecosystem, package in sorted(pairs):
            try:
                ids = query_osv(package, ecosystem, fetch=fetch)
            except Exception:  # noqa: BLE001 — degrade-and-count (advisor law)
                errors += 1
                continue
            lookup[(ecosystem, package)] = ids
            advisories += len(ids)
        tagged = 0
        for finding in enriched_findings:
            if str(finding.get("engine")) != "depintel":
                continue
            keys = {
                (str(item.get("ecosystem", "")), str(item.get("package", "")))
                for item in finding.get("detail") or ()
            }
            matched: set[str] = set()
            for eco, pkg in keys:
                matched.update(lookup.get((eco, pkg), ()))
            finding["enriched"] = True
            finding["osv_vulns"] = sorted(matched)
            tagged += 1
        summary = {
            "provider": "api.osv.dev",
            "opt_in": "--osv",
            "status": "ok" if errors == 0 else "partial",
            "queried": len(pairs),
            "tagged_findings": tagged,
            "errors": errors,
            "advisories": advisories,
        }

    enriched: dict[str, Any] = dict(envelope)
    enriched["findings"] = enriched_findings
    enriched["enrichment"] = summary
    return enriched


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "OSV_QUERY_ENDPOINT",
    "enrich_envelope",
    "query_osv",
]
