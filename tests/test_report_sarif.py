"""SARIF 2.1.0 rendering tests — SPEC §12.4 mapping + official-schema proof.

Every golden vector (A–G) and a sample of corpus fixtures (both classes)
renders through :func:`skill_lens.report.render_sarif` and validates
against the VENDORED OFFICIAL schema
(``tests/fixtures/schema/sarif-schema-2.1.0.json`` — source URL in
DECISIONS D-045). Also pins the normative §12.4 mapping rows: level bands,
fingerprint key, suppression shape, score block, enriched property bags,
and byte-stability across repeated renders.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from skill_lens.canonical import canonical_dumps
from skill_lens.engines import scan_bundle
from skill_lens.report import build_report, render_sarif

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "tests" / "fixtures" / "schema" / "sarif-schema-2.1.0.json"
VECTORS_DIR = REPO_ROOT / "corpus" / "vectors"

_SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = jsonschema.Draft7Validator(_SCHEMA)  # schema declares draft-07


def _sarif_for(bundle: Path) -> dict[str, Any]:
    return render_sarif(build_report(scan_bundle(bundle)))


# ---------------------------------------------------------------------------
# Schema validation — EVERY vector + corpus samples (PLAN Phase 3 clause)
# ---------------------------------------------------------------------------


def _vector_dirs() -> list[Path]:
    dirs = sorted(p for p in VECTORS_DIR.iterdir() if p.is_dir())
    return [d for d in dirs if (d / "SKILL.md").is_file()]


@pytest.mark.parametrize(
    "bundle",
    _vector_dirs(),
    ids=lambda p: p.name,
)
def test_every_vector_validates_against_official_schema(bundle: Path) -> None:
    sarif = _sarif_for(bundle)
    _VALIDATOR.validate(sarif)  # raises on any violation
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1


@pytest.mark.parametrize(
    "fixture",
    sorted(
        [
            *REPO_ROOT.glob("corpus/fixtures/malicious/*/SKILL.md"),
            *REPO_ROOT.glob("corpus/fixtures/benign/*/SKILL.md"),
        ]
    ),
    ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}",
)
def test_every_corpus_fixture_validates_against_schema(fixture: Path) -> None:
    _VALIDATOR.validate(_sarif_for(fixture.parent))


def test_enriched_sarif_validates_with_property_bags() -> None:
    from skill_lens.enrich.osv import enrich_envelope

    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"
    envelope = build_report(scan_bundle(fixture))
    enriched = enrich_envelope(envelope, root=fixture, fetch=lambda payload: {"vulns": []})
    sarif = render_sarif(enriched)
    _VALIDATOR.validate(sarif)
    tagged = [r for r in sarif["runs"][0]["results"] if r["properties"].get("enriched")]
    assert tagged and all(r["properties"]["osv_vulns"] == [] for r in tagged)
    assert sarif["runs"][0]["properties"]["lens"]["enrichment"]["status"] == "ok"


# ---------------------------------------------------------------------------
# §12.4 mapping rows (normative table)
# ---------------------------------------------------------------------------


def test_driver_identity_and_rule_metadata() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"
    sarif = _sarif_for(fixture)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Skill Lens"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://")
    rules_by_id = {rule["id"]: rule for rule in driver["rules"]}
    dep002 = rules_by_id["LNS-DEP-002"]
    assert dep002["shortDescription"]["text"]
    assert dep002["fullDescription"]["text"]
    assert dep002["helpUri"].endswith("#LNS-DEP-002")
    assert dep002["properties"]["capability"] == "supply-chain"
    assert dep002["properties"]["defaultSeverity"] == "MEDIUM"
    assert isinstance(dep002["properties"]["weight"], int)


def test_level_mapping_severity_bands() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"
    results = {r["ruleId"]: r for r in _sarif_for(fixture)["runs"][0]["results"]}
    assert results["LNS-DEP-001"]["level"] == "note"  # LOW -> note band
    assert results["LNS-DEP-002"]["level"] == "warning"  # MEDIUM -> warning band
    assert results["LNS-DEP-003"]["level"] == "warning"


def test_fingerprints_map_to_partialFingerprints() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "committed-keys"
    result = scan_bundle(fixture)
    envelope = build_report(result)
    sarif = render_sarif(envelope)
    by_fp = {
        f["fingerprint"]: r
        for f, r in zip(envelope["findings"], sarif["runs"][0]["results"], strict=True)
    }
    assert by_fp, "expected findings on committed-keys fixture"
    for fingerprint, sarif_result in by_fp.items():
        key = "lensPrimaryFingerprint"
        assert sarif_result["partialFingerprints"][key] == fingerprint


def test_suppressed_findings_carry_suppressions() -> None:
    from skill_lens.baseline import BaselineRecord

    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "committed-keys"
    result = scan_bundle(fixture)
    finding = result.findings[0]
    record = BaselineRecord(
        fingerprint=str(finding["fingerprint"]),
        reason="reviewed; accepted for this suite run",
        expires=None,
    )
    envelope = build_report(result, baseline_entries=[record])
    sarif = render_sarif(envelope)
    suppressed = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert suppressed
    for entry in suppressed:
        justification = entry["suppressions"][0]["justification"]
        assert "reviewed; accepted for this suite run" in justification
        assert entry["suppressions"][0]["status"] == "accepted"


def test_score_block_rides_invocation_properties() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "committed-keys"
    envelope = build_report(scan_bundle(fixture))
    score = envelope["score"]
    invocation = _sarif_for(fixture)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    lens_props = invocation["properties"]["lens"]
    assert lens_props["score"] == score["value"]
    assert lens_props["grade"] == score["grade"]
    assert lens_props["verdict"] == score["verdict"]
    assert lens_props["needs_review"] == score["needs_review"]


def test_locations_use_physical_region_and_snippet() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "committed-keys"
    envelope = build_report(scan_bundle(fixture))
    finding = next(f for f in envelope["findings"] if f["location"]["snippet"])
    sarif_result = _sarif_for(fixture)["runs"][0]["results"][envelope["findings"].index(finding)]
    physical = sarif_result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == finding["location"]["path"]
    assert physical["region"]["startLine"] == finding["location"]["start_line"]
    assert physical["region"]["snippet"]["text"] == finding["location"]["snippet"]


def test_sarif_render_is_byte_stable() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"
    first = canonical_dumps(_sarif_for(fixture))
    second = canonical_dumps(_sarif_for(fixture))
    assert first == second


def test_results_sorted_like_findings() -> None:
    fixture = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"
    envelope = build_report(scan_bundle(fixture))
    order = [r["ruleId"] for r in _sarif_for(fixture)["runs"][0]["results"]]
    assert order == [str(f["rule_id"]) for f in envelope["findings"]]
