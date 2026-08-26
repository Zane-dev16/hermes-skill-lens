"""Golden snapshot harness — byte-identical canonical inventory (Phase 0 exit).

Builds a synthetic categorized Hermes home under ``tmp_path`` exercising the
full ingest surface (≥3 categories, ≥5 bundles, metadata.hermes, malformed
SKILL.md, name/dirname mismatch, zip target, variable-depth quarantine,
lockfile provenance) and asserts :func:`skill_lens.inventory.scan_inventory`
produces a BYTE-IDENTICAL canonical envelope across two runs (DETERMINISM
LAW / PLAN Phase 0 exit), plus structural sanity on envelope contents.

Sidecar EXCLUSION (Phase 2): runtime worker state —
``<plugin-data>/lens/jobs.json`` and ``events.ndjson`` (plus cached reports
under ``reports/``) — carries wall-clock timestamps BY DESIGN and sits in
the same exemption class as ``_meta``: never an input to any canonical
envelope, therefore excluded from every determinism assertion here and in
the CI byte-compare job.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_lens.canonical import canonical_dumps
from skill_lens.inventory import scan_inventory
from tests.fixtures.synthetic_home import make_synthetic_home


@pytest.fixture()
def golden_home(tmp_path: Path) -> Path:
    return make_synthetic_home(tmp_path / "hermes-home")


# ---------------------------------------------------------------------------
# The golden assertions
# ---------------------------------------------------------------------------


def test_scan_inventory_is_byte_identical_across_runs(golden_home: Path) -> None:
    """PHASE 0 EXIT CRITERION: two runs ⇒ byte-identical canonical JSON."""
    first = canonical_dumps(scan_inventory(golden_home))
    second = canonical_dumps(scan_inventory(golden_home))
    assert first == second
    assert len(first) > 1000  # not trivially empty


def test_cli_json_output_matches_scan_inventory_bytes(
    golden_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The dogfood CLI --json stream is the same canonical envelope."""
    from skill_lens.inventory import main as cli_main

    assert cli_main(["--json", str(golden_home)]) == 0
    stdout = capsys.readouterr().out
    assert canonical_dumps(scan_inventory(golden_home)) + "\n" == stdout


def test_cli_tolerates_missing_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from skill_lens.inventory import main as cli_main

    empty = tmp_path / "nowhere"
    empty.mkdir()
    assert cli_main([str(empty)]) == 0
    assert "nothing to scan" in capsys.readouterr().out


def test_envelope_structure_and_contents(golden_home: Path) -> None:
    env = scan_inventory(golden_home)
    assert env["spec_version"] == "ir/1"
    assert env["tool"]["name"] == "lens"

    inv = env["inventory"]
    bundles = inv["bundles"]
    names = {b["bundle"]["root_label"] for b in bundles}
    # ≥3 categories × ≥5 categorized bundles + flat + 2 quarantine dirs + zip.
    assert inv["bundle_count"] == len(bundles) == 9
    assert {
        "web-design-guidelines",
        "plain-helper",
        "sketchy-dir",
        "broken-skill",
        "deployer",
        "flat-root-skill",
        "staged-one",
        "another",
        "packed",
    } <= names

    by_name = {b["bundle"]["root_label"]: b for b in bundles}

    # Categorized layout detected with category attached.
    wd = by_name["web-design-guidelines"]["bundle"]
    assert wd["category"] == "tools"
    assert wd["layout"] == "categorized"
    # $HERMES_HOME-normalized label form (scratch home ⇒ '~' prefix).
    assert wd["path_as_given"].startswith("~/skills/tools/")

    # metadata.hermes mapped into IR (typed slots).
    manifest = by_name["web-design-guidelines"]["manifest"]
    hermes = manifest["hermes"]
    assert hermes["tags"] == ["design", "web"]
    assert hermes["related_skills"] == ["plain-helper"]
    assert hermes["category"] == "tools"
    assert hermes["requires_tools"] == ["read_file"]
    assert hermes["fallback_for_tools"] == ["browser"]
    assert hermes["config"] == {"palette": "default"}
    # metadata sibling of hermes lands as vendor field, not unknown top-level.
    assert manifest["vendor_fields"] == {"vendor-note": "future-metadata-sibling"}
    assert list(manifest["unknown_fields"]) == ["version"]

    # Name/dirname mismatch recorded as structured diagnostic.
    sketch_diags = [
        d for d in by_name["sketchy-dir"]["diagnostics"] if d["code"] == "LNS-FRONT-NAME-MISMATCH"
    ]
    assert len(sketch_diags) == 1
    assert by_name["sketchy-dir"]["manifest"]["name"] == "sketch"

    # Malformed YAML degrades to partial IR with diagnostics, no exception.
    broken = by_name["broken-skill"]
    parse_diags = [d for d in broken["diagnostics"] if d["code"] == "LNS-FRONT-PARSE"]
    assert len(parse_diags) == 1
    assert broken["manifest"]["validation_errors"] == ["frontmatter missing or unparsable"]

    # Zip target ingested from quarantine with source kind zip.
    packed = by_name["packed"]["bundle"]
    assert packed["source_kind"] == "zip"
    packed_paths = {f["path"] for f in packed["files"]}
    assert {"packed/SKILL.md", "packed/scripts/run.sh"} <= packed_paths

    # Variable-depth quarantine bundles discovered.
    assert by_name["another"]["bundle"]["source_kind"] == "quarantine"
    assert by_name["staged-one"]["bundle"]["source_kind"] == "quarantine"

    # Provenance is annotation-only and enriched from lock.json (D-PROV).
    prov = wd["provenance"]
    assert prov["resolved_from"] == "hub_lock"
    assert prov["trust_level"] == "trusted"
    assert prov["hub_source"] == "github"
    assert prov["content_hash"] == "sha256:" + "11" * 32
    assert prov["scan_provenance"] == {"gate": "skills_guard", "verdict": "allow"}
    staged_prov = by_name["staged-one"]["bundle"]["provenance"]
    assert staged_prov["resolved_from"] == "hub_lock"

    # Non-UTF-8 files produce structured diagnostics, never exceptions.
    deployer_files = {f["path"]: f for f in by_name["deployer"]["bundle"]["files"]}
    assert deployer_files["scripts/deploy.sh"]["encoding"] == "lossy-replacement"
    enc_diags = [d for d in by_name["deployer"]["diagnostics"] if d["code"] == "LNS-ING-ENCODING"]
    assert len(enc_diags) >= 1

    # Every bundle hash present and stable-looking; file records hashed.
    for bundle in bundles:
        assert bundle["bundle"]["bundle_hash"].startswith("sha256:")
        for record in bundle["bundle"]["files"]:
            assert record["sha256"].startswith("sha256:")
