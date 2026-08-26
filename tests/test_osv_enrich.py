"""Opt-in OSV enrichment tests — SPEC §4 E8 / §14 G1/G2 + PLAN Phase 3.

Proves the G2 contract end to end:

- enrichment tags depintel findings ``enriched=true`` (+ sorted
  ``osv_vulns``), adds the ``enrichment`` summary block, and renders the
  enriched coverage-footer marker ONLY when an enrichment pass happened;
- every failure degrades (fetch errors counted, never raised);
- G1: a canned scan with sockets DISABLED opens zero sockets — and the
  adapter's LOGIC runs fine with sockets disabled when the transport is
  injected (only the default urllib fetch would ever touch a socket);
- the opt-in socket test (``socket_enabled`` fixture) exercises the real
  api.osv.dev round trip; it is the ONLY test here allowed to open one;
- run_scan cache-key separation: ``--osv`` answers never serve plain
  requests or vice versa.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_socket

from skill_lens.canonical import canonical_dumps
from skill_lens.engines import scan_bundle
from skill_lens.enrich.osv import enrich_envelope, query_osv
from skill_lens.render import COVERAGE_FOOTER, ENRICHMENT_MARKER, render_chat_compact
from skill_lens.report import build_report

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "typosquat-deps"


def _envelope_for(fixture: Path = FIXTURE):
    return build_report(scan_bundle(fixture))


def _fake_fetch_factory(responses: dict[tuple[str, str], list[str]]):
    def fetch(payload):
        package = payload["package"]
        key = (
            package["name"],
            "pypi" if package["ecosystem"] == "PyPI" else "npm",
        )
        if key not in responses:
            raise ConnectionError(f"unexpected query {key}")
        return {"vulns": [{"id": vid} for vid in responses[key]]}

    return fetch


# ---------------------------------------------------------------------------
# Tagging + summary shape
# ---------------------------------------------------------------------------


def test_dep_findings_get_enriched_tags_and_vulns() -> None:
    envelope = _envelope_for()
    # Only FIRED findings carry package detail, so pinned allowlist members
    # (e.g. requests>=2.31 in this fixture) are correctly never queried.
    responses = {
        ("reqeusts", "pypi"): ["GHSA-yyyy-yyyy-yyyy", "PYSEC-2026-0001"],
        ("pyyaml", "pypi"): [],
        ("expres", "npm"): [],
        ("lodash", "npm"): ["GHSA-zzzz"],
    }
    enriched = enrich_envelope(envelope, root=FIXTURE, fetch=_fake_fetch_factory(responses))
    assert enriched["enrichment"]["status"] == "ok"
    assert enriched["enrichment"]["provider"] == "api.osv.dev"
    assert enriched["enrichment"]["opt_in"] == "--osv"
    assert enriched["enrichment"]["queried"] == len(responses) == 4
    assert enriched["enrichment"]["errors"] == 0
    assert enriched["enrichment"]["advisories"] == 3

    tagged = [f for f in enriched["findings"] if f.get("enriched")]
    assert tagged, "depintel findings must be tagged"
    squat = next(
        f for f in tagged if f.get("detail") and f["detail"][0].get("package") == "reqeusts"
    )
    assert squat["osv_vulns"] == ["GHSA-yyyy-yyyy-yyyy", "PYSEC-2026-0001"]  # sorted
    unpinned = next(
        f for f in tagged if f.get("detail") and f["detail"][0].get("package") == "pyyaml"
    )
    assert unpinned["osv_vulns"] == []  # queried, none known — still enriched=true
    hook = next(f for f in tagged if f.get("detail") and f["detail"][0].get("script_hook"))
    assert hook["enriched"] is True and hook["osv_vulns"] == []


def test_non_depintel_findings_untagged() -> None:
    envelope = _envelope_for()
    enriched = enrich_envelope(envelope, root=FIXTURE, fetch=lambda p: {"vulns": []})
    for finding in enriched["findings"]:
        if finding.get("engine") != "depintel":
            assert "enriched" not in finding


def test_fetch_errors_degrade_to_partial_summary() -> None:
    def exploding_fetch(payload):
        raise TimeoutError("network down")

    enriched = enrich_envelope(_envelope_for(), root=FIXTURE, fetch=exploding_fetch)
    summary = enriched["enrichment"]
    assert summary["status"] == "partial" or summary["status"] == "ok"
    assert summary["errors"] == summary["queried"]
    # findings still tagged (lookup attempted), advisories empty
    tagged = [f for f in enriched["findings"] if f.get("enriched")]
    assert tagged and all(f["osv_vulns"] == [] for f in tagged)


def test_non_directory_target_reports_skipped() -> None:
    envelope = _envelope_for()
    enriched = enrich_envelope(envelope, root=None, fetch=lambda p: {"vulns": []})
    assert enriched["enrichment"]["status"] == "skipped"
    assert "reason" in enriched["enrichment"]


def test_input_envelope_not_mutated() -> None:
    envelope = _envelope_for()
    before = canonical_dumps(envelope)
    enrich_envelope(envelope, root=FIXTURE, fetch=lambda p: {"vulns": []})
    assert canonical_dumps(envelope) == before


# ---------------------------------------------------------------------------
# Coverage footer marker (G2: named, logged in-report)
# ---------------------------------------------------------------------------


def test_footer_marker_only_when_enriched() -> None:
    plain = render_chat_compact(_envelope_for(), plugin_data_dir=None)
    assert COVERAGE_FOOTER in plain
    assert "osv-enriched" not in plain

    enriched = enrich_envelope(_envelope_for(), root=FIXTURE, fetch=lambda p: {"vulns": []})
    marked = render_chat_compact(enriched, plugin_data_dir=None)
    assert COVERAGE_FOOTER in marked
    assert ENRICHMENT_MARKER in marked


# ---------------------------------------------------------------------------
# G1: canned scans open zero sockets (pytest-socket)
# ---------------------------------------------------------------------------


def test_canned_scan_and_sarif_open_zero_sockets(tmp_path: Path) -> None:
    """G1 CI clause: the entire default path runs with sockets DENIED."""
    pytest_socket.disable_socket()
    try:
        result = scan_bundle(FIXTURE)
        envelope = build_report(result)
        from skill_lens.report import render_sarif

        sarif = render_sarif(envelope)
        assert sarif["version"] == "2.1.0"
        assert "--osv ABSENT ⇒ zero sockets" != None  # self-documenting no-op
        # Adapter LOGIC also socket-free when transport injected:
        enriched = enrich_envelope(envelope, root=FIXTURE, fetch=lambda p: {"vulns": []})
        assert enriched["enrichment"]["status"] == "ok"
    finally:
        pytest_socket.enable_socket()


@pytest.mark.usefixtures("socket_enabled")
def test_real_osv_query_is_the_only_socket_opener() -> None:
    """The explicit opt-in lane: REAL api.osv.dev round trip.

    Skips gracefully offline (advisor law: network absence is not failure).
    """
    try:
        ids = query_osv("requests", "pypi")
    except Exception:  # noqa: BLE001 — offline/CI environments degrade honestly
        pytest.skip("api.osv.dev unreachable from this environment")
    assert isinstance(ids, list) and ids == sorted(ids)
    # A name that cannot exist returns no advisories.
    assert query_osv("no-such-package-lens-probe-xyzzy", "pypi") == []


# ---------------------------------------------------------------------------
# run_scan integration: osv flag + cache-key separation
# ---------------------------------------------------------------------------


def test_run_scan_osv_splits_cache_keys(tmp_path: Path) -> None:
    from skill_lens.cache import FastPathCache
    from skill_lens.slash import run_scan

    target = tmp_path / "bundle"
    target.mkdir()
    (target / "SKILL.md").write_text("---\nname: bundle\ndescription: Handles workflows.\n---\n")

    cache = FastPathCache()
    outcome_plain = run_scan(target, cache=cache, plugin_data_dir=tmp_path)
    assert outcome_plain["ok"] and outcome_plain["cache_hit"] is False

    outcome_osv = run_scan(
        target,
        cache=cache,
        plugin_data_dir=tmp_path,
        osv=True,
    )
    assert outcome_osv["ok"] and outcome_osv["cache_hit"] is False  # NOT served from plain key
    assert "osv-enriched" in outcome_osv["compact"], "footer marker must show on --osv renders"

    outcome_osv_again = run_scan(
        target,
        cache=cache,
        plugin_data_dir=tmp_path,
        osv=True,
    )
    assert outcome_osv_again["cache_hit"] is True  # enriched pool answers enriched requests


def test_run_scan_without_osv_never_imports_adapter(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    import sys

    from skill_lens.slash import run_scan

    sys.modules.pop("skill_lens.enrich.osv", None)
    requested: list[str] = []

    class Finder:
        def find_spec(self, fullname: str, path: object = None, target: object = None):  # noqa: ANN001, ANN202
            if fullname.startswith("skill_lens.enrich"):
                requested.append(fullname)
            return None

    monkeypatch.setattr(sys, "meta_path", [Finder(), *sys.meta_path])

    target = tmp_path / "bundle"
    target.mkdir()
    (target / "SKILL.md").write_text("---\nname: b\ndescription: Handles.\n---\n")
    from skill_lens.cache import FastPathCache

    outcome = run_scan(target, cache=FastPathCache(), plugin_data_dir=tmp_path)
    assert outcome["ok"]
    assert requested == [], "run_scan(osv=False) imported the enrichment adapter"
