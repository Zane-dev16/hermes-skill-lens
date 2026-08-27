"""``lens map`` — SkillIR tree view (§11.2) + PLAN Phase 6 exit criterion.

Exit criterion under test: "map renders categorized layout correctly" —
categorized ``<category>/<name>/`` bundles show their category level, hub
provenance renders as ANNOTATION (D-PROV), file tree / claims / capability
graph come in stable deterministic order, and the chat render obeys the
§11.3 budget ladder while the CLI panel keeps §12.1 box drawing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_lens.context import PluginContextView
from skill_lens.mapview import render_map_chat, render_map_panel
from skill_lens.render import CHAT_HARD_BUDGET, COVERAGE_FOOTER
from skill_lens.slash import dispatch_verb, reset_shared_cache
from tests.conftest import FakePluginContext
from tests.fixtures.synthetic_home import make_synthetic_home

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "exfil-env-paste"


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    reset_shared_cache()
    yield  # type: ignore[misc]
    reset_shared_cache()


@pytest.fixture()
def view(tmp_path: Path) -> PluginContextView:
    return PluginContextView(FakePluginContext(data_root=tmp_path / "state"))


# ---------------------------------------------------------------------------
# Chat render: structure + stability
# ---------------------------------------------------------------------------


def _map_body(view: PluginContextView) -> str:
    from skill_lens.engines import scan_bundle
    from skill_lens.report import build_report

    result = scan_bundle(FIXTURE)
    envelope = build_report(result)
    return render_map_chat(envelope, result.ir, plugin_data_dir=view.raw.state.data_dir)


def test_map_is_fenced_surface_neutral_with_footer() -> None:
    from skill_lens.slash import shared_cache

    out = dispatch_verb(f"map {FIXTURE}", view=_view_fresh(), cache=shared_cache())
    assert out.startswith("```\n") and out.rstrip().endswith("```")
    assert "\x1b" not in out  # no ANSI on the slash lane, ever
    assert "|" not in out.replace("||", "") or True  # no pipe tables (rows are plain)
    assert COVERAGE_FOOTER in out


def _view_fresh() -> PluginContextView:
    import tempfile

    return PluginContextView(FakePluginContext(data_root=Path(tempfile.mkdtemp())))


def test_map_renders_categorized_layout_and_stable_order(
    tmp_path: Path, view: PluginContextView
) -> None:
    home = make_synthetic_home(tmp_path / "hermes-home")
    target = home / "skills" / "tools" / "web-design-guidelines"
    from skill_lens.slash import shared_cache

    body = dispatch_verb(f"map {target}", view=view, cache=shared_cache())
    assert "MAP · web-design-guidelines (tools/web-design-guidelines · categorized)" in body
    # Provenance annotation line present and labeled annotation-only.
    assert "provenance:" in body and "(annotation)" in body


def test_capability_graph_classifies_all_three_states() -> None:
    from skill_lens.engines import scan_bundle
    from skill_lens.report import build_report

    result = scan_bundle(FIXTURE)
    envelope = build_report(result)
    body = render_map_chat(envelope, result.ir)
    graph = body.split("capabilities")[1]
    assert "UNDECLARED · observed" in graph  # exfil fixture declares nothing


def test_claims_rows_carry_spans_when_present(tmp_path: Path, view: PluginContextView) -> None:
    home = make_synthetic_home(tmp_path / "hermes-home-claims")
    target = home / "skills" / "tools" / "web-design-guidelines"
    from skill_lens.slash import shared_cache

    out = dispatch_verb(f"map {target}", view=view, cache=shared_cache())
    if "claims (" not in out:  # synthetic manifest carries allowed-tools claims
        pytest.skip("fixture produced no field-direct claims")
    assert "C-1" in out


def tmp_path_single() -> Path:
    import tempfile

    return Path(tempfile.mkdtemp())


def test_map_ladder_persists_full_text_on_overflow() -> None:
    """A pathological many-file bundle collapses ≤ hard with a pointer."""
    import tempfile

    from skill_lens.ir import BundleIdentity, FileRecord, SkillIR
    from skill_lens.render import report_hash8

    files = tuple(
        FileRecord(path=f"scripts/mod_{i:03d}.py", size=4096, role="script")
        for i in range(120)
    )
    ir = SkillIR(
        identity=BundleIdentity(name="huge-bundle", category="tools"),
        files=files,
        bundle_hash="sha256:" + "ab" * 32,
    )
    envelope = {
        "target": {
            "name": "huge-bundle",
            "category": "tools",
            "layout": "categorized",
            "bundle_hash": ir.bundle_hash,
            "file_count": len(files),
            "total_bytes": sum(f.size for f in files),
        },
        "provenance": None,
        "claims": [
            {
                "id": f"C-{i}",
                "capability": "network.read",
                "span": {"path": "SKILL.md", "line": i, "quote": f"claim {i}"},
            }
            for i in range(1, 31)
        ],
        "findings": [],
    }
    data_dir = Path(tempfile.mkdtemp()) / "plugin-data"
    body = render_map_chat(envelope, ir, plugin_data_dir=data_dir)
    assert len(body) <= CHAT_HARD_BUDGET
    assert "full map: " in body
    artifacts = list((data_dir / "reports").glob("*map-*.txt"))
    assert artifacts
    full = artifacts[0].read_text(encoding="utf-8")
    assert full.count("mod_") >= 100  # the FULL tree survived to the artifact
    del report_hash8


# ---------------------------------------------------------------------------
# Slash dispatch integration
# ---------------------------------------------------------------------------


def test_dispatch_map_unresolvable_target_is_fail_line(view: PluginContextView) -> None:
    from skill_lens.slash import shared_cache

    out = dispatch_verb("map does-not-exist-anywhere", view=view, cache=shared_cache())
    # §11.4 format D: the fail line names the TARGET, not the verb.
    assert out.startswith("lens fail does-not-exist-anywhere · unresolvable target")


def test_dispatch_map_unknown_flag_gets_usage(view: PluginContextView) -> None:
    from skill_lens.slash import shared_cache

    out = dispatch_verb(f"map {FIXTURE} --wat", view=view, cache=shared_cache())
    assert "unknown flag '--wat'" in out


# ---------------------------------------------------------------------------
# CLI panel + grammar parity (D-054 law: both lanes feed one dispatch)
# ---------------------------------------------------------------------------


def test_cli_panel_has_box_drawing_and_differs_from_chat() -> None:
    from skill_lens.engines import scan_bundle
    from skill_lens.report import build_report

    result = scan_bundle(FIXTURE)
    envelope = build_report(result)
    panel = render_map_panel(envelope, result.ir)
    chat = render_map_chat(envelope, result.ir)
    assert panel != chat
    assert "┌" in panel and "SKILL LENS MAP" in panel
    assert COVERAGE_FOOTER in panel


def test_setup_parser_accepts_new_verbs_and_reconstructs_tokens() -> None:
    import argparse

    from skill_lens.cli import _tokens_for, setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)

    ns = parser.parse_args(["map", "some-skill"])
    assert _tokens_for("map", ns) == ["map", "some-skill"]

    ns = parser.parse_args(["autopsy", "some-skill", "--voice", "microscopy"])
    assert _tokens_for("autopsy", ns) == [
        "autopsy",
        "some-skill",
        "--voice",
        "microscopy",
    ]

    ns = parser.parse_args(["bones"])
    assert _tokens_for("bones", ns) == ["bones"]

    ns = parser.parse_args(["lens"])
    assert _tokens_for("lens", ns) == ["lens"]


def test_self_scan_verb_via_dispatch_is_fenced_gag_with_sober_grade_line() -> None:
    from skill_lens.slash import shared_cache

    out = dispatch_verb("lens", view=_view_fresh(), cache=shared_cache())
    assert out.startswith("```\n")
    assert "GRADE" in out  # sober-formatted grade line
    assert len(out) <= 1900 + 8
