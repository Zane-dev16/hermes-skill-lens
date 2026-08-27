"""Budget + fence-safe chunking verification (PLAN Phase 6 exit).

Exit criterion verbatim: "chat outputs verified against 1200/1800-char
budgets and fence-safe chunking". Covers:

- ``/lens bones`` and self-scan: ONE fenced block, ≤1900 chars (F-6);
- map / autopsy slash renders: §11.3 ladder keeps them ≤ hard budget even
  for pathological inputs, with the full text persisted;
- :mod:`skill_lens.chunking`: a pathological long report (> hard budget
  inside one ```json fence) splits into segments that each obey the hard
  budget with BALANCED fences; the greedy fill is longest-legal-segment;
  rejoin undoes exactly the synthetic markers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from skill_lens.chunking import HARD_BUDGET_DEFAULT, fences_balanced, rejoin, split_chat
from skill_lens.context import PluginContextView
from skill_lens.fun import BONES_BUDGET, render_autopsy, self_scan_target
from skill_lens.ir import SkillIR
from skill_lens.mapview import render_map_chat
from skill_lens.render import CHAT_HARD_BUDGET, CHAT_SOFT_BUDGET
from skill_lens.slash import dispatch_verb, reset_shared_cache, shared_cache
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "exfil-env-paste"


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    reset_shared_cache()
    yield  # type: ignore[misc]
    reset_shared_cache()


# ---------------------------------------------------------------------------
# bones + self-scan: single fence ≤1900
# ---------------------------------------------------------------------------


def _view(tmp_path: Path) -> PluginContextView:
    return PluginContextView(FakePluginContext(data_root=tmp_path / "state"))


def test_bones_self_chart_is_one_fence_under_1900(tmp_path: Path) -> None:
    out = dispatch_verb("bones", view=_view(tmp_path), cache=shared_cache())
    assert out.count("```") == 2  # exactly ONE fenced block
    assert len(out) <= BONES_BUDGET


def test_bones_with_target_charts_that_bundle(tmp_path: Path) -> None:
    out = dispatch_verb(f"bones {FIXTURE}", view=_view(tmp_path), cache=shared_cache())
    assert "SKELETON · exfil-env-paste" in out
    assert len(out) <= BONES_BUDGET


def test_bones_chart_is_deterministic() -> None:
    from skill_lens.fun import bones_for_tree

    chart_a = bones_for_tree("skill_lens", self_scan_target())
    chart_b = bones_for_tree("skill_lens", self_scan_target())
    assert chart_a == chart_b


def test_self_scan_output_within_budget_and_fenced(tmp_path: Path) -> None:
    out = dispatch_verb("lens", view=_view(tmp_path), cache=shared_cache())
    assert out.startswith("```\n") and out.rstrip().endswith("```")
    assert len(out) <= BONES_BUDGET + 8  # fence wrapper margin


# ---------------------------------------------------------------------------
# map / autopsy ladders under pathological inputs
# ---------------------------------------------------------------------------


def _huge_envelope(count: int) -> tuple[dict[str, Any], SkillIR]:
    findings = [
        {
            "id": f"F-{i}",
            "rule_id": f"LNS-NET-{i:03d}",
            "title": f"finding {i}: " + "lorem ipsum dolor sit amet " * 6,
            "message": f"finding {i}",
            "capability": "network.send",
            "severity": "HIGH",
            "effective_severity": "HIGH",
            "confidence": 0.9,
            "declared": False,
            "suppressed": False,
            "location": {"path": f"scripts/mod_{i:03d}.py", "start_line": i},
        }
        for i in range(1, count + 1)
    ]
    from skill_lens.ir import BundleIdentity, FileRecord, SkillIR

    ir = SkillIR(
        identity=BundleIdentity(name="pathological"),
        files=tuple(
            FileRecord(path=f"scripts/mod_{i:03d}.py", size=8192, role="script")
            for i in range(count)
        ),
        bundle_hash="sha256:" + "cd" * 32,
    )
    envelope = {
        "schema": "report/1",
        "tool": {"name": "lens", "version": "0.9.0a0"},
        "target": {
            "bundle_hash": ir.bundle_hash,
            "name": "pathological",
            "category": None,
            "layout": "flat",
            "file_count": count,
            "total_bytes": count * 8192,
        },
        "provenance": None,
        "policy": {"profile": "street", "sources": []},
        "rule_pack": {"name": "core", "version": "x", "checksum": "sha256:x"},
        "score": {"value": 10, "grade": "F", "verdict": "alert", "needs_review": False},
        "findings": findings,
        "suppressed_count": 0,
        "claims": [
            {
                "id": f"C-{i}",
                "capability": "fs.write",
                "span": {"path": "SKILL.md", "line": i, "quote": "q" * 30},
            }
            for i in range(1, 25)
        ],
        "notes": [],
    }
    return envelope, ir


@pytest.mark.parametrize("count", [60, 200])
def test_map_ladder_holds_hard_budget_for_pathological_trees(
    count: int, tmp_path: Path
) -> None:
    envelope, ir = _huge_envelope(count)
    body = render_map_chat(envelope, ir, plugin_data_dir=tmp_path)
    assert len(body) <= CHAT_HARD_BUDGET
    assert "full map: " in body or len(body) <= CHAT_SOFT_BUDGET


@pytest.mark.parametrize("voice", ["clinical", "microscopy"])
def test_autopsy_ladder_holds_hard_budget_for_pathological_reports(
    voice: str, tmp_path: Path
) -> None:
    envelope, _ir = _huge_envelope(120)
    body = render_autopsy(envelope, voice=voice, plugin_data_dir=tmp_path)
    assert len(body) <= CHAT_HARD_BUDGET
    artifacts = list((tmp_path / "reports").glob("*autopsy-*.txt"))
    assert artifacts  # full narrative persisted


def test_normal_fixture_outputs_sit_under_soft_budget(tmp_path: Path) -> None:
    view = _view(tmp_path)
    for invocation in (f"map {FIXTURE}", f"autopsy {FIXTURE}"):
        out = dispatch_verb(invocation, view=view, cache=shared_cache())
        assert len(out) <= CHAT_SOFT_BUDGET, invocation


# ---------------------------------------------------------------------------
# split_chat — the reference fence-safe chunker
# ---------------------------------------------------------------------------

PATHOLOGICAL_REPORT = (
    "```json\n"
    + "\n".join(
        f'{{"finding": "F-{i}", "detail": "{"x" * 90}", "seq": {i}}}'
        for i in range(40)
    )
    + "\n```\n"
)


def test_split_chat_returns_single_chunk_under_budget() -> None:
    small = "```\nhello\n```\n"
    assert split_chat(small) == [small]


def test_pathological_report_splits_within_budget_balanced_fences() -> None:
    chunks = split_chat(PATHOLOGICAL_REPORT)
    assert len(chunks) > 1
    total = sum(len(c) for c in chunks)
    assert total >= len(PATHOLOGICAL_REPORT)  # markers add bytes, content kept
    for chunk in chunks:
        assert len(chunk) <= HARD_BUDGET_DEFAULT, "hard budget breach"
        assert fences_balanced(chunk), "unbalanced fence in segment"


def test_rejoin_restores_original_content() -> None:
    chunks = split_chat(PATHOLOGICAL_REPORT)
    rejoined = rejoin(chunks)
    # Content lines survive verbatim and in order.
    original_content = [
        line for line in PATHOLOGICAL_REPORT.splitlines() if not line.startswith("```")
    ]
    rejoined_content = [
        line for line in rejoined.splitlines() if not line.startswith("```")
    ]
    assert rejoined_content == original_content


def test_greedy_fill_is_longest_legal_segment() -> None:
    """First segment must be filled close to the budget (greedy, not naive)."""
    chunks = split_chat(PATHOLOGICAL_REPORT)
    assert len(chunks[0]) >= HARD_BUDGET_DEFAULT - 120, (
        "splitter left the first segment unfilled — not longest-legal-segment"
    )


def test_split_outside_fence_prefers_fence_boundary() -> None:
    """A break between two fenced blocks never cuts inside either."""
    text = (
        "```\n" + "a\n" * 900 + "```\n"
        "between blocks\n"
        "```\n" + "b\n" * 900 + "```\n"
    )
    chunks = split_chat(text, hard_limit=1200)
    assert len(chunks) > 1
    for chunk in chunks:
        assert fences_balanced(chunk)


def test_oversized_single_line_is_char_split_but_within_budget() -> None:
    monster = "z" * (HARD_BUDGET_DEFAULT * 3)
    chunks = split_chat(monster)
    assert all(len(chunk) <= HARD_BUDGET_DEFAULT for chunk in chunks)
    assert "".join(chunks) == monster


def test_tiny_limit_degrades_gracefully() -> None:
    chunks = split_chat("```\nshort\n```\n", hard_limit=5)
    assert chunks  # never empty, never raises
    assert all(len(chunk) <= 5 or "\n" not in chunk for chunk in chunks)
