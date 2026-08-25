"""Tests for skill_lens.diagnostics — structured failure capture."""

from __future__ import annotations

import importlib
import sys
import threading
from pathlib import Path

# Dynamic import: the checker's workspace root is the outer directory, so a
# static ``from skill_lens...`` edge cannot resolve; runtime needs repo root
# on sys.path regardless.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
_diagnostics = importlib.import_module("skill_lens.diagnostics")

CODE_INTERNAL = _diagnostics.CODE_INTERNAL
SEVERITIES = _diagnostics.SEVERITIES
SEVERITY_ERROR = _diagnostics.SEVERITY_ERROR
SEVERITY_INFO = _diagnostics.SEVERITY_INFO
SEVERITY_WARNING = _diagnostics.SEVERITY_WARNING
Diagnostic = _diagnostics.Diagnostic
DiagnosticsCollector = _diagnostics.DiagnosticsCollector


def test_record_captures_all_fields() -> None:
    collector = DiagnosticsCollector()
    diag = collector.record(
        "LNS-ING-001",
        "frontmatter parse failed",
        severity=SEVERITY_ERROR,
        path="SKILL.md",
        detail={"line": 3},
    )
    assert diag.code == "LNS-ING-001"
    assert diag.severity == SEVERITY_ERROR
    assert diag.path == "SKILL.md"
    assert diag.message == "frontmatter parse failed"
    assert diag.detail == {"line": 3}
    assert len(collector) == 1


def test_defaults_are_warning_without_path_or_detail() -> None:
    collector = DiagnosticsCollector()
    diag = collector.record("LNS-X-000", "something odd")
    assert diag.severity == SEVERITY_WARNING
    assert diag.path is None
    assert diag.detail == {}


def test_to_dict_is_json_safe_shape() -> None:
    import json

    diag = Diagnostic("C", SEVERITY_INFO, "p", "m", {"k": [1, 2]})
    dumped = json.dumps(diag.to_dict(), sort_keys=True)
    assert isinstance(dumped, str)


def test_snapshot_is_isolated_copy() -> None:
    collector = DiagnosticsCollector()
    collector.info("A-1", "one")
    snap = collector.snapshot()
    collector.warning("B-1", "two")
    assert len(snap) == 1
    assert len(collector) == 2


def test_by_severity_at_least_filters() -> None:
    collector = DiagnosticsCollector()
    collector.info("I-1", "info record")
    collector.warning("W-1", "warn record")
    collector.error("E-1", "error record")
    warnings_up = collector.by_severity_at_least(SEVERITY_WARNING)
    assert [d.code for d in warnings_up] == ["W-1", "E-1"]
    errors = collector.by_severity_at_least(SEVERITY_ERROR)
    assert [d.code for d in errors] == ["E-1"]


def test_unknown_severity_rank_survives_filtering() -> None:
    collector = DiagnosticsCollector()
    collector.record("U-1", "odd", severity="catastrophic")
    assert len(collector.by_severity_at_least(SEVERITY_ERROR)) == 1


def test_record_never_raises_on_hostile_input() -> None:
    collector = DiagnosticsCollector()

    class Hostile(dict):  # dict subclass whose dict() copy explodes
        def keys(self):  # noqa: D105 — deliberate sabotage
            raise RuntimeError("no")

    diag = collector.record("X-1", "msg", detail=Hostile())
    assert diag.code == "X-1"
    assert len(collector) == 1


def test_iteration_matches_insertion_order() -> None:
    collector = DiagnosticsCollector()
    for index in range(5):
        collector.info(f"C-{index}", f"record {index}")
    assert [d.code for d in collector] == [f"C-{i}" for i in range(5)]


def test_clear_empties_collector() -> None:
    collector = DiagnosticsCollector()
    collector.warning("W-9", "bye")
    collector.clear()
    assert len(collector) == 0


def test_concurrent_appends_all_landed() -> None:
    collector = DiagnosticsCollector()
    threads = [
        threading.Thread(
            target=lambda n=n: collector.info(f"T-{n}", f"thread {n}")  # noqa: B008
        )
        for n in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(collector) == 8


def test_severity_constants_consistent() -> None:
    assert SEVERITIES == ("debug", "info", "warning", "error")
    assert CODE_INTERNAL == "LNS-DIAG-000"
