"""§18 exit-code contract + CLI verb smoke (Phase 3 deliverable 6).

Layers proven here:

1. :func:`skill_lens.scoring.compute_exit_code` — the SINGLE-SOURCE §8.4
   projection, exhaustively over the verdict × ``--fail-on`` matrix;
2. the REAL registration seam — ``register()`` → ``register_plugin`` →
   ``ctx.register_cli_command`` — invoked exactly as the host invokes it
   (argparse namespace in, ``SystemExit`` code out);
3. live verdicts through the shared pipeline: cold ``--fail-on`` scans run
   inline (D-049) and cache hits serve envelopes through the probe sink, so
   breach/no-breach is decided from REAL corpus fixtures;
4. the §12.1 ``--plain``/``NO_COLOR`` lane: box drawing strips to ASCII,
   byte-stable.
"""

from __future__ import annotations

import argparse
import os
import pathlib
from collections.abc import Callable
from typing import Any

import pytest

from skill_lens.cli import setup_parser, to_ascii_box
from skill_lens.scoring import VERDICT_LADDER, compute_exit_code
from skill_lens.slash import reset_shared_cache, reset_shared_jobs

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MALICIOUS = REPO_ROOT / "corpus/fixtures/malicious/committed-keys"  # verdict WARN
BENIGN = REPO_ROOT / "corpus/fixtures/benign/pinned-deps-helper"  # verdict CLEAN


@pytest.fixture(autouse=True)
def _isolated_singletons():
    """Fresh cache/job singletons per test (the verbs use process-wide state)."""
    import skill_lens.slash as slash_module

    reset_shared_cache()
    reset_shared_jobs()
    yield
    manager = getattr(slash_module, "_shared_jobs", None)  # read-only teardown peek
    if manager is not None:
        manager.shutdown(timeout=2.0)
    reset_shared_cache()
    reset_shared_jobs()


# ---------------------------------------------------------------------------
# 1. compute_exit_code matrix (§8.4 normative table)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fail_on", [None, "clean", "notice", "warn", "alert"])
@pytest.mark.parametrize("verdict", list(VERDICT_LADDER))
def test_compute_exit_code_matrix(verdict: str, fail_on: str | None) -> None:
    """0 default; 1 iff explicit level ≤ verdict on the clean<notice<warn<alert ladder."""
    expected = (
        0
        if fail_on is None
        else int(VERDICT_LADDER.index(verdict) >= VERDICT_LADDER.index(fail_on))
    )
    assert compute_exit_code(verdict, fail_on) == expected


def test_compute_exit_code_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        compute_exit_code("bogus", "warn")
    with pytest.raises(ValueError):
        compute_exit_code("warn", "fatal")


# ---------------------------------------------------------------------------
# 2+3. Real registration seam + live verdicts
# ---------------------------------------------------------------------------


class Harness:
    """The host-shaped invocation path: parser → namespace → handler_fn."""

    def __init__(self, fake_ctx: Any) -> None:
        entry = fake_ctx.cli_commands["lens"]
        self.setup_fn: Callable[[Any], None] = entry["setup_fn"]
        self.handler_fn: Callable[..., Any] = entry["handler_fn"]

    def run(self, argv: list[str]) -> tuple[int, str]:
        parser = argparse.ArgumentParser()
        self.setup_fn(parser)
        namespace = parser.parse_args(argv)
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with pytest.raises(SystemExit) as excinfo:
                self.handler_fn(namespace)
        return int(excinfo.value.code or 0), buffer.getvalue()


@pytest.fixture
def harness(fake_ctx: Any, plugin_module: Any) -> Harness:
    """register() through the repo-root plugin package, then harvest the seam."""
    plugin_module.register(fake_ctx)
    return Harness(fake_ctx)


def test_registered_seam_help_exits_zero(harness: Harness) -> None:
    code, out = harness.run(["help"])
    assert code == 0
    assert out.startswith("```")  # §11.2 usage block shape unchanged


def test_unresolvable_target_exits_two(harness: Harness) -> None:
    code, out = harness.run(["scan", "/nonexistent-target-xyz"])
    assert code == 2  # §18 total-error family
    assert "unresolvable target" in out


def test_default_scan_is_advisor_zero_even_with_findings(harness: Harness) -> None:
    """§18: no --fail-on ⇒ 0 even when findings render (cache-hit compact)."""
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "alert"])[0] == 0
    code, out = harness.run(["scan", str(MALICIOUS)])
    assert code == 0
    assert "verdict warn" in out.lower()  # findings visible, exit still advisor-zero


def test_fail_on_breach_matrix_through_live_pipeline(harness: Harness) -> None:
    """Cold inline arm (D-049): committed-keys verdicts WARN ⇒ matrix below."""
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "clean"])[0] == 1
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "notice"])[0] == 1
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "warn"])[0] == 1
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "alert"])[0] == 0


def test_fail_on_clean_bundle_only_breaches_at_clean(harness: Harness) -> None:
    assert harness.run(["scan", str(BENIGN), "--fail-on", "clean"])[0] == 1
    assert harness.run(["scan", str(BENIGN), "--fail-on", "notice"])[0] == 0
    assert harness.run(["scan", str(BENIGN), "--fail-on", "warn"])[0] == 0


def test_unknown_fail_on_level_is_total_error(harness: Harness) -> None:
    code, out = harness.run(["scan", str(MALICIOUS), "--fail-on", "fatal"])
    assert code == 2
    assert "unknown --fail-on level" in out


def test_report_fail_on_uses_cached_envelope(harness: Harness) -> None:
    """Cache-hit lane: the probe sink feeds the verdict, no rescan needed."""
    # Cold INLINE scan (--fail-on arm) runs run_scan, which populates the cache.
    assert harness.run(["scan", str(MALICIOUS), "--fail-on", "alert"])[0] == 0
    assert harness.run(["report", MALICIOUS.name])[0] == 0
    assert harness.run(["report", MALICIOUS.name, "--fail-on", "warn"])[0] == 1
    assert harness.run(["report", MALICIOUS.name, "--fail-on", "alert"])[0] == 0


def test_parser_round_trips_new_flags() -> None:
    parser = argparse.ArgumentParser()
    setup_parser(parser)
    ns = parser.parse_args(["scan", "target", "--json", "--fail-on", "warn", "--plain"])
    assert ns.fail_on == "warn"
    assert ns.plain and ns.json
    assert ns.target == "target"


# ---------------------------------------------------------------------------
# 4. --plain / NO_COLOR rendering lane (§12.1)
# ---------------------------------------------------------------------------

_SAMPLE_PANEL = "┌─ SKILL LENS ─┐\n│ GRADE B      │\n├──────────────┤\n└──────────────┘\n"
_SAMPLE_PLAIN = "+- SKILL LENS -+\n| GRADE B      |\n+--------------+\n+--------------+\n"


def test_to_ascii_box_snapshot() -> None:
    assert to_ascii_box(_SAMPLE_PANEL) == _SAMPLE_PLAIN


def test_plain_flag_strips_box_drawing(harness: Harness) -> None:
    code, out = harness.run(["scan", str(BENIGN), "--plain"])
    assert code == 0
    assert "```" not in out or "+" in out  # compact fence survives; panels go ASCII
    for glyph in "┌┐└┘├┤─│":
        assert glyph not in out


def test_no_color_env_forces_ascii_lane(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from skill_lens.cli import _emit

    monkeypatch.setenv("NO_COLOR", "1")
    _emit(_SAMPLE_PANEL, plain=False)
    captured = capsys.readouterr()
    assert captured.out.rstrip("\n") == _SAMPLE_PLAIN.rstrip("\n")
    monkeypatch.delenv("NO_COLOR")
    _emit(_SAMPLE_PANEL, plain=False)
    assert capsys.readouterr().out.rstrip("\n") == _SAMPLE_PANEL.rstrip("\n")


def test_no_color_env_via_cli_run(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    code, out = harness.run(["help"])
    assert code == 0
    for glyph in "┌┐└┘├┤─│":
        assert glyph not in out
    assert os.environ["NO_COLOR"] == "1"  # env honored, never mutated
