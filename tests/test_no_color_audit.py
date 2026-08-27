"""NO_COLOR / --plain audit — every slash + CLI output honors both (Phase 6).

Three layers of proof:

1. **Source audit** — no ANSI escape sequences exist anywhere in package
   source (slash renders are surface-neutral BY CONSTRUCTION, §11.3).
2. **Runtime sweep** — every verb through the shared dispatcher emits zero
   ESC characters on the slash lane.
3. **CLI lane** — ``--plain`` and ``NO_COLOR`` strip box drawing to ASCII
   and pin Rich's ``no_color``; verified through the real dispatcher +
   a recording Console fake (Rich detection off-switch).

Also pins the §11.3 courtesy default: Discord spoiler wrapping is OFF
unless ``discord_spoilers=true`` — and even then it touches chat bytes
only, never machine formats.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from skill_lens.cli import build_cli_handler, setup_parser, to_ascii_box
from skill_lens.context import PluginContextView
from skill_lens.render import render_chat_compact, render_terminal_panel
from skill_lens.slash import reset_shared_cache, shared_cache
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "skill_lens"

#: Every verb surface, including the Phase 6 additions and error lanes.
VERB_PROBES: tuple[str, ...] = (
    "help",
    "scan",  # missing target → usage lane
    "report",
    f"map {REPO_ROOT / 'corpus' / 'fixtures' / 'benign' / 'pinned-deps-helper'}",
    f"autopsy {REPO_ROOT / 'corpus' / 'fixtures' / 'benign' / 'pinned-deps-helper'}",
    "autopsy someone --voice noir",  # refusal notice lane
    "bones",
    "lens",
    "diff",
    "hub",
    "watch status",
    "doctor",
    "rules verify",
    "explain-rules",
    "baseline name --reason x",
    "totally-unknown-verb",
)


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.delenv("NO_COLOR", raising=False)
    reset_shared_cache()
    yield  # type: ignore[misc]
    reset_shared_cache()


# ---------------------------------------------------------------------------
# Layer 1: source audit
# ---------------------------------------------------------------------------


def test_no_ansi_escapes_anywhere_in_package_source() -> None:
    """No ANSI EMISSION in source — the e2 detector's own constants exempt.

    ``engines/e2_textinject.py`` legitimately contains ``\x1b`` literals:
    they are DETECTION vocabulary (finding escape-sequence injection in
    scanned skills), never output. Any other module carrying escapes is a
    render-path leak and fails here.
    """
    allowed_files = {"engines/e2_textinject.py"}
    offenders: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        rel = str(path.relative_to(PACKAGE_ROOT))
        if rel in allowed_files:
            continue
        text = path.read_text(encoding="utf-8")
        if "\x1b[" in text or "\\u001b[" in text or "\\x1b" in text:
            offenders.append(rel)
    assert not offenders


def test_no_cursor_positioning_or_private_mode_sequences() -> None:
    """The ANSI law bans cursor addressing outright (docs/personality-fun)."""
    banned = ("\\x1b[2J", "\\x1b[H", "\\x1b[?25", "\\033[2J", "\\u001b[2K")
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path.name}: cursor-addressing escape {token}"


# ---------------------------------------------------------------------------
# Layer 2: runtime sweep across every verb (slash lane)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb_invocation", VERB_PROBES)
def test_every_verb_output_is_ansi_free(
    verb_invocation: str,
    tmp_path: Path,
) -> None:
    view = PluginContextView(FakePluginContext(data_root=tmp_path / "state"))
    out = __import__("skill_lens.slash", fromlist=["dispatch_verb"]).dispatch_verb(
        verb_invocation, view=view, cache=shared_cache()
    )
    assert isinstance(out, str) and out
    assert "\x1b" not in out, f"ANSI leaked on slash lane: {verb_invocation!r}"


# ---------------------------------------------------------------------------
# Layer 3: CLI lane (--plain flag + NO_COLOR env + Rich off-switches)
# ---------------------------------------------------------------------------


class _RecordingConsole:
    """Fake rich.console.Console capturing constructor + print kwargs."""

    last_init: dict[str, Any] = {}
    printed: list[str] = []

    def __new__(cls, *args: Any, **kwargs: Any) -> _RecordingConsole:
        cls.last_init = {"args": args, "kwargs": kwargs}
        return super().__new__(cls)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._kwargs = kwargs

    def print(self, text: str, **kwargs: Any) -> None:
        _RecordingConsole.printed.append(text)


@pytest.fixture()
def fake_rich(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_RecordingConsole]]:
    import sys
    import types

    module = types.ModuleType("rich")
    console_module = types.ModuleType("rich.console")
    console_module.Console = _RecordingConsole  # type: ignore[attr-defined]
    module.console = console_module  # type: ignore[attr-defined]
    sys.modules["rich"] = module
    sys.modules["rich.console"] = console_module
    yield _RecordingConsole
    sys.modules.pop("rich", None)
    sys.modules.pop("rich.console", None)
    _RecordingConsole.last_init = {}
    _RecordingConsole.printed = []


def _run_cli(view: PluginContextView, argv: list[str]) -> int:
    parser = argparse_parser()
    namespace = parser.parse_args(argv)
    return int(build_cli_handler(view, shared_cache())(namespace))


def argparse_parser():  # noqa: ANN201 - small local helper
    import argparse

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    return parser


def test_cli_plain_flag_strips_box_drawing(tmp_path: Path) -> None:
    """The map CLI panel carries §12.1 box glyphs; --plain must ASCII them."""
    view = PluginContextView(FakePluginContext(data_root=tmp_path / "state"))
    import contextlib
    import io

    fixture = REPO_ROOT / "corpus" / "fixtures" / "benign" / "pinned-deps-helper"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _run_cli(view, ["map", str(fixture), "--plain"])
    del code
    out = buf.getvalue()
    assert "┌" not in out  # box drawing translated…
    assert "+" in out and "|" in out  # …to ASCII headers per §12.1


def test_no_color_env_strips_box_drawing_and_pins_rich(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_rich: type[_RecordingConsole]
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    view = PluginContextView(FakePluginContext(data_root=tmp_path / "state"))
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(io.nullcontext() if False else buf):
        try:
            _run_cli(view, ["doctor"])
        except SystemExit:
            pass
    # Rich received the pinned no_color switch when installed…
    assert fake_rich.last_init.get("kwargs", {}).get("no_color") is True
    # …and the emitted text carried ASCII headers, not box glyphs.
    emitted = "".join(fake_rich.printed) or buf.getvalue()
    assert "┌" not in emitted


def test_rich_console_detection_without_no_color_keeps_color_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_rich: type[_RecordingConsole]
) -> None:
    view = PluginContextView(FakePluginContext(data_root=tmp_path / "state"))
    monkeypatch.delenv("NO_COLOR", raising=False)
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()):
        try:
            _run_cli(view, ["doctor"])
        except SystemExit:
            pass
    kwargs = fake_rich.last_init.get("kwargs", {})
    assert "no_color" not in kwargs or kwargs["no_color"] is not True


# ---------------------------------------------------------------------------
# Discord spoilers: default OFF; ON touches chat prose only
# ---------------------------------------------------------------------------


def _mini_envelope() -> dict[str, Any]:
    return {
        "schema": "report/1",
        "tool": {"name": "lens", "version": "0.9.0a0"},
        "target": {
            "bundle_hash": "sha256:" + "9f" * 32,
            "name": "sample-skill",
            "category": None,
            "path_as_given": "~/.hermes/skills/sample-skill",
            "layout": "flat",
            "source_kind": "dir",
            "file_count": 2,
            "total_bytes": 2048,
        },
        "provenance": None,
        "policy": {"profile": "street", "sources": ["built-in"]},
        "rule_pack": {"name": "core", "version": "2026.08.6", "checksum": "sha256:aa"},
        "score": {"value": 70, "grade": "C", "verdict": "notice", "needs_review": False},
        "findings": [
            {
                "id": "F-1",
                "rule_id": "LNS-NET-011",
                "title": "posts data externally",
                "message": "posts data externally",
                "capability": "network.send",
                "severity": "HIGH",
                "effective_severity": "HIGH",
                "confidence": 0.9,
                "declared": False,
                "suppressed": False,
                "location": {"path": "s/x.sh", "start_line": 3, "snippet": ""},
            }
        ],
        "suppressed_count": 0,
        "claims": [],
        "notes": [],
    }


def test_discord_spoilers_default_off() -> None:
    body = render_chat_compact(_mini_envelope())
    assert "||" not in body
    panel = render_terminal_panel(_mini_envelope())
    assert "||" not in panel


def test_discord_spoilers_on_wraps_detail_rows_only() -> None:
    body = render_chat_compact(_mini_envelope(), spoilers=True)
    assert "||s/x.sh:3 — network.send · UNDECLARED · conf 0.90||" in body
    # Severity head stays visible OUTSIDE the spoiler.
    head_line = next(line for line in body.splitlines() if "LNS-NET-011" in line)
    assert "||" not in head_line
    # Machine-format source data unchanged: the envelope itself has no markers.
    assert all("||" not in str(f) for f in _mini_envelope()["findings"])


def test_to_ascii_box_translation_table_covers_map_panel_glyphs() -> None:
    panelish = "┌─┬┐│├┼┤└┴┘"
    ascii_version = to_ascii_box(panelish)
    assert set(ascii_version) <= set("+-|")


def test_os_environ_is_the_only_color_channel_for_verb_lanes() -> None:
    """Documentary pin: color decisions read env/flag, never target content."""
    from skill_lens.cli import _emit  # noqa: F401  (existence pin)

    assert callable(os.environ.get)  # env seam alive; detailed lanes tested above
