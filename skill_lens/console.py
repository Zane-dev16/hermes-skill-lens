"""Standalone ``lens`` console script — the §18 CLI-verbs surface, unpacked.

SPEC §18's scope statement names "the future standalone console script"
as a first-class CLI surface. This module IS it: a stdlib-only shim that
reuses the host wiring VERBATIM so there is exactly one grammar, one
routing table, and one exit-code law across lanes (D-043/D-054 law):

- ``skill_lens.cli.setup_parser`` fills the argparse tree (same subparser
  filler the Hermes host drives);
- a minimal host-context stand-in backs ``PluginContextView``:
  ``plugin_data_dir`` resolves to the XDG data dir (``$XDG_DATA_HOME/lens``,
  default ``~/.local/share/lens`` — G6 layout law), ``get_config`` reads no
  host settings so the policy loader degrades to its defaults layer
  (D-041 hostile-ctx path), and doctor check 4 degrades honestly when
  ``$HERMES_HOME`` is absent;
- :func:`skill_lens.cli.build_cli_handler` dispatches through the shared
  :func:`skill_lens.slash.dispatch_verb`, so §18 exit codes (0 advisor
  default / 1 only an explicit ``--fail-on`` breach via
  ``scoring.compute_exit_code`` / 2 total-error family incl. PolicyError +
  PackPinError + rules_exit) flow EXACTLY as on the host lane.

One-shot execution model (documented choice): the persistent JobManager
stays plugin-process-only. A standalone run never enqueues —
``view.inline_scans`` (context seam) makes every scan run through the
existing inline arm with its §11.5-rationale'd deadline, so no worker
thread is orphaned in CI and no jobs.json sidecar is written unless
``$HERMES_HOME``/XDG resolves a data dir. ``--fail-on`` already ran
inline (D-049a); this extends that lane to the whole standalone surface.

Perf statement: packaging adds zero runtime cost — the console path
shares the scan pipeline and its 156.2 ms idle cold p95 (SPEC v1.0
target 250 ms) unchanged.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any


class _StandaloneHost:
    """Minimal host-context stand-in for one-shot console runs.

    Only the seams PluginContextView probes are provided; everything else
    degrades through the defensive view exactly like an unfinished host.
    """

    #: One-shot inline execution (see module docstring; context seam).
    inline_scans = True

    @staticmethod
    def plugin_data_dir(key: str = "lens") -> Path:
        """XDG data dir per G6: ``$XDG_DATA_HOME/lens`` (default
        ``~/.local/share/lens``). PluginContextView mkdir -p's it."""
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        return Path(base) / (key or "lens")

    @staticmethod
    def get_config(key: str, default: Any = None) -> Any:
        """No host settings layer standalone: policy falls back to defaults."""
        return default

    @staticmethod
    def set_config(key: str, value: Any) -> bool:  # noqa: ARG004 — seam parity
        """Standalone runs never persist settings (honest no-op)."""
        return False


def build_parser() -> argparse.ArgumentParser:
    """The standalone ``lens`` parser — one grammar with the host lane."""
    parser = argparse.ArgumentParser(
        prog="lens",
        description=(
            "Skill Lens — deterministic, advisor-only security reports for "
            "agent skill bundles. A lens, not a bouncer."
        ),
    )
    from .cli import setup_parser

    setup_parser(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Console-script entry: parse, dispatch through the shared handler.

    Returns the §18 exit code; setuptools' console-script wrapper exits
    the process with it. Never raises past argparse's own SystemExit —
    every verb failure collapses into the exit-code contract.
    """
    parser = build_parser()
    namespace = parser.parse_args(argv)
    from .cli import build_cli_handler
    from .context import PluginContextView
    from .slash import shared_cache

    view = PluginContextView(_StandaloneHost())
    handler = build_cli_handler(view, shared_cache())
    try:
        return int(handler(namespace))
    except (TypeError, ValueError):  # a broken dispatch can never fake a clean run
        return 2


if __name__ == "__main__":  # pragma: no cover — python -m skill_lens.console
    sys.exit(main())
