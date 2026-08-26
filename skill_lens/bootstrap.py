"""Plugin bootstrap: turn a raw host context into Skill Lens runtime state.

Stores a defensive :class:`PluginContextView` and registers the ``/lens``
slash command (scan|report|help — SPEC §11.2). Observer HOOKS stay
unregistered until Phase 4; what registers today is command-only, and
never a blocking hook. Any failure is logged, never raised into the host:
the advisor contract holds no matter how malformed the context is.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from .context import PluginContextView

logger = logging.getLogger("lens")

_lock = threading.Lock()
_active_view: PluginContextView | None = None


def get_context() -> PluginContextView | None:
    """Return the view stored by the most recent successful registration."""
    with _lock:
        return _active_view


def reset_context() -> None:
    """Drop the stored view (used by tests; harmless if nothing is stored)."""
    global _active_view
    with _lock:
        _active_view = None


def register_plugin(raw_ctx: Any) -> PluginContextView:
    """Store *raw_ctx* behind a defensive view; register surfaces; return it.

    Phase 4 wiring: ``/lens`` slash, ``hermes lens`` CLI, and the three
    observer hooks (on_skill_lifecycle / post_tool_call /
    transform_tool_result — skill_lens.triggers). Still NEVER a blocking
    hook. Every registration failure logs and degrades to an inert plugin
    instead of raising into the host.
    """
    global _active_view
    from . import __version__

    view = PluginContextView(raw_ctx)
    with _lock:
        _active_view = view
    _register_slash_safely(view)
    _register_cli_safely(view)
    _register_hooks_safely(view)
    _start_watcher_safely(view)
    logger.info(
        "Skill Lens %s registered (advisor mode; observer hooks only)",
        __version__,
    )
    return view


def _register_slash_safely(view: PluginContextView) -> None:
    """Register /lens; any failure stays inside this function (advisor law)."""
    try:
        from .slash import register_slash

        register_slash(view)
    except Exception:
        logger.exception("Skill Lens: /lens registration failed; slash surface inert")


def _register_cli_safely(view: PluginContextView) -> None:
    """Register ``hermes lens``; any failure stays inside (advisor law)."""
    try:
        from .cli import register_cli

        register_cli(view)
    except Exception:
        logger.exception("Skill Lens: CLI registration failed; CLI surface inert")


def _register_hooks_safely(view: PluginContextView) -> None:
    """Register the three observer hooks; any failure stays inside.

    Only ever passes OBSERVER hook names to :meth:`PluginContextView.register_hook`
    (``pre_tool_call`` is structurally unreachable from this module — advisor
    law, SPEC §11.6/T1).
    """
    try:
        from .triggers import register_triggers

        register_triggers(view)
    except Exception:
        logger.exception("Skill Lens: trigger registration failed; hooks inert")


def _start_watcher_safely(view: PluginContextView) -> None:
    """Run the §11.8 startup sweep; auto-start polling only when opted in.

    The sweep ALWAYS runs (out-of-band drift must be caught even for users
    who never enable continuous polling); continuous polling is opt-in via
    ``/lens watch start`` or the ``watch.poll`` setting. Any failure stays
    inside this function — the plugin loads inert-but-alive without it.
    """
    try:
        from .watcher import register_watcher

        register_watcher(view)
    except Exception:
        logger.exception("Skill Lens: watcher startup failed; drift watch inert")
