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
    """Store *raw_ctx* behind a defensive view; register ``/lens``; return it.

    Command registrations only in this phase — observer hooks are wired in
    Phase 4, and never a blocking hook. Slash-registration failure logs and
    degrades to an inert plugin instead of raising into the host.
    """
    global _active_view
    from . import __version__

    view = PluginContextView(raw_ctx)
    with _lock:
        _active_view = view
    _register_slash_safely(view)
    logger.info(
        "Skill Lens %s registered (advisor mode; zero blocking hooks)",
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
