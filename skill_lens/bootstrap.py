"""Plugin bootstrap: turn a raw host context into Skill Lens runtime state.

Phase 0 spine only: store a defensive :class:`PluginContextView` and log one
line. Hook/command registrations arrive in later phases; this module already
enforces the advisor contract (nothing here may raise into the host beyond
what ``register`` in the root ``__init__.py`` already contains).
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
    """Store *raw_ctx* behind a defensive view; return the view.

    Registers zero hooks and zero commands in Phase 0 — observers are wired
    in a later phase, and never a blocking hook.
    """
    global _active_view
    from . import __version__

    view = PluginContextView(raw_ctx)
    with _lock:
        _active_view = view
    logger.info(
        "Skill Lens %s registered (advisor mode; zero blocking hooks)",
        __version__,
    )
    return view
