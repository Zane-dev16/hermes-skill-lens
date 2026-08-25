"""Hermes Skill Lens — plugin entry point.

"A lens, not a bouncer." This module is what the Hermes plugin system
imports (as ``hermes_plugins.<key>``) when Skill Lens loads. It exposes the
single required ``register(ctx)`` function.

Advisor contract: ``register`` must never raise into the host, no matter how
malformed the context or our own bootstrap is. Everything interesting lives
in the :mod:`skill_lens` package; this file is only a defensive adapter.
"""

from __future__ import annotations

import logging

__all__ = ["register"]

logger = logging.getLogger("lens")


def register(ctx: object) -> None:
    """Host-mandated plugin entry point.

    Stores the host context behind a defensive view and registers nothing
    blocking (Phase 0 spine: zero hook registrations; triggers land in a
    later phase). Any failure is logged to the ``lens`` logger and swallowed:
    a malformed load can never propagate into the host process.
    """
    try:
        from .skill_lens.bootstrap import register_plugin

        register_plugin(ctx)
    except Exception:
        logger.exception("Skill Lens: register() failed; plugin stays inert for this session")
