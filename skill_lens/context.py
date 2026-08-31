"""Defensive view over the host ``PluginContext``.

The rest of Skill Lens never touches the raw host context. Every seam we
use is accessed through this wrapper, which tolerates missing attributes,
wrong shapes, and raising host methods: failures degrade to a logged
warning plus a safe default, never an exception into the host.

Seams (ground truth: hermes_cli/plugins.py @ /usr/local/lib/hermes-agent):

- ``ctx.register_hook(hook_name, callback) -> PluginRegistration``
- ``ctx.register_command(name, handler, description="", args_hint="")``
- ``ctx.register_cli_command(name, help, setup_fn, handler_fn=None, description="")``
- ``ctx.get_config(key, default=None)`` / ``ctx.set_config(key, value)``
  (reads/writes ``plugins.entries.<plugin_id>.settings.<key>``)
- durable state dir: ``ctx.state.data_dir`` -> ``<HERMES_HOME>/plugin-data/<ns>``
  in current Hermes; a hypothetical ``plugin_data_dir(key)`` callable shape
  is also honored before falling back to ``$HERMES_HOME/plugin-data/lens``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("lens")

#: Canonical plugin key (NAMING LAW). Used only as a last-resort fallback.
PLUGIN_KEY = "lens"

# Host get_config/set_config carry untyped values (see PluginContext.get_config
# in hermes_cli/plugins.py: return type is Any). We mirror that honesty.
ConfigValue = Any


class PluginContextView:
    """Thin wrapper around the raw host context with defensive accessors."""

    def __init__(self, raw_ctx: Any) -> None:
        self._raw = raw_ctx

    @property
    def raw(self) -> Any:
        """The wrapped host context. Avoid using this outside tests."""
        return self._raw

    # -- identity -------------------------------------------------------------

    def plugin_id(self) -> str:
        """Best-effort registry id (``manifest.key``/``name`` or ``lens``)."""
        try:
            pid = getattr(self._raw, "plugin_id", None)
            if isinstance(pid, str) and pid:
                return pid
            manifest = getattr(self._raw, "manifest", None)
            key = getattr(manifest, "key", None) or getattr(manifest, "name", None)
            if isinstance(key, str) and key:
                return key
        except Exception:
            logger.debug("plugin_id lookup failed", exc_info=True)
        return PLUGIN_KEY

    # -- registrations ----------------------------------------------------------

    def register_hook(
        self,
        hook_name: str,
        callback: Callable[..., Any],
    ) -> Any:
        """Register an observer hook callback. Returns the host handle or None.

        Callers are responsible for only ever passing observer hooks;
        ``pre_tool_call`` must never reach this method (advisor law).
        """
        register = getattr(self._raw, "register_hook", None)
        if not callable(register):
            logger.warning("host ctx has no register_hook(); hook %r not registered", hook_name)
            return None
        try:
            return register(hook_name, callback)
        except Exception:
            logger.exception("register_hook(%r) failed on host ctx", hook_name)
            return None

    def register_command(
        self,
        name: str,
        handler: Callable[[str], str | None],
        description: str = "",
        args_hint: str = "",
    ) -> Any:
        """Register a slash command (handler signature ``fn(raw_args) -> str|None``)."""
        register = getattr(self._raw, "register_command", None)
        if not callable(register):
            logger.warning("host ctx has no register_command(); /%s not registered", name)
            return None
        try:
            return register(name, handler, description=description, args_hint=args_hint)
        except TypeError:
            # Older host shapes without keyword support.
            try:
                return register(name, handler, description)
            except Exception:
                logger.exception("register_command(%r) failed on host ctx", name)
                return None
        except Exception:
            logger.exception("register_command(%r) failed on host ctx", name)
            return None

    def register_cli_command(
        self,
        name: str,
        help_text: str,
        setup_fn: Callable[[Any], None],
        handler_fn: Callable[..., Any] | None = None,
        description: str = "",
    ) -> Any:
        """Register a ``hermes <name>`` terminal subcommand."""
        register = getattr(self._raw, "register_cli_command", None)
        if not callable(register):
            logger.warning("host ctx has no register_cli_command(); %r not registered", name)
            return None
        try:
            return register(
                name,
                help=help_text,
                setup_fn=setup_fn,
                handler_fn=handler_fn,
                description=description,
            )
        except Exception:
            logger.exception("register_cli_command(%r) failed on host ctx", name)
            return None

    # -- settings ----------------------------------------------------------------

    def get_config(self, key: str, default: Any = None) -> Any:
        """Read ``plugins.entries.<plugin_id>.settings.<key>`` (plugin-relative)."""
        get = getattr(self._raw, "get_config", None)
        if not callable(get):
            return default
        try:
            return get(key, default)
        except Exception:
            logger.exception("get_config(%r) failed on host ctx", key)
            return default

    def set_config(self, key: str, value: Any) -> bool:
        """Write one settings value; True on success, False on any failure."""
        set_fn = getattr(self._raw, "set_config", None)
        if not callable(set_fn):
            logger.debug("host ctx has no set_config(); %r not written", key)
            return False
        try:
            set_fn(key, value)
            return True
        except Exception:
            logger.exception("set_config(%r) failed on host ctx", key)
            return False

    # -- durable state -------------------------------------------------------------

    @property
    def inline_scans(self) -> bool:
        """Standalone one-shot seam: run every scan inline, never enqueue.

        The ``lens`` console script (``skill_lens.console``) supplies a host
        stand-in with ``inline_scans = True``: a one-shot CI process has no
        reply path to protect and no worker thread to leave behind, so the
        §11.5 queue-first contract is meaningless there. The persistent
        JobManager stays plugin-process-only (host-provided contexts never
        carry this attribute and default to False).
        """
        try:
            return bool(getattr(self._raw, "inline_scans", False))
        except Exception:  # noqa: BLE001 — defensive view law
            return False

    def plugin_data_dir(self) -> Path:
        """Return this plugin's durable state directory (created if possible).

        Resolution order:
        1. ``ctx.state.data_dir`` (current Hermes shape).
        2. ``ctx.plugin_data_dir(<key>)`` callable (alternative/future shape).
        3. ``$HERMES_HOME/plugin-data/lens`` fallback.
        """
        # Shape 1: PluginState facade property.
        try:
            data_dir = getattr(getattr(self._raw, "state", None), "data_dir", None)
            path = self._coerce_and_prepare(data_dir)
            if path is not None:
                return path
        except Exception:
            logger.debug("ctx.state.data_dir probe failed", exc_info=True)

        # Shape 2: callable seam taking the plugin key.
        try:
            fn = getattr(self._raw, "plugin_data_dir", None)
            if callable(fn):
                path = self._coerce_and_prepare(fn(PLUGIN_KEY))
                if path is not None:
                    return path
        except Exception:
            logger.debug("ctx.plugin_data_dir() probe failed", exc_info=True)

        # Shape 3: environment fallback.
        home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")
        path = Path(home) / "plugin-data" / self.plugin_id()
        prepared = self._coerce_and_prepare(path)
        if prepared is not None:
            return prepared
        # Directory could not be created; hand back the path anyway so the
        # caller can surface a structured diagnostic instead of crashing.
        return path

    def llm_lane(self) -> Any | None:
        """Host ctx.llm or None. Never constructs, never raises (T4: the lane
        is the host's; its absence = choir unavailable, honestly reported)."""
        try:
            lane = getattr(self._raw, "llm", None)
            return lane
        except Exception:  # noqa: BLE001 — defensive view law
            logger.debug("llm lane probe failed", exc_info=True)
            return None

    @staticmethod
    def _coerce_and_prepare(value: Any) -> Path | None:
        """Coerce *value* to a Path, mkdir -p it; None when unusable."""
        if value is None or isinstance(value, bool):
            return None
        try:
            path = Path(os.fspath(value))
        except TypeError:
            return None
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("plugin data dir %s not creatable: %s", path, exc)
            return None
        return path
