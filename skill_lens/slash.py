"""The ``/lens`` slash command — scan | report | help (SPEC §11.2/§11.3).

Interim execution model (PLAN Phase 1, replaced by queue-first in Phase 2):
cache-hit answers inline (<200 ms); cold scans run INLINE behind an
INTERNAL DEADLINE — acceptable while dogfooding is local CLI. Ground truth:
gateway sync handlers have NO host timeout (hermes_cli/plugins.py), so the
internal ceiling is the only thing standing between a pathological target
and a wedged reply path; async handler results are capped at 30 s by the
host, hence the 25 s hard ceiling below (DECISIONS D-026).

Advisor contract for this module:

- the handler signature is ``fn(raw_args: str) -> str | None`` and it NEVER
  raises — every failure collapses to a one-line sober notice string;
- user-initiated verbs never return ``None`` (silence is for the host's
  own bookkeeping, not answers);
- unknown input gets a usage block naming the offender;
- output is surface-neutral: no ANSI, fenced blocks, no pipe tables.
"""

from __future__ import annotations

import logging
import os
import shlex
import threading
import time
from pathlib import Path
from typing import Any

from skill_lens.cache import CacheEntry, FastPathCache, key_for_ir
from skill_lens.canonical import canonical_dumps
from skill_lens.context import PluginContextView
from skill_lens.engines import ScanDeadlineBreach
from skill_lens.render import (
    counts_phrase,
    fast_line_fail,
    fast_line_ok,
    render_chat_compact,
)
from skill_lens.report import build_report

logger = logging.getLogger("lens")

#: Internal hard ceiling for inline cold scans (DECISIONS D-026). Host
#: gateway async results cap at 30 s; stay under it with margin.
INTERNAL_SCAN_DEADLINE_SECONDS = 25.0

#: Slash command name (NAMING LAW).
SLASH_COMMAND = "lens"

_USAGE = """```\
usage: /lens <verb> [target] [flags]

verbs:
  scan <name|path>   scan a skill bundle now (collapsed chat report)
  report [name]      latest cached report for an installed skill
  help               this block

flags (scan):
  --json       canonical report/1 envelope in a json fence (byte-stable)
  --no-cache   ignore the fast-path cache and rescan

advisor only — lens never blocks installs. clean scan ≠ safe skill.\
```"""


# ---------------------------------------------------------------------------
# Target resolution (§11.2 order: installed name → local dir → file)
# ---------------------------------------------------------------------------


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def resolve_target(token: str) -> tuple[Path | None, str]:
    """Resolve one target token to a filesystem path.

    Returns ``(path, display_name)``; ``(None, token)`` when unresolvable.
    Order per §11.2: existing local path first, then installed-skill name
    looked up through the categorized tree discovery.
    """
    if not token:
        return None, token
    candidate = Path(token).expanduser()
    try:
        if candidate.exists():
            return candidate, candidate.name
    except OSError:
        return None, token

    home = hermes_home()
    skills_root = home / "skills"
    if not skills_root.is_dir():
        return None, token
    from skill_lens.ingest import discover_bundles

    try:
        refs = discover_bundles(home)
    except Exception:  # noqa: BLE001 — resolution must never raise
        logger.debug("discover_bundles failed during /lens target lookup", exc_info=True)
        return None, token
    wanted = token.strip().strip("/")
    for ref in sorted(refs, key=lambda r: r.label):
        if ref.name == wanted or ref.path.name == wanted:
            return ref.path, ref.name
    return None, token


def _deadline_from_start(start: float) -> Any:
    def exceeded() -> bool:
        return (time.monotonic() - start) >= INTERNAL_SCAN_DEADLINE_SECONDS

    return exceeded


# ---------------------------------------------------------------------------
# Scan execution (interim inline model)
# ---------------------------------------------------------------------------


def run_scan(
    target_path: Path,
    *,
    cache: FastPathCache,
    plugin_data_dir: Path,
) -> dict[str, Any]:
    """One full pipeline pass; returns render inputs, never raises.

    Shape: ``{"ok": bool, "envelope": dict|None, "compact": str|None,
    "error": str|None}``. The cache is consulted after ingest (cheap hash)
    and populated on success.
    """
    from skill_lens.engines import scan_bundle

    start = time.monotonic()
    deadline = _deadline_from_start(start)

    result = scan_bundle(target_path, deadline=deadline)
    ir = result.ir
    key = key_for_ir(ir)
    cached = cache.get(key)
    if cached is not None and cached.envelope_json is not None and cached.compact_text:
        return {
            "ok": True,
            "envelope": None,
            "compact": cached.compact_text,
            "envelope_json": cached.envelope_json,
            "cache_hit": True,
            "error": None,
        }

    envelope = build_report(result)
    compact = render_chat_compact(envelope, plugin_data_dir=plugin_data_dir)
    envelope_text = canonical_dumps(envelope)
    score = envelope.get("score") or {}
    entry = CacheEntry(
        bundle_hash=key,
        name=ir.identity.name,
        grade=str(score.get("grade", "?")),
        value=int(score.get("value", 0)),
        verdict=str(score.get("verdict", "clean")),
        counts=counts_phrase(envelope),
        cached_at=time.monotonic(),
        compact_text=compact,
        envelope_json=envelope_text,
    )
    cache.put(entry)
    return {
        "ok": True,
        "envelope": envelope,
        "compact": compact,
        "envelope_json": envelope_text,
        "cache_hit": False,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Verb handlers
# ---------------------------------------------------------------------------


def _verb_scan(
    args: list[str],
    *,
    view: PluginContextView,
    cache: FastPathCache,
) -> str:
    want_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    no_cache = "--no-cache" in args
    unknown_flags = [a for a in args if a.startswith("--") and a not in ("--json", "--no-cache")]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if not positional:
        return _usage_line(missing="target")

    target_path, display_name = resolve_target(positional[0])
    if target_path is None:
        return fast_line_fail(name=display_name, reason=f"unresolvable target: {positional[0]}")

    plugin_data_dir = view.plugin_data_dir()

    # Fast path first: ingest + hash is cheap; a live cache entry answers
    # without running engines (<200 ms contract, PLAN Phase 1).
    if not no_cache:
        quick = _try_cache_hit(target_path, cache=cache, want_json=want_json)
        if quick is not None:
            return quick

    try:
        outcome = run_scan(target_path, cache=cache, plugin_data_dir=plugin_data_dir)
    except ScanDeadlineBreach as exc:
        logger.warning("/lens scan hit internal deadline: %s", exc)
        return fast_line_fail(
            name=display_name,
            reason=f"internal scan deadline ({int(INTERNAL_SCAN_DEADLINE_SECONDS)}s) exceeded",
        )
    except Exception as exc:  # noqa: BLE001 — handler never raises into the host
        logger.exception("/lens scan failed")
        reason = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return fast_line_fail(name=display_name, reason=f"unreadable target: {reason}")

    if want_json:
        body = outcome.get("envelope_json") or canonical_dumps(outcome.get("envelope") or {})
        return f"```json\n{body}\n```"
    text = outcome.get("compact")
    assert isinstance(text, str) and text  # run_scan guarantees a render
    return text


def _try_cache_hit(target_path: Path, *, cache: FastPathCache, want_json: bool) -> str | None:
    """Answer from the cache when the bundle bytes are unchanged.

    Serves whichever artifact the invocation asked for: the canonical JSON
    fence for ``--json``, the collapsed compact render otherwise.
    """
    from skill_lens.ingest import DEFAULT_CEILINGS, load_bundle

    try:
        ir = load_bundle(target_path, ceilings=DEFAULT_CEILINGS)
    except Exception:  # noqa: BLE001 — fall through to the full-scan error path
        return None
    entry = cache.get(key_for_ir(ir))
    if entry is None or entry.envelope_json is None or entry.compact_text is None:
        return None
    if want_json:
        return f"```json\n{entry.envelope_json}\n```"
    return entry.compact_text


def _verb_report(args: list[str], *, cache: FastPathCache) -> str:
    positional = [a for a in args if not a.startswith("--")]
    name = positional[0] if positional else None
    entry: CacheEntry | None = None
    if name is not None:
        entry = cache.latest_by_name(name)
        if entry is None:
            return (
                f"no lens report cached for {name!r} — run `/lens scan {name}` "
                "(cold scans answer on completion)"
            )
    else:
        entry = _latest_entry(cache)
        if entry is None:
            return "no lens reports cached yet — run `/lens scan <name|path>` first"
    if entry.compact_text:
        return entry.compact_text
    return fast_line_ok(
        name=entry.name,
        grade=entry.grade,
        value=entry.value,
        verdict=entry.verdict,
        counts=entry.counts,
        cached_seconds=entry.age_seconds(),
    )


def _latest_entry(cache: FastPathCache) -> CacheEntry | None:
    """Newest cached entry across the installed tree (deterministic walk)."""
    from skill_lens.ingest import discover_bundles

    try:
        names = {ref.name for ref in discover_bundles(hermes_home())}
    except Exception:  # noqa: BLE001 — degraded homes just see an empty set
        names = set()
    best: CacheEntry | None = None
    newest_at = -1.0
    for name in sorted(names):
        entry = cache.latest_by_name(name)
        if entry is not None and entry.cached_at > newest_at:
            newest_at = entry.cached_at
            best = entry
    return best


# ---------------------------------------------------------------------------
# Usage / errors
# ---------------------------------------------------------------------------


def _usage_line(*, offender: str | None = None, missing: str | None = None) -> str:
    if offender:
        return f"unknown flag {offender!r} — showing usage\n{_USAGE}"
    if missing:
        return f"/lens scan requires a {missing} — showing usage\n{_USAGE}"
    return _USAGE


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_shared_cache_lock = threading.Lock()
_shared_cache: FastPathCache | None = None


def shared_cache() -> FastPathCache:
    """Process-wide cache reused by register_slash and future triggers.

    Module-level singleton (one lock inside :class:`FastPathCache` already
    guards its dict); tests reset via ``reset_shared_cache()``.
    """
    global _shared_cache
    with _shared_cache_lock:
        if _shared_cache is None:
            _shared_cache = FastPathCache()
        return _shared_cache


def reset_shared_cache() -> None:
    """Drop the process-wide cache (test seam; harmless in production)."""
    global _shared_cache
    with _shared_cache_lock:
        _shared_cache = None


def make_handler(view: PluginContextView, cache: FastPathCache) -> Any:
    """Build the ``fn(raw_args) -> str | None`` slash handler."""

    def handler(raw_args: str) -> str | None:
        try:
            tokens = shlex.split(raw_args or "")
        except ValueError:
            return _usage_line(offender=(raw_args or "").split()[0] if raw_args else None)
        verb = tokens[0].lower() if tokens else "help"
        args = tokens[1:]
        if verb in ("help", "-h", "--help"):
            return _USAGE
        if verb == "scan":
            return _verb_scan(args, view=view, cache=cache)
        if verb == "report":
            return _verb_report(args, cache=cache)
        return _usage_line(offender=verb)

    def safe_handler(raw_args: str) -> str | None:
        try:
            return handler(raw_args)
        except Exception:  # noqa: BLE001 — the advisor law, enforced twice
            logger.exception("/lens handler raised; returning sober notice")
            return fast_line_fail(name="lens", reason="internal error — see logs; /lens doctor")

    return safe_handler


def register_slash(
    view: PluginContextView,
    *,
    cache: FastPathCache | None = None,
) -> FastPathCache | None:
    """Register ``/lens`` on the defensive view. Never raises into the host.

    Returns the cache backing this registration (None when the host ctx
    lacks the seam entirely), so later phases reuse one store.
    """
    owned_cache = cache if cache is not None else shared_cache()
    description = "Skill Lens — deterministic security reports for skill bundles (advisory)"
    args_hint = "scan|report|help · flags: --json --no-cache"
    handle = make_handler(view, owned_cache)
    registration = view.register_command(
        SLASH_COMMAND,
        handle,
        description=description,
        args_hint=args_hint,
    )
    if registration is None:
        logger.warning("/lens registration degraded: host ctx lacks register_command()")
        return None
    return owned_cache


__all__ = [
    "INTERNAL_SCAN_DEADLINE_SECONDS",
    "SLASH_COMMAND",
    "make_handler",
    "register_slash",
    "reset_shared_cache",
    "resolve_target",
    "run_scan",
    "shared_cache",
]
