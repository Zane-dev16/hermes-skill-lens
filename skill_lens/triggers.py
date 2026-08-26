"""Trigger wiring — the three observer hooks (SPEC §11.6, advisor law).

Skill Lens registers exactly three hooks, all observers:

- ``on_skill_lifecycle``  — best-effort lifecycle facts (created/installed/
  loaded/used/patched). Fast path: cache hit builds the §11.4 format-A
  one-liner inline (<200 ms budget, enforced internally); miss enqueues a
  cold scan on the worker and answers with format B. The host discards the
  return value — side effects are the ndjson record + queue entry.
- ``post_tool_call``      — self-filtered to ``tool_name == "skill_manage"``
  (everything else returns instantly). The authoring beat for agent-created
  skills; same fast path as the lifecycle lane.
- ``transform_tool_result`` — append-only sober notice (≤160 chars) to the
  model-visible ``skill_manage`` result, security-guidance precedent
  (plugins/security-guidance/__init__.py:227). Kill-switch:
  ``plugins.entries.lens.settings.notify = false``. Notices carry the verdict
  word + pointer ONLY — no scores, no emoji, no marketing; automation
  surfaces are permanently sober (SPEC §16 default).

Advisor laws enforced here (tests pin every one):

- NEVER ``pre_tool_call``; nothing in this module can block or veto.
- Handlers accept arbitrary kwargs (the host injects
  ``telemetry_schema_version`` and grows payloads additively), never raise
  into the host, and return ``None`` or ``str`` only.
- The reply/install beat is never delayed beyond the cached fast path;
  engines run on the worker thread only (skill_lens.jobs).

Ground truth for payload shapes: docs/host-contract.md (transcribed from
/usr/local/lib/hermes-agent emit sites).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("lens")

#: Hard ceiling for one fast-path answer (PLAN §0 Triggers row / §11.5).
FAST_PATH_BUDGET_SECONDS = 0.200

#: Internal soft deadline — optional stages are abandoned past this so total
#: handler time stays under :data:`FAST_PATH_BUDGET_SECONDS` with headroom.
_SOFT_DEADLINE_SECONDS = 0.150

#: The single tool whose results we observe/annotate (host tool name).
SKILL_MANAGE_TOOL = "skill_manage"

#: Lifecycle actions handled (SPEC §11.6); anything else is ignored cheaply.
LIFECYCLE_ACTIONS = frozenset({"created", "installed", "loaded", "used", "patched"})

#: skill_manage actions that change bundle bytes (the authoring beat).
MUTATING_ACTIONS = frozenset({"create", "edit", "patch", "write_file", "remove_file"})

#: Sober-notice cap (matches §11.4 FAST_LINE_MAX_CHARS; ASCII only).
NOTICE_MAX_CHARS = 160


# ---------------------------------------------------------------------------
# Hook-registration ledger (doctor check 5's self-audit source) -------------

#: Every (hook_name, callback) this plugin has ever passed to the host's
#: ``register_hook`` seam, in order. Doctor §11.9 check 5 audits THIS record
#: for ``pre_tool_call`` — the advisor stance made checkable. Tests inject a
#: fake blocking registration here to prove the audit fails loudly.
_registry_lock = threading.Lock()
_hook_registry: list[tuple[str, Callable[..., Any] | None]] = []


def note_hook_registration(hook_name: str, callback: Callable[..., Any] | None = None) -> None:
    """Record one hook registration in the doctor-auditable ledger.

    Production callers: :func:`register_triggers`. Test seam: inject a
    deliberate ``pre_tool_call`` entry and watch doctor check 5 fail loudly.
    Never raises.
    """
    try:
        with _registry_lock:
            _hook_registry.append((str(hook_name), callback))
    except Exception:  # noqa: BLE001 — ledger must never break triggers
        logger.debug("note_hook_registration failed", exc_info=True)


def registry_snapshot() -> tuple[tuple[str, Callable[..., Any] | None], ...]:
    """Copy of the registration ledger (doctor/test introspection)."""
    with _registry_lock:
        return tuple(_hook_registry)


def reset_hook_registry() -> None:
    """Clear the ledger (test seam; harmless in production)."""
    with _registry_lock:
        _hook_registry.clear()


# Observability counters (diagnostics only — never inputs to any report)
# ---------------------------------------------------------------------------

_stats_lock = threading.Lock()
_stats: dict[str, int] = {
    "lifecycle_events": 0,
    "post_tool_seen": 0,
    "post_tool_handled": 0,
    "cache_hits": 0,
    "enqueues": 0,
    "coalesced": 0,
    "notices_appended": 0,
    "notices_suppressed": 0,
    "overruns": 0,
    "errors": 0,
}


def stats_snapshot() -> dict[str, int]:
    """Return a copy of the trigger counters (doctor/test introspection)."""
    with _stats_lock:
        return dict(_stats)


# ---------------------------------------------------------------------------
# Recent-hash registry — lifecycle coverage ledger for the drift watcher
# ---------------------------------------------------------------------------

#: How long one fast-path-covered bundle hash stays "recently covered".
#: Generous vs the worker's p95 400 ms so a watcher diff landing seconds
#: after a lifecycle event still dedupes; small enough to stay honest.
RECENT_HASH_TTL_SECONDS = 120.0

_recent_hashes_lock = threading.Lock()
_recent_hashes: dict[str, float] = {}  # bundle_hash -> monotonic expiry


def note_handled_hash(bundle_hash: str, *, now: float | None = None) -> None:
    """Record that the fast path covered *bundle_hash* (watcher dedupe seam).

    Called from :func:`_fast_path_inner` once the canonical hash is known —
    on BOTH lanes (cache hit and enqueue), because either way the bundle was
    handled. Bounded by opportunistic expiry sweeps; never raises.
    """
    if not bundle_hash:
        return
    reference = time.monotonic() if now is None else now
    try:
        with _recent_hashes_lock:
            _recent_hashes[bundle_hash] = reference + RECENT_HASH_TTL_SECONDS
            if len(_recent_hashes) > 256:
                expired = [k for k, v in _recent_hashes.items() if v <= reference]
                for key in expired:
                    del _recent_hashes[key]
                # Still oversized ⇒ drop oldest entries by deadline.
                if len(_recent_hashes) > 256:
                    oldest = sorted(((deadline, key) for key, deadline in _recent_hashes.items()))
                    for _deadline, key in oldest[: len(oldest) - 256]:
                        del _recent_hashes[key]
    except Exception:  # noqa: BLE001 — dedupe ledger must never break triggers
        logger.debug("note_handled_hash failed", exc_info=True)


def recently_covered(bundle_hash: str, *, now: float | None = None) -> bool:
    """True when the lifecycle/post-tool fast path recently covered *hash*.

    The drift watcher consults this before enqueueing (SPEC §11.6
    double-scan avoidance): a bundle the lifecycle lane already fast-pathed
    gets a ``lens skip`` status instead of a second scan. Never raises.
    """
    if not bundle_hash:
        return False
    reference = time.monotonic() if now is None else now
    try:
        with _recent_hashes_lock:
            deadline = _recent_hashes.get(bundle_hash)
            return deadline is not None and deadline > reference
    except Exception:  # noqa: BLE001
        return False


def reset_recent_hashes() -> None:
    """Clear the coverage ledger (test seam; harmless in production)."""
    with _recent_hashes_lock:
        _recent_hashes.clear()


def reset_stats() -> None:
    """Zero the counters (test seam; harmless in production)."""
    with _stats_lock:
        for key in _stats:
            _stats[key] = 0


def _bump(key: str) -> None:
    with _stats_lock:
        _stats[key] += 1


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_triggers(view: Any) -> tuple[str, ...]:
    """Register the three observer hooks through the defensive view.

    Each registration is individually guarded: a hostile or half-missing
    context degrades to fewer live hooks, never an exception into the host.
    Returns the hook names that were actually registered. Every attempt is
    recorded in the ledger doctor check 5 audits (:func:`note_hook_registration`).
    """
    registered: list[str] = []
    for hook_name, handler in (
        ("on_skill_lifecycle", _on_skill_lifecycle),
        ("post_tool_call", _on_post_tool_call),
        ("transform_tool_result", _on_transform_tool_result),
    ):
        note_hook_registration(hook_name, handler)
        try:
            if view.register_hook(hook_name, handler) is not None or True:
                # Counted as wired even when the seam degrades to None: the
                # attempt itself is logged by the view; we must not raise.
                registered.append(hook_name)
        except Exception:  # noqa: BLE001 — advisor law: registration never raises
            _bump("errors")
            logger.exception("trigger registration failed for %r", hook_name)
    logger.info("Skill Lens triggers wired: %s (observers only)", ", ".join(registered))
    return tuple(registered)


# ---------------------------------------------------------------------------
# Hook handlers (host-visible signatures: loose kwargs, never raise)
# ---------------------------------------------------------------------------


def _on_skill_lifecycle(action: str = "", skill_name: str = "", **_: Any) -> None:
    """Observer for skill lifecycle facts; return value discarded by host."""
    try:
        if str(action) not in LIFECYCLE_ACTIONS:
            return
        name = str(skill_name or "")
        if not name:
            return
        _bump("lifecycle_events")
        _fast_path(name=name, source="lifecycle")  # line built & discarded
    except Exception:  # noqa: BLE001 — advisor law
        _bump("errors")
        logger.exception("on_skill_lifecycle handler failed")


def _on_post_tool_call(tool_name: str = "", args: Any = None, **_: Any) -> None:
    """Observer for tool completions; self-filters to skill_manage instantly."""
    try:
        if str(tool_name or "") != SKILL_MANAGE_TOOL:
            return  # instant ignore — the common case costs one string compare
        _bump("post_tool_seen")
        action, name = _action_and_name(args)
        if action not in MUTATING_ACTIONS or not name:
            return
        _bump("post_tool_handled")
        _fast_path(name=name, source="post_tool_call")  # line built & discarded
    except Exception:  # noqa: BLE001 — advisor law
        _bump("errors")
        logger.exception("post_tool_call handler failed")


def _on_transform_tool_result(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    status: str = "",
    **_: Any,
) -> str | None:
    """Append ONE sober notice line to a successful skill_manage result.

    Returns ``result + "\\n" + <notice>`` (original bytes preserved), or
    ``None`` to leave the result unchanged. Never raises; never decorates
    failures; disabled entirely by the ``notify=false`` kill-switch.
    """
    try:
        if str(tool_name or "") != SKILL_MANAGE_TOOL:
            return None
        view = _current_view()
        if view is None:
            return None
        if not _notify_enabled(view):
            _bump("notices_suppressed")
            return None
        if not isinstance(result, str):
            return None
        if str(status or "") == "error":
            return None  # don't decorate error results (security-guidance precedent)
        action, name = _action_and_name(args)
        if action not in MUTATING_ACTIONS or not name:
            return None
        if _result_reports_failure(result):
            return None
        notice = _notice_for(name)
        if notice is None:
            return None
        if _already_noticed(result, notice):
            return None
        _bump("notices_appended")
        return result + "\n" + notice
    except Exception:  # noqa: BLE001 — advisor law
        _bump("errors")
        logger.exception("transform_tool_result handler failed")
        return None


# ---------------------------------------------------------------------------
# Fast path (SPEC §11.4/§11.5/§11.6) — shared by both observer lanes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FastOutcome:
    """What one fast-path pass decided. ``line`` is the §11.4 one-liner."""

    kind: str  # "hit" | "queued" | "coalesced" | "noop"
    name: str
    entry: Any | None = None  # CacheEntry on hit
    line: str | None = None  # format-A/B one-liner where applicable


def _fast_path(*, name: str, source: str) -> FastOutcome:
    """Cache-hit ⇒ build format A inline; miss ⇒ enqueue + format B.

    Budget enforcement: perf_counter checkpoints between stages; past the
    soft deadline optional stages stop, and any overrun past the hard budget
    is counted + logged. The enqueue itself is never skipped once the hash is
    known (correctness outranks the budget); engines never run here.
    """
    start = time.perf_counter()
    outcome = _fast_path_inner(name=name, source=source, start=start)
    elapsed = time.perf_counter() - start
    if elapsed >= FAST_PATH_BUDGET_SECONDS:
        _bump("overruns")
        logger.warning(
            "fast path overran budget (%.1f ms > %.0f ms) for %r via %s",
            elapsed * 1000.0,
            FAST_PATH_BUDGET_SECONDS * 1000.0,
            name,
            source,
        )
    return outcome


def _fast_path_inner(*, name: str, source: str, start: float) -> FastOutcome:
    from .bootstrap import get_context

    view = get_context()
    if view is None:
        return FastOutcome(kind="noop", name=name)

    from .slash import resolve_target, shared_cache, shared_jobs

    target_path, display_name = resolve_target(name)
    if target_path is None or time.perf_counter() - start >= _SOFT_DEADLINE_SECONDS:
        # Unresolvable names have nothing to scan; over-budget stops here.
        return FastOutcome(kind="noop", name=display_name)

    cache = shared_cache()
    jobs = shared_jobs(view)

    baseline_records: tuple[Any, ...] = ()
    key_suffix = ""
    try:
        from .slash import _baseline_state

        baseline_records, key_suffix = _baseline_state(view, target_path)
    except Exception:  # noqa: BLE001 — broken policy config degrades, never blocks
        logger.debug("baseline state unavailable during trigger (%s)", name, exc_info=True)

    from .cache import hash8, key_for_ir
    from .ingest import DEFAULT_CEILINGS, load_bundle

    ir = None
    try:
        ir = load_bundle(target_path, ceilings=DEFAULT_CEILINGS)
    except Exception:  # noqa: BLE001 — unreadable target degrades to D-lane wording
        logger.debug("ingest failed during trigger (%s)", name, exc_info=True)
    if ir is None:
        return FastOutcome(kind="noop", name=display_name)

    bundle_hash = key_for_ir(ir)
    note_handled_hash(bundle_hash)  # watcher-dedupe ledger (either lane counts)
    # Over soft budget ⇒ skip the optional cache probe; a miss MUST still
    # reach the worker, so control falls through to the enqueue below.
    over_budget = time.perf_counter() - start >= _SOFT_DEADLINE_SECONDS
    entry = None if over_budget else cache.get(bundle_hash + key_suffix)
    if entry is not None and entry.compact_text:
        _bump("cache_hits")
        from .render import fast_line_ok

        return FastOutcome(
            kind="hit",
            name=display_name,
            entry=entry,
            line=fast_line_ok(
                name=display_name,
                grade=entry.grade,
                value=entry.value,
                verdict=entry.verdict,
                counts=entry.counts,
                cached_seconds=entry.age_seconds(),
            ),
        )

    decision = _enqueue_quietly(
        jobs,
        name=display_name,
        target=target_path,
        bundle_hash=bundle_hash,
        key_suffix=key_suffix,
        baseline_records=baseline_records,
        cache=cache,
        view=view,
    )
    if decision is None:
        return FastOutcome(kind="noop", name=display_name)
    if decision.coalesced:
        _bump("coalesced")
    else:
        _bump("enqueues")
    from .render import fast_line_scan_queued

    return FastOutcome(
        kind="queued",
        name=display_name,
        line=fast_line_scan_queued(name=display_name, hash8=hash8(bundle_hash)),
    )


def _enqueue_quietly(
    jobs: Any,
    *,
    name: str,
    target: Any,
    bundle_hash: str,
    key_suffix: str,
    baseline_records: tuple[Any, ...],
    cache: Any,
    view: Any,
) -> Any | None:
    """Enqueue one cold scan; any failure logs and returns None (never raises)."""
    try:
        from datetime import date

        from .jobs import ScanContext

        # Wall-clock here feeds ONLY the _meta/report-date sidecar lane (same
        # as the /lens scan verb) — never any deterministic artifact.
        return jobs.enqueue(
            name=name,
            target=target,
            bundle_hash=bundle_hash,
            cache_key=bundle_hash + key_suffix,
            context=ScanContext(
                baseline_records=baseline_records,
                key_suffix=key_suffix,
                report_date=date.today(),
                plugin_data_dir=view.plugin_data_dir(),
                cache=cache,
                osv=False,
            ),
        )
    except Exception:  # noqa: BLE001 — advisor law
        _bump("errors")
        logger.exception("enqueue failed during trigger (%s)", name)
        return None


# ---------------------------------------------------------------------------
# Transform-lane notices (sober automation surface — verdict word + pointer)
# ---------------------------------------------------------------------------


def _notice_for(name: str) -> str | None:
    """Run the fast path and render the sober model-visible notice.

    Verdict word + pointer only: no grade, no numeric score, no counts, no
    decoration. ``None`` when there is nothing honest to say yet.
    """
    outcome = _fast_path(name=name, source="transform")
    if outcome.kind == "hit" and outcome.entry is not None:
        verdict = str(getattr(outcome.entry, "verdict", "") or "clean")
        return _clip_notice(f"lens ok {_clean(outcome.name)} · verdict {verdict} · /lens report")
    if outcome.kind in {"queued", "coalesced"}:
        clean = _clean(outcome.name)
        return _clip_notice(f"lens scan queued: {clean} · /lens report {clean} when ready")
    return None


def _clean(fragment: str) -> str:
    """Sober-automation hygiene: collapse whitespace, drop non-printables."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in str(fragment))
    return " ".join(cleaned.split())[:64] or "unknown"


def _clip_notice(line: str) -> str:
    """One-line, control-free clip at NOTICE_MAX_CHARS.

    Keeps the house-style ``·`` separator used by every §11.4 lens line;
    strips control characters and collapses whitespace so a hostile name can
    never smuggle newlines into the model-visible result.
    """
    flat = " ".join(str(line).split())
    return flat[:NOTICE_MAX_CHARS]


def _notify_enabled(view: Any) -> bool:
    """Kill-switch: plugins.entries.lens.settings.notify (default true)."""
    raw = view.get_config("notify", True)
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() not in {"false", "0", "no", "off"}
    return bool(raw)


def _action_and_name(args: Any) -> tuple[str, str]:
    """Extract (action, name) from a tool-call args mapping, defensively."""
    if isinstance(args, dict):
        action = str(args.get("action") or "")
        name = str(args.get("name") or "")
        return action, name
    return "", ""


def _result_reports_failure(result: str) -> bool:
    """True when the skill_manage JSON result reports failure (don't decorate).

    Mirrors the security-guidance precedent of leaving error results alone:
    ``{"success": false, ...}`` / ``{"error": ...}`` shapes.
    """
    import json

    try:
        parsed = json.loads(result)
    except (ValueError, TypeError):
        return False
    if isinstance(parsed, dict):
        if parsed.get("success") is False:
            return True
        if parsed.get("error"):
            return True
    return False


def _already_noticed(result: str, notice: str) -> bool:
    """Idempotence guard: don't double-append when the tail already carries it."""
    window = result[-(len(notice) + 2) :]
    return notice in window


def _current_view() -> Any | None:
    from .bootstrap import get_context

    return get_context()


__all__ = [
    "FAST_PATH_BUDGET_SECONDS",
    "LIFECYCLE_ACTIONS",
    "MUTATING_ACTIONS",
    "NOTICE_MAX_CHARS",
    "RECENT_HASH_TTL_SECONDS",
    "SKILL_MANAGE_TOOL",
    "FastOutcome",
    "note_handled_hash",
    "note_hook_registration",
    "recently_covered",
    "register_triggers",
    "registry_snapshot",
    "reset_hook_registry",
    "reset_recent_hashes",
    "reset_stats",
    "stats_snapshot",
]
