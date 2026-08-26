"""Hub quarantine report view — co-flagship #1 (SPEC §11.7).

At ``hermes skills install`` bundles pause in ``skills/.hub/quarantine/``
behind the guard's trust gate and the SkillEvaluator Tier-1 advisory — the
install seam fires NO plugin hooks (docs/host-contract.md §5), so this view
is how Skill Lens becomes the THIRD opinion at that beat without ever
delaying it: ``/lens hub`` renders claimed-vs-actual for every staged bundle,
each through the same fast path as the triggers (cache hit ⇒ format-A line;
miss ⇒ worker enqueue ⇒ format-B pointer).

Hard non-coupling rules (R7) enforced here and pinned by tests:

- NEVER subsume the gate: output is labeled ``advisory — skills_guard
  decides install policy`` and the role-label block names all three opinions.
- NEVER read/write ``INSTALL_POLICY`` or import anything from
  ``tools.skills_guard`` / ``tools.skillevaluator_scan`` — no imports from
  the host tools tree exist anywhere in :mod:`skill_lens` (static test).
- Provenance is ANNOTATION-ONLY from ``.hub/lock.json`` (S7/D-PROV): display
  strings only; nothing here feeds scoring arithmetic.

Race law (§11.6): quarantine dirs vanish on cancel/block (rmtree both
paths). Enumeration degrades vanishing dirs to skip diagnostics (ingest),
and a bundle that vanishes between enumeration and rendering yields a
``lens skip …`` line — never an error cascade.

Surface law (§11.3): fenced chat variant, NO ANSI, no pipe tables, soft
budget 1200 / hard 1800 chars with an honest collapse ladder. The coverage
footer rides every report surface (§12.6).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .cache import hash8
from .render import (
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
    FAST_LINE_MAX_CHARS,
    _clip_fast_line,
    fast_line_fail,
    fast_line_ok,
    fast_line_scan_queued,
)

logger = logging.getLogger("lens")

#: Hub staging layout (host ground truth: tools/skills_hub.py:70–82 via
#: docs/host-contract.md §5 — ``_hub_dir``/``_quarantine_dir``).
HUB_DIRNAME = ".hub"
QUARANTINE_DIRNAME = "quarantine"

#: Confirm-beat budget for the whole cached render (PLAN Phase 4 bullet 4:
#: "<200 ms cached"). Overruns are counted + logged, never abandoned — the
#: enqueue itself must always happen once the hash is known (correctness
#: outranks the display budget, mirroring the trigger lane).
CONFIRM_BEAT_BUDGET_SECONDS = 0.200

#: The exact role-label wording per SPEC §11.7 / PLAN Phase 4 (R7). These
#: lines are part of the pinned snapshot; do not rewrap. ADVISORY_ROLE_LINE
#: is THE explicit label the specs name verbatim.
ADVISORY_ROLE_LINE = "advisory — skills_guard decides install policy"
ROLE_ROWS: tuple[str, ...] = (
    "skills_guard      : gate — decides install policy (INSTALL_POLICY; not ours to touch)",
    "SkillEvaluator T1 : advisory — warn-don't-block second opinion (PII/secrets-class confirms)",
    "lens              : depth — claimed-vs-actual report; full micrograph via /lens report",
)

#: Display clip for untrusted bundle names (mirrors render._DISPLAY_NAME_MAX).
_NAME_MAX_CHARS = 96

#: Undeclared-capability families shown in a cache-hit depth fragment.
_UNDECLARED_FAMILIES_MAX = 3


def quarantine_dir(home: Path | str) -> Path:
    """``<home>/skills/.hub/quarantine`` — the stable staging corridor."""
    return Path(home) / "skills" / HUB_DIRNAME / QUARANTINE_DIRNAME


def enumerate_quarantine(home: Path | str) -> list[Any]:
    """Bundle refs currently sitting in the quarantine corridor.

    Reuses :func:`skill_lens.ingest.discover_bundles` and keeps ONLY refs
    whose resolved path lives under ``<home>/skills/.hub/quarantine``
    (dir bundles at variable depth plus staged ``*.zip`` archives). A tree
    that vanishes mid-walk degrades to skip diagnostics inside discovery —
    this function never raises. Output follows discovery's deterministic
    relative-path ordering.
    """
    from .ingest import discover_bundles

    qroot = quarantine_dir(home)
    try:
        refs = discover_bundles(Path(home))
    except Exception:  # noqa: BLE001 — advisor law: a broken tree renders empty
        logger.debug("quarantine enumeration failed", exc_info=True)
        return []
    try:
        qres = qroot.resolve()
    except OSError:
        qres = qroot
    kept: list[Any] = []
    for ref in refs:
        try:
            resolved = ref.path.resolve()
            inside = qres == resolved or qres in resolved.parents
        except OSError:
            inside = False
        if inside:
            kept.append(ref)
    return kept


# ---------------------------------------------------------------------------
# Per-bundle fast path (same discipline as triggers._fast_path)
# ---------------------------------------------------------------------------


def _display(name: str) -> str:
    cleaned = " ".join(str(name).split())
    if len(cleaned) > _NAME_MAX_CHARS:
        cleaned = cleaned[: _NAME_MAX_CHARS - 1] + "…"
    return cleaned or "unknown"


def _provenance_note(ref: Any, lock: dict[str, dict[str, Any]]) -> str:
    """Annotation-only provenance string from .hub/lock.json (S7/D-PROV)."""
    try:
        from .ingest import enrich_provenance

        prov = enrich_provenance(ref, lock)
    except Exception:  # noqa: BLE001 — annotation must never break the render
        return "provenance unavailable"
    bits: list[str] = []
    if prov is not None:
        if prov.identifier:
            bits.append(str(prov.identifier))
        if prov.trust_level:
            bits.append(f"trust {prov.trust_level}")
    if not bits:
        bits.append("no lock entry")
    return " · ".join(bits)


def _undeclared_fragment(envelope_json: str | None) -> str:
    """Compact claimed-vs-actual fragment from a cached envelope.

    Counts ACTIVE undeclared findings by capability family — the lens-depth
    signal for this view. Deterministic (sorted families); ``""`` when there
    is nothing undeclared or the envelope cannot be parsed (never raises).
    """
    if not envelope_json:
        return ""
    try:
        envelope = json.loads(envelope_json)
    except ValueError:
        return ""
    if not isinstance(envelope, dict):
        return ""
    families: dict[str, int] = {}
    for finding in envelope.get("findings", ()) or ():
        if not isinstance(finding, dict) or finding.get("suppressed", False):
            continue
        if finding.get("declared", False):
            continue
        family = str(finding.get("capability", "")).partition(":")[0]
        if family:
            families[family] = families.get(family, 0) + 1
    if not families:
        return ""
    shown = sorted(families.items())[:_UNDECLARED_FAMILIES_MAX]
    hidden = len(families) - len(shown)
    text = " ".join(f"{name}×{count}" for name, count in shown)
    if hidden > 0:
        text += f" +{hidden} more"
    return f"claims-vs-actual: undeclared {text}"


_SKIP_LINE_TEMPLATE = (
    "lens skip {name} · vanished during view (cancelled or installed) · /lens report"
)


def _entry_status_line(
    ref: Any,
    *,
    name: str,
    bundle_hash: str | None,
    cache: Any,
    jobs: Any | None,
    view: Any | None,
    cache_key_suffix: str,
    baseline_records: tuple[Any, ...] = (),
) -> str:
    """The §11.4 status line for one staged bundle (A / B / C-skip / D).

    Cache hit ⇒ format A inline (<200 ms cached contract) plus an indented
    claims-vs-actual depth fragment when undeclared findings exist. Miss ⇒
    worker enqueue + format B pointer. Vanished mid-render ⇒ skip line.
    Never raises; correctness outranks the display budget (the enqueue is
    never skipped once the hash is known).
    """
    if bundle_hash is None:
        # Ingest failed: distinguish vanished (skip lane, §11.6) from
        # genuinely unreadable (D lane, exact CLI stderr wording).
        try:
            vanished = not ref.path.exists()
        except OSError:
            vanished = True
        if vanished:
            return _clip_fast_line(_SKIP_LINE_TEMPLATE.format(name=name))
        return fast_line_fail(name=name, reason="unreadable target · /lens doctor")

    entry = None
    try:
        entry = cache.get(bundle_hash + cache_key_suffix)
    except Exception:  # noqa: BLE001 — display probe is best-effort
        entry = None
    if entry is not None:
        raw_age = getattr(entry, "age_seconds", lambda: None)()
        cached_seconds = int(raw_age) if isinstance(raw_age, (int, float)) else None
        line = fast_line_ok(
            name=name,
            grade=str(getattr(entry, "grade", "?")),
            value=int(getattr(entry, "value", 0) or 0),
            verdict=str(getattr(entry, "verdict", "clean")),
            counts=str(getattr(entry, "counts", "") or ""),
            cached_seconds=cached_seconds,
        )
        depth = _undeclared_fragment(getattr(entry, "envelope_json", None))
        if depth:
            line = f"{line}\n  {depth}"
        return line

    decision = None
    if jobs is not None:
        decision = _enqueue(
            view=view,
            jobs=jobs,
            ref=ref,
            name=name,
            bundle_hash=bundle_hash,
            suffix=cache_key_suffix,
            baseline_records=baseline_records,
            cache=cache,
        )
    if decision is None:
        if jobs is None:
            return fast_line_fail(name=name, reason="scan worker unavailable")
        return _clip_fast_line(
            f"lens scan queued: {name} · sha256 {hash8(bundle_hash)} · p95 400ms "
            f"· /lens report {name} when ready"
        )
    if decision.coalesced:
        return _clip_fast_line(
            f"lens skip {name} · scan already in progress ({hash8(bundle_hash)}) "
            f"· /lens report {name} when ready"
        )
    return fast_line_scan_queued(name=name, hash8=hash8(bundle_hash))


def _enqueue(
    *,
    view: Any | None,
    jobs: Any,
    ref: Any,
    name: str,
    bundle_hash: str,
    suffix: str,
    baseline_records: tuple[Any, ...],
    cache: Any,
) -> Any | None:
    """Queue one cold scan for a staged bundle; never raises.

    *bundle_hash*/*suffix*/*baseline_records* arrive precomputed by
    :func:`_render_inner` (single ingest per staged bundle; same fields as
    the trigger lane so coalescing folds hub-view enqueues onto any
    already-running scan and completed results land in the SAME cache this
    view probes).
    """
    try:
        from datetime import date

        from .jobs import ScanContext

        target = ref.path if ref.path.is_dir() else ref.path.parent
        data_dir = view.plugin_data_dir() if view is not None else target.parent
        return jobs.enqueue(
            name=name,
            target=ref.path,
            bundle_hash=bundle_hash,
            cache_key=bundle_hash + suffix,
            context=ScanContext(
                baseline_records=baseline_records,
                key_suffix=suffix,
                report_date=date.today(),
                plugin_data_dir=data_dir,
                cache=cache,
                osv=False,
            ),
        )
    except Exception:  # noqa: BLE001 — advisor law
        logger.exception("hub-view enqueue failed (%s)", name)
        return None


# ---------------------------------------------------------------------------
# Full render (fenced chat variant, budget ladder)
# ---------------------------------------------------------------------------


def render_hub_view(
    *,
    home: Path | str,
    view: Any | None = None,
    cache: Any | None = None,
    jobs: Any | None = None,
    refs: list[Any] | None = None,
    lock: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Render the collapsed chat variant for staged quarantine bundles.

    Never raises; never emits ANSI. *refs*/*lock* are injection seams for
    race tests (default: enumerate live + read the real lockfile). Budget
    ladder (§11.3): full render ≤ soft budget → drop provenance notes →
    truncate entries behind a count line until ≤ soft → counts-only body.
    """
    start = time.perf_counter()
    try:
        body = _render_inner(home=home, view=view, cache=cache, jobs=jobs, refs=refs, lock=lock)
    except Exception:  # noqa: BLE001 — advisor law: the view can never fail loud
        logger.exception("hub view render failed; serving sober notice")
        body = "hub quarantine: unavailable right now — /lens doctor"
    elapsed = time.perf_counter() - start
    if elapsed >= CONFIRM_BEAT_BUDGET_SECONDS:
        logger.warning("hub view overran confirm-beat budget (%.1f ms)", elapsed * 1000.0)
    return body


def _render_inner(
    *,
    home: Path | str,
    view: Any | None,
    cache: Any | None,
    jobs: Any | None,
    refs: list[Any] | None,
    lock: dict[str, dict[str, Any]] | None,
) -> str:
    if cache is None:
        from .slash import shared_cache

        cache = shared_cache()

    if refs is None:
        refs = enumerate_quarantine(home)
    if lock is None:
        try:
            from .ingest import read_hub_lock

            lock = read_hub_lock(home)
        except Exception:  # noqa: BLE001 — annotation-only, degrade to {}
            lock = {}

    tail = (
        f"{ADVISORY_ROLE_LINE}\n"
        "next: /lens report <name> (full micrograph) · /lens help\n"
        f"{COVERAGE_FOOTER}"
    )

    if not refs:
        return "```\nhub quarantine: empty — nothing staged for review\n```\n"

    rows: list[tuple[str, str]] = []  # (display header note, status line(s))
    for ref in refs:
        name = _display(ref.name)
        note = _provenance_note(ref, lock)
        # §11.6 race law FIRST: a bundle rmtree'd between enumeration and
        # rendering (cancel/block both rmtree) yields the skip lane — never
        # an enqueue of a vanished target, never an error cascade.
        try:
            alive = ref.path.exists()
        except OSError:
            alive = False
        if not alive:
            rows.append(
                (
                    f"{name} ({note})",
                    _clip_fast_line(_SKIP_LINE_TEMPLATE.format(name=name)),
                )
            )
            continue
        # Baseline state FIRST (per-target project layer), exactly like the
        # trigger lane, so the cache probe and the worker's cache key agree.
        baseline_records: tuple[Any, ...] = ()
        suffix = ""
        target_dir = ref.path if ref.path.is_dir() else ref.path.parent
        if view is not None:
            try:
                from .slash import _baseline_state

                baseline_records, suffix = _baseline_state(view, target_dir)
            except Exception:  # noqa: BLE001 — broken config degrades, never blocks
                logger.debug("baseline state unavailable during hub view (%s)", name)
        ir = None
        try:
            from .ingest import DEFAULT_CEILINGS, load_bundle

            ir = load_bundle(ref.path, ceilings=DEFAULT_CEILINGS)
        except Exception:  # noqa: BLE001 — vanish/unreadable handled below
            logger.debug("quarantine ingest failed during hub view (%s)", name, exc_info=True)
        bundle_hash = None
        if ir is not None:
            # A partial IR (target vanished mid-window / unreadable) carries
            # error diagnostics; refuse to hash+queue it as if it were real.
            has_errors = any(
                str(getattr(d, "severity", "")).lower() == "error" for d in ir.diagnostics
            )
            if not has_errors:
                from .cache import key_for_ir

                bundle_hash = key_for_ir(ir)
        line = _entry_status_line(
            ref,
            name=name,
            bundle_hash=bundle_hash,
            cache=cache,
            jobs=jobs,
            view=view,
            cache_key_suffix=suffix,
            baseline_records=baseline_records,
        )
        head = f"{name} ({note})"
        if baseline_records:
            head += f" · {len(baseline_records)} baseline rules"
        rows.append((head, line))

    count = len(rows)
    header = (
        f"SKILL LENS hub quarantine · {count} bundle{'s' if count != 1 else ''} "
        "awaiting confirmation"
    )

    def assemble(entries: list[str]) -> str:
        sections = [header, "roles:\n  " + "\n  ".join(ROLE_ROWS)]
        if entries:
            sections.append("\n".join(entries))
        sections.append(tail)
        return "\n\n".join(sections).join(("```\n", "\n```\n"))

    full = [f"{idx}. {head}\n  {line}" for idx, (head, line) in enumerate(rows, start=1)]
    rendered = assemble(full)
    if len(rendered) <= CHAT_SOFT_BUDGET:
        return rendered

    slim = [
        f"{idx}. {_display(head.rsplit(' (', 1)[0])}\n  {line}"
        for idx, (head, line) in enumerate(rows, start=1)
    ]
    rendered = assemble(slim)
    if len(rendered) <= CHAT_SOFT_BUDGET:
        return rendered

    keep = len(slim)
    while keep > 1:
        keep -= 1
        trimmed = slim[:keep] + [f"… +{count - keep} more staged — /lens hub after review"]
        rendered = assemble(trimmed)
        if len(rendered) <= CHAT_SOFT_BUDGET:
            return rendered

    inner = (
        f"{header}\nroles:\n  " + "\n  ".join(ROLE_ROWS) + "\n\n"
        f"{count} bundles staged — output over chat budget; "
        "run /lens report <name> per bundle\n" + tail
    ).join(("```\n", "\n```\n"))
    if len(inner) > CHAT_HARD_BUDGET:  # pragma: no cover — role rows are fixed-size
        inner = f"```\n{count} bundles staged — over chat budget · /lens report <name>\n```\n"
    return inner


__all__ = [
    "ADVISORY_ROLE_LINE",
    "CONFIRM_BEAT_BUDGET_SECONDS",
    "FAST_LINE_MAX_CHARS",
    "HUB_DIRNAME",
    "QUARANTINE_DIRNAME",
    "ROLE_ROWS",
    "enumerate_quarantine",
    "quarantine_dir",
    "render_hub_view",
]
