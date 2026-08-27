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

import json
import logging
import os
import shlex
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any

from .baseline import (
    BaselineRecord,
    baseline_cache_suffix,
    baseline_path_for,
    collect_baseline_records,
    merge_records,
    read_baseline,
    resolve_baseline_entries,
    write_baseline,
)
from .cache import CacheEntry, FastPathCache, hash8, key_for_ir
from .canonical import canonical_dumps
from .context import PluginContextView
from .engines import ScanDeadlineBreach
from .policy import PolicyError, policy_failure_notice
from .render import (
    counts_phrase,
    fast_line_coalesced,
    fast_line_fail,
    fast_line_ok,
    fast_line_scan_queued,
    render_chat_compact,
)
from .report import build_report
from .scoring import FAIL_ON_LEVELS

logger = logging.getLogger("lens")

#: Internal hard ceiling for inline cold scans (DECISIONS D-026). Host
#: gateway async results cap at 30 s; stay under it with margin.
INTERNAL_SCAN_DEADLINE_SECONDS = 25.0

#: Slash command name (NAMING LAW).
SLASH_COMMAND = "lens"

_USAGE = """```\
usage: /lens <verb> [target] [flags]

verbs:
  scan <name|path>     queue a security scan (cold scans run on the lens worker;
                       cache hits answer inline)
  report [name]        latest cached report for an installed skill
  map <name|path>      SkillIR tree: files, claims vs capabilities graph,
                       hub-provenance annotation (the "what did I agree to" view)
  autopsy <name> [--voice clinical|microscopy]
                       deep narrative walkthrough of the latest report;
                       voices are OPT-IN (default clinical stays sober;
                       noir is deferred — HARD_QUESTIONS O4)
  baseline <name> --reason "…" [--expires DATE]
                       record current fingerprints into <skill>/.lens/baseline.toml
  explain-rules [--rule ID]
                       effective rule set + provenance; single-rule detail card
  diff <reportA|name> [<reportB|name>]
                       shift-stable fingerprint comparison (new/fixed/persisted)
  hub                  review bundles staged in skills/.hub/quarantine — role labels
                       + per-bundle fast-path lines (advisory lane, never blocks)
  watch [status|start [secs]|stop]
                       out-of-band drift watcher: sweep-on-start is always on;
                       start/stop toggle the opt-in continuous poller
  rules verify [path]  offline provenance check of the embedded core pack
                       against the committed ed25519 pubkey (§15); a path
                       verifies an external/community pack instead
  doctor               nine-check §11.9 self-check: pack, policy, state dirs,
                       host env, wiring audit (zero blocking hooks), network
                       isolation, lifecycle, parse, render — verdict line last
  help                 this block

also hiding: /lens bones · /lens lens   (easter eggs; opt-in by invocation)

flags (scan): --json · --no-cache · --sarif (SARIF 2.1.0 fence) · --osv or
osv:true (OPT-IN network enrichment via OSV.dev; findings tagged enriched) ·
--fail-on clean|notice|warn|alert (CLI exit-code gate; §8.4/§18) ·
--plain (ASCII headers, box drawing stripped)
also: report --fail-on/--plain · diff --plain

advisor only — lens never blocks installs. clean scan ≠ safe skill.\
```"""

_RULES_USAGE = """\
```\
usage: /lens rules verify [path] [--sig FILE] [--pubkey FILE]

No path: verify the embedded core pack against the committed
ed25519 public key and detached signature (offline; SPEC §15).
With path: structurally load an external/community pack and report
its version + content checksum; add --sig (and --pubkey for a
third-party trust root) to verify a detached release signature.

Updates are MANUAL ONLY (no fetch verb, no network, ever):
download a release artifact yourself, then let this verb prove
its bytes.
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
    from .ingest import discover_bundles

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


def _today() -> date:
    """The surface-boundary clock seam (the ONLY wall-clock read in verbs).

    Expiry enforcement (baselines, severity overrides) necessarily consumes
    a current date; the deterministic core takes it as a PARAMETER and the
    envelope never embeds it — this helper is where the boundary injects it.
    Tests drive the core with fixed dates instead.
    """
    return date.today()


def _baseline_state(
    view: PluginContextView | None, target_path: Path | None
) -> tuple[tuple[BaselineRecord, ...], str]:
    """Effective baseline records + cache-key suffix for one target.

    Raises :class:`PolicyError` on broken configuration (strict lane —
    malformed suppression metadata must never silently stop suppressing).
    The project layer resolves against the TARGET's directory: an installed
    skill or bundle dir carries its own ``.lens/`` config.
    """
    if view is None:
        return (), ""
    target_dir = target_path if (target_path is not None and target_path.is_dir()) else None
    if target_dir is None and target_path is not None:
        parent = target_path.parent
        target_dir = parent if parent.is_dir() else None
    report_date = _today()
    records = resolve_baseline_entries(view=view, target_dir=target_dir, report_date=report_date)
    return records, baseline_cache_suffix(records, report_date=report_date)


def _scan_raw(target_path: Path) -> Any:
    """Deadline-bounded scan WITHOUT suppression (fingerprint collection)."""
    from .engines import scan_bundle

    start = time.monotonic()
    return scan_bundle(target_path, deadline=_deadline_from_start(start))


# ---------------------------------------------------------------------------
# Scan execution (queue-first model, SPEC §11.5)
# ---------------------------------------------------------------------------
#
# Phase-2 execution contract: the reply path NEVER runs engines.
# run_scan remains the ONE full-pipeline pass and is now called from the
# lens worker thread only (skill_lens.jobs.pipeline_runner) plus the
# synchronous refresh arms of the baseline/diff verbs.


def run_scan(
    target_path: Path,
    *,
    cache: FastPathCache,
    plugin_data_dir: Path,
    baseline_records: tuple[BaselineRecord, ...] = (),
    key_suffix: str = "",
    report_date: date | None = None,
    osv: bool = False,
) -> dict[str, Any]:
    """One full pipeline pass; returns render inputs, never raises.

    Callers (Phase 2 queue-first model): the lens worker thread via
    :func:`skill_lens.jobs.pipeline_runner` (the ONLY cold-scan executor —
    ``/lens scan`` misses enqueue instead of calling this inline), plus the
    synchronous refresh arms of the baseline and diff verbs. Shape:
    ``{"ok": bool, "envelope": dict|None, "compact": str|None,
    "error": str|None}``. The cache is consulted after ingest (cheap hash)
    and populated on success. *key_suffix* folds the effective baseline set
    into the cache key so a changed suppression set invalidates fast-path
    answers rendered under a different one; empty suffix keeps historical
    keys byte-identical. Baselines apply AFTER dedup BEFORE scoring inside
    :func:`build_report` (DECISIONS D-042 ordering row).

    *osv* is the SPEC §14 G2 opt-in lane: True lazy-imports
    :mod:`skill_lens.enrich.osv` (the default closure NEVER imports it) and
    appends ":osv" to the cache key so enriched answers never serve plain
    requests or vice versa. Enrichment failures degrade into the summary
    block; they can never fail the scan.
    """
    from .engines import scan_bundle

    start = time.monotonic()
    deadline = _deadline_from_start(start)

    result = scan_bundle(target_path, deadline=deadline)
    ir = result.ir
    effective_suffix = key_suffix + (":osv" if osv else "")
    key = key_for_ir(ir) + effective_suffix
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

    envelope = build_report(result, baseline_entries=baseline_records, report_date=report_date)
    if osv:
        try:
            # LAZY IMPORT (G1/G3): skill_lens.enrich.osv joins the process
            # ONLY on this explicitly flagged path. Never hoist me.
            from .enrich.osv import enrich_envelope

            envelope = enrich_envelope(envelope, root=target_path)
        except Exception:  # noqa: BLE001 — enrichment degrades, never fails a scan
            envelope = dict(envelope)
            envelope["enrichment"] = {
                "provider": "api.osv.dev",
                "opt_in": "--osv",
                "status": "error",
                "reason": "enrichment adapter failed; offline report served",
            }
    compact = render_chat_compact(envelope, plugin_data_dir=plugin_data_dir)
    envelope_text = canonical_dumps(envelope)
    score = envelope.get("score") or {}
    entry = CacheEntry(
        bundle_hash=key,
        name=ir.identity.name,
        grade=str(score.get("grade", "?")),
        value=_score_int(score.get("value")),
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
    jobs: Any,
    sink: dict[str, Any] | None = None,
) -> str:
    # --fail-on is the §8.4 CI contract: CLI-only exit-code semantics, but the
    # flag parses HERE so both surfaces share one grammar (§11.2). The slash
    # lane has no exit channel (D-SURF) — the verdict already travels in the
    # rendered text — so there it is accepted-and-inert; the CLI dispatcher
    # reads sink["envelope"] and projects the code via scoring.compute_exit_code.
    rest, fail_on, fail_errors = _split_flag(args, "--fail-on")
    if fail_errors:
        return f"lens fail scan · {fail_errors[0]}"
    want_json = "--json" in rest
    want_sarif = "--sarif" in rest
    # SPEC §4 E8 / §14 G2: OSV.dev enrichment is opt-in ONLY. Both token
    # spellings are honored: CLI-style ``--osv`` and the slash-native
    # ``osv:true`` (a bare ``osv:true`` is a flag VALUE token, not positional).
    osv = "--osv" in rest or "osv:true" in rest
    known_flags = ("--json", "--no-cache", "--sarif", "--osv", "--fail-on", "--plain")
    positional = [a for a in rest if not a.startswith("--") and a != "osv:true"]
    no_cache = "--no-cache" in rest
    unknown_flags = [a for a in rest if a.startswith("--") and a not in known_flags]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if fail_on is not None and fail_on.strip().lower() not in FAIL_ON_LEVELS:
        return (
            f"lens fail scan · unknown --fail-on level {fail_on!r} "
            f"(expected one of: {', '.join(FAIL_ON_LEVELS)})"
        )
    if not positional:
        return _usage_line(missing="target")

    target_path, display_name = resolve_target(positional[0])
    if target_path is None:
        return fast_line_fail(name=display_name, reason=f"unresolvable target: {positional[0]}")

    plugin_data_dir = view.plugin_data_dir()

    # Config-seam errors (PolicyError) deliberately PROPAGATE from here:
    # the slash safe-handler renders the one-line notice; the CLI dispatcher
    # maps them to §18 exit 2. Same wording both lanes (D-SURF).
    baseline_records, key_suffix = _baseline_state(view, target_path)

    # Fast path first: ingest + hash is cheap and runs inline (<200 ms
    # contract, PLAN Phase 1); a live cache entry answers WITHOUT engines.
    fmt = "sarif" if want_sarif else ("json" if want_json else "text")
    ir, hit_text = _probe_cache(
        target_path,
        cache=cache,
        fmt=fmt,
        key_suffix=key_suffix + (":osv" if osv else ""),
        skip=no_cache,
        sink=sink,
    )
    if hit_text is not None:
        return hit_text
    if ir is None:  # load_bundle contract says never; keep a sober D-line anyway
        return fast_line_fail(name=display_name, reason=f"unreadable target: {positional[0]}")

    # --fail-on arm (§8.4): a threshold verdict must exist BEFORE the process
    # exits, so this arm runs the pipeline INLINE instead of enqueueing.
    # Rationale: §11.5's queue-first rule protects an ongoing reply path; a
    # one-shot CI invocation has none — the process ends at the exit code —
    # so nothing can wedge. Without --fail-on the queue-first contract below
    # is untouched (advisor stance always exits 0).
    if fail_on is not None:
        envelope = _fresh_envelope(view=view, cache=cache, target_path=target_path)
        if envelope is None:
            return fast_line_fail(name=display_name, reason="inline scan failed — see logs")
        if sink is not None:
            sink["envelope"] = envelope
        return render_chat_compact(envelope, plugin_data_dir=view.plugin_data_dir())

    # Cold path (SPEC §11.5): enqueue on the worker, answer with the fixed
    # format-B one-liner. The reply path never waits on engines.
    from .jobs import ScanContext  # lazy: jobs.py owns the worker seams

    bundle_hash = key_for_ir(ir)
    decision = jobs.enqueue(
        name=display_name,
        target=target_path,
        bundle_hash=bundle_hash,
        cache_key=bundle_hash + key_suffix + (":osv" if osv else ""),
        context=ScanContext(
            baseline_records=baseline_records,
            key_suffix=key_suffix,
            report_date=_today(),
            plugin_data_dir=plugin_data_dir,
            cache=cache,
            osv=osv,
        ),
    )
    if decision.coalesced:
        return fast_line_coalesced(name=display_name, hash8=hash8(bundle_hash))
    return fast_line_scan_queued(name=display_name, hash8=hash8(bundle_hash))


def _probe_cache(
    target_path: Path,
    *,
    cache: FastPathCache,
    fmt: str = "text",
    key_suffix: str = "",
    skip: bool = False,
    sink: dict[str, Any] | None = None,
) -> tuple[Any, str | None]:
    """Ingest once, then answer from the cache when bytes are unchanged.

    Returns ``(ir, hit_text)`` — *ir* feeds the enqueue hash on a miss;
    *hit_text* is the served artifact or None. *fmt* picks the artifact:
    ``text`` (compact render), ``json`` (canonical envelope fence), or
    ``sarif`` (SARIF 2.1.0 fence rendered from the stored envelope).
    *skip* (--no-cache) skips the lookup but still returns the IR so the
    scan can queue. When *sink* is given and a live entry is hit, its parsed
    envelope dict lands in ``sink["envelope"]`` — the CLI dispatcher's only
    look at the verdict for §18 exit codes (slash lane passes no sink).
    """
    from .ingest import DEFAULT_CEILINGS, load_bundle

    try:
        ir = load_bundle(target_path, ceilings=DEFAULT_CEILINGS)
    except Exception:  # noqa: BLE001 — ingest contract says never; degrade to D-lane
        return None, None
    if skip:
        return ir, None
    entry = cache.get(key_for_ir(ir) + key_suffix)
    if entry is None or entry.envelope_json is None or entry.compact_text is None:
        return ir, None
    if sink is not None and entry.envelope_json:
        try:
            data = json.loads(entry.envelope_json)
        except ValueError:
            data = None
        if isinstance(data, dict):
            sink["envelope"] = data
    if fmt == "json":
        return ir, f"```json\n{entry.envelope_json}\n```"
    if fmt == "sarif":
        import json as _json

        from .report import render_sarif

        try:
            envelope = _json.loads(entry.envelope_json)
        except ValueError:
            return ir, None
        sarif_text = canonical_dumps(render_sarif(envelope))
        return ir, f"```json\n{sarif_text}\n```"
    return ir, entry.compact_text


def _verb_report(
    args: list[str],
    *,
    cache: FastPathCache,
    jobs: Any = None,
    sink: dict[str, Any] | None = None,
) -> str:
    # --fail-on/--plain parse here so CLI and slash share one grammar; on the
    # slash lane --fail-on is inert (D-SURF: verdict travels in text) and
    # --plain is a no-op (chat renders are already ANSI/box-free).
    rest, fail_on, fail_errors = _split_flag(args, "--fail-on")
    if fail_errors:
        return f"lens fail report · {fail_errors[0]}"
    if fail_on is not None and fail_on.strip().lower() not in FAIL_ON_LEVELS:
        return (
            f"lens fail report · unknown --fail-on level {fail_on!r} "
            f"(expected one of: {', '.join(FAIL_ON_LEVELS)})"
        )
    positional = [a for a in rest if not a.startswith("--")]
    known = ("--sarif", "--json", "--fail-on", "--plain")
    unknown_flags = [a for a in rest if a.startswith("--") and a not in known]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    want_sarif = "--sarif" in args
    want_json = "--json" in args
    name = positional[0] if positional else None
    entry: CacheEntry | None = None
    if name is not None:
        entry = cache.latest_by_name(name)
        if entry is None:
            return _report_without_entry(name, jobs=jobs)
    else:
        entry = _latest_entry(cache)
        if entry is None:
            return "no lens reports cached yet — run `/lens scan <name|path>` first"
    if jobs is not None:
        jobs.mark_fetched(entry.name)  # pull clears the ready banner (§11.5)
    if sink is not None and entry.envelope_json and fail_on is not None:
        try:
            data = json.loads(entry.envelope_json)
        except ValueError:
            data = None
        if isinstance(data, dict):
            sink["envelope"] = data
    if want_sarif and entry.envelope_json:
        import json as _json

        from .report import render_sarif

        try:
            envelope = _json.loads(entry.envelope_json)
        except ValueError:
            return f"lens fail report · cached envelope unparsable for {entry.name!r}"
        return f"```json\n{canonical_dumps(render_sarif(envelope))}\n```"
    if want_json and entry.envelope_json:
        return f"```json\n{entry.envelope_json}\n```"
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


def _report_without_entry(name: str, *, jobs: Any) -> str:
    """No cached artifact: surface the job trail honestly (§11.5)."""
    job = jobs.latest_job_for_name(name) if jobs is not None else None
    if job is not None and job.state == "failed":
        return fast_line_fail(name=name, reason=job.error or "scan failed")
    if job is not None and job.state in ("queued", "scanning"):
        return fast_line_scan_queued(name=name, hash8=hash8(job.bundle_hash))
    return (
        f"no lens report cached for {name!r} — run `/lens scan {name}` "
        "(cold scans answer on completion)"
    )


def _latest_entry(cache: FastPathCache) -> CacheEntry | None:
    """Newest cached entry across the installed tree (deterministic walk)."""
    from .ingest import discover_bundles

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
# baseline · explain-rules · diff verbs (Phase 2; SPEC §11.2)
# ---------------------------------------------------------------------------


def _split_flag(args: list[str], flag: str) -> tuple[list[str], str | None, list[str]]:
    """Extract one value-carrying ``--flag VALUE`` from token list.

    Returns ``(remaining_args, value_or_None, errors)``; a dangling flag or
    a duplicate records an error string naming the offender.
    """
    remaining: list[str] = []
    value: str | None = None
    errors: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == flag:
            if index + 1 >= len(args):
                errors.append(f"{flag} requires a value")
                index += 1
                continue
            if value is not None:
                errors.append(f"{flag} given twice")
            value = args[index + 1]
            index += 2
            continue
        remaining.append(token)
        index += 1
    return remaining, value, errors


def _verb_baseline(args: list[str], *, view: PluginContextView, cache: FastPathCache) -> str:
    """``/lens baseline <name> --reason "…" [--expires DATE]`` (§11.2).

    Records the CURRENT fingerprints of one directory-resolved target into
    its canonical ``.lens/baseline.toml`` store (duplicate fingerprints keep
    the earlier expiry), then refreshes the cached report under the new
    suppression set so `/lens report` answers with post-suppression state.
    The D-CRASH isolation finding is never recorded (breakage telemetry,
    not behavior).
    """
    remaining, reason, errors = _split_flag(args, "--reason")
    remaining, expires_raw, expiry_errors = _split_flag(remaining, "--expires")
    errors.extend(expiry_errors)
    positional = [a for a in remaining if not a.startswith("--")]
    unknown_flags = [a for a in remaining if a.startswith("--")]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if errors:
        return (
            f"lens fail baseline · {errors[0]} · usage: /lens baseline <name> "
            '--reason "…" [--expires DATE]'
        )
    if not positional:
        return 'usage: /lens baseline <name> --reason "…" [--expires DATE] — a reason is REQUIRED'
    if not reason or not reason.strip():
        return "a --reason is REQUIRED (suppressions must justify themselves) — /lens help"

    target_path, display_name = resolve_target(positional[0])
    if target_path is None:
        return fast_line_fail(name=display_name, reason=f"unresolvable target: {positional[0]}")
    if not target_path.is_dir():
        return fast_line_fail(
            name=display_name,
            reason="baseline store needs a directory target (.lens/baseline.toml)",
        )

    expires = None
    if expires_raw is not None:
        try:
            expires = date.fromisoformat(expires_raw.strip())
        except ValueError:
            return f"unparsable --expires {expires_raw!r} (want ISO YYYY-MM-DD) — nothing written"

    store_path = baseline_path_for(target_path)
    existing = read_baseline(store_path)  # PolicyError ⇒ surface error lane
    try:
        existing = read_baseline(store_path)
    except PolicyError as exc:
        return policy_failure_notice(exc)

    try:
        result = _scan_raw(target_path)
    except ScanDeadlineBreach:
        return fast_line_fail(
            name=display_name,
            reason=f"internal scan deadline ({int(INTERNAL_SCAN_DEADLINE_SECONDS)}s) exceeded",
        )
    except Exception as exc:  # noqa: BLE001 — handler never raises into the host
        logger.exception("/lens baseline scan failed")
        reason_text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return fast_line_fail(name=display_name, reason=f"unreadable target: {reason_text}")

    fresh_records = collect_baseline_records(result.findings)
    if expires is not None:
        # The verb's --expires annotates the NEWLY recorded fingerprints;
        # existing entries keep their own expiry (merge keeps the earlier).
        fresh_records = [
            BaselineRecord(
                fingerprint=record.fingerprint,
                reason=record.reason,
                expires=expires,
                rule_id=record.rule_id,
                path=record.path,
            )
            for record in fresh_records
        ]
    merged = merge_records(existing, fresh_records)
    added = len(merged) - len({record.fingerprint for record in existing})
    write_baseline(store_path, merged)  # OSError ⇒ PolicyError ⇒ error lane

    # Refresh the cached report under the new suppression set.
    plugin_data_dir = view.plugin_data_dir()
    try:
        outcome = run_scan(
            target_path,
            cache=cache,
            plugin_data_dir=plugin_data_dir,
            baseline_records=merged,
            key_suffix=baseline_cache_suffix(merged, report_date=_today()),
            report_date=_today(),
        )
    except Exception:  # noqa: BLE001 — refresh is best-effort; the write already happened
        logger.exception("/lens baseline refresh scan failed")
        outcome = {}
    suppressed_now = _count_suppressed(outcome) if outcome.get("envelope_json") else 0

    expiries = sorted(record.expires for record in merged if record.expires is not None)
    expires_text = expiries[0].isoformat() if expiries else "none"
    line = (
        f"lens baseline {display_name} · +{added} new · {len(merged)} stored · "
        f"{suppressed_now} suppressed now · expires {expires_text} · /lens report {display_name}"
    )
    from .render import FAST_LINE_MAX_CHARS

    return line[: FAST_LINE_MAX_CHARS - 1] + "…" if len(line) >= FAST_LINE_MAX_CHARS else line


def _score_int(value: Any) -> int:
    """Tolerant int coercion for our own scorer output (never-raise law)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _count_suppressed(outcome: dict[str, Any]) -> int:
    """Suppressed-count from a run_scan outcome's JSON artifact (tolerant)."""
    import json as _json

    try:
        envelope = _json.loads(str(outcome.get("envelope_json") or "{}"))
        return int(envelope.get("suppressed_count") or 0)
    except Exception:  # noqa: BLE001 — display-only helper
        return 0


def _verb_explain(args: list[str], *, view: PluginContextView) -> str:
    """``/lens explain-rules [--rule ID]`` — D-EXPLAIN mechanical rendering."""
    remaining, rule_id, errors = _split_flag(args, "--rule")
    positional = [a for a in remaining if not a.startswith("--")]
    unknown_flags = [a for a in remaining if a.startswith("--")]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if positional:
        return _usage_line(offender=positional[0])
    if errors:
        return f"lens fail explain-rules · {errors[0]} · /lens help"

    from .policy import load_policy
    from .rules import load_core_pack

    policy = load_policy(ctx=view, report_date=_today())  # may raise PolicyError
    try:
        pack = load_core_pack()
    except Exception as exc:  # noqa: BLE001 — pack faults are total-error lane wording
        logger.exception("/lens explain-rules could not load the rule pack")
        detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return fast_line_fail(name="explain-rules", reason=f"rule pack unreadable: {detail}")

    from .explain import explain_rules

    text, notice = explain_rules(
        pack,
        policy,
        rule_id=rule_id,
        plugin_data_dir=view.plugin_data_dir(),
    )
    return notice if notice else text


def _load_report_envelope(
    token: str,
    *,
    view: PluginContextView,
    cache: FastPathCache,
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve one diff source: report JSON file → cached report → live scan.

    Returns ``(envelope, error_notice)`` — exactly one is non-None.
    """
    import json as _json

    candidate = Path(token).expanduser()
    try:
        if candidate.is_file():
            data = _json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("schema") == "report/1":
                return data, None
            return (
                None,
                f"not a lens report/1 JSON file: {token}",
            )
    except OSError:
        return None, f"cannot read report file {token}"
    except ValueError:
        return None, f"not valid JSON: {token}"

    entry = cache.latest_by_name(token)
    if entry is not None and entry.envelope_json:
        try:
            data = _json.loads(entry.envelope_json)
        except ValueError:
            return None, f"cached report for {token!r} is corrupt — rescan it"
        return data, None

    target_path, _display = resolve_target(token)
    if target_path is not None:
        envelope = _fresh_envelope(view=view, cache=cache, target_path=target_path)
        if envelope is not None:
            return envelope, None
        return None, f"scan failed for target {token} — see logs; /lens doctor"
    return None, f"cannot resolve diff source: {token}"


def _fresh_envelope(
    *, view: PluginContextView, cache: FastPathCache, target_path: Path
) -> dict[str, Any] | None:
    """Run one suppressed-current pipeline pass; envelope dict or None."""
    import json as _json

    try:
        baseline_records, key_suffix = _baseline_state(view, target_path)
        outcome = run_scan(
            target_path,
            cache=cache,
            plugin_data_dir=view.plugin_data_dir(),
            baseline_records=baseline_records,
            key_suffix=key_suffix,
            report_date=_today(),
        )
    except PolicyError:
        # Config seam ⇒ surface lane decides (notice vs exit 2).
        raise
    except Exception:  # noqa: BLE001 — diff degrades to a notice, never a crash
        logger.exception("diff fresh-scan failed")
        return None
    body = outcome.get("envelope_json")
    if not body:
        return None
    try:
        data = _json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _verb_diff(
    args: list[str],
    *,
    view: PluginContextView,
    cache: FastPathCache,
    sink: dict[str, Any] | None = None,  # noqa: ARG001 — grammar parity with scan/report
) -> str:
    """``/lens diff <reportA|name> [<reportB|name>]`` (§11.2).

    Two sources compare directly; ONE name diffs its latest cached report
    against a FRESH scan of that target (the §11.2 "vs installed tree" arm).
    ``--plain`` is accepted for CLI/slash grammar parity and ignored: diff
    renders are already ANSI/box-free.
    """
    positional = [a for a in args if not a.startswith("--")]
    known = ("--plain",)
    unknown_flags = [a for a in args if a.startswith("--") and a not in known]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if not positional or len(positional) > 2:
        return "usage: /lens diff <reportA|name> [<reportB|name>] — /lens help"

    from .diff import diff_reports, render_diff

    if len(positional) == 2:
        left, err_a = _load_report_envelope(positional[0], view=view, cache=cache)
        if err_a:
            return f"lens fail diff · {err_a}"
        right, err_b = _load_report_envelope(positional[1], view=view, cache=cache)
        if err_b:
            return f"lens fail diff · {err_b}"
        old_env, new_env = left, right
    else:
        target_path, display_name = resolve_target(positional[0])
        if target_path is None:
            return fast_line_fail(
                name=positional[0], reason=f"unresolvable target: {positional[0]}"
            )
        prior = cache.latest_by_name(display_name)
        old_env: dict[str, Any] | None = None
        if prior is not None and prior.envelope_json:
            import json as _json

            try:
                loaded = _json.loads(prior.envelope_json)
                old_env = loaded if isinstance(loaded, dict) else None
            except ValueError:
                old_env = None
        if old_env is None:
            return f"no cached report for {display_name!r} to diff against — run /lens scan first"
        new_env = _fresh_envelope(view=view, cache=cache, target_path=target_path)
        if new_env is None:
            return fast_line_fail(name=display_name, reason="rescan for diff failed")

    outcome = diff_reports(old_env or {}, new_env or {})
    return render_diff(
        outcome,
        plugin_data_dir=view.plugin_data_dir(),
        old_envelope=old_env,
        new_envelope=new_env,
    )


# ---------------------------------------------------------------------------
# map · autopsy · bones · self-scan verbs (Phase 6; §11.2 + SPEC §16)
# ---------------------------------------------------------------------------


def _chat_soft_budget(view: PluginContextView | None) -> int | None:
    """Effective soft budget from the pre-reserved chat_budget_chars key.

    Clamping happens in the renderers (hard ceiling stays normative at
    CHAT_HARD_BUDGET); cached artifacts keep the budget they were rendered
    under — documented courtesy-setting semantics, DECISIONS D-056.
    """
    from .fun import _setting

    raw = _setting(view, "chat_budget_chars")
    return int(raw) if isinstance(raw, int) and raw > 0 else None


def _verb_map(
    args: list[str], *, view: PluginContextView, sink: dict[str, Any] | None = None
) -> str:
    """``/lens map <name|path>`` — SkillIR tree view (§11.2).

    Runs ONE bounded pipeline pass inline (same discipline as diff's fresh
    arm: pull verbs may scan synchronously; only ``scan`` is queue-first).
    Baselines fold in so suppressed findings neither render nor count as
    observed capabilities. Provenance renders annotation-only (D-PROV).
    """
    positional = [a for a in args if not a.startswith("--")]
    unknown_flags = [a for a in args if a.startswith("--") and a != "--plain"]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if len(positional) != 1:
        return "usage: /lens map <name|path> — /lens help"

    target_path, display_name = resolve_target(positional[0])
    if target_path is None:
        return fast_line_fail(name=display_name, reason=f"unresolvable target: {positional[0]}")

    from .engines import ScanDeadlineBreach, scan_bundle
    from .mapview import render_map_chat
    from .report import build_report

    start = time.monotonic()
    try:
        # ``home`` feeds ONLY the identity annotation (categorized-vs-flat
        # decided against $HERMES_HOME/skills, D-PROV-safe): scores, hashes,
        # and findings are byte-identical with or without it. Map is the one
        # surface whose §11.2 contract names the categorized layout.
        result = scan_bundle(
            target_path, deadline=_deadline_from_start(start), home=hermes_home()
        )
        baseline_records, _suffix = _baseline_state(view, target_path)
        envelope = build_report(result, baseline_entries=baseline_records, report_date=_today())
    except ScanDeadlineBreach:
        return fast_line_fail(
            name=display_name,
            reason=f"internal scan deadline ({int(INTERNAL_SCAN_DEADLINE_SECONDS)}s) exceeded",
        )
    except PolicyError:
        raise  # config seam ⇒ surface lane decides (notice / exit 2)
    except Exception as exc:  # noqa: BLE001 — handler never raises into the host
        logger.exception("/lens map failed")
        reason_text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return fast_line_fail(name=display_name, reason=f"unreadable target: {reason_text}")

    chat_render = render_map_chat(
        envelope,
        result.ir,
        plugin_data_dir=view.plugin_data_dir(),
        soft_budget=_chat_soft_budget(view),
    )
    if sink is not None:
        # §12.1 lane split: the CLI prints the Rich-style box panel (then
        # strips it itself under --plain/NO_COLOR); the slash lane keeps the
        # fenced collapsed form. One pipeline pass feeds both renderers.
        from .mapview import render_map_panel

        sink["cli_text"] = render_map_panel(envelope, result.ir)
    return chat_render


def _verb_autopsy(args: list[str], *, view: PluginContextView, cache: FastPathCache) -> str:
    """``/lens autopsy <name> [--voice clinical|microscopy]`` (F-1, §16).

    Prefers the latest cached report for *name* (pull channel); falls back
    to one bounded inline pass when nothing is cached. Voice resolution:
    kill-switch > --voice flag > ``voice`` setting > clinical default.
    Deterministic templates ONLY — no LLM, no randomness (FUN.md Law 3).
    """
    rest, voice_flag, voice_errors = _split_flag(args, "--voice")
    if voice_errors:
        return f"lens fail autopsy · {voice_errors[0]}"
    positional = [a for a in rest if not a.startswith("--")]
    unknown_flags = [a for a in rest if a.startswith("--") and a != "--plain"]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    if len(positional) != 1:
        return (
            "usage: /lens autopsy <name> [--voice clinical|microscopy] — voices are "
            "opt-in; clinical (default) stays sober; noir is deferred (HQ O4)"
        )
    from .fun import render_autopsy, resolve_voice, validate_voice_choice

    choice_error = validate_voice_choice(voice_flag)
    if choice_error:
        return f"lens fail autopsy · {choice_error}"
    voice, voice_notice = resolve_voice(view, voice_flag)

    name = positional[0]
    import json as _json

    entry = cache.latest_by_name(name)
    envelope: dict[str, Any] | None = None
    if entry is not None and entry.envelope_json:
        try:
            loaded = _json.loads(entry.envelope_json)
            envelope = loaded if isinstance(loaded, dict) else None
        except ValueError:
            envelope = None
    if envelope is None:
        target_path, display_name = resolve_target(name)
        if target_path is None:
            return fast_line_fail(name=name, reason=f"unresolvable target: {name}")
        envelope = _fresh_envelope(view=view, cache=cache, target_path=target_path)
        if envelope is None:
            return fast_line_fail(name=name, reason="autopsy rescan failed — see logs")

    body = render_autopsy(
        envelope,
        voice=voice,
        plugin_data_dir=view.plugin_data_dir(),
        soft_budget=_chat_soft_budget(view),
    )
    return f"{voice_notice}\n{body}" if voice_notice else body


def _verb_bones(args: list[str], *, view: PluginContextView) -> str:  # noqa: ARG001
    """``/lens bones [target]`` — anatomical chart of a module tree (F-6).

    Zero args charts Skill Lens itself (the instrument examined by itself);
    a target argument charts that bundle's tree instead. One fenced block,
    ≤1900 chars by construction — the format every chunker preserves.
    Opt-in by invocation (hidden verb); read-only; exit 0 like anything else.
    """
    positional = [a for a in args if not a.startswith("--")]
    unknown_flags = [a for a in args if a.startswith("--")]
    if unknown_flags:
        return _usage_line(offender=unknown_flags[0])
    from .fun import BONES_BUDGET, bones_for_tree, self_scan_target

    if positional:
        target_path, display_name = resolve_target(positional[0])
        if target_path is None:
            return fast_line_fail(name=display_name, reason=f"unresolvable target: {positional[0]}")
        from .ingest import DEFAULT_CEILINGS, load_bundle

        try:
            ir = load_bundle(target_path, ceilings=DEFAULT_CEILINGS)
        except Exception as exc:  # noqa: BLE001 — degrade to a D-line
            logger.exception("/lens bones ingest failed")
            reason_text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            return fast_line_fail(name=display_name, reason=f"unreadable target: {reason_text}")
        art = bones_for_tree(str(ir.identity.name), target_path)
    else:
        art = bones_for_tree("skill_lens", self_scan_target())
    inner = art[: BONES_BUDGET - 8]
    return f"```\n{inner}\n```\n"


def _verb_self_scan(args: list[str], *, view: PluginContextView) -> str:  # noqa: ARG001
    """``/lens lens`` — Skill Lens scans its own codebase (F-6 twin).

    Dogfooding pressure disguised as a gag: real pipeline over a pyc-free
    mirror of the package (bytecode caches regenerate out-of-band and would
    move the hash — DETERMINISM LAW), sober-formatted grade line, gag tail
    only when nothing CRITICAL is active. Exit codes stay boring (0).
    """
    leftovers = [a for a in args if a != "--plain"]
    if leftovers:
        return _usage_line(offender=leftovers[0])
    import shutil as _shutil

    from .engines import ScanDeadlineBreach, scan_bundle
    from .fun import render_self_scan, self_scan_mirror
    from .report import build_report

    mirror = self_scan_mirror()
    try:
        start = time.monotonic()
        try:
            result = scan_bundle(mirror, deadline=_deadline_from_start(start))
            envelope = build_report(result)
        except ScanDeadlineBreach:
            return fast_line_fail(
                name="self-scan",
                reason=f"internal scan deadline ({int(INTERNAL_SCAN_DEADLINE_SECONDS)}s) exceeded",
            )
        except Exception as exc:  # noqa: BLE001 — never raise into the host
            logger.exception("self-scan failed")
            reason_text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            return fast_line_fail(name="self-scan", reason=f"unreadable target: {reason_text}")
    finally:
        _shutil.rmtree(mirror, ignore_errors=True)
    # The mirror's temp dirname must never leak into the render identity.
    display = dict(envelope)
    target = dict(display.get("target") or {})
    target["name"] = "skill_lens"
    display["target"] = target
    return render_self_scan(display)


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


_shared_jobs_lock = threading.Lock()
_shared_jobs: Any | None = None  # JobManager; typed loose to keep the lazy import


def shared_jobs(view: PluginContextView | None = None) -> Any:
    """Process-wide :class:`~skill_lens.jobs.JobManager` (lazy singleton).

    Created on first use against *view*'s plugin-data dir so jobs.json /
    events.ndjson land in durable state. Tests reset via
    :func:`reset_shared_jobs`.
    """
    global _shared_jobs
    with _shared_jobs_lock:
        if _shared_jobs is None:
            from .jobs import JobManager

            if view is not None:
                data_dir = view.plugin_data_dir()
            else:
                data_dir = hermes_home() / "plugin-data" / "lens"
            _shared_jobs = JobManager(plugin_data_dir=data_dir)
        return _shared_jobs


def reset_shared_jobs() -> None:
    """Shut down and drop the process-wide manager (test seam)."""
    global _shared_jobs
    with _shared_jobs_lock:
        manager = _shared_jobs
        _shared_jobs = None
    if manager is not None:
        try:
            manager.shutdown(timeout=2.0)
        except Exception:  # noqa: BLE001 — test seam must never raise
            logger.debug("reset_shared_jobs shutdown hiccup", exc_info=True)


# ---------------------------------------------------------------------------
# hub verb — quarantine staging review (SPEC §11.7; co-flagship #1)
# ---------------------------------------------------------------------------


def _verb_hub(
    args: list[str],
    *,
    view: PluginContextView,
    cache: FastPathCache,
    jobs: Any | None,
) -> str:
    """Render the quarantine staging view; zero-arg by design (§11.7).

    The whole render is advisor-safe by construction: it enqueues work on
    the shared worker (never runs engines inline), labels itself advisory,
    and degrades per-bundle when staged dirs vanish mid-render.
    """
    if args:
        return _usage_line(offender=args[0])
    from .hubview import render_hub_view

    return render_hub_view(
        home=hermes_home(),
        view=view,
        cache=cache,
        jobs=jobs,
    )


def _verb_rules(
    args: list[str], *, view: PluginContextView, sink: dict[str, Any] | None = None
) -> str:
    """``rules verify`` — offline provenance check (SPEC §15, D-RULEOWN).

    No argument verifies the EMBEDDED core pack against the committed
    public key + detached signature (the same engine as doctor check 1,
    so both surfaces share one implementation). A path argument loads an
    external/community pack instead: structural load + version/checksum
    report, plus detached-signature verification when ``--sig`` names a
    sidecar (public key defaults to the committed one; ``--pubkey``
    overrides for third-party trust roots).

    Updates are manual-only by design (D-RULEOWN): there is no update
    verb, no fetch, no network — users download a release artifact
    themselves and run this verb to prove its bytes.
    """
    del view  # uniform verb signature; verification needs no host state
    # ``--plain`` rides the CLI lane's _emit (namespace flag); accept and
    # ignore it here so token reconstruction never becomes a fake action.
    args = [a for a in args if a != "--plain"]
    action = args[0].lower() if args else "verify"
    if action in ("-h", "--help", "help"):
        return _RULES_USAGE
    if action != "verify":
        return fast_line_fail(
            name="rules",
            reason=f"unknown action {action!r} — usage: rules verify [path] (--sig F) (--pubkey F)",
        )
    rest = args[1:]
    sig_path: str | None = None
    pub_path: str | None = None
    positional: list[str] = []
    i = 0
    while i < len(rest):
        token = rest[i]
        if token == "--sig" and i + 1 < len(rest):
            sig_path = rest[i + 1]
            i += 2
        elif token == "--pubkey" and i + 1 < len(rest):
            pub_path = rest[i + 1]
            i += 2
        elif token.startswith("--"):
            return fast_line_fail(name="rules", reason=f"unknown flag {token}")
        else:
            positional.append(token)
            i += 1
    if len(positional) > 1:
        return fast_line_fail(
            name="rules", reason="usage: rules verify [path] (--sig F) (--pubkey F)"
        )

    from . import packsec
    from .diagnostics import DiagnosticsCollector
    from .rules import RulePackError, load_pack

    def _set_exit(code: int) -> None:
        if sink is not None:
            sink["rules_exit"] = code

    if not positional:
        report = packsec.verify_core_signature()
        _set_exit(0 if report.status != "fail" else 2)
        head = (
            f"lens rules verify · core {report.checksum[:15]}…"
            if report.status == "pass"
            else "lens rules verify · core"
        )
        body = "\n".join(report.lines)
        if report.status == "pass":
            return f"{head}\n{body}"
        prefix = "lens fail · rule-pack signature REJECTED" if report.status == "fail" else head
        return f"{prefix}\n{body}"

    target = Path(positional[0])
    try:
        pack = load_pack(target, diagnostics=DiagnosticsCollector())
    except RulePackError as exc:
        _set_exit(2)
        return fast_line_fail(name="rules verify", reason=f"rule pack unreadable: {exc}")
    lines = [
        f"lens rules verify · {pack.name} {pack.version}",
        f"{len(pack.rules)} rules ({len(pack.active_rules())} active) · {pack.content_checksum()}",
    ]
    exit_code = 0
    if sig_path or pub_path:
        default_pub, _default_sig = packsec.locate_core_keys()
        if pub_path is None and default_pub is not None:
            pub_path = str(default_pub)
        if not (sig_path and pub_path):
            _set_exit(2)
            return fast_line_fail(
                name="rules verify",
                reason=(
                    "signature check needs --sig FILE plus a pubkey "
                    "(--pubkey FILE or the committed keys/pack-signing.pub.pem)"
                ),
            )
        try:
            inputs = packsec.canonical_pack_inputs(target)
            digest = packsec.canonical_digest(inputs)
            sig_bytes = packsec.read_sig_file(sig_path)[1]
            result = packsec.verify_digest(Path(pub_path).read_bytes(), digest, sig_bytes)
        except packsec.PackSecError as exc:
            _set_exit(2)
            return fast_line_fail(name="rules verify", reason=str(exc))
        if result.ok:
            lines.append(f"signature verified ({result.fingerprint})")
        else:
            lines.append(
                f"SIGNATURE REJECTED — {result.reason}: treat these pack bytes as untrusted"
            )
            exit_code = 2
    else:
        lines.append("unsigned check (structural load only — pass --sig to verify origin)")
    _set_exit(exit_code)
    if exit_code == 2:
        return "lens fail · " + lines[-1]
    return "\n".join(lines)


def _verb_doctor(
    args: list[str], *, view: PluginContextView, sink: dict[str, Any] | None = None
) -> str:
    """§11.9 nine-check self-check; same engine as ``hermes lens doctor``.

    Never raises (the safe-handler wrapper would catch it, but the verb
    itself must not depend on that). No pull banner — operational surface,
    like ``watch``. The CLI lane reads the §11.9 exit policy (0 on warnings,
    2 on hard failures) from ``sink["doctor_exit"]``; the slash lane ignores
    the sink entirely (D-SURF).
    """
    if args:
        # ``--plain`` rides the CLI lane's _emit (namespace flag), so accept
        # and ignore it here; any other argument is a usage offense.
        leftovers = [a for a in args if a != "--plain"]
        if leftovers:
            return _usage_line(offender=leftovers[0])
    from .doctor import render_slash, run_doctor

    report = run_doctor(view)
    if sink is not None:
        sink["doctor_exit"] = report.exit_code
    return render_slash(report)


def _verb_watch(args: list[str], *, view: PluginContextView) -> str:
    """Drift-watcher control: status (default) | start [secs] | stop (§11.8).

    The startup sweep ALWAYS runs at register time regardless of this verb;
    ``start``/``stop`` govern only the opt-in continuous poller. Everything
    is advisor-safe: failures degrade to fail-lines, never exceptions.
    """
    from .watcher import shared_watcher

    sub = args[0].lower() if args else "status"
    extra = args[1:]
    if sub in ("status", "st"):
        watcher = shared_watcher(view)
        lines = watcher.status_lines()
        if len(lines) == 1:
            return f"```\n{lines[0]}\n```\n"
        body = "\n".join(lines)
        return f"```\n{body}\n```\n"
    if sub == "start":
        interval: float | None = None
        if extra:
            try:
                interval = float(extra[0])
            except ValueError:
                return fast_line_fail(
                    name="watch",
                    reason=f"bad interval {extra[0]!r} · usage: /lens watch start [seconds]",
                )
            if interval <= 0:
                return fast_line_fail(name="watch", reason="interval must be > 0 seconds")
        # A previous explicit stop must not silently win over an explicit start.
        # RELATIVE import (dual-import law): the verb must mutate the SAME
        # module-graph singleton the plugin registered against.
        from .watcher import reset_shared_watcher as _reset
        from .watcher import shared_watcher as _shared

        _reset()
        watcher = _shared(view)
        watcher.safe_sweep()  # refresh state before polling on top of it
        started = watcher.start_polling(interval)
        info = watcher.status_dict()
        mode = "inotify-accelerated" if info["inotify"] else "timed poll"
        if started:
            return (
                f"```\nlens watch · continuous polling started · base {info['base_interval']:.0f}s "
                f"(2s→30s adaptive backoff) · {mode} · /lens watch status\n```\n"
            )
        return fast_line_fail(name="watch", reason="poller already active or spawn failed")
    if sub == "stop":
        watcher = shared_watcher(view)
        stopped = watcher.stop_polling()
        return (
            "```\nlens watch · continuous polling stopped (startup sweep still runs "
            "every session)\n```\n"
            if stopped
            else fast_line_fail(name="watch", reason="poller was not running")
        )
    if sub in ("help", "-h", "--help"):
        return _WATCH_USAGE
    return _usage_line(offender=args[0])


_WATCH_USAGE = """```\
usage: /lens watch [status|start [seconds]|stop]

  status           poller state, tracked-skill count, journalled gaps
  start [seconds]  opt-in continuous drift polling (adaptive backoff 2s→30s;
                   default interval 2s; persisted across sessions)
  stop             halt the poller for this and future sessions (the startup
                   sweep that catches while-away drift always stays on)

out-of-band changes are caught by the startup sweep even without polling.
```"""


def _first_token(raw_args: str | None) -> str | None:
    tokens = (raw_args or "").split()
    return tokens[0] if tokens else None


def dispatch_verb(
    raw_args: str,
    *,
    view: PluginContextView,
    cache: FastPathCache,
    jobs: Any | None = None,
    sink: dict[str, Any] | None = None,
) -> str:
    """Route one raw verb invocation. RAISES :class:`PolicyError`.

    The shared routing table for BOTH surfaces (§11.2 verbs shared by CLI
    and slash). Callers pick the error lane: the slash safe-handler renders
    the one-line notice; the CLI dispatcher maps to §18 exit codes.

    *sink* is the CLI lane's one-way side channel: when given, verdict-bearing
    verbs stash the envelope dict behind ``sink["envelope"]`` so the dispatcher
    can project ``--fail-on`` onto §18 exit codes without re-scanning or
    text-parsing. The slash lane passes nothing (D-SURF — no exit channel).

    Pull banner (§11.5): ready-but-unfetched reports prepend a one-line
    ``N reports ready`` notice on every invocation except ``help`` and the
    fetching verb itself (``report``). The full P4 delivered-results UX
    builds on this counting seam.
    """
    try:
        tokens = shlex.split(raw_args or "")
    except ValueError:
        return _usage_line(offender=_first_token(raw_args))
    verb = tokens[0].lower() if tokens else "help"
    args = tokens[1:]
    manager = jobs if jobs is not None else shared_jobs(view)
    if verb in ("help", "-h", "--help"):
        return _USAGE
    if verb == "scan":
        result = _verb_scan(args, view=view, cache=cache, jobs=manager, sink=sink)
    elif verb == "report":
        return _verb_report(args, cache=cache, jobs=manager, sink=sink)
    elif verb == "map":
        result = _verb_map(args, view=view, sink=sink)
    elif verb == "autopsy":
        result = _verb_autopsy(args, view=view, cache=cache)
    elif verb == "baseline":
        result = _verb_baseline(args, view=view, cache=cache)
    elif verb in ("explain-rules", "explain"):
        result = _verb_explain(args, view=view)
    elif verb == "diff":
        result = _verb_diff(args, view=view, cache=cache, sink=sink)
    elif verb == "hub":
        result = _verb_hub(args, view=view, cache=cache, jobs=manager)
    elif verb == "watch":
        # Drift-watcher control/status (§11.8): operational surface — the
        # "N reports ready" pull banner is noise here, so return directly.
        return _verb_watch(args, view=view)
    elif verb == "rules":
        # §15 governance surface: operational, no pull banner. The CLI lane
        # projects sink["rules_exit"] onto §18's total-error code.
        return _verb_rules(args, view=view, sink=sink)
    elif verb == "doctor":
        # §11.9 nine-check engine: operational surface — no pull banner.
        return _verb_doctor(args, view=view, sink=sink)
    elif verb == "bones":
        # F-6 easter egg (hidden): opt-in by invocation; gags carry no pull
        # banner — a chart interrupted by queue bookkeeping isn't funny.
        return _verb_bones(args, view=view)
    elif verb == "lens":
        # F-6 self-scan twin (hidden): same no-banner rule as bones.
        return _verb_self_scan(args, view=view)
    else:
        return _usage_line(offender=verb)
    banner = manager.banner_line()
    return f"{banner}\n{result}" if banner else result


def make_handler(
    view: PluginContextView,
    cache: FastPathCache,
    *,
    jobs: Any | None = None,
) -> Any:
    """Build the ``fn(raw_args) -> str | None`` slash handler."""

    def handler(raw_args: str) -> str | None:
        return dispatch_verb(raw_args, view=view, cache=cache, jobs=jobs)

    def safe_handler(raw_args: str) -> str | None:
        try:
            return handler(raw_args)
        except PolicyError as exc:
            # Configuration-seam lane (A1 seam): malformed policy/baseline
            # config renders the ONE-LINE notice in-session, never exit codes.
            logger.warning("/lens policy error surfaced to session: %s", exc.message)
            return policy_failure_notice(exc)
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
    args_hint = (
        "scan|report|map|autopsy|baseline|explain-rules|diff|hub|watch|help"
        " · flags: --json --no-cache --voice"
    )
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
    "reset_shared_jobs",
    "resolve_target",
    "run_scan",
    "shared_cache",
    "shared_jobs",
]
