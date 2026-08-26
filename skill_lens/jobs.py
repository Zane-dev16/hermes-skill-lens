"""Async scan job model — one worker thread owns ALL cold scans (SPEC §11.5).

State machine (NORMATIVE): ``queued → scanning → ready | failed``, persisted
in ``<plugin-data>/lens/jobs.json``. Coalescing is keyed by ``bundle_hash``:
enqueuing while an identical job is ``queued``/``scanning`` returns the SAME
job id — no double scan (§11.6 double-scan avoidance). Failed jobs record
ONE-LINE why and are NEVER retried silently; a new scan happens only on an
explicit new request. Every transition mirrors into ``events.ndjson``.

Threading contract (PLAN §0 "Concurrency" row): the reply path NEVER runs
engines — cache hits answer inline (<200 ms), misses enqueue and return the
fixed-order §11.4 status one-liner. The single daemon worker thread is the
only cold-scan executor, so the install/confirm beat is never delayed.

Thread-safety audit note (cache.py under this worker): :class:`FastPathCache`
guards its OrderedDict with ONE ``threading.Lock`` around every operation
(get/put/invalidate/latest_by_name/stats) and stores frozen entries, so the
worker thread putting completed reports while handler threads read them is
safe by construction — no additional locking is layered here.

Sidecar law: ``jobs.json`` / ``events.ndjson`` carry wall-clock timestamps
and are RUNTIME STATE like ``_meta`` — exempt from the determinism tests;
they are never inputs to any canonical envelope.

Shutdown law: the worker is a daemon thread; :meth:`JobManager.shutdown`
joins with a timeout inside an atexit guard that can never raise, so the
host process never hangs on exit. Persisted ``queued``/``scanning`` jobs
found at startup are marked failed ("worker restarted") — honest recovery,
never a silent retry.
"""

from __future__ import annotations

import atexit
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

from skill_lens.cache import CacheEntry, hash8
from skill_lens.canonical import canonical_dumps

logger = logging.getLogger("lens")

#: Schema tags for the two sidecar files (both live in the plugin-data dir).
JOBS_SCHEMA = "lens.jobs/1"
EVENTS_SCHEMA = "lens.events/1"

#: State machine vocabulary (SPEC §11.5 — NORMATIVE, do not extend casually).
STATE_QUEUED = "queued"
STATE_SCANNING = "scanning"
STATE_READY = "ready"
STATE_FAILED = "failed"
LIVE_STATES = frozenset({STATE_QUEUED, STATE_SCANNING})
TERMINAL_STATES = frozenset({STATE_READY, STATE_FAILED})

#: Terminal jobs kept in jobs.json before oldest-first pruning (bound growth).
MAX_PERSISTED_JOBS = 64

#: Default grace for shutdown joins (host must never hang on us).
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 2.0

#: One-line error cap (§11.4 fast lines clip at 160; keep reasons shorter).
_REASON_MAX_CHARS = 120


class ScanFailure(Exception):
    """Raised by runners to fail a job with a one-line reason."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanContext:
    """Frozen execution inputs captured at enqueue time (in-memory ONLY).

    Never serialized into jobs.json: after a restart these objects are gone,
    which is exactly why stale queued/scanning jobs recover as *failed*
    instead of being silently re-run.
    """

    baseline_records: tuple[Any, ...] = ()
    key_suffix: str = ""
    report_date: date | None = None
    plugin_data_dir: Path | None = None
    cache: Any | None = None  # FastPathCache; typed loose to avoid import cycle


@dataclass
class JobRecord:
    """One async scan job (the persisted state-machine node)."""

    job_id: str
    name: str
    bundle_hash: str  # sha256 over the canonical IR envelope — coalescing key
    cache_key: str  # bundle_hash + baseline suffix (fast-path cache identity)
    target: str  # resolved filesystem target at enqueue time
    state: str = STATE_QUEUED
    error: str | None = None  # ONE-LINE reason when state == failed
    attempts: int = 0  # runs started; a healthy job ends its life with exactly 1
    coalesced: int = 0  # how many duplicate triggers folded into this job
    fetched: bool = False  # ready result already pulled via /lens report
    created: float = 0.0  # wall-clock epoch seconds (sidecar display only)
    updated: float = 0.0
    context: ScanContext | None = field(default=None, repr=False, compare=False)

    def to_json(self) -> dict[str, Any]:
        """Persistence shape (context deliberately excluded — see class doc)."""
        return {
            "job_id": self.job_id,
            "name": self.name,
            "bundle_hash": self.bundle_hash,
            "cache_key": self.cache_key,
            "target": self.target,
            "state": self.state,
            "error": self.error,
            "attempts": self.attempts,
            "coalesced": self.coalesced,
            "fetched": self.fetched,
            "created": self.created,
            "updated": self.updated,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> JobRecord:
        return cls(
            job_id=str(data.get("job_id", "")),
            name=str(data.get("name", "")),
            bundle_hash=str(data.get("bundle_hash", "")),
            cache_key=str(data.get("cache_key", data.get("bundle_hash", ""))),
            target=str(data.get("target", "")),
            state=str(data.get("state", STATE_FAILED)),
            error=data.get("error"),
            attempts=int(data.get("attempts", 0) or 0),
            coalesced=int(data.get("coalesced", 0) or 0),
            fetched=bool(data.get("fetched", False)),
            created=float(data.get("created", 0.0) or 0.0),
            updated=float(data.get("updated", 0.0) or 0.0),
            context=None,
        )


@dataclass(frozen=True)
class EnqueueDecision:
    """Result of one enqueue call."""

    job: JobRecord
    coalesced: bool  # True ⇒ folded onto an existing queued/scanning job


# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------

#: Runner contract: execute the full cold scan for *job*, store results
#: (normally into ``job.context.cache``), return None; raise (anything) to
#: fail the job. The failure reason becomes ONE line on the job record.
Runner = Callable[[JobRecord], None]


def _one_line(reason: str, limit: int = _REASON_MAX_CHARS) -> str:
    """Collapse any error text to ONE clipped line (never multi-line state)."""
    text = " ".join(str(reason).split())
    if not text:
        text = "unknown error"
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _exception_reason(exc: BaseException) -> str:
    first = next((ln for ln in str(exc).splitlines() if ln.strip()), "")
    return _one_line(first or exc.__class__.__name__)


def pipeline_runner(job: JobRecord) -> None:
    """Production runner: the full suppressed pipeline into the shared cache.

    Lazy import — slash.py owns the pipeline seams and imports this module,
    so the edge points one way only at call time. run_scan applies the same
    internal deadline it always has; a breach fails the job honestly.
    """
    from skill_lens.slash import run_scan, shared_cache

    context = job.context
    if context is None:
        raise ScanFailure("job lost its execution context (worker restart)")
    outcome = run_scan(
        Path(job.target),
        cache=context.cache if context.cache is not None else shared_cache(),
        plugin_data_dir=(
            context.plugin_data_dir
            if context.plugin_data_dir is not None
            else Path(job.target).parent
        ),
        baseline_records=context.baseline_records,
        key_suffix=context.key_suffix,
        report_date=context.report_date,
    )
    if not outcome.get("ok"):
        raise ScanFailure(_one_line(str(outcome.get("error") or "scan failed")))


# ---------------------------------------------------------------------------
# Event ledger (events.ndjson)
# ---------------------------------------------------------------------------


class _EventLedger:
    """Append-only NDJSON mirror of job transitions (best-effort, never raises).

    Every record is one JSON line, sort_keys stable. Wall-clock ``ts`` rides
    here only — sidecar state, exempt from determinism laws like ``_meta``.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def append(self, kind: str, job: JobRecord, *, line: str = "") -> None:
        record = {
            "schema": EVENTS_SCHEMA,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "event": kind,
            "job_id": job.job_id,
            "name": job.name,
            "state": job.state,
            "bundle_hash": job.bundle_hash,
            "line": line,
        }
        if job.error:
            record["error"] = job.error
        try:
            payload = canonical_dumps(record)
        except Exception:  # noqa: BLE001 — ledger must never break the queue
            logger.debug("events.ndjson: unserializable record dropped", exc_info=True)
            return
        try:
            with self._lock, self._path.open("a", encoding="utf-8") as handle:
                handle.write(payload + "\n")
        except OSError:
            logger.warning("events.ndjson append failed (%s)", self._path, exc_info=True)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class JobManager:
    """Owns the job table, the worker thread, and both sidecar files."""

    def __init__(
        self,
        *,
        plugin_data_dir: Path,
        runner: Runner | None = None,
        max_persisted: int = MAX_PERSISTED_JOBS,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
        register_exit: bool = True,
    ) -> None:
        self._data_dir = Path(plugin_data_dir)
        self._jobs_path = self._data_dir / "jobs.json"
        self._runner: Runner = runner if runner is not None else pipeline_runner
        self._max_persisted = max(1, int(max_persisted))
        self._shutdown_timeout = float(shutdown_timeout)

        # One lock guards the job table AND its persistence; the Condition
        # shares it so waiters wake on every transition.
        self._cond = threading.Condition()
        self._jobs: dict[str, JobRecord] = {}
        self._seq = 0
        self._stop_sent = False
        self._thread: threading.Thread | None = None

        self._ledger = _EventLedger(self._data_dir / "events.ndjson")

        self._recover_stale_jobs()
        if register_exit:
            atexit.register(self._atexit_join)

    # -- enqueue / coalescing -------------------------------------------------

    def enqueue(
        self,
        *,
        name: str,
        target: Path,
        bundle_hash: str,
        cache_key: str | None = None,
        context: ScanContext | None = None,
    ) -> EnqueueDecision:
        """Queue a cold scan; fold onto the live job when the hash matches.

        Coalescing (NORMATIVE per §11.5/§11.6): keyed by ``bundle_hash``
        alone while a job is queued/scanning — identical content is scanned
        exactly once no matter how many triggers race in.
        """
        key = cache_key if cache_key is not None else bundle_hash
        now = time.time()
        with self._cond:
            live = sorted(
                (j for j in self._jobs.values() if j.state in LIVE_STATES),
                key=lambda j: (j.created, j.job_id),
            )
            for existing in live:
                if existing.bundle_hash == bundle_hash:
                    existing.coalesced += 1
                    existing.updated = now
                    self._persist_locked()
                    decision = EnqueueDecision(job=replace(existing), coalesced=True)
                    break
            else:
                self._seq += 1
                job = JobRecord(
                    job_id=f"j-{int(now * 1000)}-{self._seq:04d}",
                    name=name,
                    bundle_hash=bundle_hash,
                    cache_key=key,
                    target=str(target),
                    state=STATE_QUEUED,
                    created=now,
                    updated=now,
                    context=context,
                )
                self._jobs[job.job_id] = job
                self._persist_locked()
                decision = EnqueueDecision(job=replace(job), coalesced=False)
                self._ensure_worker_locked()
                # Ledger BEFORE queue.put so the queued event can never be
                # overtaken by this job's own terminal event.
                self._ledger.append(
                    "scan_queued",
                    job,
                    line=_queued_line(job),
                )
                self._queue_job(job.job_id)
        if decision.coalesced:
            self._ledger.append("scan_coalesced", decision.job, line=_skip_line(decision.job))
        return decision

    def _queue_job(self, job_id: str) -> None:
        self._queue_put(job_id)

    def _queue_put(self, item: str | None) -> None:
        self._queue.put(item)

    @property
    def _queue(self) -> queue.Queue[str | None]:
        # Lazily-created bound attribute keeps __init__ readable.
        existing = getattr(self, "_queue_store", None)
        if existing is None:
            existing = queue.Queue()
            self._queue_store = existing  # type: ignore[attr-defined]
        return existing

    def _ensure_worker_locked(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        if self._stop_sent:
            return  # shut-down manager accepts no more work
        self._thread = threading.Thread(
            target=self._worker_main,
            name="lens-scan-worker",
            daemon=True,  # host exit never blocks on us
        )
        self._thread.start()

    # -- worker loop -------------------------------------------------------------

    def _worker_main(self) -> None:
        while True:
            try:
                item = self._queue.get()
            except BaseException:  # pragma: no cover — interpreter teardown
                return
            if item is None:
                return
            try:
                self._execute(item)
            except BaseException:  # noqa: BLE001 — the loop itself must never die
                logger.exception("lens worker: unexpected error executing job %s", item)
            finally:
                try:
                    self._queue.task_done()
                except BaseException:  # pragma: no cover
                    pass

    def _execute(self, job_id: str) -> None:
        with self._cond:
            job = self._jobs.get(job_id)
            if job is None or job.state != STATE_QUEUED or self._stop_sent:
                return
            job.state = STATE_SCANNING
            job.attempts += 1  # exactly once — failures are terminal (no retry)
            job.updated = time.time()
            self._persist_locked()
            self._cond.notify_all()  # wake state watchers (scanning)
        try:
            self._runner(job)
        except BaseException as exc:  # noqa: BLE001 — every failure is recorded
            reason = _exception_reason(exc)
            with self._cond:
                job.state = STATE_FAILED
                job.error = reason
                job.updated = time.time()
                self._prune_locked()
                self._persist_locked()
                self._cond.notify_all()  # wake state watchers (failed)
            self._ledger.append("scan_failed", job, line=_fail_line(job))
        else:
            with self._cond:
                job.state = STATE_READY
                job.error = None
                job.updated = time.time()
                self._persist_locked()
                self._cond.notify_all()  # wake state watchers (ready)
            self._ledger.append("scan_ready", job, line=self._ready_line(job))

    # -- public reads ---------------------------------------------------------------

    def snapshot_job(self, job_id: str) -> JobRecord | None:
        with self._cond:
            job = self._jobs.get(job_id)
            return replace(job) if job is not None else None

    def latest_job_for_name(self, name: str) -> JobRecord | None:
        with self._cond:
            matches = [j for j in self._jobs.values() if j.name == name]
        if not matches:
            return None
        return replace(max(matches, key=lambda j: (j.updated, j.job_id)))

    def reports_ready(self) -> list[JobRecord]:
        """Ready-but-unfetched jobs, oldest first (banner + pull counting)."""
        with self._cond:
            ready = [j for j in self._jobs.values() if j.state == STATE_READY and not j.fetched]
        return [replace(j) for j in sorted(ready, key=lambda j: (j.updated, j.job_id))]

    def mark_fetched(self, name: str) -> int:
        """Clear readiness for every ready job of *name*; returns count."""
        now = time.time()
        with self._cond:
            cleared = 0
            for job in self._jobs.values():
                if job.name == name and job.state == STATE_READY and not job.fetched:
                    job.fetched = True
                    job.updated = now
                    cleared += 1
            if cleared:
                self._persist_locked()
                self._cond.notify_all()
            return cleared

    def banner_line(self) -> str | None:
        """The §11.5 pull banner: ``1 report ready: <name> (scanned HH:MM:SS)``."""
        ready = self.reports_ready()
        if not ready:
            return None
        if len(ready) == 1:
            job = ready[0]
            stamp = time.strftime("%H:%M:%S", time.localtime(job.updated))
            return f"1 report ready: {job.name} (scanned {stamp})"
        names = ", ".join(j.name for j in ready[:4])
        extra = len(ready) - 4
        text = f"{len(ready)} reports ready: {names}"
        if extra > 0:
            text += f" …+{extra} more"
        return text[:159]

    def stats(self) -> dict[str, int]:
        with self._cond:
            jobs = list(self._jobs.values())
        return {
            "queued": sum(1 for j in jobs if j.state == STATE_QUEUED),
            "scanning": sum(1 for j in jobs if j.state == STATE_SCANNING),
            "ready": sum(1 for j in jobs if j.state == STATE_READY),
            "failed": sum(1 for j in jobs if j.state == STATE_FAILED),
            "coalesced_total": sum(j.coalesced for j in jobs),
        }

    def wait_for_state(
        self,
        job_id: str,
        states: frozenset[str] | set[str] | str,
        *,
        timeout: float = 10.0,
    ) -> JobRecord | None:
        """Block until the job reaches one of *states*; final snapshot or None."""
        wanted = {states} if isinstance(states, str) else set(states)
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                job = self._jobs.get(job_id)
                if job is not None and job.state in wanted:
                    return replace(job)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    # -- persistence ---------------------------------------------------------------

    def _persist_locked(self) -> None:
        """Atomically rewrite jobs.json (caller holds ``self._cond``).

        Best-effort: persistence problems log and degrade — they must never
        kill the worker or bubble into the host.
        """
        payload = {
            "schema": JOBS_SCHEMA,
            "jobs": [
                job.to_json()
                for job in sorted(self._jobs.values(), key=lambda j: (j.created, j.job_id))
            ],
        }
        tmp = self._jobs_path.with_name(f".{self._jobs_path.name}.tmp-{id(self):x}")
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            tmp.write_text(canonical_dumps(payload), encoding="utf-8")
            tmp.replace(self._jobs_path)
        except OSError:
            logger.warning("jobs.json persist failed (%s)", self._jobs_path, exc_info=True)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _load_unlocked(self) -> None:
        """Read persisted jobs (tolerant: corrupt files move aside, never raise)."""
        try:
            raw = self._jobs_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except OSError:
            logger.warning("jobs.json unreadable (%s)", self._jobs_path, exc_info=True)
            return
        import json as _json

        try:
            data = _json.loads(raw)
            rows = data["jobs"] if isinstance(data, dict) else []
            jobs = [JobRecord.from_json(row) for row in rows if isinstance(row, dict)]
        except Exception:  # noqa: BLE001 — corrupt sidecar never breaks startup
            logger.exception("jobs.json corrupt; moving aside")
            backup = self._jobs_path.with_name(self._jobs_path.name + ".corrupt")
            try:
                self._jobs_path.replace(backup)
            except OSError:
                pass
            return
        for job in jobs:
            if job.job_id:
                self._jobs[job.job_id] = job

    def _recover_stale_jobs(self) -> None:
        """Crash recovery: interrupted jobs fail HONESTLY (never silent retry).

        A persisted ``queued``/``scanning`` job at construction time means the
        owning process died mid-flight; its execution context is gone, so the
        only truthful terminal state is failed with a restart notice. Re-run
        requires an explicit new ``/lens scan`` — the §11.5 no-silent-retry
        law applied across restarts.
        """
        self._load_unlocked()
        recovered: list[JobRecord] = []
        now = time.time()
        with self._cond:
            for job in self._jobs.values():
                if job.state in LIVE_STATES:
                    job.state = STATE_FAILED
                    job.error = _one_line(
                        "interrupted: lens worker restarted before this scan ran "
                        "— submit /lens scan again"
                    )
                    job.updated = now
                    recovered.append(replace(job))
            if recovered:
                self._persist_locked()
        for job in recovered:
            self._ledger.append("scan_failed", job)
        if recovered:
            with self._cond:
                self._cond.notify_all()

    def _prune_locked(self) -> None:
        """Drop oldest TERMINAL jobs past the cap (live jobs always kept)."""
        terminal = sorted(
            (j for j in self._jobs.values() if j.state in TERMINAL_STATES),
            key=lambda j: (j.updated, j.job_id),
        )
        excess = len(terminal) - self._max_persisted
        for job in terminal[:excess]:
            del self._jobs[job.job_id]

    # -- event lines (mirror §11.4 vocabulary into events.ndjson) --------------------

    def _ready_line(self, job: JobRecord) -> str:
        entry: CacheEntry | None = None
        context = job.context
        cache = context.cache if context is not None else None
        if cache is not None:
            try:
                entry = cache.peek(job.cache_key)
            except Exception:  # noqa: BLE001 — display-only best effort
                entry = None
        if entry is not None:
            from skill_lens.render import fast_line_ok

            return fast_line_ok(
                name=entry.name,
                grade=entry.grade,
                value=entry.value,
                verdict=entry.verdict,
                counts=entry.counts,
            )
        return f"lens ready {job.name} · /lens report {job.name}"

    # -- shutdown ---------------------------------------------------------------

    def shutdown(self, timeout: float | None = None) -> bool:
        """Stop the worker; join with timeout. Idempotent, never raises.

        Returns True when no worker thread remains alive. Queued-but-unrun
        jobs stay persisted as queued and recover as failed on next start —
        an honest trail, not a silent drop.
        """
        try:
            with self._cond:
                thread = self._thread
                if not self._stop_sent:
                    self._stop_sent = True
                    self._queue_put(None)
            if thread is None:
                return True
            thread.join(self._shutdown_timeout if timeout is None else timeout)
            return not thread.is_alive()
        except Exception:  # noqa: BLE001 — shutdown is a never-raise seam
            logger.debug("lens worker shutdown hiccup", exc_info=True)
            return False

    def _atexit_join(self) -> None:
        """Interpreter-exit guard: bounded join, swallow everything."""
        try:
            self.shutdown(timeout=self._shutdown_timeout)
        except Exception:  # noqa: BLE001 — atexit must never raise into host
            pass

    # introspection used by tests/doctor ----------------------------------------------

    @property
    def worker_thread(self) -> threading.Thread | None:
        return self._thread

    @property
    def jobs_path(self) -> Path:
        return self._jobs_path

    @property
    def events_path(self) -> Path:
        return self._ledger._path


# ---------------------------------------------------------------------------
# §11.4 line builders shared by the enqueue path and the event ledger
# ---------------------------------------------------------------------------


def _queued_line(job: JobRecord) -> str:
    from skill_lens.render import fast_line_scan_queued

    return fast_line_scan_queued(name=job.name, hash8=hash8(job.bundle_hash))


def _skip_line(job: JobRecord) -> str:
    from skill_lens.render import fast_line_coalesced

    return fast_line_coalesced(name=job.name, hash8=hash8(job.bundle_hash))


def _fail_line(job: JobRecord) -> str:
    from skill_lens.render import fast_line_fail

    return fast_line_fail(name=job.name, reason=job.error or "scan failed")


__all__ = [
    "DEFAULT_SHUTDOWN_TIMEOUT_SECONDS",
    "EVENTS_SCHEMA",
    "JOBS_SCHEMA",
    "LIVE_STATES",
    "MAX_PERSISTED_JOBS",
    "EnqueueDecision",
    "JobManager",
    "JobRecord",
    "ScanContext",
    "ScanFailure",
    "pipeline_runner",
]
