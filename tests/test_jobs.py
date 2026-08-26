"""Async job model — worker thread, coalescing, persistence (SPEC §11.5).

PLAN Phase 2 exit criterion under test here: "two concurrent triggers for
the same bundle produce exactly one scan job". Also pins the NORMATIVE
state machine (queued→scanning→ready|failed), one-line failure reasons,
no-silent-retry semantics, jobs.json/events.ndjson sidecar behavior,
clean shutdown, and cache thread-safety under the worker.

Determinism note: jobs.json and events.ndjson are RUNTIME SIDECAR state
(like ``_meta``) — wall-clock timestamps live here by design and these
files are exempt from the determinism harness (see
tests/test_snapshot_golden.py).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from skill_lens.cache import CacheEntry, FastPathCache
from skill_lens.context import PluginContextView
from skill_lens.jobs import (
    JOBS_SCHEMA,
    STATE_FAILED,
    STATE_QUEUED,
    STATE_READY,
    STATE_SCANNING,
    EnqueueDecision,
    JobManager,
    JobRecord,
    ScanContext,
)
from tests.conftest import FakePluginContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_bundle(root: Path, name: str = "demo-skill") -> Path:
    """Minimal benign bundle (fast engines, deterministic shape)."""
    bundle = root / name
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Supercharges synergy quietly.\n"
        "disable-model-invocation: true\n---\n\nbody\n",
        encoding="utf-8",
    )
    return bundle


class _Counter:
    """Thread-safe invocation counter shared between tests and fake runners."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.count = 0

    def bump(self) -> int:
        with self.lock:
            self.count += 1
            return self.count


def _manager(tmp_path: Path, runner=None, **kwargs) -> JobManager:
    kwargs.setdefault("register_exit", False)  # keep atexit clean in tests
    return JobManager(plugin_data_dir=tmp_path / "plugin-data" / "lens", runner=runner, **kwargs)


def _entry_for(bundle_hash: str, name: str = "fake") -> CacheEntry:
    return CacheEntry(
        bundle_hash=bundle_hash,
        name=name,
        grade="A",
        value=100,
        verdict="clean",
        counts="",
        cached_at=time.monotonic(),
    )


# ---------------------------------------------------------------------------
# State machine proof (queued → scanning → ready)
# ---------------------------------------------------------------------------


def test_state_machine_transitions_observed(tmp_path: Path) -> None:
    """queued observed while worker is gated, scanning inside the runner, ready after."""
    gate = threading.Event()
    seen_in_runner: list[str] = []
    first_id: list[str] = []

    def runner(job: JobRecord) -> None:
        seen_in_runner.append(job.job_id)

    # Occupying job keeps the worker busy so the second enqueue is provably queued.
    def make_occupier():
        def blocking_first(job: JobRecord) -> None:
            first_id.append(job.job_id)
            assert occupier.snapshot_job(job.job_id).state == STATE_SCANNING
            gate.wait(5)

        return _manager(tmp_path / "occ", runner=blocking_first)

    occupier = make_occupier()
    occ_decision = occupier.enqueue(
        name="occupier", target=tmp_path, bundle_hash="sha256:" + "11" * 32
    )
    deadline = time.monotonic() + 5
    while not first_id and time.monotonic() < deadline:
        time.sleep(0.005)

    manager = _manager(tmp_path, runner=runner)
    decision = manager.enqueue(
        name="demo",
        target=tmp_path,
        bundle_hash="sha256:" + "22" * 32,
        context=ScanContext(),
    )
    queued_state = manager.snapshot_job(decision.job.job_id).state
    assert queued_state == STATE_QUEUED  # observed BEFORE the worker picks it up

    gate.set()
    assert occupier.wait_for_state(occ_decision.job.job_id, STATE_READY, timeout=5)
    final = manager.wait_for_state(decision.job.job_id, {STATE_READY, STATE_FAILED}, timeout=10)
    assert final is not None and final.state == STATE_READY
    assert seen_in_runner == [decision.job.job_id]  # exactly one execution
    assert final.attempts == 1


def test_worker_executes_and_fills_cache_via_default_pipeline(tmp_path: Path) -> None:
    """The default pipeline runner produces a servable cache entry."""
    bundle = _write_bundle(tmp_path)
    cache = FastPathCache()
    manager = _manager(tmp_path)  # real pipeline_runner
    decision = manager.enqueue(
        name=bundle.name,
        target=bundle,
        bundle_hash="sha256:" + "33" * 32,  # coalescing key irrelevant here
        context=ScanContext(cache=cache, plugin_data_dir=tmp_path / "pd"),
    )
    final = manager.wait_for_state(decision.job.job_id, {STATE_READY, STATE_FAILED}, timeout=30)
    assert final is not None, "pipeline job did not settle"
    assert final.state == STATE_READY, final.error
    # run_scan keys entries by the REAL canonical IR hash (+suffix), so probe
    # by name rather than the synthetic enqueue hash used above.
    entry = cache.latest_by_name(bundle.name)
    assert entry is not None and entry.compact_text


# ---------------------------------------------------------------------------
# Coalescing proofs (PLAN exit criterion)
# ---------------------------------------------------------------------------


def test_two_concurrent_triggers_produce_exactly_one_scan_job(tmp_path: Path) -> None:
    counter = _Counter()
    gate = threading.Event()

    def runner(job: JobRecord) -> None:
        counter.bump()
        gate.wait(5)  # hold the "scan" open so both triggers overlap it
        cache = job.context.cache
        cache.put(_entry_for(job.bundle_hash, job.name))

    manager = _manager(tmp_path, runner=runner)
    bundle = tmp_path / "same-bundle"
    bundle_hash = "sha256:" + "44" * 32
    barrier = threading.Barrier(2)
    ids: list[str] = []
    errors: list[BaseException] = []

    def trigger() -> None:
        try:
            barrier.wait(5)
            decision = manager.enqueue(
                name="same-bundle",
                target=bundle,
                bundle_hash=bundle_hash,
                context=ScanContext(cache=FastPathCache()),
            )
            ids.append(decision.job.job_id)
            if decision.coalesced:
                return
        except BaseException as exc:  # pragma: no cover — surfaced via assert
            errors.append(exc)

    threads = [threading.Thread(target=trigger) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not errors, errors
    assert len(ids) == 2
    assert ids[0] == ids[1], "concurrent identical triggers must share ONE job id"
    gate.set()
    assert manager.wait_for_state(ids[0], STATE_READY, timeout=5) is not None
    assert counter.count == 1, "exactly ONE scan may execute for one hash"
    assert manager.stats()["coalesced_total"] >= 1
    payload = json.loads(manager.jobs_path.read_text(encoding="utf-8"))
    matching = [j for j in payload["jobs"] if j["bundle_hash"] == bundle_hash]
    assert len(matching) == 1, "jobs.json must record a single job per hash"


def test_sequential_duplicate_trigger_coalesces_while_in_flight(tmp_path: Path) -> None:
    gate = threading.Event()
    counter = _Counter()

    def runner(job: JobRecord) -> None:
        counter.bump()
        gate.wait(5)

    manager = _manager(tmp_path, runner=runner)
    first = manager.enqueue(name="a", target=tmp_path, bundle_hash="sha256:" + "55" * 32)
    second = manager.enqueue(name="a", target=tmp_path, bundle_hash="sha256:" + "55" * 32)
    assert isinstance(first, EnqueueDecision) and isinstance(second, EnqueueDecision)
    assert not first.coalesced and second.coalesced
    assert first.job.job_id == second.job.job_id
    gate.set()
    manager.wait_for_state(first.job.job_id, STATE_READY, timeout=5)
    assert counter.count == 1


# ---------------------------------------------------------------------------
# Failure path: one line, no silent retry
# ---------------------------------------------------------------------------


def test_failure_records_one_line_reason_and_never_retries(tmp_path: Path) -> None:
    counter = _Counter()

    def runner(job: JobRecord) -> None:
        counter.bump()
        raise RuntimeError("disk on fire\nsecond line must be collapsed")

    manager = _manager(tmp_path, runner=runner)
    decision = manager.enqueue(name="doomed", target=tmp_path, bundle_hash="sha256:" + "66" * 32)
    final = manager.wait_for_state(decision.job.job_id, STATE_FAILED, timeout=5)
    assert final is not None
    assert final.state == STATE_FAILED
    assert final.error == "disk on fire"
    assert "\n" not in (final.error or "")
    assert final.attempts == 1
    manager._queue.join()  # queue fully drained — nothing pending
    time.sleep(0.05)
    assert counter.count == 1, "no silent retries after failure"
    # The D-format mirror lands in events.ndjson.
    events = manager.events_path.read_text(encoding="utf-8").splitlines()
    kinds = [json.loads(line)["event"] for line in events]
    assert "scan_failed" in kinds


@pytest.mark.parametrize("payload", [RuntimeError("boom"), OSError(13, "permission denied")])
def test_any_exception_shape_fails_the_job(payload: Exception, tmp_path: Path) -> None:
    def runner(job: JobRecord) -> None:
        raise payload

    manager = _manager(tmp_path, runner=runner)
    decision = manager.enqueue(name="x", target=tmp_path, bundle_hash="sha256:" + "77" * 32)
    final = manager.wait_for_state(decision.job.job_id, STATE_FAILED, timeout=5)
    assert final is not None and final.error


def test_resubmit_after_failure_is_an_explicit_new_job(tmp_path: Path) -> None:
    behaviors = iter([RuntimeError("first attempt fails"), None])
    lock = threading.Lock()
    counter = _Counter()

    def runner(job: JobRecord) -> None:
        with lock:
            behavior = next(behaviors)
        counter.bump()
        if behavior is not None:
            raise behavior

    manager = _manager(tmp_path, runner=runner)
    first = manager.enqueue(name="retry-me", target=tmp_path, bundle_hash="sha256:" + "88" * 32)
    assert manager.wait_for_state(first.job.job_id, STATE_FAILED, timeout=5) is not None
    second = manager.enqueue(name="retry-me", target=tmp_path, bundle_hash="sha256:" + "88" * 32)
    assert second.job.job_id != first.job.job_id, "explicit resubmit ⇒ NEW job id"
    assert not second.coalesced
    final = manager.wait_for_state(second.job.job_id, STATE_READY, timeout=5)
    assert final is not None and final.attempts == 1
    assert counter.count == 2


# ---------------------------------------------------------------------------
# Persistence + recovery
# ---------------------------------------------------------------------------


def test_jobs_json_round_trip_and_events_mirror(tmp_path: Path) -> None:
    cache = FastPathCache()

    def runner(job: JobRecord) -> None:
        job.context.cache.put(_entry_for(job.bundle_hash, job.name))

    manager = _manager(tmp_path, runner=runner)
    decision = manager.enqueue(
        name="persisted",
        target=tmp_path,
        bundle_hash="sha256:" + "99" * 32,
        context=ScanContext(cache=cache),
    )
    assert manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=5)

    payload = json.loads(manager.jobs_path.read_text(encoding="utf-8"))
    assert payload["schema"] == JOBS_SCHEMA
    row = next(j for j in payload["jobs"] if j["job_id"] == decision.job.job_id)
    assert row["state"] == STATE_READY
    assert row["attempts"] == 1

    raw_events: list[str] = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        raw_events = manager.events_path.read_text(encoding="utf-8").splitlines()
        if any('"scan_ready"' in line for line in raw_events):
            break
        time.sleep(0.01)  # ledger appends are async-by-design (best effort)
    events = [json.loads(line) for line in raw_events]
    kinds = [event["event"] for event in events]
    assert kinds[0] == "scan_queued"  # ledger order: queued before terminal
    ready_event = events[kinds.index("scan_ready")]
    assert ready_event["job_id"] == decision.job.job_id
    assert ready_event["line"].startswith("lens ")


def test_stale_live_jobs_fail_honestly_on_restart(tmp_path: Path) -> None:
    """A crash leaves queued/scanning rows behind; restart marks them failed."""
    data_dir = tmp_path / "plugin-data" / "lens"
    data_dir.mkdir(parents=True, exist_ok=True)
    stale = {
        "schema": JOBS_SCHEMA,
        "jobs": [
            {
                "job_id": "j-stale-1",
                "name": "ghost",
                "bundle_hash": "sha256:" + "aa" * 32,
                "cache_key": "sha256:" + "aa" * 32,
                "target": str(tmp_path),
                "state": STATE_QUEUED,
                "error": None,
                "attempts": 0,
                "coalesced": 0,
                "fetched": False,
                "created": 1.0,
                "updated": 1.0,
            },
            {
                "job_id": "j-done",
                "name": "done",
                "bundle_hash": "sha256:" + "bb" * 32,
                "cache_key": "sha256:" + "bb" * 32,
                "target": str(tmp_path),
                "state": STATE_READY,
                "error": None,
                "attempts": 1,
                "coalesced": 0,
                "fetched": False,
                "created": 2.0,
                "updated": 2.0,
            },
        ],
    }
    (data_dir / "jobs.json").write_text(json.dumps(stale), encoding="utf-8")

    manager = _manager(tmp_path)
    ghost = manager.snapshot_job("j-stale-1")
    assert ghost is not None and ghost.state == STATE_FAILED
    assert "restarted" in (ghost.error or "")
    done = manager.snapshot_job("j-done")
    assert done is not None and done.state == STATE_READY  # terminal rows untouched
    events = manager.events_path.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line)["event"] == "scan_failed" for line in events)


# ---------------------------------------------------------------------------
# Shutdown + atexit law
# ---------------------------------------------------------------------------


def test_shutdown_joins_cleanly_and_atexit_never_raises(tmp_path: Path) -> None:
    gate = threading.Event()

    def runner(job: JobRecord) -> None:
        gate.wait(5)

    manager = JobManager(
        plugin_data_dir=tmp_path / "pd",
        runner=runner,
        register_exit=True,
    )
    decision = manager.enqueue(name="busy", target=tmp_path, bundle_hash="sha256:" + "cc" * 32)
    manager.wait_for_state(decision.job.job_id, STATE_SCANNING, timeout=5)

    exited = manager.shutdown(timeout=0.05)  # busy worker cannot exit that fast
    assert exited is False
    assert manager.worker_thread.is_alive()

    gate.set()
    assert manager.shutdown(timeout=5) is True
    assert not manager.worker_thread.is_alive()
    assert manager.shutdown() is True  # idempotent no-op
    manager._atexit_join()  # direct call must never raise either


def test_shutdown_before_any_enqueue_is_immediate(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    assert manager.shutdown() is True
    assert manager.worker_thread is None


def test_enqueue_after_shutdown_refuses_new_work(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manager.shutdown()
    decision = manager.enqueue(name="late", target=tmp_path, bundle_hash="sha256:" + "dd" * 32)
    assert manager.worker_thread is None
    assert decision.job.state == STATE_QUEUED  # persisted honestly, never runs silently
    time.sleep(0.05)
    assert manager.snapshot_job(decision.job.job_id).state == STATE_QUEUED


# ---------------------------------------------------------------------------
# Cache thread-safety audit under the worker
# ---------------------------------------------------------------------------


def test_fast_path_cache_survives_worker_plus_hammer_threads(tmp_path: Path) -> None:
    """One lock suffices: concurrent puts from the worker + reader hammering."""
    cache = FastPathCache(max_entries=8)
    stop = threading.Event()
    errors: list[BaseException] = []

    def runner(job: JobRecord) -> None:
        cache.put(_entry_for(job.bundle_hash, job.name))

    def hammer() -> None:
        index = 0
        try:
            while not stop.is_set():
                key = f"sha256:{index:064x}"
                cache.put(_entry_for(key, "hammer"))
                cache.get(key)
                cache.latest_by_name("hammer")
                cache.stats()
                cache.invalidate(key)
                index += 1
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    manager = _manager(tmp_path, runner=runner)
    threads = [threading.Thread(target=hammer) for _ in range(4)]
    for thread in threads:
        thread.start()
    try:
        for seq in range(20):
            decision = manager.enqueue(
                name=f"h{seq}",
                target=tmp_path,
                bundle_hash=f"sha256:{seq:064x}"[:-8].__add__(f"{seq:08x}"),
                context=ScanContext(cache=cache),
            )
            assert manager.wait_for_state(
                decision.job.job_id, {STATE_READY, STATE_FAILED}, timeout=10
            )
    finally:
        stop.set()
        for thread in threads:
            thread.join(10)
    assert not errors, errors
    assert len(cache) <= 8


# ---------------------------------------------------------------------------
# Pull accounting: reports-ready counting + banner
# ---------------------------------------------------------------------------


def test_reports_ready_counting_and_fetch_clearing(tmp_path: Path) -> None:
    cache = FastPathCache()

    def runner(job: JobRecord) -> None:
        job.context.cache.put(_entry_for(job.bundle_hash, job.name))

    manager = _manager(tmp_path, runner=runner)
    assert manager.reports_ready() == []
    assert manager.banner_line() is None

    decision = manager.enqueue(
        name="pulled",
        target=tmp_path,
        bundle_hash="sha256:" + "ee" * 32,
        context=ScanContext(cache=cache),
    )
    manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=5)

    ready = manager.reports_ready()
    assert [job.name for job in ready] == ["pulled"]
    banner = manager.banner_line()
    assert banner is not None and banner.startswith("1 report ready: pulled (scanned ")
    assert manager.mark_fetched("pulled") == 1
    assert manager.reports_ready() == []
    assert manager.banner_line() is None
    assert manager.mark_fetched("pulled") == 0  # already fetched


def test_banner_lists_multiple_names(tmp_path: Path) -> None:
    cache = FastPathCache()

    def runner(job: JobRecord) -> None:
        job.context.cache.put(_entry_for(job.bundle_hash, job.name))

    manager = _manager(tmp_path, runner=runner)
    for seq in range(3):
        decision = manager.enqueue(
            name=f"skill-{seq}",
            target=tmp_path,
            bundle_hash=f"sha256:{seq:064x}",
            context=ScanContext(cache=cache),
        )
        assert manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=5)
    banner = manager.banner_line()
    assert banner == "3 reports ready: skill-0, skill-1, skill-2"


# ---------------------------------------------------------------------------
# Slash integration (queue-first scan verb)
# ---------------------------------------------------------------------------


def _handler(tmp_path: Path, cache: FastPathCache, manager: JobManager):
    ctx = FakePluginContext(data_root=tmp_path / "home")
    from skill_lens.slash import make_handler

    return make_handler(PluginContextView(ctx), cache, jobs=manager), ctx


def test_slash_scan_cold_queues_then_report_pulls(tmp_path: Path) -> None:
    import time as _time

    from skill_lens.jobs import pipeline_runner
    from skill_lens.slash import make_handler

    bundle = _write_bundle(tmp_path / "tree")
    ctx = FakePluginContext(data_root=tmp_path / "home")
    cache = FastPathCache()
    manager = JobManager(
        plugin_data_dir=tmp_path / "jobs", runner=pipeline_runner, register_exit=False
    )
    handler = make_handler(PluginContextView(ctx), cache, jobs=manager)

    answer = handler(f'scan "{bundle}"')
    assert answer.startswith("lens scan queued:"), answer
    assert "/lens report" in answer
    assert "· sha256 " in answer

    compact = None
    for _ in range(300):
        compact = handler(f'report "{bundle.name}"')
        if not compact.startswith(("lens scan queued:", "no lens report")):
            break
        _time.sleep(0.02)
    assert compact is not None and "findings:" in compact, compact

    # Same bytes again ⇒ inline cache hit (<200 ms path unchanged): the
    # cached chat-compact fence answers without any queued line.
    hit = handler(f'scan "{bundle}"')
    assert not hit.startswith("lens scan queued:"), hit
    assert hit.startswith("```"), hit


def test_slash_scan_second_call_while_running_is_skip(tmp_path: Path) -> None:
    gate = threading.Event()

    def runner(job: JobRecord) -> None:
        gate.wait(5)

    bundle = _write_bundle(tmp_path / "tree")
    handler, _ctx = _handler(tmp_path, FastPathCache(), _manager(tmp_path, runner=runner))
    first = handler(f'scan "{bundle}"')
    assert first.startswith("lens scan queued:")
    second = handler(f'scan "{bundle}"')
    assert second.startswith("lens skip "), second
    gate.set()


def test_slash_report_surfaces_failed_job_reason(tmp_path: Path) -> None:
    def runner(job: JobRecord) -> None:
        raise ValueError("unreadable target: scripts/ (permission denied)")

    bundle = _write_bundle(tmp_path / "tree")
    handler, _ctx = _handler(tmp_path, FastPathCache(), _manager(tmp_path, runner=runner))
    assert handler(f'scan "{bundle}"').startswith("lens scan queued:")
    line = None
    for _ in range(200):
        line = handler(f'report "{bundle.name}"')
        if line.startswith("lens fail "):
            break
        time.sleep(0.01)
    assert line is not None
    assert line.startswith("lens fail "), line
    assert "unreadable target" in line and "/lens doctor" in line
    assert "\n" not in line.strip()


def test_slash_banner_prepends_until_fetched(tmp_path: Path) -> None:
    cache = FastPathCache()

    def runner(job: JobRecord) -> None:
        job.context.cache.put(_entry_for(job.bundle_hash, job.name))

    bundle_a = _write_bundle(tmp_path / "tree-a", "skill-a")
    bundle_b = _write_bundle(tmp_path / "tree-b", "skill-b")
    manager = _manager(tmp_path, runner=runner)
    handler, _ctx = _handler(tmp_path, cache, manager)

    first = handler(f'scan "{bundle_a}"')
    assert manager.wait_for_state(first and "", set(), timeout=0) is None  # noop guard
    # Wait for completion via the manager API using the single enqueued job.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not manager.reports_ready():
        time.sleep(0.01)
    assert manager.reports_ready(), "runner must have completed"

    other = handler(f'scan "{bundle_b}"')
    assert other.splitlines()[0].startswith(("1 report ready: skill-a", "2 reports ready:")), other

    # The banner persists until each advertised report is FETCHED.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not any(
        job.name == "skill-b" for job in manager.reports_ready()
    ):
        time.sleep(0.01)  # wait for SKILL-B specifically (skill-a already counted)
    fetched = handler('report "skill-a"')
    assert not fetched.startswith("1 report ready")
    assert [job.name for job in manager.reports_ready()] == ["skill-b"]
    handler('report "skill-b"')
    assert manager.reports_ready() == []

    after = handler(f'scan "{bundle_a}"')  # cache hit path — no banner left
    assert not after.startswith("1 report ready"), after


# ---------------------------------------------------------------------------
# Determinism-law guardrails
# ---------------------------------------------------------------------------


def test_job_records_carry_no_context_into_persistence(tmp_path: Path) -> None:
    """ScanContext (baselines, cache ref) stays in memory — never serialized."""
    record = JobRecord(
        job_id="j-x",
        name="n",
        bundle_hash="sha256:" + "ff" * 32,
        cache_key="sha256:" + "ff" * 32,
        target="/tmp/x",
        context=ScanContext(baseline_records=("secret",), cache=None),
    )
    payload = record.to_json()
    assert "context" not in payload
    restored = JobRecord.from_json(payload)
    assert restored.context is None
