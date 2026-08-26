"""Drift watcher tests — SPEC §11.8 + PLAN §0 Watcher row + Phase 4 exit 3.

Pinned behaviors:

- Startup sweep ALWAYS runs; first contact SILENTLY establishes the baseline
  (pre-existing skills are never reported as new).
- While-away drift replays EXACTLY ONCE across simulated restarts (fresh
  DriftWatcher instance, same watch-state.json): the ``replayed`` marker +
  persisted hashes make a restart unable to re-notify.
- Rename = delete+create pair; delete journals without enqueueing.
- Create/rename/delete churn storms converge with NO duplicate scans
  (500 ms debounce collapse + hash-keyed coalescing against the lifecycle
  fast path via ``triggers.recently_covered``).
- Opt-in poller: daemon thread, adaptive backoff ladder (pure function),
  joins with timeout on shutdown, poll-only fallback when the inotify
  accelerator is unavailable.
- Advisor law: nothing raises into the host under hostile inputs.

Plugin wiring tests follow the dual-import law: seams are reached through
``plugin_module.skill_lens.*``, never top-level imports.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from skill_lens.jobs import JobManager
from skill_lens.watcher import (
    DEBOUNCE_SECONDS,
    POLL_MAX_SECONDS,
    POLL_MIN_SECONDS,
    DriftWatcher,
    InotifyAccelerator,
    advance_backoff,
    configured_poll_interval,
    fingerprint_bundle,
    load_state,
    save_state,
)

SKILL_MD = (
    "---\nname: {name}\ndescription: Supercharges synergy quietly.\n"
    "disable-model-invocation: true\n---\n\nbody\n"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_home(tmp_path: Path, *names: str) -> Path:
    """Scratch Hermes home with categorized skill bundles."""
    home = tmp_path / "hermes-home"
    for name in names:
        bundle = home / "skills" / "tools" / name
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "SKILL.md").write_text(SKILL_MD.format(name=name), encoding="utf-8")
    return home


class _RecordingJobs:
    """Fake JobManager: records enqueue calls, never runs engines."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.explode = False
        self.lock = threading.Lock()

    def enqueue(self, *, name: str, target, bundle_hash: str, cache_key=None, context=None):
        if self.explode:
            raise RuntimeError("hostile queue")
        with self.lock:
            self.calls.append(
                {
                    "name": name,
                    "target": target,
                    "bundle_hash": bundle_hash,
                    "cache_key": cache_key,
                }
            )
        return ("decision", name, bundle_hash)


def _watcher(
    tmp_path: Path,
    *,
    home: Path | None = None,
    jobs: Any | None = None,
    **kwargs: Any,
) -> DriftWatcher:
    kwargs.setdefault("register_exit", False)
    return DriftWatcher(
        home=home if home is not None else tmp_path / "hermes-home",
        data_dir=tmp_path / "plugin-data" / "lens",
        jobs=jobs,
        **kwargs,
    )


@pytest.fixture(autouse=True)
def _clean_triggers_ledger():
    """Isolate the lifecycle coverage ledger around each test."""
    from skill_lens.triggers import reset_recent_hashes

    reset_recent_hashes()
    yield
    reset_recent_hashes()


# ---------------------------------------------------------------------------
# Baseline establishment + replay-once across restarts
# ---------------------------------------------------------------------------


class TestSweepAndReplay:
    def test_first_sweep_establishes_baseline_silently(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha", "beta")
        jobs = _RecordingJobs()
        w = _watcher(tmp_path, home=home, jobs=jobs)
        result = w.safe_sweep()
        assert result.established_baseline is True
        assert result.tracked == 2
        assert [g for g in result.gaps] == []
        assert jobs.calls == []  # pre-existing skills NEVER scanned as "new"
        assert w.state_path.exists()

    def test_drift_replays_exactly_once_across_restart(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha", "ghost")
        jobs = _RecordingJobs()
        # Instance A (process 1): establish the baseline, then "exit".
        watcher_a = _watcher(tmp_path, home=home, jobs=jobs)
        watcher_a.safe_sweep()
        # While away: out-of-band edit (git pull / cp -r) + a removal.
        (home / "skills/tools/alpha/SKILL.md").write_text(
            SKILL_MD.format(name="alpha") + "tampered\n", encoding="utf-8"
        )
        import shutil

        shutil.rmtree(home / "skills/tools/ghost")

        # Instance B (simulated restart, SAME state file): replays each gap.
        watcher_b = _watcher(tmp_path, home=home, jobs=jobs)
        result_b = watcher_b.safe_sweep()
        kinds_b = sorted(g.kind for g in result_b.gaps)
        assert kinds_b == ["changed", "removed"]
        assert len(jobs.calls) == 1  # only the surviving bundle is scannable
        assert result_b.lines[0].startswith("lens watch: while away — 2 changes")

        # Instance C (another restart): NOTHING left to notify.
        watcher_c = _watcher(tmp_path, home=home, jobs=jobs)
        result_c = watcher_c.safe_sweep()
        assert result_c.gaps == ()
        assert result_c.lines == ()
        assert len(jobs.calls) == 1  # no second scan ever

    def test_replayed_marker_blocks_replay_even_when_hash_persist_fails(self, tmp_path: Path):
        """Crafted state: gap journaled unreplayed + hashes ALREADY current ⇒
        exactly one replay, then silence (the belt to the braces)."""
        home = _make_home(tmp_path, "alpha")
        w = _watcher(tmp_path, home=home, jobs=_RecordingJobs())
        w.safe_sweep()  # baseline on disk
        state = load_state(w.state_path)
        key = next(iter(state["hashes"]))
        state["gaps"].append(
            {
                "key": key,
                "kind": "changed",
                "old": "fp:deadbeefdeadbeef",
                "new": state["hashes"][key],
                "at": time.time(),
                "replayed": False,
            }
        )
        save_state(w.state_path, state)
        first = _watcher(tmp_path, home=home, jobs=_RecordingJobs())
        r1 = first.safe_sweep()
        assert len(r1.lines) == 2  # header + one replay line
        assert "CHANGED" in r1.lines[1]
        second = _watcher(tmp_path, home=home, jobs=_RecordingJobs())
        r2 = second.safe_sweep()
        assert r2.lines == () and r2.gaps == ()

    def test_rename_is_delete_plus_create_pair(self, tmp_path: Path):
        home = _make_home(tmp_path, "original")
        jobs = _RecordingJobs()
        w = _watcher(tmp_path, home=home, jobs=jobs)
        w.safe_sweep()
        target = home / "skills/tools/original"
        renamed = home / "skills/tools/renamed"
        target.rename(renamed)
        (renamed / "SKILL.md").write_text(SKILL_MD.format(name="renamed"), encoding="utf-8")
        result = w.sweep()
        kinds = sorted(g.kind for g in result.gaps)
        assert kinds == ["added", "removed"]  # the required delete+create pair
        keys = {g.key.rpartition("/")[2]: g.kind for g in result.gaps}
        assert keys == {"original": "removed", "renamed": "added"}
        # Only the surviving bundle is scannable → one enqueue.
        assert len(jobs.calls) == 1
        assert jobs.calls[0]["name"] == "renamed"

    def test_removed_gap_journalled_without_enqueue(self, tmp_path: Path):
        home = _make_home(tmp_path, "doomed")
        jobs = _RecordingJobs()
        w = _watcher(tmp_path, home=home, jobs=jobs)
        w.safe_sweep()
        import shutil

        shutil.rmtree(home / "skills/tools/doomed")
        result = w.sweep()
        assert [g.kind for g in result.gaps] == ["removed"]
        assert jobs.calls == []
        line = result.lines[1]
        assert line.startswith("lens skip doomed · removed while away")

    def test_corrupt_state_rebuilds_without_crashing(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha")
        w = _watcher(tmp_path, home=home)
        w.state_path.parent.mkdir(parents=True, exist_ok=True)
        w.state_path.write_text("{not json!!", encoding="utf-8")
        result = w.safe_sweep()
        assert result.established_baseline is True  # honest rebuild
        assert load_state(w.state_path)["schema"] == "lens.watch/1"


# ---------------------------------------------------------------------------
# Churn storm convergence + no duplicate scans (PLAN exit criterion)
# ---------------------------------------------------------------------------


class TestChurnStorm:
    def test_storm_converges_no_duplicate_scans(self, tmp_path: Path):
        home = _make_home(tmp_path, "storm-target")
        jobs = _RecordingJobs()
        w = _watcher(tmp_path, home=home, jobs=jobs, debounce_seconds=0.02)
        w.safe_sweep()
        bundle = home / "skills/tools/storm-target"
        # Ten rapid mutations of ONE bundle inside the debounce window…
        for i in range(10):
            (bundle / "SKILL.md").write_text(
                SKILL_MD.format(name="storm-target") + f"rev{i}\n", encoding="utf-8"
            )
            # …plus create/delete noise that vanishes before settling.
            ghost = home / "skills/tools/ghost-x"
            ghost.mkdir(exist_ok=True)
            (ghost / "SKILL.md").write_text(SKILL_MD.format(name="ghost-x"), encoding="utf-8")
        import shutil

        shutil.rmtree(home / "skills/tools/ghost-x")
        result = w._cycle_once()
        assert len(result) == 1  # only the surviving drifted bundle
        assert result[0].kind == "changed"
        assert len(jobs.calls) == 1  # hash coalescing proof: exactly ONE scan
        # Convergence: further cycles see an unchanged tree.
        assert w._cycle_once() == ()
        assert w._cycle_once() == ()

    def test_two_cycles_same_hash_coalesce_on_live_job(self, tmp_path: Path):
        """Real JobManager: two watcher cycles for the same content fold onto
        one live job — the §11.6 double-scan guarantee at queue level."""
        home = _make_home(tmp_path, "alpha")
        release = threading.Event()
        first_running = threading.Event()

        def blocker(job: Any) -> None:
            first_running.set()
            release.wait(timeout=10)  # hold the job LIVE across both cycles

        manager = JobManager(plugin_data_dir=tmp_path / "pd", runner=blocker, register_exit=False)
        w = _watcher(tmp_path, home=home, jobs=manager, debounce_seconds=0.0)
        w.safe_sweep()
        (home / "skills/tools/alpha/SKILL.md").write_text(
            SKILL_MD.format(name="alpha") + "v2\n", encoding="utf-8"
        )
        assert w._cycle_once()
        assert first_running.wait(timeout=5.0), "worker never picked up the scan"
        # Same bytes re-detected against a stale baseline (simulates racing lanes).
        with w._lock:
            w._state["hashes"]["tools/alpha"] = "fp:stale"
        decision_lines = w._cycle_once()
        assert decision_lines  # surfaced again...
        snapshot = manager.latest_job_for_name("alpha")
        assert snapshot is not None and snapshot.coalesced >= 1  # …but ONE job
        release.set()
        manager.shutdown(timeout=2.0)

    def test_lifecycle_coverage_dedupes_against_fast_path(self, tmp_path: Path):
        from skill_lens.cache import key_for_ir
        from skill_lens.ingest import DEFAULT_CEILINGS, load_bundle
        from skill_lens.triggers import note_handled_hash

        home = _make_home(tmp_path, "covered")
        jobs = _RecordingJobs()
        view_stub = None
        w = _watcher(tmp_path, home=home, jobs=jobs, debounce_seconds=0.0, view=view_stub)
        w.safe_sweep()
        (home / "skills/tools/covered/SKILL.md").write_text(
            SKILL_MD.format(name="covered") + "edited-by-agent\n", encoding="utf-8"
        )
        # The lifecycle lane fires FIRST (post_tool_call beat) and covers the hash:
        ir = load_bundle(home / "skills/tools/covered", ceilings=DEFAULT_CEILINGS)
        note_handled_hash(key_for_ir(ir))
        result = w._cycle_once()
        assert len(result) == 1
        assert jobs.calls == []  # NO duplicate scan enqueued
        stats = w.stats_snapshot()
        assert stats["skipped_covered_by_lifecycle"] == 1
        line = result[0].line or ""
        assert line.startswith("lens skip covered · scan already in progress")


# ---------------------------------------------------------------------------
# Fingerprint semantics
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_deterministic_and_content_sensitive(self, tmp_path: Path):
        a = _make_home(tmp_path, "x") / "skills/tools/x"
        fp1 = fingerprint_bundle(a)
        fp2 = fingerprint_bundle(a)
        assert fp1 == fp2 and fp1.startswith("fp:")
        (a / "extra.txt").write_text("payload", encoding="utf-8")
        assert fingerprint_bundle(a) != fp1

    def test_vanished_bundle_is_none(self, tmp_path: Path):
        missing = tmp_path / "nowhere"
        assert fingerprint_bundle(missing) is None

    def test_unreadable_entry_degrades_not_flaps(self, tmp_path: Path):
        bundle = _make_home(tmp_path, "y") / "skills/tools/y"
        (bundle / "sub").mkdir()
        (bundle / "sub" / "s.txt").write_text("ok", encoding="utf-8")
        good = fingerprint_bundle(bundle)
        # Replace file with an unreadable-to-open directory entry (OSError lane).
        (bundle / "sub" / "s.txt").unlink()
        (bundle / "sub" / "s.txt").mkdir()  # open() on a dir raises OSError
        degraded = fingerprint_bundle(bundle)
        again = fingerprint_bundle(bundle)
        assert degraded == again  # stable across calls — no flapping
        assert degraded != good


# ---------------------------------------------------------------------------
# Backoff ladder + debounce constants
# ---------------------------------------------------------------------------


class TestBackoff:
    def test_ladder_bounds(self):
        interval = POLL_MIN_SECONDS
        seen_max = interval
        for _ in range(40):
            interval = advance_backoff(interval, activity=False)
            seen_max = max(seen_max, interval)
        assert seen_max == POLL_MAX_SECONDS  # capped at 30 s
        assert advance_backoff(POLL_MAX_SECONDS, activity=True) == POLL_MIN_SECONDS
        assert advance_backoff(3.0, activity=False) == pytest.approx(4.5)

    def test_custom_base_respected(self):
        assert advance_backoff(9.9, activity=True, base=0.05) == pytest.approx(0.05)
        assert advance_backoff(0.05, activity=False, base=0.05) == pytest.approx(0.075)

    def test_debounce_constant_normative(self):
        assert DEBOUNCE_SECONDS == 0.5


# ---------------------------------------------------------------------------
# Inotify accelerator + poll-only fallback
# ---------------------------------------------------------------------------


class TestAccelerator:
    def test_create_on_missing_root_fails_soft(self, tmp_path: Path):
        accel = InotifyAccelerator.create(tmp_path / "nope")
        if accel is not None:  # exotic platforms may succeed; still must be safe
            accel.close()
            return
        # None is the expected soft failure — nothing raised.

    @pytest.mark.skipif(not hasattr(__import__("os"), "uname"), reason="non-posix")
    def test_events_flip_dirty_and_close_is_idempotent(self, tmp_path: Path):
        root = _make_home(tmp_path, "watched")
        accel = InotifyAccelerator.create(root)
        if accel is None:
            pytest.skip("inotify unavailable in this environment")
        try:
            assert accel.available
            assert accel.drain(0.05) is False  # quiet
            (root / "skills/tools/watched/SKILL.md").write_text(
                SKILL_MD.format(name="watched") + "touch\n", encoding="utf-8"
            )
            deadline = time.monotonic() + 5.0
            dirty = False
            while time.monotonic() < deadline:
                if accel.drain(0.25):
                    dirty = True
                    break
            assert dirty, "inotify did not signal the write within 5s"
        finally:
            accel.close()
            accel.close()  # idempotent
        assert accel.available is False

    def test_poll_only_fallback_converges(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha")
        jobs = _RecordingJobs()
        w = _watcher(tmp_path, home=home, jobs=jobs, use_inotify=False, debounce_seconds=0.0)
        assert w.inotify_active is False
        w.safe_sweep()
        (home / "skills/tools/alpha/SKILL.md").write_text(
            SKILL_MD.format(name="alpha") + "v2\n", encoding="utf-8"
        )
        assert len(w._cycle_once()) == 1
        assert len(jobs.calls) == 1


# ---------------------------------------------------------------------------
# Thread discipline (PLAN Phase 4 exit: daemon, joins with timeout)
# ---------------------------------------------------------------------------


class TestThreadDiscipline:
    def test_poller_is_daemon_and_shutdown_joins(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha")
        w = _watcher(tmp_path, home=home, base_interval=0.05, debounce_seconds=0.01)
        assert w.start_polling() is True
        thread = w._thread
        assert thread is not None and thread.daemon is True
        assert w.polling_active is True
        assert w.start_polling() is False  # idempotent
        deadline = time.monotonic() + 5.0
        joined = w.shutdown(timeout=2.0)
        assert joined is True
        assert time.monotonic() <= deadline + 2.5  # bounded shutdown
        assert w.polling_active is False
        assert not thread.is_alive()

    def test_real_thread_detects_churn_end_to_end(self, tmp_path: Path):
        home = _make_home(tmp_path, "live")
        jobs = _RecordingJobs()
        w = _watcher(
            tmp_path,
            home=home,
            jobs=jobs,
            base_interval=0.05,
            debounce_seconds=0.02,
            use_inotify=False,  # deterministic timing on every platform
        )
        w.safe_sweep()
        w.start_polling()
        try:
            (home / "skills/tools/live/SKILL.md").write_text(
                SKILL_MD.format(name="live") + "hot-edit\n", encoding="utf-8"
            )
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not jobs.calls:
                time.sleep(0.05)
            assert len(jobs.calls) == 1, "poller did not converge on the churn"
        finally:
            w.shutdown(timeout=2.0)

    def test_loop_survives_snapshot_crash(self, tmp_path: Path, monkeypatch):
        home = _make_home(tmp_path, "alpha")
        w = _watcher(tmp_path, home=home, base_interval=0.03, debounce_seconds=0.0)
        calls = {"n": 0}
        original = w._cycle_once

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient apocalypse")
            return original()

        monkeypatch.setattr(w, "_cycle_once", flaky)
        w.start_polling()
        time.sleep(0.25)  # ≥ several ticks: crash tick + recovery tick
        w.shutdown(timeout=2.0)
        assert calls["n"] >= 2 and w.stats_snapshot()["errors"] >= 1
        assert not w.polling_active  # loop survived AND stopped cleanly


# ---------------------------------------------------------------------------
# Hostile-input safety (advisor law)
# ---------------------------------------------------------------------------


class TestNeverRaises:
    def test_missing_home_sweeps_empty(self, tmp_path: Path):
        w = _watcher(tmp_path, home=tmp_path / "void")
        result = w.safe_sweep()
        assert result.established_baseline is True and result.tracked == 0

    def test_hostile_jobs_queue_degrades_to_interim_line(self, tmp_path: Path):
        home = _make_home(tmp_path, "alpha")
        jobs = _RecordingJobs()
        jobs.explode = True
        w = _watcher(tmp_path, home=home, jobs=jobs, debounce_seconds=0.0)
        w.safe_sweep()
        (home / "skills/tools/alpha/SKILL.md").write_text(
            SKILL_MD.format(name="alpha") + "v2\n", encoding="utf-8"
        )
        gaps = w._cycle_once()  # must not raise despite exploding enqueue
        assert len(gaps) == 1
        assert gaps[0].line is not None and gaps[0].line.startswith("lens scan queued:")

    def test_hostile_view_config_degrades_to_off(self):
        class Boom:
            def get_config(self, *_a, **_k):
                raise RuntimeError("hostile host")

        assert configured_poll_interval(Boom()) is None
        assert configured_poll_interval(None) is None

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(2, 2.0), (0.5, 0.5), ("3", 3.0), (0, None), (-1, None), (True, None), (False, None)],
    )
    def test_watch_poll_setting_shapes(self, raw, expected):
        class Ctx:
            def get_config(self, _key, default=None):
                return raw

        got = configured_poll_interval(Ctx())
        assert got == expected


# ---------------------------------------------------------------------------
# Plugin wiring (dual-import law: everything via plugin_module)
# ---------------------------------------------------------------------------


MINIMAL_HOME_FILES = ("demo",)


@dataclass
class WiredSeams:
    """Instance-bound plugin seams for the wiring tests (dual-import law)."""

    home: Path
    ctx: Any
    watcher: Any
    slash: Any
    triggers: Any
    bootstrap: Any


@pytest.fixture
def wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plugin_module: Any) -> Any:
    """Registered plugin over a scratch home; exposes instance-bound seams."""
    import importlib

    home = _make_home(tmp_path, *MINIMAL_HOME_FILES)
    monkeypatch.setenv("HERMES_HOME", str(home))
    from tests.conftest import FakePluginContext

    tl = getattr(plugin_module, "skill_lens", None)
    if tl is None:
        tl = importlib.import_module(f"{plugin_module.__name__}.skill_lens")
    prefix = tl.__name__

    def sub(name: str) -> Any:
        mod = getattr(tl, name, None)
        if mod is not None:
            return mod
        return importlib.import_module(f"{prefix}.{name}")

    ctx = FakePluginContext(data_root=tmp_path / "data")
    watcher_mod = sub("watcher")
    slash_mod = sub("slash")
    triggers_mod = sub("triggers")
    bootstrap_mod = sub("bootstrap")
    watcher_mod.reset_shared_watcher()
    slash_mod.reset_shared_cache()
    slash_mod.reset_shared_jobs()
    triggers_mod.reset_recent_hashes()
    bootstrap_mod.reset_context()
    plugin_module.register(ctx)
    yield WiredSeams(
        home=home,
        ctx=ctx,
        watcher=watcher_mod,
        slash=slash_mod,
        triggers=triggers_mod,
        bootstrap=bootstrap_mod,
    )
    watcher_mod.reset_shared_watcher()
    slash_mod.reset_shared_jobs()
    slash_mod.reset_shared_cache()
    triggers_mod.reset_recent_hashes()
    bootstrap_mod.reset_context()


class TestPluginWiring:
    def test_register_runs_startup_sweep_and_keeps_hooks_observer_only(self, wired: WiredSeams):
        assert wired.watcher.shared_watcher(wired.bootstrap.get_context()) is not None
        # State lives under the FakePluginState data dir, not HERMES_HOME;
        # verify via the watcher instance itself instead.
        inst = wired.watcher.shared_watcher(wired.bootstrap.get_context())
        assert inst.state_path.exists(), "startup sweep must persist watch-state.json"
        assert inst.status_dict()["tracked"] == len(MINIMAL_HOME_FILES)
        # Advisor law unchanged by Phase 4 bullet 3:
        names = wired.ctx.registered_hook_names
        assert names == ["on_skill_lifecycle", "post_tool_call", "transform_tool_result"]
        assert "pre_tool_call" not in names

    def test_watch_status_start_stop_via_slash(self, wired: WiredSeams):
        handler = wired.ctx.commands["lens"]["handler"]
        status = handler("watch")
        assert "polling off" in status and "tracking 1 skills" in status
        started = handler("watch start")
        assert "polling started" in started
        inst = wired.watcher.shared_watcher(wired.bootstrap.get_context())
        assert inst.polling_active is True
        assert load_state(inst.state_path).get("poll_enabled") is True
        stopped = handler("watch stop")
        assert "polling stopped" in stopped
        assert inst.polling_active is False
        assert load_state(inst.state_path).get("poll_enabled") is False

    def test_explicit_stop_wins_over_setting_on_next_register(
        self, wired: WiredSeams, plugin_module: Any
    ):
        handler = wired.ctx.commands["lens"]["handler"]
        handler("watch stop")
        # Fresh registration (simulated restart) with watch.poll present:
        wired.ctx.set_config("watch.poll", 2)
        wired.bootstrap.register_plugin(wired.ctx)
        inst = wired.watcher.shared_watcher(wired.bootstrap.get_context())
        assert inst.polling_active is False  # explicit opt-out persists

    def test_watch_poll_setting_autostarts_after_restart(self, wired: WiredSeams):
        wired.ctx.set_config("watch.poll", 2)
        wired.bootstrap.register_plugin(wired.ctx)
        inst = wired.watcher.shared_watcher(wired.bootstrap.get_context())
        try:
            assert inst.polling_active is True
        finally:
            inst.stop_polling(timeout=2.0)

    def test_watch_unknown_subcommand_gets_usage(self, wired: WiredSeams):
        handler = wired.ctx.commands["lens"]["handler"]
        out = handler("watch frobnicate")
        assert "usage" in out.lower()

    def test_state_file_shape_is_schema_tagged(self, wired: WiredSeams):
        inst = wired.watcher.shared_watcher(wired.bootstrap.get_context())
        raw = json.loads(inst.state_path.read_text(encoding="utf-8"))
        assert raw["schema"] == "lens.watch/1"
        assert isinstance(raw["hashes"], dict) and isinstance(raw["gaps"], list)


# ---------------------------------------------------------------------------
# Terminal-state sanity for the real worker path used above
# ---------------------------------------------------------------------------


def test_job_manager_runner_placeholder_reaches_ready(tmp_path: Path):
    """Guard the noop-runner assumption used in coalescing test setup."""
    manager = JobManager(
        plugin_data_dir=tmp_path / "pd2", runner=lambda job: None, register_exit=False
    )
    from datetime import date

    from skill_lens.jobs import STATE_READY, ScanContext

    decision = manager.enqueue(
        name="x",
        target=tmp_path,
        bundle_hash="sha256:" + "aa" * 32,
        context=ScanContext(report_date=date.today(), plugin_data_dir=tmp_path),
    )
    record = manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=2.0)
    assert record is not None
    manager.shutdown(timeout=1.0)


def test_setup_parser_accepts_watch_verb() -> None:
    """CLI lane parity: `hermes lens watch [status|start N|stop]` parses and
    reconstructs the same argv tokens the slash dispatch consumes (D-052)."""
    import argparse

    from skill_lens.cli import _tokens_for, setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)

    ns = parser.parse_args(["watch"])
    assert ns.lens_verb == "watch"
    assert ns.action == "status"
    assert _tokens_for("watch", ns) == ["watch", "status"]

    ns = parser.parse_args(["watch", "start", "5"])
    assert _tokens_for("watch", ns) == ["watch", "start", "5"]

    ns = parser.parse_args(["watch", "stop", "--plain"])
    assert _tokens_for("watch", ns) == ["watch", "stop", "--plain"]
