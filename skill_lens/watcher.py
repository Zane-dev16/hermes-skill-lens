"""Drift watcher — watch without a daemon (SPEC §11.8, PLAN §0 Watcher row).

The install seam fires no plugin hooks and skills can drift out-of-band
(manual ``cp -r``, ``git pull`` into ``~/.hermes/skills/**``) while no
process is loaded, so Skill Lens owns a filesystem guarantee layer:

- **Startup sweep ALWAYS runs** on register (:func:`register_watcher`, wired
  from :mod:`skill_lens.bootstrap`): a persisted-hash comparison against
  ``<plugin-data>/watch-state.json`` catches while-away drift for everyone,
  even users who never enable continuous polling. The FIRST sweep on an
  empty state file silently ESTABLISHES the baseline — pre-existing skills
  are never reported as "new". Subsequent sweeps replay each detected gap
  exactly ONCE and mark it ``replayed`` so a restart does not re-notify;
  hashes persist at the same moment, which is what makes replay-once hold.
- **Continuous hash-polling is OPT-IN**: ``/lens watch start|stop`` or the
  ``watch.poll`` plugin setting (positive seconds). Adaptive backoff runs
  2 s → 30 s (×1.5 per idle cycle, reset on any detected change); raw fs
  activity settles behind a 500 ms debounce before acting, so create/rename/
  delete churn collapses into one settled diff. An inotify accelerator
  (pure ctypes, Linux only — see DECISIONS D-052) wakes the loop early; on
  macOS/Termux/watch-failure the SAME loop degrades to timed polling with
  zero correctness loss, because truth is always the HASH DIFF, never raw
  inode events (docs/hook-and-watch.md §2.2).
- **Hash-keyed coalescing vs the lifecycle lane**: before enqueueing a scan,
  the watcher asks :func:`skill_lens.triggers.recently_covered` whether the
  lifecycle fast path already covered that exact ``bundle_hash`` (or the
  fast-path cache already holds it). Covered bundles emit a ``lens skip``
  status instead of a second scan; everything else flows into the SAME
  jobs queue/coalescing as lifecycle triggers (§11.6 double-scan avoidance).

Thread discipline (advisor law): one daemon thread, dies with the process,
joined with a timeout on shutdown; every public entry point is wrapped so
nothing ever raises into the host. Live deltas log via the ``lens`` logger
from the poller thread; gateway processes accumulate them in watch-state +
events.ndjson for pull — the honest §11.5 limitation, no daemon invented.

Determinism law untouched: this module writes ONLY its own operational
state file and jobs-queue entries (wall-clock lives there by precedent,
like ``jobs.json``). No report/scoring artifact reads anything from here.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("lens")

#: Persisted-state schema tag (mirror of jobs.JOBS_SCHEMA discipline).
WATCH_STATE_SCHEMA = "lens.watch/1"

#: Raw-activity settle window (PLAN Phase 4 bullet 3: "500 ms debounce").
DEBOUNCE_SECONDS = 0.5

#: Adaptive backoff bounds + growth (SPEC §11.8: "2 s → 30 s adaptive").
POLL_MIN_SECONDS = 2.0
POLL_MAX_SECONDS = 30.0
POLL_BACKOFF_FACTOR = 1.5

#: Base interval when neither ``watch.poll`` nor an explicit value is given.
DEFAULT_POLL_INTERVAL_SECONDS = 2.0

#: Gap journal cap inside watch-state.json (oldest dropped first).
MAX_JOURNALED_GAPS = 128

#: Max single accelerator wait — bounds shutdown latency of the poller.
_ACCEL_SLICE_SECONDS = 0.25

#: Fingerprint caps (honest truncation, deterministic per content).
_FP_PER_FILE_BYTES = 8 * 1024 * 1024
_FP_PER_BUNDLE_BYTES = 64 * 1024 * 1024

#: Gap kinds (display vocabulary mirrors the §11.8 sample's CHANGED form).
KIND_CHANGED = "changed"
KIND_ADDED = "added"
KIND_REMOVED = "removed"


# ---------------------------------------------------------------------------
# Cheap deterministic bundle fingerprint (hash-diff truth — NOT the IR hash)
# ---------------------------------------------------------------------------


def fingerprint_bundle(path: Path | str) -> str | None:
    """Cheap stable content fingerprint of one bundle directory.

    sha256 over sorted ``(relpath, size, file-bytes)`` triples — full bytes
    streamed in chunks, capped honestly at :data:`_FP_PER_FILE_BYTES` per
    file and :data:`_FP_PER_BUNDLE_BYTES` per bundle (overflow folded into
    the digest deterministically, so identical content ⇒ identical fp).
    Unreadable entries contribute a stable ``ioerror`` marker instead of
    failing the walk (no flapping). Returns ``None`` only when *path* itself
    is gone — the watcher's "removed" signal. This is an OPERATIONAL drift
    key only; scan/cache identity remains the canonical IR hash.
    """
    root = Path(path)
    try:
        if not root.exists():
            return None
        rows: list[str] = []
        budget = _FP_PER_BUNDLE_BYTES
        overflow = False
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))  # no cycles
            )
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if os.path.islink(full):
                    rows.append(f"{rel}\0link\0-")
                    continue
                try:
                    size = os.path.getsize(full)
                    digest = hashlib.sha256()
                    read = 0
                    with open(full, "rb") as fh:
                        while read < _FP_PER_FILE_BYTES and read < budget:
                            chunk = fh.read(min(65536, _FP_PER_FILE_BYTES - read))
                            if not chunk:
                                break
                            digest.update(chunk)
                            read += len(chunk)
                    budget -= read
                    if size > read or budget < 0:
                        overflow = True
                        rows.append(f"{rel}\0{size}\0trunc@{read}:{digest.hexdigest()[:16]}")
                    else:
                        rows.append(f"{rel}\0{size}\0{digest.hexdigest()}")
                except OSError:
                    rows.append(f"{rel}\0ioerror\0-")
        payload = "\n".join(rows).encode("utf-8", "surrogatepass")
        if overflow:
            payload += b"|overflow"
        return "fp:" + hashlib.sha256(payload).hexdigest()[:32]
    except OSError:
        return None


def snapshot_tree(home: Path | str) -> dict[str, str]:
    """Fingerprint every discovered bundle under ``<home>/skills``.

    Keys are posix paths relative to the skills root (stable identity);
    discovery reuses :func:`skill_lens.ingest.discover_bundles` so scope
    matches every other lens surface (categorized tree + quarantine
    corridor + staged zips). Vanished-mid-walk trees degrade gracefully:
    missing fingerprints are simply absent from the map. Never raises.
    """
    from .ingest import discover_bundles

    home_p = Path(home)
    skills_root = home_p / "skills"
    out: dict[str, str] = {}
    try:
        refs = discover_bundles(home_p)
    except Exception:  # noqa: BLE001 — advisor law: broken tree ⇒ empty snapshot
        logger.debug("watcher snapshot discovery failed", exc_info=True)
        return out
    for ref in refs:
        try:
            rel = ref.path.resolve().relative_to(skills_root.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        fp = fingerprint_bundle(ref.path)
        if fp is not None:
            out[rel] = fp
    return out


# ---------------------------------------------------------------------------
# Watch-gap model + persisted state
# ---------------------------------------------------------------------------


@dataclass
class WatchGap:
    """One detected drift delta (the unit of replay-once semantics)."""

    key: str  # skills-root-relative posix path
    kind: str  # KIND_CHANGED / KIND_ADDED / KIND_REMOVED
    old_fp: str | None
    new_fp: str | None
    at_wall: float  # wall-clock epoch (operational state, like jobs.json)
    replayed: bool = False  # THE marker: surfaced once, never re-notified
    line: str | None = None  # rendered status line once surfaced
    suppressed: bool = False  # baseline-establishment pass never surfaces

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "old": self.old_fp,
            "new": self.new_fp,
            "at": self.at_wall,
            "replayed": self.replayed,
            "suppressed": self.suppressed,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> WatchGap:
        return cls(
            key=str(data.get("key", "")),
            kind=str(data.get("kind", KIND_CHANGED)),
            old_fp=data.get("old"),
            new_fp=data.get("new"),
            at_wall=float(data.get("at") or 0.0),
            replayed=bool(data.get("replayed", False)),
            suppressed=bool(data.get("suppressed", False)),
        )


@dataclass
class SweepResult:
    """What one startup/manual sweep decided (doctor/test introspection)."""

    lines: tuple[str, ...] = ()
    gaps: tuple[WatchGap, ...] = ()
    established_baseline: bool = False
    tracked: int = 0
    errors: int = 0


def load_state(path: Path) -> dict[str, Any]:
    """Load watch-state.json; corrupt/missing degrades to a fresh shape."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": WATCH_STATE_SCHEMA, "hashes": {}, "gaps": []}
    except (OSError, ValueError):
        logger.warning("lens watcher: watch-state.json unreadable; rebuilding baseline")
        return {"schema": WATCH_STATE_SCHEMA, "hashes": {}, "gaps": []}
    if not isinstance(raw, dict):
        return {"schema": WATCH_STATE_SCHEMA, "hashes": {}, "gaps": []}
    raw.setdefault("schema", WATCH_STATE_SCHEMA)
    hashes = raw.get("hashes")
    raw["hashes"] = {str(k): str(v) for k, v in hashes.items()} if isinstance(hashes, dict) else {}
    gaps = raw.get("gaps")
    raw["gaps"] = (
        [WatchGap.from_json(g).to_json() for g in gaps if isinstance(g, dict)]
        if isinstance(gaps, list)
        else []
    )[-MAX_JOURNALED_GAPS:]
    poll = raw.get("poll_enabled", None)
    raw["poll_enabled"] = poll if isinstance(poll, bool) else None
    return raw


def save_state(path: Path, state: dict[str, Any]) -> bool:
    """Atomic tmp+rename persistence; failures log, never raise."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(state, ensure_ascii=True, sort_keys=True, indent=1),
            encoding="utf-8",
        )
        os.replace(tmp, path)
        return True
    except OSError:
        logger.exception("lens watcher: could not persist watch-state.json")
        return False


# ---------------------------------------------------------------------------
# Inotify accelerator — pure ctypes, optional, correctness-neutral
# ---------------------------------------------------------------------------

_IN_CLOSE_WRITE = 0x0008
_IN_MOVED_FROM = 0x0040
_IN_MOVED_TO = 0x0080
_IN_CREATE = 0x0100
_IN_DELETE = 0x0200
_IN_DELETE_SELF = 0x0400
_IN_MOVE_SELF = 0x0800
_IN_IGNORED = 0x8000
_IN_ISDIR = 0x4000_0000
_WATCH_MASK = (
    _IN_CLOSE_WRITE
    | _IN_MOVED_FROM
    | _IN_MOVED_TO
    | _IN_CREATE
    | _IN_DELETE
    | _IN_DELETE_SELF
    | _IN_MOVE_SELF
)
_EVENT_STRUCT = struct_format = "iIII"  # wd, mask, cookie, len

_MAX_WATCHED_DIRS = 512


class InotifyAccelerator:
    """Linux-only early-wake layer over ctypes inotify (no compiled deps).

    Correctness NEVER depends on it: events only flip a dirty flag so the
    poller wakes before its backoff timer; the hash diff remains the sole
    truth. Construction fails soft (non-Linux, fd limits, seccomp) to
    ``None`` via :meth:`create`; the owner then times its waits plainly.
    """

    def __init__(self, fd: int, libc: Any) -> None:
        self._fd = fd
        self._libc = libc
        self._wds: set[int] = set()
        self._lock = threading.Lock()

    @classmethod
    def create(cls, root: Path) -> InotifyAccelerator | None:
        """Build + seed watches under *root*, or None when unavailable."""
        try:
            import ctypes
            import select as _select  # noqa: F401 — capability probe only

            libc = ctypes.CDLL(None, use_errno=True)
            IN_NONBLOCK = os.O_NONBLOCK
            libc.inotify_init1.argtypes = (ctypes.c_int,)
            libc.inotify_init1.restype = ctypes.c_int
            fd = libc.inotify_init1(IN_NONBLOCK)
            if fd < 0:
                return None
            accel = cls(fd, libc)
            seeded = accel._add_tree(root)
            if not seeded and not root.exists():
                os.close(fd)
                return None
            return accel
        except Exception:  # noqa: BLE001 — accelerator is pure optimization
            logger.debug("inotify accelerator unavailable; poll-only mode", exc_info=True)
            return None

    @property
    def available(self) -> bool:
        return self._fd >= 0

    def _add_tree(self, root: Path) -> int:
        import ctypes

        added = 0
        try:
            libc_add = self._libc.inotify_add_watch
            libc_add.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
            libc_add.restype = ctypes.c_int
            for dirpath, dirnames, _files in os.walk(root):
                if len(self._wds) >= _MAX_WATCHED_DIRS:
                    break
                try:
                    wd = libc_add(self._fd, os.fsencode(dirpath), _WATCH_MASK)
                except Exception:  # noqa: BLE001 — per-dir best effort
                    continue
                if wd and wd > 0:
                    with self._lock:
                        self._wds.add(wd)
                    added += 1
                dirnames.sort()
        except OSError:
            logger.debug("inotify seeding partial under %s", root, exc_info=True)
        return added

    def drain(self, timeout: float) -> bool:
        """Wait up to *timeout* seconds; True when any fs event arrived."""
        if self._fd < 0 or timeout <= 0:
            time.sleep(min(timeout, 0.05) if timeout > 0 else 0)
            return False
        try:
            import select

            readable, _, _ = select.select([self._fd], [], [], timeout)
            if not readable:
                return False
            events = 0
            while True:
                try:
                    buf = os.read(self._fd, 65536)
                except BlockingIOError:
                    break
                if not buf:
                    break
                import struct

                offset = 0
                total = len(buf)
                while offset + 16 <= total:
                    wd, mask, _cookie, name_len = struct.unpack_from(_EVENT_STRUCT, buf, offset)
                    offset += 16 + name_len
                    if mask & _IN_IGNORED:
                        with self._lock:
                            self._wds.discard(wd)
                        continue
                    if mask & _IN_ISDIR and mask & (_IN_CREATE | _IN_MOVED_TO):
                        # New subdir: extend coverage lazily (best effort).
                        pass
                    events += 1
            return events > 0
        except Exception:  # noqa: BLE001 — accelerator must never break the loop
            logger.debug("inotify drain hiccup", exc_info=True)
            return False

    def close(self) -> None:
        try:
            if self._fd >= 0:
                os.close(self._fd)
        except OSError:
            pass
        self._fd = -1


# ---------------------------------------------------------------------------
# DriftWatcher
# ---------------------------------------------------------------------------


def advance_backoff(interval: float, *, activity: bool, base: float | None = None) -> float:
    """One step of the adaptive backoff ladder (SPEC §11.8: 2 s → 30 s).

    Detected drift resets to the base interval; an idle cycle grows the wait
    by :data:`POLL_BACKOFF_FACTOR`, capped at :data:`POLL_MAX_SECONDS`. Pure
    function so the ladder is unit-testable without threads.
    """
    floor = POLL_MIN_SECONDS if base is None else max(float(base), 0.001)
    if activity:
        return floor
    return min(max(interval, floor) * POLL_BACKOFF_FACTOR, POLL_MAX_SECONDS)


class DriftWatcher:
    """Owns watch-state, the sweep, and the opt-in poller thread.

    Constructed per (home, plugin-data) pair via :func:`shared_watcher`.
    Every public method is advisor-safe: worst case is a logged debug line,
    never an exception into the host.
    """

    def __init__(
        self,
        *,
        home: Path | str,
        data_dir: Path | str,
        view: Any | None = None,
        jobs: Any | None = None,
        cache: Any | None = None,
        state_path: Path | None = None,
        debounce_seconds: float = DEBOUNCE_SECONDS,
        base_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        register_exit: bool = True,
        use_inotify: bool = True,
    ) -> None:
        self.home = Path(home)
        self.data_dir = Path(data_dir)
        self.state_path = Path(state_path) if state_path else self.data_dir / "watch-state.json"
        self.view = view
        self._jobs = jobs
        self._cache = cache
        self._debounce = max(0.0, float(debounce_seconds))
        self._base_interval = min(max(float(base_interval), 0.01), POLL_MAX_SECONDS)

        self._lock = threading.Lock()
        self._state = load_state(self.state_path)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats: dict[str, int] = {
            "sweeps": 0,
            "gaps_detected": 0,
            "replayed_once": 0,
            "skipped_covered_by_lifecycle": 0,
            "enqueues": 0,
            "baseline_establishments": 0,
            "errors": 0,
        }
        self.last_sweep_wall: float | None = (
            float(self._state["updated_at"])
            if isinstance(self._state.get("updated_at"), (int, float))
            else None
        )
        self._accel: InotifyAccelerator | None = (
            InotifyAccelerator.create(self.home / "skills") if use_inotify else None
        )
        if register_exit:
            import atexit

            atexit.register(self._atexit_join)

    # -- identity -------------------------------------------------------------

    @property
    def identity(self) -> tuple[str, str]:
        """Rebuild key: (home, data_dir) pair this instance is bound to."""
        return (str(self.home), str(self.data_dir))

    @property
    def inotify_active(self) -> bool:
        return self._accel is not None and self._accel.available

    @property
    def poll_enabled_state(self) -> bool | None:
        """Persisted explicit start/stop choice (None = unset → setting decides)."""
        return self._state.get("poll_enabled")

    # -- stats ---------------------------------------------------------------

    def stats_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.stats)

    def _bump(self, key: str) -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    # -- sweep ----------------------------------------------------------------

    def safe_sweep(self) -> SweepResult:
        """Public sweep wrapper: never raises (advisor law)."""
        try:
            return self.sweep()
        except Exception:  # noqa: BLE001 — advisor law
            self._bump("errors")
            logger.exception("lens watcher: sweep failed (degraded to no-op)")
            return SweepResult(errors=1)

    def sweep(self) -> SweepResult:
        """Replay journaled gaps once, diff the tree, act, persist.

        First-ever run (empty persisted hashes) SILENTLY establishes the
        baseline — nothing pre-existing is reported or scanned. Otherwise
        every difference between the tree and persisted hashes becomes a
        gap, is surfaced exactly once (skip-or-enqueue decision below), and
        both the new hashes and the ``replayed`` markers persist together.
        """
        current = snapshot_tree(self.home)
        with self._lock:
            state = self._state
            persisted: dict[str, str] = dict(state.get("hashes", {}))
            journal: list[dict[str, Any]] = list(state.get("gaps", []))
            establishing = not persisted

        lines: list[str] = []
        gaps: list[WatchGap] = []

        if establishing:
            self._bump("baseline_establishments")
        else:
            # (a) Crash-window replay: gaps journaled by a previous run that
            # died before marking them replayed surface HERE, once.
            for raw in journal:
                gap = WatchGap.from_json(raw)
                if gap.replayed or gap.suppressed:
                    continue
                gap.line = self._describe_gap_line(gap)
                lines.append(gap.line)
                gap.replayed = True
                gaps.append(gap)
                self._bump("replayed_once")

            # (b) Fresh while-away drift: diff current tree vs persisted.
            for key in sorted(set(persisted) | set(current)):
                old_fp = persisted.get(key)
                new_fp = current.get(key)
                if old_fp == new_fp:
                    continue
                kind = (
                    KIND_REMOVED
                    if new_fp is None
                    else (KIND_ADDED if old_fp is None else KIND_CHANGED)
                )
                gap = WatchGap(
                    key=key,
                    kind=kind,
                    old_fp=old_fp,
                    new_fp=new_fp,
                    at_wall=time.time(),
                )
                gap.line = self._act_on_gap(gap)
                if gap.line:
                    lines.append(gap.line)
                gap.replayed = True  # surfaced during THIS sweep
                gaps.append(gap)
                self._bump("gaps_detected")

        header = (
            f"lens watch: baseline established ({len(current)} skill"
            f"{'s' if len(current) != 1 else ''})"
            if establishing
            else (f"lens watch: while away — {len(lines)} change{'s' if len(lines) != 1 else ''}")
            if lines
            else ""
        )
        report_lines = [header, *lines] if header else tuple()

        # Persist hashes + journal TOGETHER (single atomic write): this is
        # what makes replay-once hold across restarts. A crash BEFORE this
        # point replays next start (at-least-once under crash — documented).
        with self._lock:
            self._state["schema"] = WATCH_STATE_SCHEMA
            self._state["hashes"] = current
            # Journal fresh gaps (already marked replayed) + keep history,
            # deduped by (key, at), newest writes first, bounded.
            seen: set[tuple[str, float]] = set()
            kept: list[dict[str, Any]] = []
            for item in [g.to_json() for g in gaps] + list(journal):
                mark = (str(item.get("key")), float(item.get("at") or 0.0))
                if mark in seen:
                    continue
                seen.add(mark)
                kept.append(item)
            self._state["gaps"] = kept[-MAX_JOURNALED_GAPS:]
            self._state["updated_at"] = time.time()
            self.last_sweep_wall = self._state["updated_at"]
            save_ok = save_state(self.state_path, self._state)
        if not save_ok:
            self._bump("errors")

        self._bump("sweeps")
        return SweepResult(
            lines=tuple(report_lines),
            gaps=tuple(gaps),
            established_baseline=establishing,
            tracked=len(current),
            errors=self.stats_snapshot()["errors"],
        )

    # -- per-gap action (same queue/coalescing as lifecycle triggers) ---------

    def _act_on_gap(self, gap: WatchGap) -> str | None:
        """Surface one gap: skip-line or enqueue on the shared worker.

        Removed bundles cannot be scanned (journaled honestly). Changed/
        added bundles compute the canonical IR hash exactly like the trigger
        lane, then dedupe against the lifecycle fast path — covered hashes
        emit a skip status instead of a duplicate scan; everything else goes
        through ``jobs.enqueue`` whose live-job coalescing folds concurrent
        duplicates. Failures degrade to fail-lines, never exceptions.
        """
        name = gap.key.rpartition("/")[2] or gap.key
        try:
            if gap.kind == KIND_REMOVED:
                return self._clip(
                    f"lens skip {name} · removed while away · was {_fp8(gap.old_fp)} · "
                    f"/lens report {name}"
                )

            target = self.home / "skills" / Path(gap.key)
            if not target.exists():
                return self._clip(f"lens skip {name} · vanished mid-watch (churn) · /lens report")
            envelope_hash, suffix, target_path, display = self._scan_identity(target, name)
            if envelope_hash is None:
                return self._clip(f"lens fail {name} · unreadable after drift · /lens doctor")

            # Lifecycle-lane dedupe (§11.6): already fast-pathed or cached?
            if self._covered_by_lifecycle(envelope_hash, suffix):
                self._bump("skipped_covered_by_lifecycle")
                from .cache import hash8
                from .render import fast_line_coalesced

                return fast_line_coalesced(name=display, hash8=hash8(envelope_hash))

            enqueued = self._enqueue(target_path, display, envelope_hash, suffix)
            if enqueued is None:
                return self._clip(
                    f"lens scan queued: {display} · sha256 {_fp8(envelope_hash)} · p95 400ms "
                    f"· /lens report {display} when ready"
                )
            self._bump("enqueues")
            from .cache import hash8
            from .render import fast_line_scan_queued

            return fast_line_scan_queued(name=display, hash8=hash8(envelope_hash))
        except Exception:  # noqa: BLE001 — advisor law: one bad gap ≠ broken sweep
            self._bump("errors")
            logger.exception("lens watcher: gap action failed (%s)", gap.key)
            return self._clip(f"lens fail {name} · watcher action error · /lens doctor")

    def _describe_gap_line(self, gap: WatchGap) -> str:
        """Replay rendering for journaled-but-unmarked gaps (crash window)."""
        name = gap.key.rpartition("/")[2] or gap.key
        arrow = f"{_fp8(gap.old_fp)}→{_fp8(gap.new_fp)}"
        return self._clip(f"lens watch {name} · {gap.kind.upper()} · {arrow} · /lens report {name}")

    def _scan_identity(self, target: Path, name: str) -> tuple[str | None, str, Path, str]:
        """Canonical IR hash + baseline suffix for one drifted bundle.

        Mirrors the trigger/hub lanes so completed scans land in the SAME
        cache namespace and coalesce onto live jobs. Returns
        ``(bundle_hash, suffix, target_path, display_name)``; hash None when
        ingest fails or the IR carries error diagnostics (vanished/unreadable).
        """
        from .cache import key_for_ir
        from .ingest import DEFAULT_CEILINGS, load_bundle

        ir = None
        try:
            ir = load_bundle(target, ceilings=DEFAULT_CEILINGS)
        except Exception:  # noqa: BLE001 — degraded identity handled by caller
            logger.debug("watcher ingest failed (%s)", name, exc_info=True)
        if ir is None:
            return None, "", target, name
        has_errors = any(
            str(getattr(d, "severity", "")).lower() == "error"
            for d in getattr(ir, "diagnostics", ())
        )
        if has_errors:
            return None, "", target, name
        suffix = ""
        if self.view is not None:
            try:
                from .slash import _baseline_state

                _records, suffix = _baseline_state(self.view, target)
            except Exception:  # noqa: BLE001 — config problems degrade to ""
                suffix = ""
        return key_for_ir(ir), suffix, target, name

    def _covered_by_lifecycle(self, bundle_hash: str, suffix: str) -> bool:
        """True when the lifecycle/post-tool fast path already handled *hash*."""
        try:
            from .triggers import recently_covered

            if recently_covered(bundle_hash):
                return True
        except Exception:  # noqa: BLE001 — dedupe probe is best-effort
            pass
        if self._cache is not None:
            try:
                if self._cache.get(bundle_hash + suffix) is not None:
                    return True
            except Exception:  # noqa: BLE001
                pass
        return False

    def _enqueue(self, target: Path, name: str, bundle_hash: str, suffix: str) -> Any | None:
        """Queue one cold scan on the SHARED worker; None ⇒ render interim B."""
        jobs = self._jobs
        if jobs is None:
            return None
        try:
            from datetime import date

            from .jobs import ScanContext

            return jobs.enqueue(
                name=name,
                target=target,
                bundle_hash=bundle_hash,
                cache_key=bundle_hash + suffix,
                context=ScanContext(
                    baseline_records=(),
                    key_suffix=suffix,
                    report_date=date.today(),
                    plugin_data_dir=self.data_dir,
                    cache=self._cache,
                    osv=False,
                ),
            )
        except Exception:  # noqa: BLE001 — advisor law
            self._bump("errors")
            logger.exception("lens watcher: enqueue failed (%s)", name)
            return None

    # -- polling (opt-in) ------------------------------------------------------

    @property
    def polling_active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def autostart_desired(self) -> bool:
        """Opt-in resolution: explicit start/stop flag wins, then watch.poll."""
        explicit = self.poll_enabled_state
        if explicit is not None:
            return explicit
        return configured_poll_interval(self.view) is not None

    def start_polling(self, interval: float | None = None) -> bool:
        """Start the daemon poller (idempotent); persists the opt-in flag.

        Never raises; returns False when polling is already active or the
        spawn fails (poll-only sweep mode keeps all guarantees except low
        latency — SPEC §11.8's honest degradation).
        """
        try:
            with self._lock:
                if self.polling_active:
                    return False
                self._stop.clear()
                effective = interval if interval else self._base_interval
                self._base_interval = min(max(float(effective), 0.01), POLL_MAX_SECONDS)
                self._thread = threading.Thread(
                    target=self._poll_loop,
                    name="lens-watcher",
                    daemon=True,  # dies with the process — no daemon (N8)
                )
                self._thread.start()
                self._state["poll_enabled"] = True
                save_state(self.state_path, self._state)
            logger.info(
                "lens watcher: continuous polling started (base %.1fs, %s)",
                self._base_interval,
                "inotify-accelerated" if self.inotify_active else "timed poll",
            )
            return True
        except Exception:  # noqa: BLE001 — advisor law
            self._bump("errors")
            logger.exception("lens watcher: start_polling failed")
            return False

    def stop_polling(self, timeout: float = 2.0) -> bool:
        """Signal stop + join with timeout; persists the opt-out flag."""
        thread = None
        with self._lock:
            self._stop.set()
            thread = self._thread
            self._thread = None
            self._state["poll_enabled"] = False
            save_state(self.state_path, self._state)
        joined = True
        if thread is not None and thread.is_alive():
            thread.join(timeout)
            joined = not thread.is_alive()
        logger.info("lens watcher: polling stopped (joined=%s)", joined)
        return joined

    def shutdown(self, timeout: float = 2.0) -> bool:
        """Process-exit politeness: stop polling, close the accelerator.

        The thread is a daemon either way (dies with the process); the join
        merely lets tests assert clean teardown. Never raises.
        """
        try:
            stopped = self.stop_polling(timeout)
        except Exception:  # noqa: BLE001
            stopped = False
        if self._accel is not None:
            self._accel.close()
        return stopped

    def _atexit_join(self) -> None:
        try:
            if self.polling_active:
                self.shutdown(timeout=1.0)
        except Exception:  # noqa: BLE001 — test seam must never raise
            pass

    # -- poll loop --------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Adaptive-backoff poller: 2 s idle-growth toward 30 s, reset on drift.

        Waits ride the inotify accelerator when available (early wake on fs
        events) and plain timed waits otherwise. Truth is ALWAYS the debounced
        hash diff; accelerator events only lower latency.
        """
        interval = self._base_interval
        while not self._stop.is_set():
            if self._accel is not None and self._accel.available:
                # Early wake on fs events, sliced so an incoming stop signal
                # is honored within ~250 ms instead of a full backoff wait.
                # The debounced hash diff below remains the sole truth.
                remaining = interval
                while remaining > 0 and not self._stop.is_set():
                    if self._accel.drain(min(remaining, _ACCEL_SLICE_SECONDS)):
                        break  # fs activity — go diff now
                    remaining -= _ACCEL_SLICE_SECONDS
                if self._stop.is_set():
                    break
            else:
                if self._stop.wait(interval):
                    break
            activity = False
            try:
                gaps = self._cycle_once()
                activity = bool(gaps)
            except Exception:  # noqa: BLE001 — the loop must survive anything
                self._bump("errors")
                logger.exception("lens watcher: poll cycle failed")
            interval = advance_backoff(interval, activity=activity, base=self._base_interval)

    def _cycle_once(self) -> tuple[WatchGap, ...]:
        """One debounced diff-and-act cycle; returns the gaps it acted on."""
        with self._lock:
            baseline = dict(self._state.get("hashes", {}))
        current = snapshot_tree(self.home)
        if current == baseline:
            return ()
        # Debounce: let churn storms settle, then take the FINAL snapshot.
        if self._debounce > 0:
            if self._stop.wait(self._debounce):
                return ()
            current = snapshot_tree(self.home)
        result = self.safe_sweep_inner(baseline=baseline)
        for line in result.lines:
            # Live delta surfacing (CLI sessions see host logs; gateways
            # accumulate in watch-state/events.ndjson for pull — §11.5/§11.8).
            logger.info("%s", line)
        return result.gaps

    def safe_sweep_inner(self, *, baseline: dict[str, str]) -> SweepResult:
        """Sweep variant used by the poller: diff against a KNOWN baseline.

        Shares all action/persist machinery with :meth:`sweep`; exists so
        the debounce window's final snapshot (not the stale persisted map)
        defines what persists, while *baseline* (pre-churn state) defines
        what counts as a gap — keeping storm semantics exact.
        """
        try:
            return self._sweep_against(baseline)
        except Exception:  # noqa: BLE001 — advisor law
            self._bump("errors")
            logger.exception("lens watcher: inner sweep failed")
            return SweepResult(errors=1)

    def _sweep_against(self, baseline: dict[str, str]) -> SweepResult:
        current = snapshot_tree(self.home)
        lines: list[str] = []
        gaps: list[WatchGap] = []
        for key in sorted(set(baseline) | set(current)):
            old_fp = baseline.get(key)
            new_fp = current.get(key)
            if old_fp == new_fp:
                continue
            kind = (
                KIND_REMOVED if new_fp is None else (KIND_ADDED if old_fp is None else KIND_CHANGED)
            )
            gap = WatchGap(key=key, kind=kind, old_fp=old_fp, new_fp=new_fp, at_wall=time.time())
            gap.line = self._act_on_gap(gap)
            if gap.line:
                lines.append(gap.line)
            gap.replayed = True
            gaps.append(gap)
            self._bump("gaps_detected")
        with self._lock:
            self._state["hashes"] = current
            journal = [g for g in self._state.get("gaps", [])]
            journal.extend(g.to_json() for g in gaps)
            seen: set[tuple[str, float]] = set()
            kept: list[dict[str, Any]] = []
            for item in journal:
                mark = (str(item.get("key")), float(item.get("at") or 0.0))
                if mark in seen:
                    continue
                seen.add(mark)
                kept.append(item)
            self._state["gaps"] = kept[-MAX_JOURNALED_GAPS:]
            self._state["updated_at"] = time.time()
            self.last_sweep_wall = self._state["updated_at"]
            save_state(self.state_path, self._state)
        self._bump("sweeps")
        return SweepResult(lines=tuple(lines), gaps=tuple(gaps), tracked=len(current))

    # -- status -------------------------------------------------------------------

    def status_dict(self) -> dict[str, Any]:
        """Machine-readable status (verb output + future doctor check)."""
        with self._lock:
            gaps = [WatchGap.from_json(g) for g in self._state.get("gaps", [])]
            pending = [g for g in gaps if not g.replayed and not g.suppressed]
            return {
                "polling": self.polling_active,
                "base_interval": self._base_interval,
                "inotify": self.inotify_active,
                "tracked": len(self._state.get("hashes", {})),
                "journalled_gaps": len(gaps),
                "pending_replays": len(pending),
                "last_sweep": self.last_sweep_wall,
                "stats": dict(self.stats),
            }

    def status_lines(self) -> tuple[str, ...]:
        """Sober fixed-order status block (§16 automation-safe)."""
        info = self.status_dict()
        poll = (
            f"polling on · base {info['base_interval']:.0f}s"
            if info["polling"]
            else "polling off (opt-in: /lens watch start)"
        )
        accel = "accelerated" if info["inotify"] else "timed"
        pending_note = (
            f" · {info['pending_replays']} awaiting replay" if info["pending_replays"] else ""
        )
        head = (
            f"lens watch · {poll} · {accel} · tracking {info['tracked']} skills · "
            f"gaps journalled {info['journalled_gaps']}{pending_note}"
        )
        extra: list[str] = []
        if info["pending_replays"]:
            extra.append("(restart replay will surface them once)")
        return (head, *extra)

    # -- misc ---------------------------------------------------------------

    @staticmethod
    def _clip(line: str, limit: int = 160) -> str:
        flat = " ".join(str(line).split())
        return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _fp8(fp: str | None) -> str:
    """8-char display shard of a fingerprint (mirrors cache.hash8 style)."""
    if not fp:
        return "—"
    body = fp.split(":", 1)[1] if ":" in fp else fp
    return body[:8]


def configured_poll_interval(view: Any | None) -> float | None:
    """Resolve the ``watch.poll`` plugin setting (positive seconds) or None.

    Type/mirror of policy.py's recognized-settings handling: int/float > 0
    accepted; everything else (absent, zero, negative, junk) means OFF.
    """
    if view is None:
        return None
    try:
        raw = view.get_config("watch.poll", None)
    except Exception:  # noqa: BLE001 — hostile ctx degrades to off
        return None
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    elif isinstance(raw, str):
        try:
            value = float(raw.strip())
        except ValueError:
            return None
    else:
        return None
    return value if value > 0 else None


# ---------------------------------------------------------------------------
# Process-wide singleton + registration seam
# ---------------------------------------------------------------------------

_shared_lock = threading.Lock()
_shared_watcher: DriftWatcher | None = None


def _coerce_dir(value: object) -> Path | None:
    """Coerce *value* to a directory Path; None when not str/PathLike.

    Mirrors :meth:`skill_lens.context.PluginContextView._coerce_and_prepare`
    minus the mkdir side effect: only ``str`` and ``PathLike[str]`` values
    can build a Path, so anything else (int, bool, hostile junk) degrades to
    the caller's fallback. Never raises.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (str, os.PathLike)):
            return Path(os.fspath(value))
    except (TypeError, ValueError, OSError):
        return None
    return None


def shared_watcher(
    view: Any | None = None,
    *,
    home: Path | str | None = None,
    data_dir: Path | str | None = None,
    jobs: Any | None = None,
    cache: Any | None = None,
) -> DriftWatcher:
    """Process-wide watcher bound to ONE (home, data-dir) pair.

    Re-registration against a different Hermes home/plugin-data dir (tests,
    HERMES_HOME overrides) transparently shuts down and replaces the old
    instance, so a stale tree is never watched. Tests reset via
    :func:`reset_shared_watcher`.
    """
    global _shared_watcher
    from .slash import hermes_home

    resolved_home = Path(home) if home is not None else hermes_home()
    if data_dir is not None:
        resolved_data = Path(data_dir)
    elif view is not None:
        # Defensive probe: real PluginContextView exposes plugin_data_dir();
        # raw/hostile contexts degrade to the HERMES_HOME convention.
        resolver = getattr(view, "plugin_data_dir", None)
        resolved_data = _coerce_dir(resolver()) if callable(resolver) else None
        if resolved_data is None:
            resolved_data = resolved_home / "plugin-data" / "lens"
    else:
        resolved_data = resolved_home / "plugin-data" / "lens"
    with _shared_lock:
        existing = _shared_watcher
        if existing is not None and existing.identity == (
            str(resolved_home),
            str(resolved_data),
        ):
            return existing
        if existing is not None:
            try:
                existing.shutdown(timeout=1.0)
            except Exception:  # noqa: BLE001 — replacement must proceed
                logger.debug("stale watcher shutdown hiccup", exc_info=True)
    # Build OUTSIDE the lock (constructor does IO); rebuild race is benign:
    # last writer wins, both instances are advisor-safe daemons.
    watcher = DriftWatcher(
        home=resolved_home,
        data_dir=resolved_data,
        view=view,
        jobs=jobs,
        cache=cache,
    )
    with _shared_lock:
        _shared_watcher = watcher
    return watcher


def reset_shared_watcher() -> None:
    """Shut down and drop the process-wide watcher (test seam)."""
    global _shared_watcher
    with _shared_lock:
        watcher = _shared_watcher
        _shared_watcher = None
    if watcher is not None:
        try:
            watcher.shutdown(timeout=2.0)
        except Exception:  # noqa: BLE001 — test seam must never raise
            logger.debug("reset_shared_watcher shutdown hiccup", exc_info=True)


def register_watcher(view: Any) -> DriftWatcher | None:
    """Startup-seam called from bootstrap.register_plugin — NEVER raises.

    Always runs the startup sweep (persisted-hash comparison; silent
    baseline establishment on first contact), then auto-starts the poller
    only when opted in (explicit flag in watch-state.json, else the
    ``watch.poll`` setting). Returns the watcher for introspection.
    """
    try:
        from .slash import shared_cache, shared_jobs

        watcher = shared_watcher(view, jobs=shared_jobs(view), cache=shared_cache())
    except Exception:  # noqa: BLE001 — advisor law: wiring never breaks loading
        logger.exception("lens watcher: construction failed; watcher inert")
        return None
    result = watcher.safe_sweep()
    if result.established_baseline:
        logger.info("lens watcher: baseline established (%d skills)", result.tracked)
    elif result.lines:
        logger.info("lens watcher: %s", result.lines[0])
        for line in result.lines[1:]:
            logger.info("lens watcher:   %s", line)
    if not watcher.polling_active and watcher.autostart_desired():
        interval = configured_poll_interval(view)
        watcher.start_polling(interval if interval else None)
    return watcher


__all__ = [
    "DEBOUNCE_SECONDS",
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "DriftWatcher",
    "InotifyAccelerator",
    "KIND_ADDED",
    "KIND_CHANGED",
    "KIND_REMOVED",
    "POLL_MAX_SECONDS",
    "POLL_MIN_SECONDS",
    "SweepResult",
    "WATCH_STATE_SCHEMA",
    "WatchGap",
    "configured_poll_interval",
    "fingerprint_bundle",
    "load_state",
    "register_watcher",
    "reset_shared_watcher",
    "save_state",
    "shared_watcher",
    "snapshot_tree",
]
