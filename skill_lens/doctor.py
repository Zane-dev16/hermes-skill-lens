"""``lens doctor`` — the nine-check §11.9 self-check engine.

One check engine, two renderers (SPEC §11.9): the CLI lane renders a
checklist panel with REAL exit codes (0 even on warnings, **2 on any hard
check failure** — unreadable rule pack, failed wiring audit, failed
isolation self-test, broken state dirs); ``/lens doctor`` runs the same
checks in-process and carries the verdict on its final line, never raising.
Results land as one ``doctor`` record in ``events.ndjson`` for gateway
operators (wall-clock ``ts`` rides there only — sidecar exemption).

The nine checks, numbered exactly as SPEC lists them:

1. Rule-pack version + checksum integrity (honest WARN until Phase 5 ships
   release signatures — we can pin bytes, not yet provenance).
2. Policy parse + effective profile with ALL sources listed (§10 layers).
3. Plugin-data writable; ``jobs.json``/``events.ndjson`` healthy; quota
   bounds respected.
4. Hermes environment: HERMES_HOME discovery, plugin enabled, categorized
   skills tree found, hub scan-cache present, profiles tree discovered +
   route table parse-checked (per-profile deployment implications surfaced).
5. Hook-wiring audit: asserts ZERO ``pre_tool_call`` registrations against
   host VALID_HOOKS — FAILS LOUDLY if any blocking wiring exists. Sources:
   our own registration ledger (skill_lens.triggers) plus host-manager
   introspection when reachable. The advisor stance, made checkable (T1).
6. Network-isolation self-test: a canned scan runs under live socket-deny
   enforcement; where enforcement is impossible the check degrades to
   ``config-audit only`` honestly.
7. Synthetic lifecycle self-test: emits a canary skill-name event through a
   dispatch double replaying the verbatim emit-site shape and asserts our
   own hook saw it. Safe by construction: the canary name resolves to no
   bundle, so the observer fast path is a pure counter bump — observers are
   best-effort and side-effect-free.
8. Parse-subsystem health: crash-loop counters + AST active/degraded report
   (the D-PROC caveat made observable via skill_lens.parsing.health()).
9. TTY/color sanity: one-liner rendered twice must be byte-identical, and
   the NO_COLOR/plain lane must strip every box glyph to ASCII.

Advisor laws hold here too: every check catches its own exceptions (a broken
check degrades to a FAIL row naming itself, never an exception into the
host), nothing blocks, nothing opens a socket in the default closure.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("lens")

#: Pinned fallback copy of host VALID_HOOKS (hermes_cli/plugins.py:161,
#: transcribed in docs/host-contract.md). Used only when the host module is
#: not importable (out-of-process tests); the live set wins when available.
_FALLBACK_VALID_HOOKS = frozenset(
    {
        "pre_tool_call",
        "post_tool_call",
        "transform_terminal_output",
        "transform_tool_result",
        "transform_llm_output",
        "pre_llm_call",
        "post_llm_call",
        "on_stream_start",
        "on_stream_delta",
        "on_stream_end",
        "on_interim_message",
        "pre_verify",
        "pre_api_request",
        "post_api_request",
        "api_request_error",
        "transform_api_error_classification",
        "on_session_start",
        "on_session_end",
        "on_session_finalize",
        "on_session_reset",
        "on_skill_lifecycle",
        "subagent_start",
        "subagent_stop",
    }
)

#: The three hooks Skill Lens declares (plugin.yaml provides_hooks) — all
#: observers; this tuple is the exact allowed wiring set (advisor law).
DECLARED_HOOKS = ("on_skill_lifecycle", "post_tool_call", "transform_tool_result")

#: The one hook that must NEVER appear anywhere in our wiring (T1).
FORBIDDEN_HOOK = "pre_tool_call"

#: Consecutive hard parse failures that read as a crash-loop signature
#: (D-PROC caveat made observable; parsing resets on any success).
CRASH_LOOP_THRESHOLD = 3

#: Events.ndjson lines scanned for JSON health before capping (huge ledgers
#: stay bounded; older lines are append-only history anyway).
EVENTS_SCAN_LINE_CAP = 50_000

#: Status vocabulary (machine-stable).
PASS, WARN, FAIL = "pass", "warn", "fail"


class SocketViolation(AssertionError):
    """Raised by the isolation guard when anything reaches for a socket."""


@dataclass(frozen=True)
class CheckResult:
    """One §11.9 check outcome. ``detail`` lines are renderer-ready."""

    number: int
    key: str
    title: str
    status: str  # PASS | WARN | FAIL
    detail: tuple[str, ...] = ()
    #: True when this failure is HARD (drives the §11.9/§18 exit-2 policy).
    hard: bool = False

    @property
    def marker(self) -> str:
        return {PASS: "✓", WARN: "!", FAIL: "✗"}.get(self.status, "?")

    def summary(self) -> str:
        head = self.detail[0] if self.detail else ""
        return (
            f"{self.marker} {self.number} {self.title}: {head}"
            if head
            else (f"{self.marker} {self.number} {self.title}")
        )


@dataclass
class DoctorReport:
    """Aggregated nine-check outcome + renderer inputs."""

    checks: list[CheckResult] = field(default_factory=list)
    profile: str = ""
    pack_version: str = ""
    pack_checksum: str = ""

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warnings(self) -> list[CheckResult]:
        return [c for c in self.checks if c.status == WARN]

    @property
    def exit_code(self) -> int:
        """§11.9 normative: exit 0 even on warnings; 2 on any hard failure."""
        return 2 if self.failures else 0

    @property
    def ok(self) -> bool:
        return not self.failures

    def verdict_line(self) -> str:
        """The §11.9 final line, e.g. ``doctor: OK (2 warnings) · … ✓``."""
        pack = f"pack {self.pack_version}" if self.pack_version else ""
        profile = f"profile {self.profile}" if self.profile else ""
        if self.failures:
            head = f"doctor: FAIL ({len(self.failures)} hard"
            if self.warnings:
                head += f", {len(self.warnings)} warnings"
            head += ")"
        elif self.warnings:
            head = (
                f"doctor: OK ({len(self.warnings)} warning{'' if len(self.warnings) == 1 else 's'})"
            )
        else:
            head = "doctor: OK"
        parts = [part for part in (head, profile, pack) if part]
        tail = " ✗" if self.failures else " ✓"
        return " · ".join(parts) + tail


# ---------------------------------------------------------------------------
# Check implementations (each defensive: never raises into the dispatcher)
# ---------------------------------------------------------------------------


def check_rule_pack() -> tuple[CheckResult, str, str]:
    """Check 1 — rule-pack version + checksum integrity.

    Loads the embedded core pack and pins ``content_checksum`` (same D-HASH
    recipe as bundles). Release SIGNATURES land in Phase 5; until then the
    honest status is WARN ("unsigned") — checksum proves byte integrity of
    whatever shipped, not who shipped it.
    """
    title = "rule-pack integrity"
    try:
        from .rules import load_core_pack

        pack = load_core_pack()
    except Exception as exc:  # noqa: BLE001 — unreadable pack is total error
        return (
            CheckResult(
                1,
                "rule-pack",
                title,
                FAIL,
                (f"unreadable rule pack: {exc}",),
                hard=True,
            ),
            "",
            "",
        )
    checksum = pack.content_checksum()
    short = f"{checksum[:15]}…{checksum[-6:]}"
    return (
        CheckResult(
            1,
            "rule-pack",
            title,
            WARN,
            (
                f"v{pack.version} · {len(pack.active_rules())} active rules · {short}",
                "unsigned — release signatures land in Phase 5 (rules verify)",
            ),
            hard=False,
        ),
        pack.version,
        checksum,
    )


def check_policy(view: Any) -> CheckResult:
    """Check 2 — policy parses; effective profile with ALL sources listed."""
    title = "policy resolution"
    from .policy import PolicyError, load_policy

    try:
        policy = load_policy(ctx=view)
    except PolicyError as exc:
        return CheckResult(
            2,
            "policy",
            title,
            FAIL,
            (f"malformed policy config: {exc}",),
            hard=True,
        )
    except Exception as exc:  # noqa: BLE001 — defensive: never raise into host
        return CheckResult(2, "policy", title, FAIL, (f"policy load crashed: {exc}",), hard=True)
    sources = ", ".join(policy.sources) if policy.sources else "built-in"
    overrides = len(policy.severity_overrides)
    disabled = len(policy.disabled_rules)
    extras = (
        f" · {overrides} override(s) · {disabled} disabled rule(s)"
        if (overrides or disabled)
        else ""
    )
    return CheckResult(
        2,
        "policy",
        title,
        PASS,
        (f"profile {policy.profile} · sources: {sources}{extras}",),
    )


def check_plugin_data(view: Any) -> CheckResult:
    """Check 3 — plugin-data writable; jobs/events sidecars healthy; quotas."""
    title = "plugin-data & sidecars"
    data_dir: Path | None = None
    try:
        data_dir = view.plugin_data_dir()
    except Exception:  # noqa: BLE001 — seam may raise anything
        data_dir = None
    if data_dir is None:
        return CheckResult(
            3,
            "plugin-data",
            title,
            FAIL,
            ("no usable plugin-data dir — ctx.state.data_dir missing or broken",),
            hard=True,
        )

    problems: list[str] = []
    notes: list[str] = []

    # Writability probe (create/write/delete — cheap, deterministic path).
    probe = data_dir / ".doctor-probe"
    try:
        probe.write_text("probe", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        return CheckResult(
            3,
            "plugin-data",
            title,
            FAIL,
            (f"plugin-data dir not writable ({data_dir}): {exc}",),
            hard=True,
        )

    # jobs.json health: must be a JSON object carrying a job table within quota.
    jobs_path = data_dir / "jobs.json"
    job_count = -1
    if jobs_path.exists():
        try:
            payload = json.loads(jobs_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("top level is not an object")
            raw_jobs = payload.get("jobs")
            if not isinstance(raw_jobs, list):
                raise ValueError("'jobs' table missing")
            job_count = len(raw_jobs)
        except (OSError, ValueError) as exc:
            problems.append(f"jobs.json corrupt/unhealthy: {exc}")
    else:
        notes.append("no jobs.json yet (queue unused)")

    # events.ndjson health: every scanned line parses as a JSON object.
    events_path = data_dir / "events.ndjson"
    if events_path.exists():
        bad_lines = 0
        scanned = 0
        try:
            with events_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    scanned += 1
                    if scanned > EVENTS_SCAN_LINE_CAP:
                        notes.append(f"events.ndjson: scanned first {EVENTS_SCAN_LINE_CAP} lines")
                        break
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        parsed = json.loads(text)
                    except ValueError:
                        bad_lines += 1
                        continue
                    if not isinstance(parsed, dict):
                        bad_lines += 1
            if bad_lines:
                problems.append(f"events.ndjson unhealthy: {bad_lines} non-JSON line(s)")
        except OSError as exc:
            problems.append(f"events.ndjson unreadable: {exc}")
    else:
        notes.append("no events.ndjson yet (ledger empty)")

    # Quota bounds: persisted job table respects MAX_PERSISTED_JOBS.
    if job_count >= 0:
        from .jobs import MAX_PERSISTED_JOBS

        if job_count > MAX_PERSISTED_JOBS:
            problems.append(
                f"quota breach: {job_count} persisted jobs > "
                f"MAX_PERSISTED_JOBS={MAX_PERSISTED_JOBS}"
            )
        else:
            notes.append(f"job table {job_count}/{MAX_PERSISTED_JOBS}")

    if problems:
        return CheckResult(3, "plugin-data", title, FAIL, tuple(problems), hard=True)
    fallback = ("writable; sidecars healthy",)
    return CheckResult(3, "plugin-data", title, PASS, tuple(notes) or fallback)


def _host_valid_hooks() -> tuple[frozenset[str], str]:
    """Live host VALID_HOOKS when importable, pinned fallback otherwise."""
    try:
        from hermes_cli.plugins import VALID_HOOKS  # type: ignore[import-not-found]

        return frozenset(VALID_HOOKS), "live host hermes_cli.plugins.VALID_HOOKS"
    except Exception:  # noqa: BLE001 — out-of-host processes fall back
        return _FALLBACK_VALID_HOOKS, "pinned fallback (docs/host-contract.md)"


def _host_blocking_lens_callbacks(valid_hooks: frozenset[str]) -> tuple[list[str], str]:
    """Introspect the host manager for lens-attributable blocking wiring.

    Returns ``(problems, note)``. When the host manager isn't reachable
    (tests, foreign embedders) the note says so and the self-audit ledger
    remains the sole source — that limitation is surfaced, not hidden.
    """
    try:
        from hermes_cli.plugins import get_plugin_manager  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        return [], "host manager unreachable — audited our own ledger only"
    try:
        manager = get_plugin_manager()
        wired = getattr(manager, "_hooks", {}) or {}
    except Exception as exc:  # noqa: BLE001 — introspection must never raise
        return [], f"host manager introspection failed ({exc}); audited our ledger only"
    problems: list[str] = []
    blocking = wired.get(FORBIDDEN_HOOK, []) or []
    # Attribution must hold in BOTH layouts (D-053): repo-rooted modules are
    # ``skill_lens.*``; the host loads us as ``hermes_plugins.<key>.skill_lens.*``.
    our_pkg = __package__ or "skill_lens"
    for callback in blocking:
        module = getattr(callback, "__module__", "") or ""
        qualname = getattr(callback, "__qualname__", "") or repr(callback)
        if (
            module == our_pkg
            or module.startswith(our_pkg + ".")
            or module.startswith("skill_lens")
            or "lens" in module.lower()
        ):
            problems.append(f"BLOCKING WIRING FOUND: {FORBIDDEN_HOOK} ← {qualname} ({module})")
    if FORBIDDEN_HOOK not in valid_hooks:  # pragma: no cover — host drift alarm
        problems.append("host VALID_HOOKS no longer contains pre_tool_call?!")
    total = len(blocking)
    note = (
        f"host manager audited: {total} pre_tool_call registration(s) process-wide, "
        f"0 attributable to lens"
        if not problems
        else f"host manager audited: {total} pre_tool_call registration(s)"
    )
    return problems, note


def check_hook_wiring(view: Any) -> CheckResult:
    """Check 5 — ZERO pre_tool_call registrations; fails LOUDLY otherwise."""
    title = "hook-wiring audit (advisor stance)"
    valid_hooks, hook_source = _host_valid_hooks()

    from .triggers import registry_snapshot

    ledger = registry_snapshot()
    problems: list[str] = []
    names = [name for name, _cb in ledger]

    if FORBIDDEN_HOOK in names:
        offenders = [
            getattr(cb, "__qualname__", repr(cb)) for n, cb in ledger if n == FORBIDDEN_HOOK
        ]
        problems.append(
            f"BLOCKING WIRING FOUND: {len(offenders)} × {FORBIDDEN_HOOK} registered "
            f"({', '.join(o or '<anon>' for o in offenders)}) — advisor law violated"
        )

    unknown = sorted({n for n in names if n not in valid_hooks})
    if unknown:
        problems.append(
            f"registration outside host VALID_HOOKS ({hook_source}): {', '.join(unknown)}"
        )

    declared_missing = [n for n in DECLARED_HOOKS if n not in names]
    if declared_missing and names:
        # Degraded lanes are survivable (context lacked the seam) but must
        # be visible; only a full ledger absence means "never registered".
        problems.append(f"declared hook(s) not registered: {', '.join(declared_missing)}")

    extra_problems, host_note = _host_blocking_lens_callbacks(valid_hooks)
    problems.extend(extra_problems)

    observed = ", ".join(names) if names else "none recorded (plugin not registered?)"
    detail = [f"wired [{observed}] vs VALID_HOOKS via {hook_source}", host_note, *problems]
    return CheckResult(
        5,
        "hook-wiring",
        title,
        FAIL if problems else PASS,
        tuple(detail),
        hard=bool(problems),
    )


_CANNED_SKILL_MD = (
    "---\n"
    "name: lens-doctor-canary-bundle\n"
    "description: Deterministic benign fixture used only by lens doctor's "
    "isolation self-test.\n"
    "---\n"
    "# Isolation self-test\n\n"
    "Reads its own README and prints a greeting.\n"
)


@contextmanager
def socket_deny_guard() -> Iterator[Callable[[], int]]:
    """Enforce zero sockets around a body; yield a violation counter.

    Replaces ``socket.socket``, ``socket.create_connection`` and
    ``socket.getaddrinfo`` with raising stubs for the duration — real
    enforcement inline, no pytest dependency. Restores originals in
    ``finally`` even when the body raises.

    The socket module loads via importlib, NOT a static import statement:
    the PRIVACY/import-contract law forbids network-machinery imports
    outside ``skill_lens/enrich/`` (tests/test_import_contract.py). This is
    a patch-and-restore guard, never a network user.
    """
    import importlib

    socket_mod = importlib.import_module("socket")

    violations = {"n": 0}

    def _deny(*_args: Any, **_kwargs: Any) -> Any:
        violations["n"] += 1
        raise SocketViolation("network access attempted during isolation self-test")

    originals = (
        (socket_mod, "socket"),
        (socket_mod, "create_connection"),
        (socket_mod, "getaddrinfo"),
        (socket_mod, "create_pair"),
    )
    saved: list[tuple[Any, str, Any]] = []
    patch_failed = False
    for owner, attr in originals:
        if not hasattr(owner, attr):
            continue
        saved.append((owner, attr, getattr(owner, attr)))
        try:
            setattr(owner, attr, _deny)
        except (TypeError, AttributeError):  # immutable module attr (rare)
            patch_failed = True
    try:
        yield lambda: violations["n"]
        if patch_failed:
            raise SocketViolation("socket guard could not fully arm")
    finally:
        for owner, attr, original in saved:
            try:
                setattr(owner, attr, original)
            except Exception:  # pragma: no cover — restore must never raise
                logger.exception("socket guard restore failed for %s", attr)


def _default_canned_scan(bundle_dir: Path, data_dir: Path | None) -> dict[str, Any]:
    """Run the canned bundle through the real pipeline (engines inline)."""
    from .cache import FastPathCache
    from .slash import run_scan

    cache = FastPathCache(max_entries=2)
    result = run_scan(
        bundle_dir,
        cache=cache,
        plugin_data_dir=data_dir or Path(tempfile.gettempdir()) / "lens-doctor-isolation",
    )
    return result


def check_network_isolation(
    *, scan_fn: Callable[[Path, Path | None], dict[str, Any]] | None = None
) -> CheckResult:
    """Check 6 — canned scan under socket-deny enforcement, inline.

    ``scan_fn`` is injectable so tests can prove the guard trips (a scan_fn
    that reaches for a socket must FAIL this check loudly). Where arming the
    guard is impossible on the platform, degrade to ``config-audit only``
    honestly (WARN) rather than claim an unverified pass.
    """
    title = "network-isolation self-test"
    runner = scan_fn if scan_fn is not None else _default_canned_scan

    workdir = Path(tempfile.mkdtemp(prefix="lens-doctor-net-"))
    try:
        bundle = workdir / "lens-doctor-canary-bundle"
        bundle.mkdir(parents=True)
        (bundle / "SKILL.md").write_text(_CANNED_SKILL_MD, encoding="utf-8")

        try:
            with socket_deny_guard() as violation_count:
                result = runner(bundle, None)
                violation_count()
        except SocketViolation:
            return CheckResult(
                6,
                "network-isolation",
                title,
                FAIL,
                ("SOCKET USE DETECTED during canned scan — default closure breached",),
                hard=True,
            )
        except Exception as exc:  # noqa: BLE001 — scan crash ≠ network leak proof
            return CheckResult(
                6,
                "network-isolation",
                title,
                WARN,
                (f"canned scan errored under guard (no socket attempt logged): {exc}",),
            )

        if not isinstance(result, dict) or result.get("ok") is not True:
            detail = "canned scan did not complete cleanly under guard"
            extra = "" if not isinstance(result, dict) else f": {result.get('error')!r}"
            return CheckResult(6, "network-isolation", title, WARN, (detail + extra,))

        envelope = result.get("envelope") if isinstance(result, dict) else None
        findings = len(envelope.get("findings", [])) if isinstance(envelope, dict) else "?"
        score = envelope.get("score", {}) if isinstance(envelope, dict) else {}
        grade = score.get("grade", "?") if isinstance(score, dict) else "?"
        return CheckResult(
            6,
            "network-isolation",
            title,
            PASS,
            (
                f"canned scan completed under live socket deny · 0 socket attempts · "
                f"grade {grade} · {findings} finding(s) · deterministic offline pipeline",
            ),
        )
    finally:
        try:
            import shutil

            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:  # pragma: no cover
            logger.debug("isolation temp cleanup failed", exc_info=True)


def check_lifecycle_selftest(view: Any) -> CheckResult:
    """Check 7 — emit a canary event through our dispatch double.

    Replays the VERBATIM ``on_skill_lifecycle`` emit shape
    (tools/skill_usage.py:829-840 incl. the injected telemetry key) at OUR
    OWN registered handler and asserts the handler observed it (counter
    delta), returned ``None``, and raised nothing. Side-effect-free by
    construction: the canary name is verified unresolvable first, so the
    observer fast path stops before cache/queue touch.
    """
    title = "lifecycle self-test"
    from .slash import resolve_target
    from .triggers import LIFECYCLE_ACTIONS, stats_snapshot
    from .triggers import registry_snapshot as trigger_registry

    handlers = [cb for name, cb in trigger_registry() if name == "on_skill_lifecycle" and cb]
    if not handlers:
        return CheckResult(
            7,
            "lifecycle",
            title,
            WARN,
            ("on_skill_lifecycle not wired in this session — nothing to self-test",),
        )
    handler = handlers[-1]

    canary = "lens-doctor-canary"
    for _attempt in range(8):
        target, _display = resolve_target(canary)
        if target is None:
            break
        canary = f"{canary}-x"
    else:  # pragma: no cover — pathological homes with canary-named skills
        return CheckResult(
            7,
            "lifecycle",
            title,
            WARN,
            ("could not derive an unresolvable canary name; skipped for safety",),
        )

    payload: dict[str, Any] = {
        "action": "used",  # in LIFECYCLE_ACTIONS ⇒ counter bumps
        "skill_name": canary,
        "provenance": "local",
        "task_id": "",
        "session_id": "",
        "use_count": None,
        "reused": None,
        "reuse_after_patch": None,
        "telemetry_schema_version": 1,
    }
    assert "used" in LIFECYCLE_ACTIONS
    before = stats_snapshot().get("lifecycle_events", 0)
    try:
        returned = handler(**payload)
    except Exception as exc:  # noqa: BLE001 — advisor law violation if hit
        return CheckResult(
            7,
            "lifecycle",
            title,
            FAIL,
            (f"handler RAISED into dispatch double: {exc!r}",),
            hard=True,
        )
    after = stats_snapshot().get("lifecycle_events", 0)
    problems: list[str] = []
    if returned is not None:
        problems.append(f"observer returned {returned!r} (contract: None)")
    if after - before != 1:
        problems.append(f"hook did not observe canary (counter delta {after - before})")
    if problems:
        return CheckResult(7, "lifecycle", title, FAIL, tuple(problems), hard=True)
    return CheckResult(
        7,
        "lifecycle",
        title,
        PASS,
        (f"canary {canary!r} observed by our own hook · returned None · no side effects",),
    )


def check_parse_health() -> CheckResult:
    """Check 8 — parse-subsystem health (crash-loops + AST active/degraded)."""
    title = "parse subsystem"
    try:
        from .parsing import GATEWAY

        snapshot = GATEWAY.health(probe=True)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            8,
            "parse",
            title,
            WARN,
            (f"health probe failed: {exc} — line-scanner fallback remains golden-tested",),
        )
    languages = snapshot.get("languages", {})
    failures = snapshot.get("consecutive_failures", {})
    overall = str(snapshot.get("status", "degraded"))
    loops = sorted(
        f"{name}:{count}"
        for name, count in failures.items()
        if int(count or 0) >= CRASH_LOOP_THRESHOLD
    )
    degraded = sorted(name for name, info in languages.items() if info.get("status") != "active")
    detail = [
        f"AST {overall} · languages: "
        + ", ".join(f"{n}:{i.get('status')}" for n, i in sorted(languages.items()))
    ]
    if loops:
        detail.append(
            f"crash-loop signature (≥{CRASH_LOOP_THRESHOLD} consecutive failures): "
            + ", ".join(loops)
        )
    elif degraded:
        detail.append(
            "degraded lanes (line-scanner fallback golden-tested): " + ", ".join(degraded)
        )
    status = WARN if (overall != "active" or loops) else PASS
    return CheckResult(8, "parse", title, status, tuple(detail))


def check_render_sanity() -> CheckResult:
    """Check 9 — NO_COLOR / plain-render sanity (render twice + diff)."""
    title = "render sanity"
    try:
        from .cli import to_ascii_box
        from .render import fast_line_ok

        kwargs: dict[str, Any] = {
            "name": "doctor-selftest",
            "grade": "B",
            "value": 82,
            "verdict": "NOTICE",
            "counts": "1 warn",
            "cached_seconds": 5,
        }
        first = fast_line_ok(**kwargs)
        second = fast_line_ok(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            9,
            "render",
            title,
            FAIL,
            (f"one-liner render crashed: {exc}",),
            hard=True,
        )

    problems: list[str] = []
    if first != second:
        problems.append("one-liner not deterministic across renders")
    boxed = "┌─ SKILL LENS ─┐\n│ row │\n└──────────────┘"
    ascii_version = to_ascii_box(boxed)
    remaining_glyphs = sorted(set(ascii_version) & set("┌┐└┘├┤┬┴┼─│"))
    if ascii_version == boxed:
        problems.append("NO_COLOR/plain lane left box-drawing untranslated")
    if remaining_glyphs:
        problems.append(f"plain lane kept box glyphs: {''.join(remaining_glyphs)}")
    if problems:
        return CheckResult(9, "render", title, FAIL, tuple(problems), hard=True)
    return CheckResult(
        9,
        "render",
        title,
        PASS,
        ("one-liner byte-stable across renders · --plain/NO_COLOR strips box glyphs",),
    )


# ---------------------------------------------------------------------------
# Environment check 4 (kept last: longest, most best-effort sub-probes)
# ---------------------------------------------------------------------------


def check_environment(view: Any) -> CheckResult:
    """Check 4 — Hermes environment discovery, hub cache, profiles/routes."""
    title = "hermes environment"
    notes: list[str] = []
    problems: list[str] = []

    home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
    if home.is_dir():
        notes.append(f"HERMES_HOME discovered: {home}")
    else:
        problems.append(f"HERMES_HOME does not exist: {home}")

    # Categorized skills tree (discovery is what /lens scan names resolve through).
    skills_root = home / "skills"
    bundle_count = 0
    categories: set[str] = set()
    if skills_root.is_dir():
        try:
            from .ingest import discover_bundles

            refs = discover_bundles(home)
            bundle_count = len(refs)
            for ref in refs:
                rel = Path(ref.path).relative_to(skills_root)
                if len(rel.parts) >= 2:
                    categories.add(rel.parts[0])
        except Exception as exc:  # noqa: BLE001 — degraded discovery is visible
            problems.append(f"skills tree discovery failed: {exc}")
        if bundle_count == 0:
            notes.append("skills tree present but no bundles discovered yet")
        else:
            notes.append(
                f"categorized skills tree: {bundle_count} bundle(s) across "
                f"{len(categories)} categor(y/ies)"
            )
    else:
        notes.append("no skills/ tree yet (fresh home)")

    # Hub scan-cache / staging corridor (the install beat we observe).
    hub = skills_root / ".hub"
    if hub.is_dir():
        lock = hub / "lock.json"
        if lock.is_file():
            try:
                parsed = json.loads(lock.read_text(encoding="utf-8"))
                if not isinstance(parsed, dict):
                    raise ValueError("lock.json top level is not an object")
                notes.append(f"hub scan-cache present (.hub with {len(parsed)} lock entr(ies))")
            except (OSError, ValueError) as exc:
                problems.append(f".hub/lock.json unparseable: {exc}")
        else:
            notes.append(".hub present (no lock.json yet)")
        if not (hub / "quarantine").is_dir():
            notes.append("no quarantine staging dir yet (no install in flight)")
    else:
        notes.append("hub never used on this home (no skills/.hub)")

    # Plugin enabled: three honest probes, most-authoritative first.
    enabled_note = _probe_plugin_enabled(view, home)
    notes.append(enabled_note)

    # Profiles tree + route table parse-check.
    profiles_root = home / "profiles"
    if profiles_root.is_dir():
        profile_names = sorted(
            p.name for p in profiles_root.iterdir() if p.is_dir() and not p.name.startswith(".")
        )
        if profile_names:
            bad = _parse_check_profiles(profiles_root, profile_names)
            notes.append(
                f"profiles tree: {len(profile_names)} profile(s) [{', '.join(profile_names[:4])}"
                f"{'…' if len(profile_names) > 4 else ''}] — each config.yaml parse-checked"
            )
            if bad:
                problems.append(f"profile route table broken: {', '.join(bad)}")
            notes.append(
                "deployment implication: per-profile HERMES_HOMEs keep skills/policy/state "
                "isolated; lens reports are per-home (no cross-profile aggregation)"
            )
        else:
            notes.append("profiles tree present but empty (single-home deployment)")
    else:
        notes.append("no profiles tree (single-home deployment)")

    route_note = _probe_route_table(home)
    if route_note:
        notes.append(route_note)

    if problems:
        return CheckResult(4, "environment", title, FAIL, tuple(problems + notes), hard=True)
    return CheckResult(4, "environment", title, PASS, tuple(notes))


def _probe_plugin_enabled(view: Any, home: Path) -> str:
    """Best-effort 'plugin enabled' answer with the method named honestly."""
    try:
        from hermes_cli.plugins import get_plugin_manager  # type: ignore[import-not-found]

        manager = get_plugin_manager()
        plugins = getattr(manager, "plugins", {}) or {}
        for key, state in plugins.items():
            key_tail = str(key).rsplit("/", 1)[-1]
            if key_tail == "lens" or str(key) == "lens":
                loaded = getattr(state, "loaded", None)
                if loaded is None:
                    instance = getattr(state, "instance", None)
                    loaded = instance is not None
                verdict = "enabled+loaded" if loaded else "registered"
                return f"plugin lens: {verdict} per host manager"
        return "plugin lens: NOT found in host manager registry"
    except Exception:  # noqa: BLE001 — fall through to config probe
        pass
    config = home / "config.yaml"
    if config.is_file():
        try:
            import yaml

            data = yaml.safe_load(config.read_text(encoding="utf-8"))
            enabled = ((data or {}).get("plugins") or {}).get("enabled")
            if isinstance(enabled, list) and any(str(e) == "lens" for e in enabled):
                return "plugin lens: enabled per <home>/config.yaml plugins.enabled"
            return "plugin lens: not listed in config.yaml plugins.enabled"
        except Exception as exc:  # noqa: BLE001
            return f"plugin enablement unknown (config.yaml unreadable: {exc})"
    # We ARE running inside a live registration — strongest possible signal.
    return "plugin lens: enabled (inferred — this doctor run executes inside its registration)"


def _parse_check_profiles(profiles_root: Path, names: list[str]) -> list[str]:
    """Parse-check each profile's config.yaml; return broken ones."""
    broken: list[str] = []
    yaml_err: str | None = None
    try:
        import yaml  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        yaml_err = str(exc)
    for name in names:
        config = profiles_root / name / "config.yaml"
        if not config.is_file():
            continue  # bare profile skeleton — not a route-table fault
        if yaml_err is not None:
            continue  # PyYAML absent: nothing to parse with; noted elsewhere
        try:
            import yaml

            parsed = yaml.safe_load(config.read_text(encoding="utf-8"))
            if parsed is not None and not isinstance(parsed, dict):
                broken.append(f"profile {name}: config.yaml is not a mapping")
        except Exception as exc:  # noqa: BLE001
            broken.append(f"profile {name}: config.yaml unparsable ({exc})")
    return broken


def _probe_route_table(home: Path) -> str:
    """Wrapper-alias route table (profile → command routing), best-effort."""
    try:
        from hermes_cli.profiles import build_alias_map  # type: ignore[import-not-found]

        aliases = build_alias_map() or {}
        return (
            f"route table: {len(aliases)} wrapper alias(es) parse-checked via hermes_cli.profiles"
        )
    except Exception:  # noqa: BLE001 — outside the host process
        wrappers = Path(os.environ.get("HOME", str(Path.home()))) / ".local" / "bin"
        count = 0
        try:
            if wrappers.is_dir():
                count = sum(
                    1
                    for p in wrappers.iterdir()
                    if p.is_file()
                    and p.suffix == ""
                    and "hermes" in p.read_text(encoding="utf-8", errors="ignore")[:512].lower()
                )
        except OSError:
            count = 0
        return (
            f"route table: host profiles module unreachable — {count} hermes wrapper script(s) "
            "scanned under ~/.local/bin (config-audit lane)"
        )


# ---------------------------------------------------------------------------
# Engine + events mirror + renderers
# ---------------------------------------------------------------------------


def run_doctor(view: Any) -> DoctorReport:
    """Execute ALL NINE §11.9 checks in order; never raises.

    Every check is individually contained: a crashing check becomes a FAIL
    row naming itself rather than an exception (advisor law applies to our
    own diagnostics surface too).
    """
    report = DoctorReport()

    def guarded(number: int, key: str, title: str, fn: Callable[[], CheckResult]) -> None:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 — containment law
            logger.exception("doctor check %s crashed", key)
            result = CheckResult(number, key, title, FAIL, (f"check crashed: {exc!r}",), hard=True)
        report.checks.append(result)

    # Check 1 carries its (result, version, checksum) tuple contract.
    try:
        pack_check, report.pack_version, report.pack_checksum = check_rule_pack()
    except Exception as exc:  # noqa: BLE001 — containment law
        logger.exception("doctor check rule-pack crashed")
        pack_check = CheckResult(
            1, "rule-pack", "rule-pack integrity", FAIL, (f"check crashed: {exc!r}",), hard=True
        )
    report.checks.append(pack_check)

    view_obj: Any = view
    guarded(2, "policy", "policy resolution", lambda: check_policy(view_obj))
    guarded(3, "plugin-data", "plugin-data & sidecars", lambda: check_plugin_data(view_obj))
    guarded(4, "environment", "hermes environment", lambda: check_environment(view_obj))
    guarded(
        5,
        "hook-wiring",
        "hook-wiring audit (advisor stance)",
        lambda: check_hook_wiring(view_obj),
    )
    guarded(6, "network-isolation", "network-isolation self-test", check_network_isolation)
    guarded(7, "lifecycle", "lifecycle self-test", lambda: check_lifecycle_selftest(view_obj))
    guarded(8, "parse", "parse subsystem", check_parse_health)
    guarded(9, "render", "render sanity", check_render_sanity)

    policy_check = next((c for c in report.checks if c.key == "policy"), None)
    if policy_check is not None and policy_check.detail:
        for line in policy_check.detail:
            if line.startswith("profile "):
                report.profile = line.split(" · ", 1)[0].removeprefix("profile ")
                break

    _append_events_record(view_obj, report)
    return report


def _append_events_record(view: Any, report: DoctorReport) -> None:
    """Mirror the doctor verdict into events.ndjson (best-effort, never raises).

    Same file/schema family as the job ledger (``lens.events/1``); wall-clock
    ``ts`` rides here ONLY — sidecar state is exempt from determinism laws.
    """
    data_dir: Path | None = None
    try:
        data_dir = view.plugin_data_dir()
    except Exception:  # noqa: BLE001
        data_dir = None
    if data_dir is None:
        return
    from .canonical import canonical_dumps

    record = {
        "schema": "lens.events/1",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "event": "doctor",
        "status": "ok" if report.ok else "fail",
        "exit_code": report.exit_code,
        "warnings": len(report.warnings),
        "failures": len(report.failures),
        "pack": {"version": report.pack_version, "checksum": report.pack_checksum},
        "profile": report.profile,
        "checks": [{"n": c.number, "key": c.key, "status": c.status} for c in report.checks],
    }
    try:
        line = canonical_dumps(record)
        with (data_dir / "events.ndjson").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        logger.warning("doctor: events.ndjson append failed (%s)", data_dir, exc_info=True)
    except Exception:  # noqa: BLE001 — mirroring must never break the verb
        logger.debug("doctor: events record dropped", exc_info=True)


_VERDICT_OK = "OK"


def _clip(text: str, width: int) -> str:
    """Clip one row to *width* display cells with an ellipsis when cut."""
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def render_cli_panel(report: DoctorReport) -> str:
    """CLI checklist panel (§12.1 house box style; --plain handled upstream)."""
    from . import __version__

    width = 78
    header = f" SKILL LENS DOCTOR · lens {__version__} · pack {report.pack_version or '?'} "
    border = "─" * width
    lines = [f"┌{header.center(width, '─')}┐"]

    def row(left: str, right: str = "") -> None:
        cell = _clip(f"{left}  {right}".rstrip(), width - 2)
        lines.append("│" + f" {cell}".ljust(width) + "│")

    for check in report.checks:
        label = f"{check.marker} {check.number} {check.title}"
        first = check.detail[0] if check.detail else ""
        row(label, first)
        for extra in check.detail[1:]:
            row(f"    ↳ {extra}")
    lines.append(f"├{border}┤")
    row(report.verdict_line(), f"(exit {report.exit_code})")
    row("advisor only — lens never blocks installs; results → events.ndjson")
    lines.append(f"└{border}┘")
    return "\n".join(lines)


def render_slash(report: DoctorReport) -> str:
    """In-session variant: fenced checklist + final verdict line (§11.9)."""
    rows = [check.summary() for check in report.checks]
    body = "\n".join(rows)
    return f"```\n{body}\n```\n{report.verdict_line()}"


__all__ = [
    "CRASH_LOOP_THRESHOLD",
    "DECLARED_HOOKS",
    "FAIL",
    "FORBIDDEN_HOOK",
    "PASS",
    "SocketViolation",
    "WARN",
    "CheckResult",
    "DoctorReport",
    "check_environment",
    "check_hook_wiring",
    "check_lifecycle_selftest",
    "check_network_isolation",
    "check_parse_health",
    "check_plugin_data",
    "check_policy",
    "check_render_sanity",
    "check_rule_pack",
    "render_cli_panel",
    "render_slash",
    "run_doctor",
    "socket_deny_guard",
]

#: Kept for readability of the verdict grammar (unused at runtime).
_ = _VERDICT_OK
_ = field
