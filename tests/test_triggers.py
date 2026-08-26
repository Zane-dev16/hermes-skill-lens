"""Phase 4 host-contract tests — triggers replay VERBATIM emit-site shapes.

Every payload below is transcribed from the host tree documented in
``docs/host-contract.md`` (ground truth: ``/usr/local/lib/hermes-agent``,
line numbers recorded there):

- ``on_skill_lifecycle``  — tools/skill_usage.py:829-840 via
  ``_emit_skill_lifecycle`` (funnel :811); kwargs include
  ``telemetry_schema_version`` injected by hermes_cli/plugins.py:5133.
- ``post_tool_call``      — model_tools.py:1172-1187 (funnel :1136).
- ``transform_tool_result`` — model_tools.py:1563-1577 (first valid string
  return wins; non-string returns ignored).

IMPORTANT (dual-import law): ``plugin_module`` is loaded exactly the way the
host does — namespace package ``hermes_plugins.lens_test_spine`` — so the
wired handlers close over THAT instance's ``skill_lens.*`` modules. All seam
assertions here go through :func:`seams`, never through top-level imports.

Advisor laws pinned here: handlers return None-or-str, never raise (hostile /
truncated / malformed payloads included), never register ``pre_tool_call``,
and the fast path stays inside its <200 ms budget (perf_counter-asserted).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SKILL_NAME = "web-design-guidelines"
MINIMAL_SKILL_MD = (
    "---\n"
    f"name: {SKILL_NAME}\n"
    "description: Ship accessible interfaces with design-system tokens.\n"
    "---\n"
    "Body text.\n"
)

#: OBSERVER_SCHEMA_VERSION is injected by PluginManager.invoke_hook
#: (hermes_cli/plugins.py:5133). Value opaque to us; carried verbatim.
TELEMETRY = {"telemetry_schema_version": 1}


# ---------------------------------------------------------------------------
# Fixtures — a scratch Hermes home + a fully registered plugin instance
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_singletons(plugin_module: Any):
    """Reset every process-wide seam around each test (instance-bound).

    Top-level singletons too, in case another suite's leftovers linger — but
    the wired plugin ALWAYS gets its own instance reset via *plugin_module*.
    """
    import importlib

    tl = getattr(plugin_module, "skill_lens", None)
    if tl is None:  # not yet imported (register() imports it lazily)
        tl = importlib.import_module(f"{plugin_module.__name__}.skill_lens")
    prefix = tl.__name__
    sl = tl.slash if hasattr(tl, "slash") else importlib.import_module(f"{prefix}.slash")
    bs = (
        tl.bootstrap if hasattr(tl, "bootstrap") else importlib.import_module(f"{prefix}.bootstrap")
    )
    tl = tl.triggers if hasattr(tl, "triggers") else importlib.import_module(f"{prefix}.triggers")
    sl.reset_shared_cache()
    sl.reset_shared_jobs()
    bs.reset_context()
    tl.reset_stats()
    yield
    sl.reset_shared_jobs()
    sl.reset_shared_cache()
    bs.reset_context()
    tl.reset_stats()


@pytest.fixture
def lens_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Scratch HERMES_HOME with one categorized skill bundle."""
    home = tmp_path / "hermes-home"
    skill_dir = home / "skills" / "tools" / SKILL_NAME
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(MINIMAL_SKILL_MD, encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


@pytest.fixture
def registered(fake_ctx: Any, plugin_module: Any, lens_home: Path) -> SimpleNamespace:
    """Run the real register() path; expose handlers + instance-bound seams."""
    plugin_module.register(fake_ctx)
    assert fake_ctx.registered_hook_names == [
        "on_skill_lifecycle",
        "post_tool_call",
        "transform_tool_result",
    ]
    return SimpleNamespace(
        handlers=dict(fake_ctx.registered_hooks),
        triggers=plugin_module.skill_lens.triggers,
        slash=plugin_module.skill_lens.slash,
        bootstrap=plugin_module.skill_lens.bootstrap,
        ctx=fake_ctx,
    )


def lifecycle_payload(action: str, **overrides: Any) -> dict[str, Any]:
    """Exact shape emitted at tools/skill_usage.py:829-840."""
    payload: dict[str, Any] = {
        "action": action,
        "skill_name": SKILL_NAME,
        "provenance": "agent_created",
        "task_id": "",
        "session_id": "",
        "use_count": None,
        "reused": None,
        "reuse_after_patch": None,
        **TELEMETRY,
    }
    payload.update(overrides)
    return payload


def tool_payload(
    hook: str,
    *,
    action: str = "create",
    result: Any = f'{{"success": true, "name": "{SKILL_NAME}"}}',
    status: str = "ok",
    **overrides: Any,
) -> dict[str, Any]:
    """Exact shapes from model_tools.py: post_tool_call :1172-1187 and
    transform_tool_result :1563-1577 (identical kwargs, different contract)."""
    payload: dict[str, Any] = {
        "tool_name": "skill_manage",
        "args": {"action": action, "name": SKILL_NAME, "content": MINIMAL_SKILL_MD},
        "result": result,
        "task_id": "t-1",
        "session_id": "s-1",
        "tool_call_id": "call-1",
        "turn_id": "turn-1",
        "api_request_id": "req-1",
        "duration_ms": 12,
        "status": status,
        "error_type": None,
        "error_message": None,
        **TELEMETRY,
    }
    if hook == "post_tool_call":
        payload["middleware_trace"] = []
    payload.update(overrides)
    return payload


def skill_target(ns: SimpleNamespace) -> Path:
    return Path(ns.slash.hermes_home()) / "skills" / "tools" / SKILL_NAME


def prime_cache(ns: SimpleNamespace) -> None:
    """Fill the fast-path cache exactly the way the worker thread does."""
    view = ns.bootstrap.get_context()
    assert view is not None
    outcome = ns.slash.run_scan(
        skill_target(ns),
        cache=ns.slash.shared_cache(),
        plugin_data_dir=view.plugin_data_dir(),
    )
    assert outcome["ok"] is True


# ---------------------------------------------------------------------------
# Registration contract
# ---------------------------------------------------------------------------


def test_wiring_registers_exactly_three_observer_hooks(fake_ctx: Any, plugin_module: Any) -> None:
    plugin_module.register(fake_ctx)
    assert sorted(fake_ctx.registered_hook_names) == sorted(
        ("on_skill_lifecycle", "post_tool_call", "transform_tool_result")
    )


def test_zero_pre_tool_call_registrations_extended(fake_ctx: Any, plugin_module: Any) -> None:
    """Extended smoke law: blocking hooks never appear, even after re-register."""
    plugin_module.register(fake_ctx)
    plugin_module.register(fake_ctx)
    assert fake_ctx.registered_hook_names.count("pre_tool_call") == 0
    assert set(fake_ctx.registered_hook_names) <= {
        "on_skill_lifecycle",
        "post_tool_call",
        "transform_tool_result",
    }


# ---------------------------------------------------------------------------
# on_skill_lifecycle replay (emit-site shapes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["created", "installed", "loaded", "used", "patched"])
def test_lifecycle_actions_replay_never_raise_and_return_none(
    registered: SimpleNamespace, action: str
) -> None:
    handler = registered.handlers["on_skill_lifecycle"]
    assert handler(**lifecycle_payload(action)) is None
    snapshot = registered.triggers.stats_snapshot()
    assert snapshot["lifecycle_events"] == 1
    assert snapshot["errors"] == 0


@pytest.mark.parametrize("action", ["created", "installed", "loaded", "used", "patched"])
def test_lifecycle_cold_miss_enqueues_one_scan_per_hash(
    registered: SimpleNamespace, action: str
) -> None:
    handler = registered.handlers["on_skill_lifecycle"]
    handler(**lifecycle_payload(action))
    first = registered.triggers.stats_snapshot()
    assert first["enqueues"] == 1
    # Same bytes again (the sibling post_tool_call beat): coalesces, no 2nd scan.
    handler(**lifecycle_payload(action))
    second = registered.triggers.stats_snapshot()
    assert second["enqueues"] == 1
    assert second["coalesced"] == 1


def test_lifecycle_unknown_action_ignored_cheaply(registered: SimpleNamespace) -> None:
    handler = registered.handlers["on_skill_lifecycle"]
    # set_state emits archived/stale/restored (skill_usage.py:1024) — not ours.
    assert handler(**lifecycle_payload("archived")) is None
    assert handler(**lifecycle_payload("edited")) is None  # bump_patch edit variant
    snapshot = registered.triggers.stats_snapshot()
    assert snapshot["lifecycle_events"] == 0
    assert snapshot["enqueues"] == 0


def test_lifecycle_cache_hit_builds_format_a_inline(
    registered: SimpleNamespace,
) -> None:
    prime_cache(registered)
    handler = registered.handlers["on_skill_lifecycle"]
    start = time.perf_counter()
    assert handler(**lifecycle_payload("used")) is None
    elapsed = time.perf_counter() - start
    stats = registered.triggers.stats_snapshot()
    assert stats["cache_hits"] == 1
    assert stats["enqueues"] == 0
    assert elapsed < registered.triggers.FAST_PATH_BUDGET_SECONDS


# ---------------------------------------------------------------------------
# post_tool_call replay — self-filtering authoring beat
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name", ["write_file", "bash", "read_file", "", None])
def test_post_tool_call_non_skill_manage_returns_instantly(
    registered: SimpleNamespace, tool_name: Any
) -> None:
    handler = registered.handlers["post_tool_call"]
    payload = tool_payload("post_tool_call")
    payload["tool_name"] = tool_name
    start = time.perf_counter()
    assert handler(**payload) is None
    assert time.perf_counter() - start < 0.05
    assert registered.triggers.stats_snapshot()["post_tool_seen"] == 0


@pytest.mark.parametrize("action", ["create", "edit", "patch", "write_file", "remove_file"])
def test_post_tool_call_mutating_actions_enqueue(registered: SimpleNamespace, action: str) -> None:
    handler = registered.handlers["post_tool_call"]
    assert handler(**tool_payload("post_tool_call", action=action)) is None
    assert registered.triggers.stats_snapshot()["enqueues"] == 1


@pytest.mark.parametrize("action", ["delete", "read", ""])
def test_post_tool_call_non_mutating_actions_ignored(
    registered: SimpleNamespace, action: str
) -> None:
    handler = registered.handlers["post_tool_call"]
    assert handler(**tool_payload("post_tool_call", action=action)) is None
    stats = registered.triggers.stats_snapshot()
    assert stats["post_tool_seen"] == 1  # seen but not handled
    assert stats["post_tool_handled"] == 0
    assert stats["enqueues"] == 0


def test_post_tool_call_error_status_still_scans_current_bytes(
    registered: SimpleNamespace,
) -> None:
    """Observer lane ignores status (queue side effect is silent); only the
    transform lane refuses to touch failures."""
    handler = registered.handlers["post_tool_call"]
    payload = tool_payload("post_tool_call", status="error", error_type="tool_error")
    assert handler(**payload) is None
    assert registered.triggers.stats_snapshot()["post_tool_handled"] == 1


# ---------------------------------------------------------------------------
# transform_tool_result replay — append-only sober notice lane
# ---------------------------------------------------------------------------


def test_transform_cold_miss_appends_queued_notice_preserving_result(
    registered: SimpleNamespace,
) -> None:
    original = f'{{"success": true, "name": "{SKILL_NAME}"}}'
    handler = registered.handlers["transform_tool_result"]
    returned = handler(**tool_payload("transform_tool_result", result=original))
    assert isinstance(returned, str)
    assert returned.startswith(original)  # APPEND-ONLY: original bytes preserved
    notice = returned[len(original) :]
    assert notice.startswith("\n") and "\n" not in notice[1:]  # exactly ONE line
    line = notice[1:]
    assert len(line) <= registered.triggers.NOTICE_MAX_CHARS
    assert line.count("\n") == 0  # notices are ONE line by construction
    assert line.startswith("lens scan queued:")
    assert "/lens report" in line
    assert "/100" not in line and "score" not in line.lower()  # no scores, ever


def test_transform_cache_hit_notice_carries_verdict_word_only(
    registered: SimpleNamespace,
) -> None:
    prime_cache(registered)
    entry = registered.slash.shared_cache().latest_by_name(SKILL_NAME)
    assert entry is not None
    original = '{"success": true}'
    returned = registered.handlers["transform_tool_result"](
        **tool_payload("transform_tool_result", result=original)
    )
    assert isinstance(returned, str)
    line = returned[len(original) + 1 :]
    assert line.startswith(f"lens ok {SKILL_NAME} · verdict ")
    verdict_word = line.split(" · verdict ", 1)[1].split(" · ", 1)[0]
    assert verdict_word in {"clean", "notice", "warn", "alert"}
    assert "/100" not in line  # grade/score numerics never reach automation
    assert all(ch.isprintable() or ch == "\n" for ch in line)


def test_transform_kill_switch_notify_false_disables_lane(
    registered: SimpleNamespace,
) -> None:
    handler = registered.handlers["transform_tool_result"]
    registered.ctx.set_config("notify", False)
    assert handler(**tool_payload("transform_tool_result")) is None
    registered.ctx.set_config("notify", "false")  # host settings are untyped
    assert handler(**tool_payload("transform_tool_result")) is None
    stats = registered.triggers.stats_snapshot()
    assert stats["notices_suppressed"] == 2
    assert stats["notices_appended"] == 0


def test_transform_notify_defaults_on(registered: SimpleNamespace) -> None:
    """No config set anywhere ⇒ the notice lane is live (default true)."""
    out = registered.handlers["transform_tool_result"](**tool_payload("transform_tool_result"))
    assert out is not None
    assert registered.triggers.stats_snapshot()["notices_appended"] == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        tool_payload("transform_tool_result", status="error", error_type="tool_error"),
        tool_payload("transform_tool_result", result='{"success": false, "error": "nope"}'),
        tool_payload("transform_tool_result", result='{"error": "boom"}'),
        tool_payload("transform_tool_result", result=None),
        tool_payload("transform_tool_result", result=b"bytes"),  # type: ignore[dict-item]
        tool_payload("transform_tool_result", args=None),
        tool_payload("transform_tool_result", args="hostile"),
        tool_payload("transform_tool_result", args={"action": "delete", "name": SKILL_NAME}),
        tool_payload("transform_tool_result", args={"action": "create"}),
    ],
)
def test_transform_declines_to_decorate_failures_and_hostile_args(
    registered: SimpleNamespace, kwargs: dict[str, Any]
) -> None:
    assert registered.handlers["transform_tool_result"](**kwargs) is None


def test_transform_is_idempotent_while_scan_pending(registered: SimpleNamespace) -> None:
    original = '{"success": true}'
    handler = registered.handlers["transform_tool_result"]
    once = handler(**tool_payload("transform_tool_result", result=original))
    twice = handler(**tool_payload("transform_tool_result", result=original))
    assert isinstance(once, str) and isinstance(twice, str)
    assert once.count("lens scan queued:") == 1
    assert twice.endswith(once[len(original) :]) and len(twice) == len(once)


# ---------------------------------------------------------------------------
# Fast-path latency budget (perf_counter-asserted, PLAN §0 Triggers row)
# ---------------------------------------------------------------------------


def test_fast_path_budget_hit_and_miss(registered: SimpleNamespace) -> None:
    post = registered.handlers["post_tool_call"]
    start = time.perf_counter()
    assert post(**tool_payload("post_tool_call")) is None
    miss_elapsed = time.perf_counter() - start
    assert miss_elapsed < registered.triggers.FAST_PATH_BUDGET_SECONDS

    prime_cache(registered)

    start = time.perf_counter()
    assert post(**tool_payload("post_tool_call")) is None
    hit_elapsed = time.perf_counter() - start
    assert hit_elapsed < registered.triggers.FAST_PATH_BUDGET_SECONDS
    stats = registered.triggers.stats_snapshot()
    assert stats["overruns"] == 0


def test_worker_eventually_completes_queued_trigger_scan(
    registered: SimpleNamespace,
) -> None:
    """End-to-end §11.5 sequence: trigger enqueues, worker fills jobs.json."""
    handler = registered.handlers["on_skill_lifecycle"]
    assert handler(**lifecycle_payload("created")) is None
    jobs = registered.slash.shared_jobs()
    job = jobs.latest_job_for_name(SKILL_NAME)
    assert job is not None
    final = jobs.wait_for_state(job.job_id, {"ready", "failed"}, timeout=10.0)
    assert final is not None and final.state == "ready"
    events_path = jobs.events_path
    assert events_path.is_file()
    assert "scan_queued" in events_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Hostile / malformed / truncated payloads — advisor law under fire
# ---------------------------------------------------------------------------


HOSTILE_PAYLOADS = [
    {},
    {"action": None, "skill_name": None},
    {"action": 42, "skill_name": 3.14},
    {"action": "created", "skill_name": ""},
    {"action": "created", "skill_name": "../../etc/passwd"},
    {"action": "x" * 10000, "skill_name": "y" * 10000},
    {"tool_name": None, "args": None, "result": None},
    {"tool_name": "skill_manage", "args": [], "result": []},
    {"tool_name": "skill_manage", "args": {"action": "create", "name": None}},
    {"tool_name": "skill_manage", "args": {"action": "create", "name": 7}, "result": "{"},
    {"tool_name": "skill_manage", "args": {}, "result": '{"truncated...'},
]


@pytest.mark.parametrize("hook", ["on_skill_lifecycle", "post_tool_call"])
@pytest.mark.parametrize("payload", HOSTILE_PAYLOADS)
def test_observers_survive_hostile_payloads(
    registered: SimpleNamespace, hook: str, payload: dict[str, Any]
) -> None:
    handler = registered.handlers[hook]
    fused = dict(payload)
    fused.setdefault("telemetry_schema_version", 1)
    try:
        result = handler(**fused)  # must NEVER raise into the host
    except Exception as exc:  # pragma: no cover — failure IS the bug
        pytest.fail(f"{hook} raised into host: {exc!r}")
    assert result is None


@pytest.mark.parametrize("payload", HOSTILE_PAYLOADS)
def test_transform_survives_hostile_payloads(
    registered: SimpleNamespace, payload: dict[str, Any]
) -> None:
    handler = registered.handlers["transform_tool_result"]
    fused = dict(payload)
    fused.setdefault("telemetry_schema_version", 1)
    result = handler(**fused)  # must NEVER raise into the host
    assert result is None or isinstance(result, str)


def test_handlers_return_none_or_str_only(registered: SimpleNamespace) -> None:
    """Contract sweep across happy + hostile inputs for all three lanes."""
    observers = (
        registered.handlers["on_skill_lifecycle"],
        registered.handlers["post_tool_call"],
    )
    for handler in observers:
        assert handler() is None
        assert handler(telemetry_schema_version=99) is None
    transform = registered.handlers["transform_tool_result"]
    for extra in ({}, {"result": "{}"}):
        out = transform(**extra)
        assert out is None or isinstance(out, str)
    assert json.loads('{"ok": true}') == {"ok": True}  # sanity: suite alive
