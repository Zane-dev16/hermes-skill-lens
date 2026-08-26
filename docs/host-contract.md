# Host contract — consumed hooks, verbatim emit sites, payload shapes

**Status:** Phase 4 ground truth. Every shape below was transcribed from the host
tree (`/usr/local/lib/hermes-agent`, verified this phase), not guessed. Line
numbers refer to that tree and are re-checked whenever the host pin moves.
Rule: **read emit sites, never guess payload shapes.**

## 0. Registration mechanics

| Seam | Host location | Shape |
| --- | --- | --- |
| `VALID_HOOKS` | `hermes_cli/plugins.py:161` | `Set[str]`; includes `pre_tool_call` (:162), `post_tool_call` (:163), `transform_tool_result` (:165), `on_skill_lifecycle` (:223). Unknown names warn-and-store (`register_hook`, plugins.py:3114–3135). |
| `ctx.register_hook(name, cb)` | `hermes_cli/plugins.py:3114` | Returns a `PluginRegistration` handle; never raises on unknown hook name (warns). We always pass names ∈ VALID_HOOKS ∩ provides_hooks. |
| dispatch | `hermes_cli/plugins.py:5104` (`PluginManager.invoke_hook`) | Callbacks invoked as `cb(**kwargs)`; narrow signatures get only declared kwargs, `**kwargs` gets all. Each callback individually try/except'd (:5139–5151) — a raise is logged by the host AND we still never raise (advisor law is ours, not leased from the host). Non-`None` returns collected into a list (:5141–5142); observers may return anything, host discards. |
| schema marker | `hermes_cli/plugins.py:5133` | `kwargs.setdefault("telemetry_schema_version", OBSERVER_SCHEMA_VERSION)` injected on every non-gateway hook ⇒ handlers MUST tolerate extra unknown kwargs (`**_`). |
| wrappers | `hermes_cli/lifecycle.py:11` (`invoke_hook`), `:25` (`has_hook`) | Emit sites import these lazily; `has_hook()` short-circuits to one dict lookup when nobody listens. |

## 1. `on_skill_lifecycle` (observer; return discarded)

Single emit funnel: `tools/skill_usage.py:811` `_emit_skill_lifecycle(...)` →
guarded by `has_hook("on_skill_lifecycle")` at **:826**, fired via
`invoke_hook("on_skill_lifecycle", ...)` at **:829–840**. Best-effort:
any failure is swallowed at :841–846.

Kwargs exactly as emitted (:829–840):

```python
action=str            # see action table below
skill_name=str        # local skill name (may contain ":" plugin prefixes)
provenance=str        # telemetry_provenance(): installed|agent_created|external|local|unknown (skill_usage.py:783)
task_id=str           # "" when absent (task_id or "")
session_id=str        # "" when absent
use_count=int|None    # only on "loaded"
reused=bool|None      # only on "loaded"
reuse_after_patch=bool|None  # only on "loaded"
# + telemetry_schema_version injected by dispatch
```

Action emit sites (all route through the funnel above):

| Action | Emitted from | Trigger in host |
| --- | --- | --- |
| `"created"` | `skill_usage.py:960` (`record_created`) | successful `skill_manage(create)` provenance persist |
| `"installed"` | `skill_usage.py:979` (`record_installed`) | Skills Hub install completes (`install_from_quarantine`) |
| `"loaded"` | `skill_usage.py:899` (`bump_use`) | skill actively used (session, slash, cron scheduler) |
| `"used"` | reserved vocabulary (SPEC §11.6); no current emit site — handled for forward-compat | — |
| `"patched"` / `"edited"` | `skill_usage.py:932` (`bump_patch`) | `skill_manage(patch | edit)` |
| `"archived"`/`"stale"`/`"restored"` | `skill_usage.py:1024` (`set_state`) | curator state changes (outside our five; ignored) |

## 2. `post_tool_call` (observer; self-filtered to `skill_manage`)

Emit funnel: `model_tools.py:1136` `_emit_post_tool_call_hook(...)`, gated on
`has_hook("post_tool_call")` at **:1165**, dispatched at **:1172–1187**.
Primary success-path call site **model_tools.py:1536** (`_emit_post_tool_call_hook(...)`
after tool dispatch, before transform lane; the :1493–1505 range is dispatch
tear-down — corrected in Phase-4 contract audit); error paths re-emit through the same funnel
(model_tools.py:1596+, cancelled-terminal variants `agent/tool_executor.py:280,325`).

Kwargs exactly as emitted (:1172–1187):

```python
tool_name=str         # function_name — WE FILTER: != "skill_manage" returns instantly
args=dict             # raw function_args of the tool call
result=Any            # final tool result (for skill_manage: JSON str, see §4)
task_id=str           # "" when absent
session_id=str        # "" when absent
tool_call_id=str
turn_id=str
api_request_id=str
duration_ms=int       # monotonic-derived dispatch latency (model_tools.py:1466)
status=str            # "ok"|"error"|"blocked"|"cancelled" — derived via _tool_result_observer_fields (model_tools.py:1115) or explicit
error_type=str|None   # e.g. "tool_error", "edit_approval_error"
error_message=str|None
middleware_trace=list[dict]
# + telemetry_schema_version injected by dispatch
```

## 3. `transform_tool_result` (append-only lane)

Emit site: **`model_tools.py:1551–1584`**, immediately after the
`post_tool_call` emit and before the result rejoins conversation context.
Gated on `has_hook("transform_tool_result")` (**:1559**); status fields derived
at :1560; dispatched at **:1563–1577**: `invoke_hook("transform_tool_result", ...)`
with kwargs:

```python
tool_name=str         # filter: act only on "skill_manage"
args=dict             # tool call args
result=Any            # the model-visible result string we may replace
task_id=str; session_id=str; tool_call_id=str; turn_id=str; api_request_id=str
duration_ms=int
status=str            # "ok"|"error" (same derivation as §2)
error_type=str|None; error_message=str|None
# + telemetry_schema_version injected
```

Return contract (host, :1568–1573): the **first valid `str` return wins and
REPLACES the result**; non-string returns are ignored; fail-open around the
whole block (:1578–1584). Precedent studied: bundled
`plugins/security-guidance/__init__.py:227–257` (`_on_transform_tool_result`)
— returns `result + "\n\n" + block`, returns `None` for non-str results and
declines to decorate error results. Skill Lens appends ONE sober ≤160-char
line (`"\n" + notice`), preserving original bytes; `None` leaves unchanged.

## 4. `skill_manage` tool surface (the beat we observe)

Definition: `tools/skill_manager_tool.py:1543`
`skill_manage(action, name, content=None, category=None, file_path=None,
file_content=None, old_string=None, new_string=None, replace_all=False,
absorbed_into=None, task_id=None, session_id=None) -> str`.

- Result: **JSON string**, success shape `{"success": true, ...}`,
  failure shapes `{"success": false, "error": <str>}` / `tool_error(...)`
  (:330–1019 passim) — so `status=="error"` payloads carry `success:false`.
- Mutating actions observed on the authoring beat: `create`, `edit`,
  `patch`, `write_file`, `remove_file` (dispatch ladder :1600–1634).
  `delete` needs no scan; gate/staging replays return early and must not
  double-trigger.
- Lifecycle coupling: create→`record_created` ("created"), patch/edit→
  `bump_patch` ("patched"/"edited") ⇒ a single in-session authoring write
  fires BOTH `post_tool_call` AND `on_skill_lifecycle`. Double-scan avoidance
  relies on bundle-hash coalescing (§11.6), not on assuming one event.

## 5. Hub staging ground truth (no-hook install seam)

`tools/skills_hub.py` contains **zero** `invoke_hook`/`register_hook` calls —
`do_install`/confirm fires NO plugin hooks; filesystem watching is the only
lane during staging.

| Path resolver | Location | Value |
| --- | --- | --- |
| `_hub_dir` | `skills_hub.py:70` | `<skills>/.hub` (env-overridable `HUB_DIR`) |
| `_lock_file` | `skills_hub.py:78` | `<hub>/lock.json` — provenance/trust resolution source (annotation-only, D-PROV/S7) |
| `_quarantine_dir` | `skills_hub.py:82` | `<hub>/quarantine` (env-overridable `QUARANTINE_DIR`) |
| `quarantine_bundle` | `skills_hub.py:3889` | writes bundle files to `<quarantine>/<name>/` pre-scan |
| `install_from_quarantine` | `skills_hub.py:3940` | moves scanned bundle into `<category>/<name>` then `record_installed` fires the lifecycle event |

Skills tree: `~/.hermes/skills/<category>/<name>/SKILL.md` (categorized;
hidden dirs `.hub`, `.trash` skipped — `hermes_cli/skills_hub.py:226`).

## 6. Config namespace

Plugin settings resolve through
`plugins.entries.lens.settings.<key>` (`hermes_cli/plugins.py`
`get_config`/`set_config`; mirrored defensively by
`skill_lens.context.PluginContextView`). Phase-4 keys:

- `notify` (default `true`): kill-switch for the `transform_tool_result`
  append-only notice lane. `false` ⇒ transform handler always returns `None`.
  Observer hooks (lifecycle/post_tool_call queue side effects) are NOT gated
  by `notify` — they are silent by construction.

## 7. Advisor invariants restated (checked by tests)

1. Zero `pre_tool_call` registrations, ever (`tests/test_register_smoke.py`).
2. Handlers accept arbitrary kwargs, never raise, return `None` or `str`.
3. Fast path budget: cache hit ⇒ one-liner built inline; miss ⇒ enqueue +
   status line; internally deadline-guarded (<200 ms; PLAN §0 Triggers row).
4. Notices: verdict word + pointer only — no scores, no emoji, no marketing;
   ≤160 chars; automation surfaces stay permanently sober (§16 default).

## 8. Terminal-print seam investigation (H13 — Phase 4 UX deliverable)

Question: can a plugin print delivered-result stat lines from a worker
thread into an interactive CLI session (the §11.5 "worker prints delivered
summary directly" row)? Answer: **no plugin-accessible seam exists**;
full evidence in `docs/limitations.md` L1.

| Probe | Location | Result |
| `run_in_terminal` precedent | `cli.py:3613–3710` (`_cprint`) | REAL but module-private to `hermes_cli/cli.py`; cross-thread prints route through prompt_toolkit `run_in_terminal` via `loop.call_soon_threadsafe`. Not exported; not on any PluginContext surface. |
| PluginContext surface audit | `hermes_cli/plugins.py:1393–2216` | Registration/config/state/spawn_task/inject_message/platform_actions/llm/call_mcp seams only — zero print/notify APIs. |
| Hook taxonomy | `VALID_HOOKS` plugins.py:161 | No output hook. `transform_terminal_output` transforms terminal TOOL results (`tools/terminal_tool.py:3467`), not a print channel. |
| Nearest lane rejected | `inject_message` plugins.py:1973 | Queues a USER-role message that starts/interrupts an agent turn — fabricates conversation turns; off-lane for stat lines. Not used. |

Consequence: v0.9 ships the honest fallback (events.ndjson + ready banner +
`/lens report` pull); the fallback is the §11.5 normative pull row verbatim.
