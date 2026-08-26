# Known limitations — honest boundaries (v0.9)

Every entry states what is NOT possible today, why (with host-source ground
truth), and what ships instead. Advisor-safest framing throughout.

## L1 — Delivered-result stat lines cannot print from the worker thread (no plugin terminal-print seam)

**What the spec hoped for (SPEC §11.5, row "CLI interactive session"):**
when a queued cold scan finishes on the lens worker thread, a delivered
summary line prints directly into an interactive CLI session — the
established host pattern for background summaries.

**Ground truth (verified this phase against `/usr/local/lib/hermes-agent`):**

- The precedent is REAL but INTERNAL: `cli.py::_cprint` (:3613) routes
  cross-thread prints through prompt_toolkit's ``run_in_terminal`` via
  ``loop.call_soon_threadsafe`` (:3619–3710). That is how the self-improvement
  background review's summary reaches the screen.
- It is **not plugin-accessible**: `_cprint` is module-private to
  `hermes_cli/cli.py` with no export; `PluginContext`
  (`hermes_cli/plugins.py:1393–2216`) exposes registration seams
  (`register_hook/command/cli_command/tool/context_engine/...`),
  config/state, `spawn_task`, `inject_message`, `platform_actions`, `llm`,
  `call_mcp` — **no print/notify/toast surface of any kind**.
- `VALID_HOOKS` (`plugins.py:161`) contains no output hook;
  `transform_terminal_output` transforms the agent's terminal *tool* results
  (`tools/terminal_tool.py:3467`) — not a plugin print channel.
- The nearest lane, `PluginContext.inject_message` (:1973), queues a
  USER-role message that starts/interrupts an agent turn. Using it for scan
  completions would fabricate conversation turns — intrusive, off-lane, and
  contrary to the observer stance. Not used.

**What ships instead (the §11.5 pull row, already normative):**

1. Every job transition mirrors durably into `<plugin-data>/lens/
   events.ndjson` (`scan_queued` / `scan_started` / `scan_ready` /
   `scan_failed` / `scan_coalesced`).
2. Any later `/lens` invocation prepends the ready banner —
   `1 report ready: <name> (scanned HH:MM:SS)` or
   `N reports ready: <a>, <b> …` — until `/lens report <name>` pulls it
   (mark_fetched clears readiness).
3. `/lens report` surfaces failed jobs' one-line reasons and still-queued
   jobs as format-B lines when no artifact exists yet.

Gateway proactive push stays unavailable for the same reason (no plugin
push API; PLAN §0 Concurrency row records this as the H13 limitation).
DeliveryRouter-based push remains a v1.0 stretch only if the owner elects
the coupling. If the host ever grows a plugin-accessible terminal-print
seam, the worker-side printer slots in behind `JobManager._execute`'s
terminal transition without contract changes.

## L2 — Hub view cannot appear inside the install confirm beat itself

The confirm beat belongs to `hermes skills install`
(`skills_hub.py::do_install`), which invokes NO plugin hooks
(docs/host-contract.md §5). Lens therefore cannot inject its role-labeled
panel between the guard report and the y/N prompt. `/lens hub` renders the
same information ON DEMAND while bundles sit staged in quarantine (the
prompt pauses there indefinitely for human input, so a parallel
`/lens hub` invocation lands well within the beat). The fast-path line per
staged bundle answers inline when cached (<200 ms); cold bundles enqueue on
the shared worker and answer with format-B pointers.

## L3 — Hub-view chat overflow does not persist artifacts

`render_chat_compact` spills oversized reports to
`<plugin-data>/lens/reports/<name>-<hash8>.txt`. The hub view instead
collapses (provenance notes dropped → entries truncated behind a
count line → counts-only body) because every staged bundle's FULL report is
already reachable through its own pointer line (`/lens report <name>`);
persisting a second artifact would duplicate that trail without adding
reachability.
