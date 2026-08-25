# Hook & Watch Surfaces — Architecture Decisions

**Phase:** Spec critique and architectural decisions · **Label:** hook and watch
**Scope:** How xray detects third-party skill/plugin/MCP installations and changes across Hermes, OpenCode, and Claude Code without blocking the agent loop; delivery UX; `xray doctor`, `xray watch`, editor hints; v1 vs v1.1 cut.
**Method:** Verified against live APIs — Claude Code hooks reference (code.claude.com/docs/en/hooks), OpenCode plugin docs (opencode.ai/docs/plugins), Hermes local install (`hermes hooks`, features/hooks.md, config schema), plus prior-phase docs (`threat-taxonomy.md` §2.4/§2.8/§3.2, `scoring-rubrics.md` §3 SARIF).

---

## 0. Framing correction (critique of the premise)

The phase questions bundle four mechanisms as peers. They are not:

1. **Agent-native hooks** (Claude Code / Hermes / OpenCode) are the *primary* detection surface — they carry intent (which command ran, exit status, tool args) that no filesystem signal can infer.
2. **Filesystem watching** is the *guarantee* layer — catches installs that happen outside any hooked session (another terminal, `git pull`, marketplace CLIs, closed agents). It watches **manifest hashes**, not raw inode events.
3. **Shell wrappers** and **git hooks** are rejected for v1 (§2).

Second correction: **"<200ms fast path?" and "<2s hook print?" conflate two budgets.** The right decomposition is in §5: hook overhead (must be ~zero), reconcile-no-change fast path (<200ms), scan tiers (seconds, async), delivery (channel semantics matter more than duration).

Third correction: **the "scanning…" placeholder question largely dissolves.** All three hosts own their TUI render region and give xray only append-only or structured channels (verified below). In-place spinner rewrites fight the host renderer and orphan lines. Design for *silent-until-result* with fast-path caching, not progress theater (§6).

---

## 1. Verified integration inventory

| Host | Interception points | Delivery-to-user channels | Notes verified |
| --- | --- | --- | --- |
| **Claude Code** | `PostToolUse` (supports `async: true`; `asyncRewake: true` wakes Claude on exit 2 even when idle); `PreToolUse` (blocking); `Stop`; `SessionStart` (returns `watchPaths`, `reloadSkills`, context); `FileChanged` (host-side fs watcher, matcher = literal filenames); `ConfigChange` (matcher `skills` fires on `.claude/skills/**` changes, can block) | `systemMessage` (user-visible), `additionalContext` (model-visible), `terminalSequence` (OSC notifications), stderr-on-exit-2 | Hooks run **without a controlling terminal** — cannot write `/dev/tty`; async hook output delivered next turn; `-p` sessions kill async hooks at teardown. Plugins ship `hooks/hooks.json` → distribution vehicle |
| **OpenCode** | Plugin API (TS): `tool.execute.before/after`; session events (`session.created`, `session.idle`); TUI events incl. `tui.toast.show` | Toasts (auto-expiring — safe for transient states), prompt append | Plugin = npm package / local dir registered in config; verify exact payload shapes against docs at implementation time |
| **Hermes** | Four hook systems. Best fit: **shell hooks** in `config.yaml` (`hooks:` block; `pre_tool_call`/`post_tool_call` with regex matcher; JSON on stdin→stdout; subprocess per event; consent allowlist `~/.hermes/shell-hooks-allowlist.json`). Richer: **plugin hooks** `ctx.register_hook("post_tool_call")`, plus `on_skill_lifecycle` (fires on skill state changes with `action`/`skill_name`/`provenance`) | Console output from hooks is isolated (errors logged, agent never crashes); gateway/webhook channels available | `hermes hooks doctor` already checks exec bit, allowlist, mtime drift, JSON validity, synthetic run timing — xray must be a good citizen of that contract |

Watch-target set (from taxonomy §2.4/§2.8 — these paths are what "an install happened" means):

```text
~/.claude/skills/**, <proj>/.claude/skills/**          # Claude Code skills
~/.claude/settings.json, ~/.claude.json, .mcp.json     # permissions allowlists, MCP servers
<proj>/.claude/{settings,settings.local}.json
~/.config/opencode/**, opencode plugin/package manifests
~/.hermes/skills/**, ~/.hermes/config.yaml (hooks: block),
  ~/.hermes/plugins/**, ~/.hermes/shell-hooks-allowlist.json
~/.pi/agent/skills/**, ~/.agents/skills/**              # pi-family (cheap to cover, same watcher)
AGENTS.md / CLAUDE.md / .cursorrules-class writes       # persistence class, flag-only in v1 logs
.git/hooks/* + git config core.hooksPath                # persistence watchlist
```

---

## 2. Mechanism evaluation

### 2.1 Agent-native hooks — **primary, ship in v1**

Carries the richest signal: command string, tool args, exit status (`PostToolUse` fires only on success; Hermes `post_tool_call` includes `status`). Zero polling cost. Weakness: only sees activity inside hooked sessions → pair with watcher.

- **Claude Code**: distributed as a *plugin*. Two hook entries:
  - `PostToolUse` on `Bash|PowerShell|Write|Edit` with `async: true` → parse `tool_input`, if install-shaped (writes/commands touching watch-target paths, `git clone`, marketplace installs) enqueue scan. Async means **zero added latency**, framework does the backgrounding.
  - Same handler registered secondarily with `asyncRewake: true` logic internally (or a thin wrapper): exits 2 **only** for score ≥ 0.90 findings (taxonomy §3.2 block band) so the model is woken immediately with evidence; everything else rides normal async delivery.
  - `SessionStart`: reconcile backlog (scans finished while idle/teardown-killed), emit one-line status via stdout-context, return `watchPaths` seeding `FileChanged` on the project's `.claude/skills/**`, `settings.local.json`, `.mcp.json` for in-session coverage without our daemon.
- **OpenCode**: plugin subscribing `tool.execute.after` (same install-shape predicate) firing an async scan task; results via `tui.toast.show`; `session.created` performs backlog reconcile. Fire-and-forget promise → never blocks the tool pipeline.
- **Hermes**: shell hook `post_tool_call`, matcher `terminal|write_file|patch`, script reads JSON payload, spawns detached `xray scan-enqueue`, exits 0 instantly. Installed by `xray connect hermes` (writes the `hooks:` block, requests consent allowlist entry — respecting Hermes' first-use consent model). v1.1 upgrades to a native plugin for `on_skill_lifecycle` provenance.

### 2.2 Filesystem watcher — **guarantee layer, ship in v1 (polling form)**

Three sub-decisions:

**(a) Hash-first, events-second.** Unit of truth = content hash of the manifest set above (~dozens of small files per project). An install is *defined* as a hash-set transition, regardless of how many fs events produced it. Native events merely accelerate discovery; the hash sweep reconciles missed/dropped/duplicated events. This eliminates the classic watcher failure modes (inotify watch exhaustion, network-FS silence, event storms during `cp -r` of a skill bundle, WSL/container quirks).

**(b) Library choice is a v1 non-question.** With ~20–50 small files, a jittered hash poll every 2s costs <10ms/tick and zero dependencies. chokidar/@parcel/watcher/notify/fsevents buy *latency* (2s → ~100ms) and idle-CPU, not correctness — and correctness is what polling maximizes. Defer native backends to v1.1 (§8):

- If xray core is Rust: `notify` (wraps inotify/fsevents/ReadDirectoryChangesW).
- If Node: `@parcel/watcher` **over** chokidar — prebuilt native bindings, batched events, and `getEventsSince()` snapshot catch-up which is exactly right for daemon-restart reconciliation; chokidar's remaining value (globs, JS fallbacks) we don't need.
- fsevents alone: macOS-only, disqualified as a strategy.

**(c) Daemon shape**: one process per user, project registry at `~/.xray/projects.jsonl` (`xray watch add .` + auto-discovery of known agent dirs). Stateless-on-start: first tick rebuilds hashes from disk, so crashes cost nothing. Sleep handled by monotonic-clock gap detection (>30s jump ⇒ immediate full reconcile).

### 2.3 Shell wrapper — **reject for v1**

Wrapping `npm`/`git`/`curl` via PATH shim fails on every axis that matters here: agents invoke tools through absolute paths and non-interactive shells; shims must transparently forward stdio/signals/exit codes (easy to half-break); recursive-invocation and double-wrap hazards; a security tool shadowing `git` is itself antivirus-flag material and a trust smell; and — decisively — the dominant skill-install primitive is **file creation** (`mkdir` + write SKILL.md), which no package-manager wrapper sees. Revisit only as opt-in `xray shim` experiment if some ecosystem ends up otherwise uncoverable.

### 2.4 Post-install git hooks — **reject**

`post-merge`/`post-checkout` would catch repo-synced skill updates, but require per-repo installation, collide with husky/`core.hooksPath`, and stay blind to every non-git vector. The watcher covers git-originated changes for free (worktree hash changes). Not worth the setup friction or the footprint in repos — ironic for a tool whose taxonomy flags `.git/hooks/*` writes (§2.4) as suspicious.

---

## 3. Install-completion detection without intercept

Signal ranking (use highest available per event):

1. **Hook payload status** — Claude `PostToolUse` fires only on success; Hermes `post_tool_call.status`. Most reliable; no inference needed.
2. **Manifest hash transition** — ground truth for all other cases.
3. **Quiescence debounce** — installs fan out many writes (dir, SKILL.md, scripts, registry update). Debounce: scan starts **750ms** after the last change in a burst; cap wait at 5s.
4. **Completion markers** where hosts provide them (e.g., plugin dirs appearing fully-formed, `node_modules/.package-lock.json`-style markers) — used opportunistically, never required.

**Intercept stays out of v1.** `PreToolUse`/`pre_tool_call` gating is a different product posture (blocking, latency-sensitive, FP-liability). It ships as opt-in `xray gate` in v1.1: synchronous hook, ≤200ms decision budget, blocks only score ≥ 0.90 findings, fail-open on timeout (consistent with taxonomy §3.2 and Claude Code's own guidance that hooks are best-effort filters).

---

## 4. Double-scan avoidance

Four layers, all keyed off one shared state dir (`~/.xray/state/`) — no IPC between surfaces required:

1. **Single-flight**: `flock` per project scope (`<scope-hash>.lock`). Concurrent triggers collapse onto one scan.
2. **Content-addressed memoization**: scan key = `sha256(sorted manifest hashes ‖ detector-pack version ‖ advisory-DB epoch)`. Cache hit short-circuits in <5ms. Re-scan only on content change, detector-pack bump, or daily advisory epoch roll (or `--force`).
3. **Coalescing queue**: 750ms trailing-edge debounce merges path sets; bursts (install 3 skills) = one scan.
4. **Cross-surface suppression**: hook enqueues `{source: claude-hook, scope, expected-hashes}`; watcher's subsequent hash transition finds an in-flight/satisfied key → skips. Because both surfaces compute the same content key, ordering races degrade to "one extra cached lookup," never duplicate work.

---

## 5. Performance budget

| Operation | Budget | Basis |
| --- | --- | --- |
| Sync hook overhead (enqueue + exit) | **≤50ms p95**, target ≤15ms | Detached-spawn then exit; Claude `async:true` moves even this off-path |
| Fast path (reconcile, nothing changed) | **<200ms p95** end-to-end | Hashing ~dozens of KB is µs; process startup dominates → single static binary goal; daemon socket amortizes repeat invocations |
| Scan tier L1 (normalize + regex, typical skill <5MB) | <2s p50, <5s p95 | Threat-taxonomy normalization front-end + pattern pass |
| Scan tier L2 (AST/dataflow on bundled scripts) | <30s p95, queued async | Only for bundles containing executables; never in delivery path |
| Tier L3 (sandboxed runtime) | minutes, queued, off-hot-path | Ground-truth verification only (taxonomy §1) |
| Critical-finding rewake | ≤2s after scan completes | `asyncRewake` exit-2 path; rate-limited to ≥0.90 scores |
| Watch daemon idle | <1% CPU, <50MB RSS | Poll tick ≈ <10ms for 20 projects × ~30 files |

**Answers to the posed numbers:** <200ms fast path — yes, and it's achievable because the fast path is *pure hashing*, never scanning. <2s hook print — acceptable **as a ceiling**, but the design target is result-by-next-render (~300ms) via cache hits; past that, prefer silent async delivery over holding any UI slot (§6).

---

## 6. TTY print timing and delivery UX

Verified constraint: **none of the three hosts gives xray a free-form terminal.** Claude Code hooks have no controlling tty (`/dev/tty` unavailable; `suppressOutput` is a no-op; escape sequences only via allowlisted `terminalSequence`). OpenCode gives append-only toasts. Hermes isolates hook output. In-place "scanning…" spinners (erase-and-redraw) fight host renderers, orphan lines on repaint, and are racy under tmux. Decision:

- **No placeholders by default.** Silent-at-trigger, one-line result at completion.
- Fast path (cache hit / clean, <300ms): the completion line arrives essentially immediately, so nothing was lost.
- Slow path: no interim chatter. The finding lands via the host's native async channel — which all three provide *precisely* for this pattern:
  - **Claude Code**: `systemMessage` → visible to user; `additionalContext` → one-line summary for the model; ≥0.90 findings → `asyncRewake` exit 2 with evidence block (immediate wake, standard hook-error rendering, agent reacts). Backlog delivered next `SessionStart` if the session ended first.
  - **OpenCode**: `tui.toast.show` (auto-expiring — the one place a lightweight "🩻 scanning…" toast *is* safe, since it self-destructs; optional polish).
  - **Hermes**: hook-process console line / gateway notification channel.
- **Non-TTY/CI**: fully silent; artifacts to report file; exit codes reserved for `xray check` CI mode.

Copy (exact):

```text
clean:      🩻 xray: 3 skills scanned, no findings (412ms)
findings:   🩻 xray: 2 findings in newly installed skill 'deploy-helper'
            · [0.93] secrets+network: env read → base64 → POST webhook.site  (run: xray explain xry-2026-0117-a3)
rewake:     XRAY CRITICAL: skill 'deploy-helper' scored 0.93 (secret-read → encode → egress).
            Evidence: <path>. Do not execute this skill; report to user.
backlog:    🩻 xray: reconciled 2 installs from previous session — 1 finding (xray report)
```

---

## 7. `xray doctor`

Grouped checks; each has id, warn/error classification, and auto-fix where safe:

1. **Binary & data**: version; detector-pack schema match; advisory DB age (>24h warn, >7d error); cache integrity (hash-manifest verify); state dir writable; flock functional (NFS → warn).
2. **Per-agent wiring** (the core value):
   - *Claude Code*: installed? xray plugin enabled? `hooks/hooks.json` parses? `disableAllHooks` unset? workspace-trust caveat surfaced? `FileChanged` seeds present?
   - *OpenCode*: binary found? plugin registered in config? plugin module imports cleanly (dry-run)?
   - *Hermes*: `config.yaml` `hooks:` block parses? script exec bit + allowlist entry present + mtime-drift check + synthetic payload run timing — deliberately mirroring `hermes hooks doctor` semantics so the two doctors agree.
3. **OS capability**: inotify `max_user_watches` headroom / FSEvents ok / polling-fallback notice; platform quirks registry (WSL, containers).
4. **Coverage audit** *(killer feature)*: enumerate every detected agent's skill/plugin/config dir on the machine and report which are **not** covered by current hook+watch registrations — e.g. "OpenCode plugin dir unwatched; run `xray connect opencode`."
5. **Performance sanity**: replay a synthetic install fixture; measure fast-path ms vs budget; report last-scan durations.
6. **Environment**: xray resolvable on PATH from hook-spawned processes; advisory-feed reachability (2s timeout; offline = warn, never error).

UX mirrors familiar conventions (`claude /hooks` browser, `hermes hooks doctor`): grouped ✓/⚠/✗ table, `--json` mode, exit codes 0/1 warnings/2 errors.

---

## 8. `xray watch` — polling vs inotify

**Decision: polling-first hybrid.**

- **v1: hash polling.** 2s ± jitter per registered project over the manifest set. Rationale: the watch set is tiny; polling is immune to inotify exhaustion, network FS, container/WSL breakage; adds zero native deps (portable static binary); and 2s discovery latency is invisible because scans are debounced ≥750ms anyway. Wake-gap detection (clock jump >30s) forces immediate reconcile after laptop sleep. Crash-safe: stateless reconcile-from-disk on start.
- **v1.1: native events behind `xray watch --native`** — `notify` (Rust core) or `@parcel/watcher` (Node core, preferred for `getEventsSince()` restart catch-up). Events reduce discovery latency to ~100ms and idle CPU to ~0, but are **never trusted alone**: mandatory 60s reconciliation sweep (events drop), and hash transitions remain the sole scan trigger. chokidar explicitly not adopted: its advantages (globs, pure-JS fallback breadth) target problems we engineered away by watching a tiny manifest set.

Commands: `xray watch add .` · `xray watch rm .` · `xray watch status` (per-project last-seen hash age, pending scans, daemon pid) · `--foreground` for debugging.

---

## 9. Editor hint — LSP diagnostics vs file decoration

- **(a) LSP diagnostics** — `xray lsp`: minimal language server publishing Diagnostics on manifest-ish files (SKILL.md frontmatter, plugin manifests, `.mcp.json`, dependency manifests) with `didChangeWatchedFiles` registration on skill dirs; severity maps from scoring-rubric confidence×severity bands; diagnostic carries rule id → `xray explain`. One implementation serves VSCode/Neovim/Zed/Helix through generic LSP client config; reuses scanner core wholesale.
- **(b) File decoration / editor extension** — gutter icons, tree view, code actions. Richest UX, but per-editor port burden and a whole extension codebase to keep in trust-parity with the scanner.
- **(c) Report-only** — SARIF emission (already specified in `scoring-rubrics.md` §3) consumed by GitHub code scanning / SARIF viewers. Zero incremental cost.

**Decision:** v1 ships (c) — SARIF + JSON + human report (already committed) — and (a) `xray lsp` in v1.1, since its marginal cost atop the scanner core is small and it covers every editor at once. (b) VSCode extension defers to v1.2 unless LSP adoption shows friction (squiggles on markdown feel unusual; mitigate by anchoring diagnostics to frontmatter/manifest regions, not prose).

---

## 10. Ship plan

| Surface | Release | Exact UX |
| --- | --- | --- |
| Claude Code plugin (PostToolUse async enqueue + asyncRewake critical path + SessionStart reconcile/watchPaths + Stop-free) | **v1** | `claude plugin add <marketplace>/xray` → first-session line: `🩻 xray active — watching skills for this project`; thereafter §6 copy |
| OpenCode plugin (`tool.execute.after` enqueue, toast delivery, `session.created` reconcile) | **v1** | Toast: `🩻 xray: scanned deploy-helper — clean (380ms)` / finding toast with explain id |
| Hermes shell hook (`post_tool_call`, matcher `terminal\|write_file\|patch`) via `xray connect hermes` | **v1** | Respects consent allowlist; verifiable with `hermes hooks test post_tool_call` and `hermes hooks doctor` |
| `xray watch` polling daemon + project registry | **v1** | `xray watch add .`; statusline-style `xray watch status`; sleep-gap reconcile |
| `xray doctor` (incl. cross-agent coverage audit) | **v1** | Grouped ✓/⚠/✗, `--json`, exit 0/1/2 |
| Dedupe/single-flight/content-addressed cache | **v1** | Invisible; observable via `(412ms)` timings and `xray doctor` perf check |
| Reports: human table + `--json` + SARIF | **v1** | `xray report`, `xray report --sarif` |
| Native fs events (`--native`, notify/@parcel/watcher + 60s reconcile) | v1.1 | Flag-gated; polling remains default and fallback |
| `xray gate` blocking mode (sync ≤200ms, ≥0.90 only, fail-open) | v1.1 | Opt-in `xray connect --gate`; loud banner in doctor when enabled |
| `xray lsp` editor diagnostics | v1.1 | `xray lsp` stdio server + copy-paste editor configs printed by doctor |
| Hermes native plugin (`on_skill_lifecycle` provenance enrichment) | v1.1 | Upgrades shell hook without changing UX |
| VSCode extension (tree view, code actions) | v1.2 | Only if LSP telemetry shows friction |
| Shell wrappers, per-repo git hooks, in-place TUI spinners | **non-goals** | §2.3/§2.4/§6 rationale |

**Resilience invariant** (the property that makes non-blocking safe): *no finding ever depends on same-session delivery.* Every trigger is an accelerator; the watcher + SessionStart reconcile is the guarantee. Worst case for any dropped async result (`-p` teardown, idle session, daemon death) is the finding appearing at next session start or in `xray report` — never lost, never blocking.
