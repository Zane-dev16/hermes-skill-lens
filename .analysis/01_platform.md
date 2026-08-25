# Skill X-Ray — Platform Dossier: Hermes Agent plugin & skill machinery

Ground truth read from source at `/usr/local/lib/hermes-agent` (Python). Home: `~/.hermes`.
All citations `file:line` refer to this tree. Verified against the live install (`~/.hermes/config.yaml`, `skills/`, `cron/`).

---

## 1. Plugin API surface

### 1.1 Discovery & loading

Four sources, later overrides earlier on name collision (`hermes_cli/plugins.py:1-27`):

1. Bundled `<repo>/plugins/<name>/` (memory/, context_engine/ excluded)
2. User `~/.hermes/plugins/<name>/`
3. Project `./.hermes/plugins/<name>/` (opt-in via `HERMES_ENABLE_PROJECT_PLUGINS`)
4. Pip packages exposing entry-point group `hermes_agent.plugins` (`ENTRY_POINTS_GROUP`, plugins.py:410)

Each dir plugin needs `plugin.yaml` + `__init__.py::register(ctx)` (plugins.py:24-28).
Debug: `HERMES_PLUGINS_DEBUG=1` (plugins.py:96-135).

### 1.2 plugin.yaml manifest fields

Known fields `_KNOWN_MANIFEST_FIELDS` (plugins.py:656-667); unknown fields warn, never fail load (plugins.py:805-813). `SUPPORTED_MANIFEST_VERSION = 2` (plugins.py:670).

- **v1**: `name`, `version`, `description`, `author`, `requires_env`, `provides_tools`, `provides_hooks`, `kind`, `hooks`, `label`, `optional_env`, `platforms`, `external_dependencies`, `pip_dependencies`, `provides_browser_providers`, `provides_web_providers`
- **v2** (#64165): `manifest_version`, `api_version`, `requires_plugins`, `python_dependencies`, `config_schema`, `license`, `homepage`, `tags`; reserved (no enforcement yet): `capabilities`, `emits`, `listens`, `hermes`, `depends`

Semantics from the `PluginManifest` dataclass (plugins.py:1036-1129):

- `kind`: `standalone` (default) | `backend` | `exclusive` | `platform` (plugins.py:1043-1055)
- `key`: registry key used by `plugins.enabled/disabled` and `plugins.entries.*` config; path-derived, e.g. `disk-cleanup` or nested `image_gen/openai` (plugins.py:1057-1061)
- `capabilities`: consent metadata only — live only when user granted `plugins.entries.<id>.granted_capabilities` or legacy `allow_*` key (plugins.py:1064-1070)
- `requires_plugins`: advisory; missing dep warns but loads; load ORDER honors edges (plugins.py:1079+)
- `python_dependencies`: validated/surfaced only — Hermes NEVER auto-installs (plugins.py:1088-1091)
- `config_schema`: JSON-schema-ish map validating keys under `plugins.entries.<id>.settings`; mismatches are warnings (plugins.py:1093-1096)
- `emits`/`listens`: event-bus discoverability only, not enforced (plugins.py:1105-1109)

### 1.3 VALID_HOOKS — complete enumeration (37 hooks, plugins.py:161-405)

Tool path:

| Hook | Payload / contract |
| --- | --- |
| `pre_tool_call` | kwargs: `tool_name, args, task_id, session_id, tool_call_id, turn_id, api_request_id` (+`middleware_trace`). Return directives: `{"action":"block","message":…}` (vetoes call), `{"action":"approve","message":…,"rule_key"?}` (escalates to human approval — **fail-closed**: gate error/deny/timeout ⇒ block), `{"action":"modify", args…}` merges modified args. Single invocation point `_dispatch_pre_tool_call_hooks` returns `(block_message, modified_args)` (plugins.py:6001-6095, 6158-6269) |
| `post_tool_call` | Observer. kwargs: `tool_name, args, result, task_id, session_id, tool_call_id, turn_id, api_request_id, duration_ms, status, error_type, error_message, middleware_trace` (model_tools.py:1173-1187). Fire sites after success/error/approval-deny paths (model_tools.py:1247,1405,1429,1447,1536,1597). Suppressible per-context via `suppress_post_tool_call_hook` (model_tools.py:45-57). Regex `matcher` supported for pre/post tool hooks only |
| `transform_tool_result` | kwargs same as post_tool_call minus `middleware_trace`, with derived `status/error_type/error_message`. First callback returning a **string replaces the result the model sees** (model_tools.py:1559-1582) |
| `transform_terminal_output` | terminal output transform |

LLM path: `transform_llm_output` (first non-None string wins, plugins.py:166-168), `pre_llm_call`, `post_llm_call`, streaming observers `on_stream_start/on_stream_delta/on_stream_end/on_interim_message` (async off token path, immutable payloads, cannot transform, plugins.py:169-176), `pre_verify` (verification-loop gate: return `{"action":"continue","message":…}` or Claude-Code `{"decision":"block","reason":…}`; bounded by `agent.max_verify_nudges`, plugins.py:177-190), `pre_api_request/post_api_request/api_request_error`, `transform_api_error_classification` (run-all-then-first-valid-wins; may carry unredacted provider error dumps; in `SHELL_UNSUPPORTED_HOOKS`, plugins.py:191-215 + 407-412).

Session/subagent: `on_session_start/end/finalize/reset`, `subagent_start/stop`.

Skill telemetry: `on_skill_lifecycle` — see §1.5.

Gateway/platform: `pre_gateway_dispatch` (kwargs `event, gateway, session_store`; may return `{"action":"skip"|"rewrite"|"allow"}`, fires BEFORE auth/pairing, plugins.py:226-233); `gateway_platform_event` (normalized envelopes only — Telegram reaction/message_edited, Discord message_edited/deleted/thread_created/thread_renamed, plugins.py:383-400); `pre_command` (slash-command observer, v1 return values ignored; deliberately NOT fired for running-agent control-plane intercepts, plugins.py:401-412).

Approvals: `pre_approval_request` / `post_approval_response` — observers only, cannot veto (kwargs documented plugins.py:240-252).

Others: `pre_transcription` (last-writer-wins per field, `file_path` immutable, plugins.py:253-266); kanban lifecycle observers `kanban_task_claimed/completed/blocked`, `on_kanban_worker_spawned/exited/stale_claim`, `on_kanban_task_updated` (field NAMES only), `on_kanban_dispatch_tick` (all post-lock, best-effort, has_hook() short-circuited, plugins.py:267-382).

### 1.4 PluginContext methods (plugins.py, class PluginContext)

Config/state:

- `get_config(key, default)` / `set_config(key, value)` — namespaced to `plugins.entries.<plugin_id>.settings.<key>`; atomic write; legacy nested-config migration compat (plugins.py:1427-1509)
- `state` → `PluginState`: atomic quota-bounded JSON KV at `~/.hermes/plugin-data/<namespace>/state.json`, **profile-scoped** (plugins.py:1511-1515, 1320-1337)
- `has_plugin(id)`, `platform_actions`, `subagent_lifecycle`, `profile_name`, `spawn_task(coro, name=)` (in-process background task), `on_unload(cb)`
- `llm` → host-owned `PluginLlm` facade (see §4.1)

Registration:

- `register_hook(hook_name, callback)` — unknown names warn but stored (plugins.py:3114-3137)
- `register_tool(name, toolset, schema, handler, check_fn=None, requires_env=None, is_async=False, description="", emoji="", override=False)` (plugins.py:1705+) — `override=True` against a built-in requires operator opt-in `plugins.entries.<id>.allow_tool_override: true`, else raises `PluginToolOverrideError` (plugins.py:127-131, 1723-1737)
- `register_cli_command(name, help, setup_fn, handler_fn)` (2066); `register_command(name, handler, description="")` slash command (2106); `dispatch_tool(name, args)`
- Providers/backends: `register_context_engine` (single winner), `register_context_reference`, `register_memory_provider`, `register_image_gen_provider`, `register_dashboard_auth_provider`, `register_video_gen_provider`, `register_web_search_provider`, `register_browser_provider`, `register_secret_source`, `register_tts_provider`, `register_transcription_provider`, `register_platform` (gateway adapter), `register_slack_action_handler`, `register_auxiliary_task(key, display_name, description,…)` (LLM routing slot usable via `ctx.llm.complete(task=key)`), `register_redaction_patterns(patterns)`, `register_system_prompt_section(id, content, …)`, `register_skill(name, path, …)` (plugin-bundled skills, surfaced as `plugin:skill`)
- Events: `emit(event, payload)`, `subscribe(event, cb)` (host-owned ledger + worker queue, plugins.py:1119-1135); `register_middleware(kind, cb)`
- Gated surfaces: `call_mcp(server, tool, args)` (per-plugin allowlist), `inject_message(...)` (gated by `_gateway_injection_allowed`), `register_approval_transport(name, present_fn)` (inactive until operator selects it), `has_capability(cap)`

### 1.5 `on_skill_lifecycle` exact kwargs

Fire site `_emit_skill_lifecycle` (tools/skill_usage.py:811-838), invoked AFTER authoritative state changes:

```
invoke_hook("on_skill_lifecycle",
    action=action,            # "created" | "loaded" | "used" | "patched" | "installed" | state changes
    skill_name=skill_name,
    provenance=...,           # bounded classification: "installed"|"agent_created"|"external"|"local"|"unknown"
                              #   (telemetry_provenance, skill_usage.py:783-808)
    task_id=task_id or "",
    session_id=session_id or "",
    use_count=use_count,      # Optional[int]
    reused=reused,            # Optional[bool]
    reuse_after_patch=reuse_after_patch)
```

Emitters: `record_installed` → action `"installed"` (skill_usage.py:979), `bump_use/bump_view/bump_patch` → loaded/used/patched (899, 932, 960), state changes (1024). Shared-metrics relay strips to classifications only (hermes_cli/observability/relay_shared_metrics.py:54-58) — but a *local plugin* receives the raw `skill_name`.

---

## 2. Skill machinery

### 2.1 `skill_manage` (agent-facing mutation tool, tools/skill_manager_tool.py:1543+)

Signature: `action, name, content, category, file_path, file_content, old_string, new_string, replace_all, absorbed_into, task_id, session_id` → JSON result string.

Actions: `create` (full SKILL.md text required), `edit` (full replacement), `patch` (old/new_string ± file_path ± replace_all), `delete` (`absorbed_into` records consolidation), `write_file`, `remove_file`.

Flow in order (1543-1700+):

1. `_background_review_preflight` (self-improvement fork guard)
2. **Write gate** `_apply_skill_write_gate`: when `skills.write_approval: true` (default false), ALL writes stage for review instead of committing (`/skills pending|diff|approve|reject`) regardless of origin
3. **Audit ledger** `capture_before` (tools/skill_ledger.py): append-only JSONL at `~/.hermes/skills/.curator_ledger.jsonl` with before/after content-addressed blobs under `~/.hermes/.curator_backups/blobs/`; telemetry, never blocks
4. Action handler (`_create_skill/_edit_skill/_patch_skill/_delete_skill/_write_file/_remove_file`)
5. On success → optional security scan `_security_scan_skill` (only if `skills.guard_agent_created: true`, default OFF; uses skills_guard with `source="agent-created"`; dangerous verdict ⇒ returned as tool error so agent can retry, skill_manager_tool.py:100-145, 946/1039/1168/1347)
6. `record_mutation` ledger append; prompt-cache invalidation; telemetry `record_created`(agent_created only when background review)/`bump_patch`/`forget`; debounced sync push hook

### 2.2 `skills_list` / `skills_view` tools (tools/skills_tool.py)

Registered in global registry, `toolset="skills"` (skills_tool.py:2005-2016). Progressive disclosure: `skill_view` first call returns SKILL.md content + `linked_files` dict (references/templates/scripts); second call with `file_path` serves linked file (schema at 1985-2003). Repeat-view dedup: unchanged file (mtime+size fingerprint) returns a stub pointing at earlier copy (2029-2109). Plugin skills served qualified as `plugin:skill` (`_serve_plugin_skill`, 880). Readiness checks: required env vars, platform/environment frontmatter matching (228-551).

Skill discovery tiers: bundled manifest, hub-installed (lockfile), project-local trusted dirs, `skills.external_dirs`, agent-created — precedence handled in `_find_all_skills` (673+) and `tools/skill_usage.py` provenance helpers.

### 2.3 Hub install flow end-to-end (`hermes_cli/skills_hub.py::do_install`, 536-847)

1. `ensure_hub_dirs()` creates `~/.hermes/skills/.hub/{quarantine/, audit.log, taps.json, index-cache/, lock.json, scan-cache/}` (tools/skills_hub.py:72-110, 3872-3887)
2. Resolve identifier through source router (`GitHubAuth` + `create_source_router`); optional `source_id` pinning refuses fuzzy re-resolution that would change provenance (565-585); bare short names resolved via search (49-97)
3. Fetch → `SkillBundle{name, source, trust_level, files{relpath→str|bytes}, metadata}`; URL installs without frontmatter `name:` need `--name` on non-interactive surfaces (608-663); category auto-detect for official nested ids (673-681)
4. Already-installed check via `HubLockFile.get_installed`; refuse without `--force` (683-690)
5. **Quarantine**: `quarantine_bundle()` validates name + every rel path, wipes stale quarantine dir, writes bundle to `~/.hermes/skills/.hub/quarantine/<name>/` (tools/skills_hub.py:3889-3913); invalid paths logged to audit as BLOCKED
6. **Scan**: `scan_skill_cached(q_path, source, source_url, cache_dir=~/.hermes/skills/.hub/scan-cache/)` → `(ScanResult, provenance)`; cache keyed by canonical sha256 over sorted rel-paths+bytes + scanner_version + source identity; `fresh` flag distinguishes cached attestations (tools/skills_guard.py:699-784)
7. **Policy**: `should_allow_install(result, force)` — matrix below; BLOCKED ⇒ rmtree quarantine + audit log entry
8. Advisory Tier 1 SkillEvaluator scan (warn-only, see §3.2); upstream metadata panel
9. **Confirm**: interactive `y/N` behind risk-scaled disclaimer panels (official vs third-party); `--force`/`skip_confirm` bypass
10. **Install**: `install_from_quarantine()` validates quarantine containment, resolves lock-path validator (symlink redirect refusal), refuses nesting into an existing skill dir and refusing to wipe category buckets (issues #75983/#75983-sibling), rmtree-collide guards, then moves to `~/.hermes/skills/[category/]<name>/` (tools/skills_hub.py:3940-4060)
11. **Provenance record**: `HubLockFile.record_install` → `~/.hermes/skills/.hub/lock.json` entry `{source, identifier, trust_level, scan_verdict, content_hash (sha256:…), install_path, files[], metadata{}, scan_provenance{}, installed_at, updated_at}` (tools/skills_hub.py:3732-3808); name/path shape validated at write time (anti-poisoning for uninstall rmtree escape)
12. Audit log line appended (`.hub/audit.log`, 3851-3866); blueprint block (`metadata.hermes.blueprint`) registered as cron SUGGESTION — never auto-scheduled (skills_hub.py cli 786-830); skills prompt cache invalidated

Bundle locations timeline: upstream registry/repo → in-memory SkillBundle → `.hub/quarantine/<name>/` (scan window) → `skills/[category/]<name>/` (live). Updates (`do_update`, cli 1107+) pin resolution to the lockfile's recorded source to prevent provenance swap. Uninstall records removal + audit (tools/skills_hub.py:4106).

### 2.4 TRUSTED_REPOS + INSTALL_POLICY

`TRUSTED_REPOS` (tools/skills_guard.py:44-53): `openai/skills`, `anthropics/skills`, `huggingface/skills`, `NVIDIA/skills` (NVIDIA entries ship signed `skill.oms.sig` + governance `skill-card.md`; sync drops unsigned). Note: module docstring (lines 14-17) still says "openai/skills and anthropics/skills only" — doc drift.

Trust resolution `_resolve_trust_level` (1123-1150): `"official"`→`builtin`; `"agent-created"`→own tier; exact-or-slash-prefix match against TRUSTED_REPOS (no sibling-prefix trust) →`trusted`; else `community`. skills.sh aliases normalized first.

Verdict `_determine_verdict` (1152-1159): any critical ⇒ `dangerous`; any high ⇒ `caution`; medium/low alone ⇒ `safe`.

`INSTALL_POLICY` (52-59), rows trust × cols (safe/caution/dangerous):

| trust | safe | caution | dangerous |
| --- | --- | --- | --- |
| builtin | allow | allow | allow |
| trusted | allow | allow | block |
| community | allow | block | block |
| agent-created | allow | allow | **ask** (error to agent; gate only when `skills.guard_agent_created` on) |

Force semantics (should_allow_install, 787-829): `--force` overrides blocks EXCEPT `dangerous` verdict on community/trusted sources (hard-blocked); `ask` returns tri-state None ⇒ confirmation.

Taps: `TapsManager` adds custom GitHub repos as sources (`.hub/taps.json`, 3812-3849).

---

## 3. Existing security layers

### 3.1 `tools/skills_guard.py` (enforcement scanner, SCANNER_VERSION `skills-guard-v1`)

- ~120 regex THREAT_PATTERNS (79-553) across categories: exfiltration (curl/wget/fetch/httpx/requests secret interpolation, credential-store dirs ~/.ssh/.aws/.gnupg/.kube/.docker, hermes .env, secrets-file reads, env dumps, DNS exfil, tmp staging, markdown image/link exfil, context-window exfil), injection (ignore-previous-instructions, role hijack, deception, sysprompt override/extraction, conditional deception "when no one is watching", translate-execute, HTML comment/hidden-div, DAN/dev-mode jailbreaks, fake-update/policy pretext), destructive (rm -rf /, chmod 777, mkfs, dd, rmtree), persistence (crontab, shell rc refs, authorized_keys, ssh-keygen, systemd, launchd, sudoers, git config --global, **AGENTS.md/CLAUDE.md/.cursorrules**, **.hermes/config.yaml/SOUL.md**), network (reverse shells nc/socat//dev/tcp, tunnels ngrok/cloudflared, hardcoded ip:port, webhook/paste services), obfuscation (base64 decode pipes, hex/unicode escape chains, eval/exec strings, echo|bash, compile-exec, getattr builtins, **import**, chr-building, String.fromCharCode, atob/btoa, string reversal), execution (subprocess/os.system/os.popen/child_process/Runtime.exec/backticks), traversal (deep ../, /etc/passwd, /proc, /dev/shm), crypto mining, supply chain (curl|sh, unpinned pip/npm, uv run, remote fetch, git clone, docker pull), privilege escalation (sudo, setuid, NOPASSWD, allowed-tools informational-low only), credential exposure (hardcoded keys, private key PEM, ghp_/github_pat_/sk-/sk-ant-/AKIA/gpat patterns)
- Structural checks (MAX_FILE_COUNT=50, MAX_TOTAL_SIZE_KB=1024, MAX_SINGLE_FILE_KB=256, SUSPICIOUS_BINARY_EXTENSIONS, symlink checks — 555-573 region + `_check_structure` 885+)
- **Unicode stego**: `INVISIBLE_CHARS` set of 18 zero-width/bidi/isolate chars (U+200B/C/D, U+2060-64, U+FEFF, U+202A-E, U+2066-69) detected per-file with char names (`_unicode_char_name` 1014+)
- `.skillignore`/`.clawhubhide` honored BUT SKILL.md always scanned (646-651)
- Content digest binds attestation to exact bytes (canonical SHA-256 over sorted rel-posix paths + bytes, 699-728)
- Verdict shape `ScanResult{skill_name, source, trust_level, verdict(safe/caution/dangerous), findings[Finding{pattern_id, severity, category, file, line, match, description}], scanned_at, summary, scan_provenance{bundle_hash, scanner_version, rules, source_url, scanned_at, fresh}}` (86-95)

**Covers well**: single-line obvious exfil/credential/reverse-shell/jailbreak signatures; leaked tokens; zero-width stego; structural anomalies; supply-chain download-and-execute.

**Misses (relevant gaps for X-Ray)**:

- **Line-local matching only** — nearly all patterns are `[^\n]*` single-line; multi-line constructs (secret read on one line, exfil 50 lines later) produce no finding. No dataflow/taint analysis.
- **Cross-file flows invisible**: pattern hits are per-file; nothing correlates `scripts/a.sh` reading env with `lib/upload.py` POSTing.
- **Claimed-vs-actual diff absent**: SKILL.md prose is never compared to what shipped scripts actually do.
- Unicode coverage limited to invisibility; homoglyph/confusable attacks (Cyrillic 'а', tag chars U+E0000 block, variation selectors) not covered.
- No AST-level analysis of shipped Python/JS/shell; obfuscation heuristics are shallow.
- Verdict collapses to critical⇒dangerous/high⇒caution: one noisy critical pattern (e.g. `printenv`) forces block regardless of context; conversely safe-verdict skills pass with medium findings unreviewed.
- Runtime behavior of INSTALLED skills is never re-scanned (content-hash exists but no periodic re-verify hook).

### 3.2 `tools/skillevaluator_scan.py` (advisory Tier 1)

Contract (module docstring 1-60 + code): optional `skillevaluator` binary (uv tool install, NVIDIA SkillEvaluator; `security` check delegates to pinned NVIDIA SkillSpector static-rules mode, keyless/no LLM). `TIER1_CHECKS = "pii,unicode,lint,license,security"` (64), timeout 120s (69). **Warn-don't-block**: PII-class findings informational (known FP classes); SECRETS_CLASS_CHECKS {database_credentials, hardcoded_secrets, jwt_tokens, webhook_urls, aws_identifiers, github_tokens, private_keys} earn one interactive confirm beat (74-82); scanner missing/crash/timeout/unparseable ⇒ no-op, never breaks installs. Enabled by `skills.tier1_advisory` (default true). Report shapes `Tier1Finding{check, validator, severity, message, file, line, suggestion}` / `Tier1Report{available, passed, findings, incomplete_checks, error}` (82-116).

### 3.3 `security-guidance` plugin (bundled pattern reference, plugins/security-guidance/**init**.py)

Wires `pre_tool_call` + `transform_tool_result` (register at :258-260). Warn mode (default): scans CONTENT args of `write_file(path,content)`, `patch(path,new_string|patch)`, `skill_manage(file_path,file_content|new_string)` (:33-40) for dangerous-code patterns (eval(, pickle.load, yaml.load, os.system, subprocess shell=True, dangerouslySetInnerHTML, verify=False, ECB, XXE parsers, GH Actions `${{ github.event.* }}`, torch.load w/o weights_only…) forked from Anthropic claude-plugins-official; appends `⚠️ Security warning` Markdown block to the JSON tool result — model self-corrects next turn; skips >256KB and error results (:44-48, 216-230). Block mode via `SECURITY_GUIDANCE_BLOCK=1` flips to pre_tool_call veto (:160-177). Rationale documented: non-trivial FP rate makes blocking wrong for layer 1 (:7-18).

This is the closest existing analog to X-Ray's runtime annotation layer — note it inspects *args being written*, not *results being consumed*; annotating `skill_view` results would be new surface.

---

## 4. Host services a plugin may use

### 4.1 `ctx.llm` / `agent/plugin_llm.py` — YES, plugins can make LLM calls through Hermes' own provider connection

`PluginLlm.complete(messages, *, provider=None, model=None, temperature=None, max_tokens=None, timeout=None, agent_id=None, profile=None, purpose=None, task=None) -> PluginLlmCompleteResult{text, provider, model, agent_id, usage, audit}` (740-809); `complete_structured(...)` similarly (811+); async variants present. Default route = **the operator's active main model/connection** (attribution falls back to `_read_main_provider/_read_main_model`, 654-713) or a registered auxiliary-task slot.

Cost/accounting: usage extracted from provider response (`PluginLlmUsage{input_tokens, output_tokens, total_tokens, cache_read_tokens, cache_write_tokens, cost_usd(host estimate)}`, 124-134, 603-628); each call logged `plugin_llm.complete plugin=… provider=… tokens=N` (806-808). **Calls bill to the operator's account**; there is no per-plugin spend cap found — only override gating.

Trust gate `_resolve_trust_policy` reads `plugins.entries.<id>.llm.{allow_provider_override, allowed_providers, allow_model_override, allowed_models, allow_agent_id_override, allow_profile_override, allow_task_override}` — default deny per override, resolved per-call (173-261). Plain calls on the current main model require NO capability/grant. `task=` routing through foreign aux slots requires `allow_task_override` (347-446).

For X-Ray: free to run LLM triage (e.g. semantic claimed-vs-actual diff) on the host's connection; set `purpose="xray-triage"` for auditability; expect it to cost the user tokens.

### 4.2 Cron facilities

No plugin registration API for cron (no `register_cron` on ctx). Jobs persist in `~/.hermes/cron/jobs.json` (`JOBS_FILE`, cron/jobs.py:85) managed by CLI (`hermes cron add`) / slash commands; scheduler daemon fires them (cron/scheduler.py). The sanctioned automation intake for installed skills is blueprint detection → `register_blueprint_suggestion` → user accepts via `/suggestions` (cli skills_hub 786-830) — installing never silently schedules. In-process alternatives for a plugin: `ctx.spawn_task(coro)` (lifetime-bound only). For scheduled rescans, X-Ray must piggyback on user-owned cron jobs, kanban tasks, or rescan opportunistically on `on_session_start`.

Live store observed: `~/.hermes/cron/{jobs.json, executions.db, output/, usage_audit.jsonl}`.

### 4.3 Gateway/Discord rendering constraints

Discord adapter (plugins/platforms/discord/adapter.py): `MAX_MESSAGE_LENGTH = 2000`, split threshold 1900, max 8 back-to-back chunks before rate-limit damping (1045-1054); Discord markdown renders natively incl. fenced code blocks (`supports_code_blocks = True`, 1047); GFM tables converted to bullet lists since Discord can't render them (5771); link labels escaped + `<url>` form to keep truncation clickable (43-57); streaming edit previews capped at 2000 chars. Implication for X-Ray reports: anything surfaced through chat must survive chunking — write full reports to disk (`ctx.state.data_dir`) and emit a short summary + path; avoid wide tables.

Gateway hooks available: `pre_gateway_dispatch` (filter/rewrite inbound BEFORE auth/pairing), `gateway_platform_event` (observe edits/deletes/threads), `transform_llm_output` (rewrite outbound text).

### 4.4 Profile routing — YES, skills vary per profile

`gateway/profile_routing.py`: hierarchical routes (thread spec 14 > channel 6 > guild 2 > default) map Discord/other-platform scopes to named profiles; each profile gets its own model, tools, memory, persona (docstring 1-47). A named profile is a full HERMES_HOME at `~/.hermes/profiles/<name>/` (config.py:919-923; profile-home logic hermes_constants.py:1043-1050; sandbox mirror layout agent/file_safety.py:568-611) with its own config.yaml, `skills/`, SOUL.md, `memories/`, `plugin-data/`. Consequences: (a) X-Ray must be installed/enabled per profile where coverage is wanted; (b) a scanner seeing "the" skills dir sees only that profile's; (c) `PluginState`/`get_config` are profile-scoped — cross-profile correlation needs an explicit shared location.

### 4.5 SOUL.md / MEMORY.md roles

- `SOUL.md` at HERMES_HOME root: identity/persona injected into system prompt (`load_soul`, agent/prompt_builder.py:2323+, 1483); seeded from `DEFAULT_SOUL_MD` (hermes_cli/default_soul.py); legacy-template upgrade-safe. It is the identity slot — a persistence target malicious skills want to poison (skills_guard has dedicated patterns for references to it, THREAT_PATTERNS "hermes_config_mod").
- `MEMORY.md` + `USER.md` under `~/.hermes/memories/`: agent's personal notes vs knowledge-about-user, loaded each session with char limits and nudge intervals (tools/memory_tool.py:6-8, 247-248; config memory.*). Prompt-injected ⇒ part of the attack surface for indirect injection via skill content.
- Both are plain files any tool call can rewrite — no integrity monitoring exists today (X-Ray opportunity).

### 4.6 Sandboxes dir

`~/.hermes/sandboxes/` holds terminal-backend sandboxes (live: `singularity/`). Recognized mirror-root layout `<HERMES_HOME>/profiles/<name>/sandboxes/<backend>/<task>/home/.hermes/...` with warnings when tools touch mirrored state (agent/file_safety.py:568-611). Relevant if X-Ray scans inside sandbox homes vs real home (double-counting hazard).

---

## 5. Config structure

### 5.1 `plugins.entries.<id>.*` (observed in code)

- `settings.<key>` — plugin's own subtree; sole surface for `ctx.get_config/set_config`; optionally described by manifest `config_schema`
- `enabled` / `disabled` lists at `plugins.` level (discovery gating)
- `allow_tool_override: true` — permits built-in tool replacement (plugins.py:1723-1737)
- `granted_capabilities: [...]` (+ legacy `allow_*` keys) — activates declared capabilities (plugins.py:1064-1070)
- `llm.{allow_provider_override, allowed_providers, allow_model_override, allowed_models, allow_agent_id_override, allow_profile_override, allow_task_override}` — LLM trust policy (plugin_llm.py:216-261)

### 5.2 `skills.*` keys that exist today (config_defaults.py:2045-2098)

| key | default | meaning |
| --- | --- | --- |
| `external_dirs` | `[]` | extra skill source dirs |
| `project_discovery` | true | repo-local `.hermes/skills/`, `.agents/skills/` discovery |
| `trusted_project_dirs` | `[]` | project roots allowed to contribute skills (`hermes skills trust`) |
| `template_vars` | true | substitute `${HERMES_SKILL_DIR}`/`${HERMES_SESSION_ID}` in SKILL.md |
| `inline_shell` | false | execute `` !`cmd` `` snippets in SKILL.md bodies (host code exec from skill author!) |
| `inline_shell_timeout` | 10 | per-snippet seconds |
| `guard_agent_created` | false | skills_guard scan on skill_manage writes |
| `tier1_advisory` | true | NVIDIA Tier 1 advisory scan on hub installs |
| `write_approval` | false | stage skill_manage writes for `/skills approve` review |
| `ledger` | true | JSONL mutation ledger + curator rollback |
| `creation_nudge_interval` | (int) | seen live in `~/.hermes/config.yaml`; creation-nudge cadence |

Also related: `platform_toolsets.<platform>` lists gate which tools (incl. `skill_manage`, `skills_list/view`) exist per surface; `skills.disabled`/platform-disabled lookups via `agent.skill_utils.get_disabled_skill_names` (skills_tool.py:623-632).

---

## Integration opportunities & constraints (opinionated)

1. **Ship X-Ray as a standalone plugin** — register `pre_tool_call` (block/approve escalation is fail-closed and human-gated: ideal for hard vetoes), `transform_tool_result` (annotate `skill_view` results with risk flags exactly when the agent consumes a skill — a layer nobody covers today; security-guidance only annotates writes), `post_tool_call` (behavioral observation), `on_skill_lifecycle` (inventory telemetry incl. raw skill names local-only).
2. **Install-time seam is NOT hookable**: `do_install` never invokes plugin hooks — to intercept installs, watch `~/.hermes/skills/.hub/quarantine/` (stable staging dir, guaranteed pre-confirm pause) or poll `.hub/lock.json` / listen for `on_skill_lifecycle(action="installed")` which fires post-hoc (skill_usage.py:979).
3. **Reuse, don't reimplement**: import `tools.skills_guard.scan_skill_cached` + `ScanResult` directly in-process; extend rather than fork — but its regexes are line-local; X-Ray's differentiators should be cross-file dataflow, claimed-vs-actual diff, confusable-unicode, and AST analysis of scripts/.
4. **Biggest uncovered gap = claimed-vs-actual**: nothing compares SKILL.md promises to script behavior; feasible with `ctx.llm.complete(purpose="xray")` semantic diff — costs the operator tokens, no per-plugin budget exists, so self-throttle and cache aggressively.
5. **Unicode story is half-done**: 18 invisible chars covered; homoglyphs, variation selectors, and tag-block stego are open — cheap, high-value win.
6. **Verdict collapse is exploitable noise-floor**: one critical hit ⇒ dangerous ⇒ block; conversely safe-verdict bundles ship with medium findings unseen. X-Ray should publish severity-weighted, context-aware scores rather than mimic the binary collapse.
7. **Installed skills are never re-scanned**: content hashes exist in lock.json but nothing verifies drift; a `on_session_start` re-hash + diff against `scan_provenance.bundle_hash` is a near-free continuous-integrity feature.
8. **Reporting constraint**: gateway output dies past ~1900-char chunks ×8 and tables get flattened (Discord) — write full reports under `ctx.state.data_dir` (quota-bounded, profile-scoped) and surface summaries + paths.
9. **Profiles multiply deployment**: every profile home (`~/.hermes/profiles/*/*`) has its own skills/plugins/state; decide explicitly whether X-Ray runs per-profile (isolated views) or centralizes via a shared absolute path — plugin state will NOT aggregate automatically.
10. **No scheduling API**: recurring deep-scans need user-owned cron jobs or opportunistic session-start triggers; blueprint suggestions are the only sanctioned automation intake and are user-approved.
11. **Trust gates cut both ways**: overriding built-in tools or LLM providers needs explicit operator config (`allow_tool_override`, `llm.allow_*`); design X-Ray to need zero grants for core function so adoption friction stays minimal.
12. **SOUL.md/MEMORY.md have no integrity monitoring** despite being prime poisoning targets (and skills_guard already flags *references* to them) — a hash-watch + alert there is high-value, low-cost.
13. **Agent-created skills are unguarded by default** (`skills.guard_agent_created=false` because terminal parity argument); X-Ray's write-path scan via transform_tool_result on `skill_manage` closes this without the friction debate.
14. **Quarantine→install race**: scanning happens once, between quarantine write and y/N confirm; a plugin scanning concurrently must tolerate the dir disappearing on cancel/block (rmtree on both paths).
15. **Manifest forward-compat**: target `manifest_version: 2`, declare only known fields (unknown ones warn), declare `provides_hooks` accurately — VALID_HOOKS doubles as the shell-hook allowlist and misdeclared hooks confuse the ecosystem's discovery surfaces.
