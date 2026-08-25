# Hermes Skill Lens — Execution Plan

**Version:** 4.0 (owner-arbitration pass applied — HARD_QUESTIONS rev. 3, 2026-08-23) · **Owner:** 1 senior Python engineer · **Target:** Hermes plugin **v0.9** in ~12
weeks (honest range **11–13**)
**Product shape (owner decision, 2026-08-22):** pure-Python Hermes plugin — installed via
`hermes plugins install <git-repo>`, triggered by `on_skill_lifecycle` +
`post_tool_call(skill_manage)` (+ quarantine-dir view at the hub confirm beat), queried via the
`/lens` slash command. Other harnesses are unported by design in v0.9.
**Ground truth:** this version is re-derived from the Hermes source audit (`.analysis/01_platform`,
`02_decisions`, `04_ux`) — hook contracts, manifest v2 fields, gateway rendering limits, and
profile semantics are cited from the live tree, not assumed.
**Contract:** Where this plan and SPEC.md disagree, SPEC.md wins. This plan executes SPEC §13's
v0.9 line.

---

## 0. Locked architecture decisions (mirroring SPEC; single source of truth is SPEC.md)

| Question | Decision |
| --- | --- |
| Language | **Python 3.11+**, in-process (D-LANG rev. 2). Matches host venv; triggers are best-effort observers, so startup budget is irrelevant. Import name `skill_lens`; repo `hermes-skill-lens`; slash `/lens`. |
| Engine model | In-process engines behind an `Engine` protocol; per-engine `except Exception` ⇒ synthetic INFO finding (`LNS-ENG-000`). Containment is scoped honestly: it covers **Python exceptions only** — vendored tree-sitter grammars are native code parsing adversarial bytes inside the agent process, so grammar-input fuzzing is normative, doctor notes parse-crash loops, and subprocess parse-isolation stays the documented v1.0 escape hatch (D-PROC caveat). |
| Plugin wiring | `plugin.yaml` **manifest v2** (`manifest_version: 2`, `api_version` pinned, known fields only — unknown fields warn on the host side anyway), `provides_hooks` declared accurately. `__init__.py::register(ctx)` registers observer hooks + `/lens` via `ctx.register_command`. All durable state under `plugin_data_dir("lens")` → `<HERMES_HOME>/plugin-data/lens/`. Config read through `ctx.get_config` namespaced keys (`plugins.entries.lens.settings.*`); no capability grants, no tool overrides, zero `allow_*` config needed for core function. |
| Triggers | `on_skill_lifecycle` + `post_tool_call` self-filtered to `skill_manage` — **observers only, never `pre_tool_call`** (the blocking hook exists; abstention is the stance). Lifecycle payloads carry bounded provenance classes, so provenance display is enriched at scan time from hub lockfiles (`trust_level_for`) — annotation, never arithmetic (S7). Sober queued/delivered one-liners reach the model via `transform_tool_result(skill_manage)` append — the security-guidance precedent (H8) — append-only, ≤160 chars, config kill-switch. |
| Surfaces | `/lens` returns **surface-neutral output**: no ANSI, Unicode boxes/fences only, aligned rows never pipe tables (Slack drops tables), soft budget 1200 / hard 1800 chars with overflow to `<plugin-data>/lens/reports/<name>-<hash8>.txt` + path pointer. Full Rich panels + real exit codes live in CLI verbs via `ctx.register_cli_command`. Gateway sync handlers have **no timeout** → cold scans never run inline there; async handler results are capped at 30 s by the host — queue-first design respects both. |
| Detection core | Deterministic-only in v0.9. Choir ships as contract stub (config key + downgrade-only protocol) with zero adapters; the LLM adjudicator is scheduled for a v1.0 promotion eval as opt-in `/lens second-opinion` (HQ R2). The NVIDIA SkillEvaluator advisory stays untouched — relationship per HARD_QUESTIONS R7: integrated display with role labels, never subsume, never port guard regexes, label ours "advisory — skills_guard decides install policy". |
| Scoring | Rubric v2 exactly per SPEC §8. Integer math; ceilings clamp score AND grade; `needs_review` is a flag, not a verdict. **The `verdict` field is THE automation interface everywhere** (X2): exit codes are its projection onto CLI verbs only (0 clean · 1 only under `--fail-on` · 2 total error); slash/hook paths render text and never raise into the host. |
| Rules storage | YAML rule packs shipped in-repo; engine + pack versions travel together through git tags (D-RULEOWN). Community packs opt-in, SHA256-pinned, capped at MEDIUM until promoted. Policy = TOML files + the plugin-settings layer per SPEC §10 resolution order. User-authored `re:` allowlists deferred (R3 — globs + PSL + deny-wins cover observed cases). |
| Concurrency | Cached fast path (<200 ms one-liner, keyed by canonical bundle hash) answers synchronously; cold scans run on a single plugin worker thread (`queued→scanning→ready | failed` in `jobs.json`), coalesced by bundle hash. The install/confirm beat is never delayed. Proactive push to gateway sessions does not exist in the plugin API (H13) — honest limitation:`events.ndjson` + pull banners instead. |
| Watcher | In-process poller owned by the loading process (dies with it). **Startup sweep always runs** (persisted-hash comparison catches out-of-band drift for everyone); continuous hash-polling (2 s→30 s adaptive backoff, 500 ms debounce) is opt-in. State persists across sessions in `watch-state.json`; gaps replay once on start. No daemon in v0.9; no cron API exists to abuse. |
| Privacy | Zero *direct* egress: lens opens no sockets and imports no network machinery in the default closure (test-enforced: pytest-socket + import-contract test — G1/G3 restated for in-process reality). Any model access rides exclusively the host `ctx.llm` lane; v0.9 ships templates-only narration; the only planned model access is the opt-in `/lens second-opinion` downgrade-only adapter, scheduled for a v1.0 promotion eval (R2). Lens generates no LLM prose in any version — narrator cut by owner arbitration. |
| Profiles | Hermes profiles are full HERMES_HOMEs; plugin state/config are profile-scoped. v0.9 stance: Lens runs **per-profile** and scans the tree of the profile that loaded it; cross-profile aggregation is a documented out-of-scope (would need an explicit shared path). |
| Distribution | The plugin repo IS the artifact (`hermes plugins install owner/hermes-skill-lens`). Tree-sitter delivery lane pinned (D-PARSE weakened): grammars declared in manifest `python_dependencies` **plus** vendored wheels where platform-clean, doctor reports "AST active/degraded", and the line-scanner fallback is golden-tested first-class output — if neither lane clears git-install cleanly by end of Phase 1.5, AST engines demote to v1.0 honestly. Optional PyPI console-script CLI deferred to v1.0 per SPEC §13. |

**Finding schema, fingerprints, dedup — conform to SPEC §7 verbatim:** `evidence_kind ∈ {ast,
crossref, regex, manifest, unicode}`; `fingerprint = sha256(rule_id ‖ capability ‖
normalized-evidence)` stable across line shifts; within-report dedup collapses on fingerprint with
max-5 attached locations; severity-tier weights use the first/subsequent schedule.

---

## 1. Phased build order

### Phase 0 — Plugin spine ("Lens can see") — wk 1–2

Plugin scaffold + ingestion of the real Hermes skill tree into SkillIR; deterministic inventory
report with frontmatter validation. No security findings yet.

- Repo layout: `plugin.yaml` (manifest v2, `api_version` pinned, accurate `provides_hooks`),
  `__init__.py` (`register(ctx)` skeleton), `lens/` package (IR types, canonical JSON writer with
  `_meta` sidecar split), `tests/`; import package `skill_lens`
- Ingest: categorized layout `~/.hermes/skills/<category>/<name>/`, hub quarantine dir
  (`skills/.hub/quarantine/` — tolerant of the rmtree race when an install is cancelled/blocked),
  `metadata.hermes` frontmatter fields into IR, hub lockfile provenance records enriched at scan
  time (annotation-only per S7); dir/zip/git-URL/single-SKILL.md targets; resource ceilings per
  SPEC §5.1
- Golden snapshot harness (pytest): byte-identical canonical JSON across runs
- **Scratch `HERMES_HOME` test loop:** every day ends with the plugin enabled in a throwaway home
  (`HERMES_ENABLE_PROJECT_PLUGINS=1` for repo-local iteration), exercising load → enable → unload;
  malformed SKILL.md must produce structured diagnostics, never an exception escaping `register`
- **wk-1 parallel track:** name registration (`hermes-skill-lens` on GitHub, `skill_lens` import
  reserved; PyPI squatted ahead of v1.0 per HQ R6), rule-pack signing key ceremony, CI scaffold
  (pytest + ruff + coverage)

**Exit:** scanning this machine's actual `~/.hermes/skills` tree produces byte-identical canonical
JSON twice; the scratch-home loop loads/enables/disables cleanly with `hermes plugins enable lens`;
quarantine dir disappearing mid-walk degrades to a logged skip, never a crash.

### Phase 1 — Claims (field-direct), first engines, scoring v2, slash command, fast-path cache — wk 3–5

The claimed-vs-actual diff is the product thesis and Phase 1 arithmetic depends on it, so it lands here.

- **Claims subsystem:** ClaimRecord IR; **field-direct extractor** (`allowed-tools`,
  `compatibility`, Hermes `metadata.hermes` hints); overreach = actual ∧ ¬claimed; report overreach
  section; `LNS-MAN-004` vague-description finding; deterministic §9.3 templates. (Lexicon
  extractor lands Phase 1.5.)
- **Engines E1 manifest, E3 shellscan, E6 netgraph, E7 secretscan** (E6 includes money-rail host
  classes so the money ceiling is exercisable from day one)
- **Scoring v2** exactly per SPEC §8 (weights −40/−25 · −18/−12 cap −36 · −7/−4 cap −20 · −2/−1
  cap −6; ×0.5 static_only/declared modifiers; ceilings 25/40/70/80 clamping score AND grade;
  grades A–F; verdicts {alert,warn,notice,clean}; `needs_review` flag)
- **`/lens scan|report <name|path>` slash command** via `ctx.register_command`: collapsed chat
  variant by default — count line + worst-5 findings + report pointer (fenced block, ≤1800 chars
  hard budget, overflow written to plugin-data reports dir with path pointer; Surface Principle,
  HQ O2 — stat lines, never clunky summaries); no ANSI, no pipe tables. Interim execution
  model: cache-hit answers inline (<200 ms); cold scans run inline behind an internal deadline,
  acceptable because dogfooding is local CLI — replaced by queue-first in Phase 2
- **Fast-path cache** keyed by canonical bundle hash (short-circuits repeat scans; later reused by
  lifecycle triggers and watcher coalescing)
- Rule-pack YAML loader + embedded `core` pack v0.1 (~15 rules across the four shipped engines)

**Exit (exact test oracle — no tolerance):** golden vectors reproduce SPEC §8.3 examples A–G
**exactly**: A=100/A·clean · B=91/A·notice · C=25/F·alert · C′=40/D·warn·needs_review ·
D(lab)=85/B·notice · E=80/C·warn · F=83/B·notice · G=70/C·warn. Vectors committed under
`corpus/vectors/`. Every core rule fires on ≥1 malicious fixture and stays silent on the benign
set; a deliberately raising test engine changes neither results nor UX; `/lens scan --json` returns
the canonical envelope byte-stable.

### Phase 1.5 — AST engines + lexicon claims — wk 6–7

- Official tree-sitter Python bindings; grammars for sh/bash, Python, JS/TS. Delivery lane pinned:
  declared in manifest `python_dependencies` (declaration seam only — the host warns, never
  auto-installs) + vendored wheels where platform-clean; **doctor check reports "AST active /
  degraded"**; graceful degradation to line-scanners is golden-tested first-class behavior, not a
  shadow mode (D-PARSE disposition)
- **E4 pyscan, E5 jsscan** (AST sinks, same-file source→sink dataflow, base64-decode-to-exec chains)
- **E2 textinject** full (Unicode Tags/zero-width/bidi/homoglyphs/confusables, ghost-text stream,
  injection grammars) — closes the gap the host guard leaves open beyond its 18 invisible chars
- **Lexicon claim extractor** (verb-object mining over description/body, quote spans preserved);
  declared-discount applies from lexicon-extracted claims
- Grammar-input fuzz corpus normative (native code parses adversarial bytes in-process — D-PROC
  caveat); crash-loop surfaced to doctor

**Exit:** AST evidence demonstrably beats regex on the FP corpus at equal TP; unicode-stego fixture
caught; degraded mode produces golden-identical line-scanner output when a grammar is absent or
fails to load; fuzzer green over the grammar corpora.

### Phase 2 — Policy, baseline, explain, diff; worker-thread hardening — wk 8–9

- `policy.toml` loader + `ctx.get_config` plugin-settings layer per SPEC §10 resolution order
  (provenance strings include the settings layer); street/lab profiles; merge semantics (scalars
  override, maps deep-merge, lists replace unless `+`); `severity_override` with mandatory
  reason+expiry; host-list semantics (allow ⇒ INFO + `allow_matched`; deny ⇒ annotation only)
- Baselines: `.lens/baseline.toml` canonical store via `/lens baseline <name> --reason "…"
  [--expires DATE]`; expiry enforced; suppressed findings machine-visible
- `explain-rules [--rule ID]` with provenance rendering (works both as CLI verb and slash verb);
  **`lens diff`** (report-vs-report, shift-stable fingerprints)
- **Worker-thread + coalescing cache hardening:** single worker thread owns all cold scans;
  `jobs.json` state machine (`queued→scanning→ready|failed`); coalescing keyed by bundle_hash
  (double-scan avoidance); failed jobs state why in one line and never retry silently

**Exit:** baseline round-trip suppresses exactly the baselined findings; settings-layer precedence
unit-tested against `ctx.get_config` fakes; diff survives a 10-line shift without flagging drift;
malformed policy exits 2 on CLI verbs, renders a one-line notice in-session; two concurrent
triggers for the same bundle produce exactly one scan job.

### Phase 3 — E8 depintel + corpus + determinism/privacy/perf CI — wk 9.5–11

- **E8 depintel** (unpinned-dependency notes, typosquat heuristics offline; `--osv` opt-in network
  enrichment tagged `enriched=true`)
- Corpus **≥40 malicious + ≥30 benign** fixtures authored directly as categorized-layout bundles
  (dogfoods the ingest path) with `expected.toml` manifests — a single public corpus published at
  full fidelity (HQ O5 resolved by owner: no stub/private split; publication risk accepted).
  **Licensing/provenance review gate BEFORE authoring the ~10 real-world-derived fixtures**
  (retained); the malicious set ships those real-world-derived fixtures at full fidelity; benign
  set keeps the hard cases (pentest labs with `[lab:declared-offensive]`, docker/k8s helpers,
  docs-heavy skills, non-English descriptions, unusual-but-legal frontmatter, Hermes-native skills)
- Determinism CI job (byte-compare canonical envelope across two runners / TZ / locale / path
  prefix; `_meta` excluded)
- **Privacy enforcement CI:** pytest-socket canned-scan tests asserting zero sockets (G1) **plus**
  an import-contract test asserting `skill_lens` imports no network modules in the default closure
  (G3 restated); SARIF validated against official schema; FP regression process live (every closed
  FP becomes a benign fixture)
- **Perf budgets measured inside a fake lifecycle dispatch** (fake `PluginContext` invoking the
  registered callback, not a bare function call): p95 cold ≤400 ms on ≤1 MB bundle; cached fast
  path <200 ms

**Exit:** 100% malicious fixtures caught in expected severity band; 100% benign ≥B on street;
corpus published full-fidelity public (HQ O5 owner call); determinism + socket-deny + import-contract jobs red-on-drift; perf budgets green
inside the fake dispatch.

### Phase 4 — Full trigger wiring, async delivered-results UX, watcher, hub view, doctor — wk 11–12.5

- **Trigger wiring in `register(ctx)`:** `on_skill_lifecycle` (created/installed/loaded/used/patched →
  fast-path one-liner or enqueue; return value discarded by the host — side effects are the
  ndjson record + queue entry), `post_tool_call` self-filtered to `skill_manage` (covers the
  agent-created gap the guard structurally misses); sober notices appended to model-visible tool
  results via `transform_tool_result(skill_manage)` (security-guidance precedent, H8), config
  kill-switch, automation surfaces permanently sober
- **Async delivered-results UX (04_ux §1.3/M3):** cache hit answers inline <200 ms; miss enqueues
  and returns the fixed-order status one-liner (`lens ok|scan|skip|fail … · /lens report`);
  delivered-result stat lines print from the worker thread in CLI sessions (H13 `run_in_terminal`
  precedent); any-session pull via `/lens report` + "N reports ready" banner on next invocation;
  everything mirrored to `events.ndjson`; gateway proactive push documented as unavailable (no
  plugin API) — stretch goal recorded, not promised
- **Watcher thread** for out-of-band drift in `~/.hermes/skills/**`: startup sweep always runs
  (persisted-hash compare; replays the while-away gap once), continuous 2 s→30 s adaptive backoff
  polling opt-in (`/lens watch start` / `watch.poll`), inotify accelerator, 500 ms debounce,
  hash-keyed coalescing with lifecycle fast path (`skip` status)
- **Hub quarantine view:** claimed-vs-actual render for bundles sitting in
  `skills/.hub/quarantine/` during the confirm beat — co-flagship moment; fast-path line within the
  beat, full report lands via worker + `/lens`; rendered alongside the existing advisory panels
  with explicit role labels ("advisory — skills_guard decides install policy"); rmtree-race
  tolerant; never touches `INSTALL_POLICY`
- **Doctor (Hermes-aware)** — same nine-check engine as SPEC §11.9, CLI renderer + in-session
  renderer: (1) rule-pack version/checksum vs release signature; (2) policy parse + effective
  profile with **all** sources (files, plugin settings, flags); (3) plugin-data dirs writable,
  `jobs.json`/`events.ndjson` healthy, quota bounds; (4) Hermes environment — `HERMES_HOME`
  discovery, plugin enabled, categorized skills tree found, hub scan-cache present, profiles tree
  discovered + route table parse-checked; (5) hook-wiring audit — assert zero `pre_tool_call`
  registrations against host `VALID_HOOKS`, fails loudly if any blocking wiring exists; (6)
  network-isolation self-test (canned scan; honest `config-audit only` where sandboxing is
  unavailable); (7) synthetic lifecycle self-test — emit canary event, assert Lens's own hook saw
  it (safe: observers best-effort, side-effect-free); (8) parse-subsystem health — crash-loop
  detection, reports AST active/degraded (D-PARSE lane made observable); (9) NO_COLOR/plain-render
  sanity. Doctor results land in `events.ndjson`

**Exit:** installing a RememberAll-style fixture via `hermes skills install` completes normally;
Lens prints its ≤200 ms cached line or queues silently and surfaces via `/lens`; installer path
untouched in every case; doctor catches a deliberately broken/deliberately-blocking wiring in
tests; watcher survives create/rename/delete churn and replays drift after a simulated restart;
agent-created skill write triggers the post_tool_call path.

### Phase 5 — Rule-pack governance + release engineering — wk 12.5–13

- Pack semver per SPEC §15 (**YYYY.MM.N**; new rule = patch; weight/severity change = minor +
  changelog rationale; deprecation ≥2 minors); ed25519-signed pack artifacts on GitHub Releases;
  `rules update/verify` manual-only (D-RULEOWN); rule-author CI (mandatory positive+negative
  fixtures per rule)
- Release engineering: git-tagged plugin versions (engine + pack pin together), upgrade story
  (`hermes plugins update`), changelog discipline, README quickstart + rule-author guide +
  threat-model & limitations statement ("static analysis only; clean ≠ safe"; coverage-honesty
  footer copy byte-frozen — it renders on every surface including slash output, R5)

**Exit:** tampered pack rejected; new rule travels PR→published entirely through CI; fresh
`hermes plugins install` from the release tag works end-to-end; downgrade of the plugin pins the
matching pack.

### Phase 6 — Surfaces polish + opt-in personality — wk 12.5–13 (parallel-friendly with P5)

- `map` (SkillIR rendering incl. hub-provenance annotations, categorized Hermes layout),
  `autopsy` clinical voice (+ microscopy alternate; noir stays deferred — tone-bleed rationale,
  O4), `bones` / self-scan gags adapted to fenced slash-command form
- NO_COLOR/`--plain` audit across slash + CLI outputs; Discord spoilers flag default-off; docs
  completion; FUN translation matrix conformance (F-1, F-3–F-6 per 04_ux §6 — F-2/F-9 cut by
  owner arbitration, HQ O3)

**Exit:** snapshot tests prove JSON/SARIF/effect-free behavior identical with every fun flag on/off;
map renders categorized layout correctly; chat outputs verified against 1200/1800-char budgets and
fence-safe chunking.

**Calendar:** P0 wk1–2 · P1 wk3–5 · P1.5 wk6–7 · P2 wk8–9 · P3 wk9.5–11 · P4 wk11–12.5 ·
P5+P6 wk12.5–13 (parallel) → **v0.9 ≈ week 11 if tree-sitter wheels land clean and corpus
authoring keeps pace with P1 slack; week 13 typical ceiling.** Working plugin cut weekly from
Day 1 (installable in a scratch `HERMES_HOME`).

## 2. First ten days (rolling lookahead; extended every Friday)

| Day | Work | Output |
| --- | --- | --- |
| 1 | Repo scaffold `hermes-skill-lens`: `plugin.yaml` manifest v2 (`api_version` pinned), `register(ctx)` skeleton, import `skill_lens`, pytest+ruff CI, licenses, signing key ceremony, scratch `HERMES_HOME` enable script | Plugin enables cleanly in scratch HERMES_HOME |
| 2 | SkillIR dataclasses + canonical JSON writer (`sort_keys`, `_meta` sidecar split); error taxonomy → structured diagnostics | Inventory dump works |
| 3 | Ingest walk of categorized `skills/<category>/<name>/`; frontmatter parser incl. `metadata.hermes`; name↔dirname check; unknown-field tolerance | Real-tree inventory prints |
| 4 | Edge cases: hub quarantine dir + rmtree-race tolerance, nested categories, symlinks, non-UTF8, huge files; hub lockfile provenance into IR (annotation-only) | Snapshot edge tests green |
| 5 | zip/dir/SKILL.md ingest targets; resource ceilings; `Engine` protocol + exception-isolation harness; daily scratch-home loop automated | Ceiling + isolation tests green |
| 6 | ClaimRecord IR + field-direct extractor (`allowed-tools`, `compatibility`, `metadata.hermes` hints); overreach primitive | Claims visible in IR dump |
| 7 | E7 secretscan: key prefixes + Shannon entropy + docs/examples allowlist | Planted AWS-key fixture caught |
| 8 | E6 netgraph: URL/IP extraction, dead-drop/tunnel/money-rail host classes, undeclared-host cross-check | Exfil fixture CRITICAL; money ceiling reachable |
| 9 | E3 shellscan (curl\|sh, rm -rf outside root, eval/base64 chains) + declared-discount vs field-direct claims; E1 manifest engine | Lab discounts apply; E1 findings render |
| 10 | Scoring v2 + renderer (chat-collapsed + terminal variants) + `/lens scan` slash command; fast-path cache; smoke over A–G; first dogfood on own skills tree | Demo-able v0.0.1 reproducing A–G exactly |

## 3. Testing strategy

1. **Host-contract tests:** a fake `PluginContext` (records `register_hook`/`register_command`
   calls, replays `on_skill_lifecycle`/`post_tool_call` kwargs shapes verbatim from the audited
   emit sites) asserting handlers **never raise into the host, never block** beyond the fast-path
   budget, degrade to one-line notices, and that zero blocking-capable hooks are ever registered.
   Perf budgets are measured through this fake dispatch, not bare calls.
2. **Golden-file corpus** with `expected.toml` manifests (findings by rule_id, severity band,
   exact score/grade/verdict). Fixtures authored as categorized-layout bundles (dogfoods ingest);
   HQ O5 resolved: corpus publishes full fidelity (owner arbitration).
3. **Determinism:** corpus scanned twice (different runner/TZ/locale/path prefix), byte-compare
   canonical envelope only (`json.dumps(sort_keys=True)` + `_meta` excluded). Fingerprints never
   embed absolute paths/timestamps.
4. **FP-as-fixture regression:** every closed FP adds a permanent benign fixture; deleting a rule
   requires its malicious fixtures to fail CI; mutation negatives of each malicious fixture must
   not fire. FP rate per release tracked in CHANGELOG.
5. **Property tests:** scorer monotonicity, cap-idempotence, dedup associativity, grade-clamp
   behavior under ceilings, fingerprint stability under line insertion.
6. **Privacy enforcement:** pytest-socket around canned scans (zero sockets) + import-contract test
   (no network modules in the default dependency closure) — G1/G3 as restated for in-process.
7. **Degradation goldens:** line-scanner fallback output golden-tested per engine so
   missing-grammar installs behave identically everywhere.
8. **Dogfooding:** Lens watches the maintainer's real `~/.hermes/skills` tree daily from Day 10;
   regressions on the live tree block release.

## 4. Rule pack governance

Conforms to SPEC §15 (canonical): packs are directories of YAML rules + `pack.yaml`; embedded
`core` works offline; semver **YYYY.MM.N** — new rule = patch bump, weight/severity change = minor
bump with changelog rationale, deprecation after ≥2 minor releases; positive+negative example
mandatory per rule; community packs SHA-pinned + capped at MEDIUM until promoted; packs signed
(ed25519) and published on GitHub Releases; updates manual only. User rules in `.lens/rules/`
(project) or `~/.config/lens/rules/` (personal) with `community/<pack>/LNS-…` id namespacing.

## 5. Distribution

The plugin repo is the artifact: `hermes plugins install <owner>/hermes-skill-lens`. Releases are git
tags + signed rule packs; engine and pack versions pin together per tag. No compiled components
shipped by us; tree-sitter grammars ride the pinned dual lane (declared `python_dependencies` +
vendored wheels, doctor-reported active/degraded, golden fallback). Standalone PyPI console-script
CLI deferred to v1.0 (SPEC §13). Naming: repo `hermes-skill-lens`, package import `skill_lens`, slash
command `/lens`.

## 6. Risks & mitigations

| # | Risk | L | I | Mitigation |
| 1 | High FP rate kills adoption (Cisco #138 mode) | M | H | Deterministic-only; declared/static discounts; tier caps; benign-corpus gate; FP-as-fixture process |
| 2 | Hook latency leaks into installs/agent turns | M | H | Fast-path-only synchronous work (<200 ms); cold scans on worker thread; host-contract tests assert non-blocking; slash handlers never run cold scans inline after P2; lifecycle emit site is best-effort try/except by design |
| 3 | Hermes plugin API evolution (manifest v2 young) | M | M | Pin `api_version`; use only audited seams (`register_hook`, `register_command`, `register_cli_command`, `get_config`, plugin-data dir); host-contract suite doubles as conformance tests against the bundled Hermes version; tolerate-and-warn unknown manifest fields (host precedent); unknown hook names warn-not-fail upstream |
| 4 | Native tree-sitter crash in-process (segfault uncatchable) | L | H | Grammar-input fuzzing normative; doctor parse-crash-loop note; subprocess parse-isolation documented as v1.0 escape hatch; golden fallback keeps degraded mode fully functional |
| 5 | `python_dependencies` never auto-install → silent AST loss | M | M | Dual delivery lane; doctor "AST active/degraded" check; degraded mode is golden-tested first-class output; changelog states the degradation honestly |
| 6 | Gateway sync-handler wedge (no timeout on sync command path) | M | H | Queue-first after P2; internal deadline in interim; async-result 30 s host cap respected (worker finishes independently of the reply) |
| 7 | Chat-surface rendering breakage (chunking, tables, ANSI) | M | M | Surface-neutral renderer: no ANSI, fences + aligned rows only, 1200/1800 budgets with disk overflow; snapshot tests per surface shape |
| 8 | Malicious corpus licensing/contamination | M | M | Public full fidelity, risk accepted by owner (HQ O5 resolved); legal read before authoring derived fixtures |
| 9 | Rule pack supply chain | L | H | Signed packs, SHA pins, manual updates only, provenance fields |
| 10 | Solo bus factor / slip | M | M | Weekly installable cut from Day 1; phases independently shippable; §8 cut list pre-agreed |
| 11 | Score gaming under thresholds | M | M | Caps make single-critical unavoidable; weights out of user-reachable policy; rubric published |
| 12 | Profile-scoped state confuses users (per-profile installs/views) | M | L | Per-profile stance documented in README + doctor output; cross-profile aggregation explicitly out-of-scope note |

## 7. Definition of done — v0.9 (Hermes plugin)

- [ ] `hermes plugins install <tag>` works end-to-end; enable/disable clean; malformed input → structured diagnostics, never an exception into the host
- [ ] All eight engines shipped: E1–E8 (E8 offline-mode if OSV deferred); tree-sitter dual-lane delivery resolved honestly; graceful grammar degradation golden-proven
- [ ] Claims subsystem complete: field-direct + lexicon extractors, overreach templates, LNS-MAN-004, report overreach section
- [ ] Core pack **30–40 rules**, every rule corpus-tested both ways
- [ ] Rubric v2 implemented exactly; SPEC §8.3 vectors A–G reproduced exactly; rubric documented publicly
- [ ] Triggers live and host-contract tested: `on_skill_lifecycle` + `post_tool_call(skill_manage)` + `transform_tool_result` sober notices (kill-switchable) + `/lens` slash command — observers only, zero blocking registrations asserted
- [ ] Async UX complete: fast-path one-liners (fixed field order, statuses ok/scan/skip/fail), `jobs.json` state machine, coalescing by bundle_hash, delivered-results printing in CLI sessions, `events.ndjson` mirror, gateway-push limitation documented
- [ ] Watcher covers out-of-band drift: always-on startup sweep + opt-in adaptive polling + gap replay; survives create/rename/delete churn
- [ ] Hub quarantine view live at the confirm beat, role-labeled, rmtree-race tolerant, never touching `INSTALL_POLICY`; skills_guard relationship per R7 recorded
- [ ] Doctor: nine checks green including synthetic-event self-test, blocking-wiring audit, AST active/degraded report, network-isolation self-test
- [ ] street/lab profiles + TOML & plugin-settings layers + merge semantics + severity_overrides with reason+expiry; `--fail-on` honored by CLI verbs; verdict documented as THE automation interface
- [ ] Baseline round-trip via `.lens/baseline.toml`; suppressed findings machine-visible; `lens diff` shift-stable
- [ ] `--json` (canonical envelope + `_meta` sidecar), `--sarif` (schema-validated), surface-neutral slash output within 1200/1800 budgets; byte-determinism CI green across runners
- [ ] Corpus ≥40 malicious / ≥30 benign all green, published full fidelity (HQ O5 owner call); licensing gate done
- [ ] Privacy G1–G6 test-enforced (socket-deny + import-contract green); perf budgets green inside fake lifecycle dispatch (p95 ≤400 ms cold, <200 ms cached)
- [ ] Signed rule packs (YYYY.MM.N); PR→published pipeline automated; plugin downgrade pins matching pack
- [ ] Choir stub present (contract + config, zero adapters); provenance rendered as annotation-only (enriched from hub lockfiles)
- [ ] Per-profile stance documented; profile-scoped behavior verified in a second scratch profile
- [ ] Fun modules strictly opt-in with snapshot-proven data-invariance; NO_COLOR/--plain respected; coverage-honesty footer on every surface
- [ ] Docs: README quickstart, rule-author guide, threat-model & limitations statement ("static analysis only; clean ≠ safe"), CHANGELOG
- [ ] Dogfooded on the maintainer's own `~/.hermes/skills` tree

*(Deferred per SPEC §13 — version assignments there are canonical: cross-file taint, subprocess parse-isolation escape hatch, community SHA-pin loading, standalone PyPI console-script (`lens`), **GitHub Action + SARIF upload**, opt-in `/lens second-opinion` LLM adjudicator promotion eval (the only model access — narrator cut, downgrade-only, `llm_touched`, ctx.llm-only; HQ R2), and the DeliveryRouter proactive-gateway-push stretch → **v1.0**; external ports, upstream-scanner choir interop, signature-awareness, proactive gateway delivery → **v1.1** —
stretch goals, designed not drifted.)*

## 8. Honest cut list (if ~9 weeks is all there is)

Ship P0 + P1 + P2 + corpus-lite (20 malicious / 20 benign) + full trigger wiring (lifecycle +
post_tool_call + transform notices) + `/lens scan|report` + doctor-lite (checks 1/2/5/7), with
E4/E5 as golden line-scanners (tree-sitter deferred), and E8/map/diff/watcher/hub-view deferred.
Everything cut is recorded in the changelog with its SPEC §13 home. The advisor stance,
determinism, scoring-v2 contracts, the non-blocking host contract, and the privacy guarantees are
never cut.
