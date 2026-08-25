# BUILD PROMPT — Hermes Skill Lens v0.9

> Hand this document to a coding agent as its prime directive. It is self-contained: every truth
> it needs lives in this repository or in the Hermes source tree on this machine.

---

## 0. Your mission

You are building **Hermes Skill Lens** (`skill_lens`) — a **pure-Python Hermes Agent plugin** that
scans agent skill bundles and produces a deterministic security report: trust score, grade,
claimed-vs-actual capability diff, evidence-cited findings. It is an **advisor, not a gate**: it
never blocks an install, never refuses a download, never interferes with creating or editing a
skill. You are implementing v0.9 exactly as specified, phase by phase, until the Definition of Done
(§7 of `PLAN.md`) is met.

Work inside this directory (`/root/hermes-skill-lens/`). `git init` here first; this repo IS the
distribution artifact (`hermes plugins install owner/hermes-skill-lens`).

## 1. Read these, in this order, before writing any code

| Order | File | Role |
| --- | --- | --- |
| 1 | `SPEC.md` | **Canonical product truth.** Pipeline, engines, IR/Finding schemas, scoring rubric v2 (worked examples A–G), policy layers, surfaces, privacy guarantees, governance, threat matrix, exit codes. Where any document disagrees with SPEC, SPEC wins. |
| 2 | `PLAN.md` v4.0 | Build order, phase exit criteria, first-10-days table, testing strategy, risks, DoD checklist, honest cut list. Your schedule. |
| 3 | `HARD_QUESTIONS.md` rev.3 | **Owner law.** R1–R8 are resolved decisions; O1–O5 carry owner rulings recorded inline. Never relitigate these. If you find code you're about to write that contradicts them — stop and conform. |
| 4 | `FUN.md` | Opt-in personality module. Clinical + microscopy voices only; share cards are REJECTED (do not revive); default output stays sober. |
| 5 | `docs/` | Historical phase archive. Provenance only — names in there are stale (pre-rename). Read for rationale if stuck; never copy stale identifiers from it. |
| 6 | `.analysis/` | Research dossiers (platform integration facts with Hermes file:line citations). Useful grounding; same staleness caveat. |

## 2. Non-negotiables (violating any of these is a failed build)

1. **Advisor, not gate.** You register ONLY observer hooks: `on_skill_lifecycle`,
   `post_tool_call` (self-filtered to `skill_manage`). You NEVER register `pre_tool_call`. Hook
   callbacks never raise into the host, never return blocking directives, always behave
   success-shaped. There is a doctor check (#5) that fails loudly if blocking wiring exists — keep
   it green.
2. **Deterministic core.** Same input bundle + same rule pack ⇒ byte-identical canonical JSON.
   Sort everything (`sort_keys=True` canonical dumps), integer-point scoring, stable sorts by
   `(rule_id, path, start_line)`. Wall-clock/timings live ONLY in the `_meta` sidecar, which the
   determinism tests exclude.
3. **Scoring rubric v2, exactly.** Weights, tier caps, ×0.5 modifiers, ceilings (which clamp grade
   too), grades A≥90/B≥75/C≥60/D≥40/F<40, verdicts, `needs_review` as a FLAG (never a fifth
   verdict). Phase 1 exits only when the golden vectors reproduce SPEC §8.3 examples A–G EXACTLY:
   A=100/A·clean · B=91/A·notice · C=25/F·alert · C′=40/D·warn·needs_review · D(lab)=85/B·notice ·
   E=80/C·warn · F=83/B·notice · G=70/C·warn. No ±1 tolerance.
4. **Python 3.11+, zero compiled components** except tree-sitter via official bindings
   (`python_dependencies` + vendored wheels where platform-clean). Line-scanner fallback is
   first-class, golden-tested output; if grammar delivery can't clear git-install cleanly by end of
   Phase 1.5, AST engines demote to v1.0 honestly.
5. **Privacy G1–G6.** Zero network sockets in the default path — proven by pytest-socket tests.
   No telemetry, ever. Secrets never rendered unredacted. `--osv` and `/lens second-opinion` are
   the only opt-in network/model surfaces, both labeled `enriched=true` in reports.
6. **No model prose, any version.** The narrator was cut outright by owner ruling. Lens generates
   no LLM text. Model access exists solely as opt-in `/lens second-opinion` (downgrade-only choir,
   v1.0 promotion eval). Explanations are deterministic templates + rule text.
7. **No share cards.** Rejected outright by owner (HQ O3). No SVG posters, plates, themes,
   `/lens card`, `--card`, or `card_theme` setting — not in v0.9, not later, unless the owner edits
   `HARD_QUESTIONS.md`.
8. **Corpus is public full-fidelity.** One public corpus (≥40 malicious / ≥30 benign fixtures with
   `expected.toml` manifests). NO stub/private split, NO parity-invariant machinery. The
   licensing/provenance review gate before authoring real-world-derived fixtures STAYS.
9. **Exit codes (CLI verbs only):** 0 default (advisor stance — findings are not failures);
   1 only under explicit `--fail-on LEVEL`; 2 total error. Slash commands and hooks return
   strings/behave success-shaped; the verdict field is THE automation interface everywhere else.
10. **Surface Principle:** in-session output is stat lines — collapsed count-line + worst-5 +
    pointers. The full radiology panel renders on CLI/explicit `/lens report`. Never dump panels
    into chat.
11. **Naming:** brand "Skill Lens" (formal "Hermes Skill Lens"), CLI `lens`, slash `/lens`, import
    `skill_lens`, plugin key `lens`, rule prefix `LNS-`, repo `hermes-skill-lens`.

## 3. Environment facts (verified on this machine)

- Hermes source: `/usr/local/lib/hermes-agent` (read it — do not guess APIs). Home:
  `~/.hermes` (respects `HERMES_HOME`).
- Plugin system: `plugin.yaml` manifest (v2 fields supported; unknown fields warn-and-continue)
  - `__init__.py` exposing `register(ctx)`. Hooks via `ctx.register_hook(name, fn)` — the full
  valid set is `VALID_HOOKS` in `hermes_cli/plugins.py`. Slash commands via
  `ctx.register_command(name, handler, description)`; handler signature `fn(raw_args) -> str|None`.
  Namespaced settings via `ctx.get_config/set_config` (config path
  `plugins.entries.lens.settings`). Study bundled references: `plugins/disk-cleanup/` (hooks +
  slash command), `plugins/security-guidance/` (tool-result transform lane, warning tone),
  `tools/skills_guard.py` + `tools/skillevaluator_scan.py` (the layers you complement — never
  modify, never subsume; your relationship is R7: render advisory reports on hub-quarantined
  bundles with role labels, strict policy non-coupling).
- Skills live at `~/.hermes/skills/<category>/<name>/SKILL.md`; hub staging at
  `skills/.hub/quarantine/` (watch it — `do_install` fires no hooks); provenance in
  `.hub/lock.json`.
- Isolated test loop: `export HERMES_HOME=/tmp/lens-dev && mkdir -p $HERMES_HOME`, then
  `hermes plugins enable lens` (or install from your repo path) and drive installs through
  `hermes skills ...` to exercise triggers without touching the real home.
- Trigger payloads: `on_skill_lifecycle(action ∈ created|installed|loaded|used|patched,
  skill_name, provenance, task_id, session_id, ...)`. Fast path (<200 ms cached one-liner)
  synchronous; cold scans enqueue to ONE worker thread; results land in `jobs.json` /
  `events.ndjson` and surface via `/lens report` ("N reports ready") or watch deltas. Skill
  installation never waits on Lens.

## 4. Execution protocol

1. Work phases in order (PLAN §1): P0 spine → P1 claims+E1/E3/E6/E7+scoring+`/lens scan` →
   P1.5 AST engines+lexicon → P2 policy/baseline/explain/diff → P3 depintel+corpus+CI →
   P4 trigger wiring/watcher/hub view/doctor → P5 governance/release → P6 polish+fun.
   Each phase has explicit **exit criteria** — they are gates. Do not start a phase before the
   previous gate is green.
2. First-day tasks (PLAN §2, Day 1): git init, plugin scaffold (`plugin.yaml` v2 + `register(ctx)`
   skeleton that loads clean in a scratch HERMES_HOME), pytest+ruff CI, licenses, rule-pack signing
   key ceremony, name registration (`hermes-skill-lens` GitHub / `skill_lens` PyPI / `skill-lens`).
3. Maintain a `DECISIONS.md`: every implementation choice the specs don't pin down, with rationale.
   Advisor-safest option wins ties. If a conflict between documents can't be resolved by the
   precedence rule (§1), fix toward SPEC and log it.
4. Testing discipline (PLAN §3): golden-file corpus with `expected.toml` per fixture;
   determinism job (byte-compare canonical envelope across two runners); FP-as-fixture (every
   closed false positive becomes a permanent benign fixture); property tests (monotonicity,
   cap-idempotence, dedup associativity); host-contract tests with a fake `PluginContext`
   asserting never-block/never-raise; socket-deny privacy tests; perf budgets (p95 cold ≤400 ms
   on ≤1 MB, <200 ms cached fast path) measured inside a fake lifecycle dispatch.
5. Cut an installable, working plugin **weekly**, tagged, into a scratch HERMES_HOME. A phase
   without a demoable artifact at its end did not happen.
6. Rule pack: 30–40 rules at v0.9. Every rule ships WITH ≥1 true-positive golden fixture AND ≥1
   benign lookalike negative fixture — missing negatives block merge (SPEC §15). Budget ~27–30 of
   them for the Hermes-precedent threat set (SPEC §17): persona/SOUL poisoning, related_skills
   chaining, metadata.hermes abuse, control-plane writes, agent-cron persistence, channels,
   profile-crossing.
7. When you hit something genuinely ambiguous after checking the precedence chain: implement the
   advisor-safest reading, log to `DECISIONS.md`, keep moving. Do not stall the build for
   arbitration; surface open questions in a `QUESTIONS_FOR_OWNER.md` instead and continue on
   unaffected phases.

## 5. Done means (full list: PLAN §7)

All nine doctor checks green · eight engines shipped with graceful degradation proven · claims
subsystem complete · 30–40-rule pack fully corpus-tested both ways · vectors A–G exact · triggers
live and host-contract-tested · watcher covering out-of-band drift · street/lab + baselines +
explain-rules + diff working · JSON/SARIF validated + byte-determinism CI green · corpus ≥40/≥30
all green with legal review done · privacy + perf budgets CI-enforced · signed packs + PR→publish
pipeline · choir stub present · fun strictly opt-in behind data-invariance snapshots · docs
complete (README quickstart, rule-author guide, threat-model & limitations statement: "static
analysis only — runtime-injected instructions are out of scope · clean ≠ safe") · dogfooded on the
maintainer's own `~/.hermes/skills` tree.

If time-boxed below ~10 weeks, apply PLAN §8's cut list in order and record every cut in the
changelog with its roadmap home. The advisor stance, determinism, scoring-v2 contracts, and the
non-blocking host contract are never cut.

## 6. Standing orders

- The user's phrase for the product posture: **"A lens, not a bouncer."** Every design argument
  resolves toward more transparency, less intervention.
- Report progress as: phase, gate status, artifacts cut, open questions. Keep `DECISIONS.md` and
  `QUESTIONS_FOR_OWNER.md` current.
- Start now: read §1's documents in order, then execute Day 1.
