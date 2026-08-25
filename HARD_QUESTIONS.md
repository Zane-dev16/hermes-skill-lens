# Hermes Skill Lens — HARD QUESTIONS

**Owner arbitration document · rev. 3 (all questions arbitrated) · 2026-08-23**

Thirteen dispositions: twelve former questions plus one the reframe itself surfaced. **All thirteen are now arbitrated.** The owner's 2026-08-22 decision — Skill Lens (then named Skill X-Ray) is a pure-Python Hermes plugin — triggered a decision-reversal audit (`.analysis/02_decisions.md`) against verified host source (`.analysis/01_platform.md`). The reframe didn't merely reshape architecture; it answered several former questions outright. Once Lens lives inside Hermes, language is settled by definition, the privacy question becomes "zero *direct* egress with any future model access riding the host's own `ctx.llm` lane," the regex-allowlist and advocacy questions gain decisive evidence, and the skills_guard relationship concretizes into a specified contract. Those are recorded below as **closed, with rationale** — reopening one requires new facts, not new moods.

The final five were taste- or two-sided after all evidence: rule-pack provenance values, the in-session loudness dial, share-card art direction, voice-pack scope, and fixture-corpus publication risk. Each records why it was hard → the options → the recommendation → the owner's ruling inline under **Owner's answer.**

Everything else was considered and **excluded as settled** — see the ledger at the bottom.

---

## Resolved by the reframe

### R1 · Implementation language: Python *(formerly Q1; owner decision 2026-08-22)*

**Decision:** Pure-Python Hermes plugin (SPEC §4, D-LANG rev. 2). The retired Rust-vs-Go analysis stays retired unless a v1.x standalone compiled CLI ever ships.

**Rationale:** Confirmed by direct inspection, not deference: built-in plugins are ordinary in-process Python packages loaded via `register(ctx)` (plugins.py:24–28), the host runs a single venv, and zero foreign-language plugin seams exist. The observer-hook timing (`on_skill_lifecycle` fires best-effort after authoritative state changes) genuinely dissolves the startup-budget argument that once favored compiled languages.

---

### R2 · Offline posture: templates-only in v0.9; claim restated as zero direct egress *(formerly Q2)*

**Decision:** v0.9 ships templates-only explanations — no model code in the truth path. **Owner arbitration: the `--llm` narrator is cut outright.** Lens generates no explanatory prose in any version — every coding agent that reads a Lens report explains it natively, so a built-in narrator would duplicate the host and clutter lean surfaces. The LLM layer is therefore exactly one thing: `/lens second-opinion` — detection for what rules can't catch.

**Owner doctrine (elevates this from "optional add-on" to core):** the LLM layer is a **core product pillar** (SPEC §1, pillar 3) — semantic second-opinion review only — because static rules establish *what happened* while only language understanding establishes *whether it matters*. Core ≠ default-on: phasing is deliberate, v0.9 = deterministic base whose zero-egress/deterministic claims are the launch marketing, v1.0 = `/lens second-opinion` delivered over the host lane behind its promotion gate.

**Rationale:** Verified against the platform dossier: `ctx.llm.complete/complete_structured` route over the operator's own provider connection with host-owned auth, routing, timeouts, and fallback — the plugin never touches credentials, every call bills to the operator's meter and lands in the host audit log, and override attempts fail closed behind `plugins.entries.<id>.llm.allow_*`. The binary-era claim ("this process has no network path, provably") is therefore dead, but the surviving claim is the one that matters: **zero direct egress** — lens opens no sockets and imports no network machinery; any future model access rides exclusively the host's consented lane. Templates-only still wins v0.9 on determinism (T2), cheapest-defensible-trust positioning, and phone-home optics (findings text flowing to a provider is exactly what the G-guarantees exist to avoid). *(Superseded by owner arbitration: the narrator was cut outright — sole model access ever is `/lens second-opinion`: opt-in, redacted finding-card payloads only, output tagged `llm_touched`, excluded from the canonical envelope, never severity-raising.)*

---

### R3 · Regex host/path allowlists: defer *(formerly Q4)*

**Decision:** Defer `re:` allowlists to v1.1; globs + PSL + deny-wins ship; the unstable flag is never shipped.

**Rationale:** The defer position gained two arguments: (1) idiom consistency — skills_guard's own policy matching is glob/`fnmatch`-class, so teaching Hermes users a second, sharper config dialect in the same breath they learn Lens's is avoidable cognitive tax; (2) the config surface grew a layer (`plugins.entries.lens.settings.*` via `ctx.get_config`), and every layer multiplies the audit burden of the most dangerous primitive a security tool can ship — user-authored regexes evaluated for match semantics. Globs cover the observed cases; promote on beta evidence through the same benign-corpus calibration gate as rules.

---

### R4 · Advocacy: rejected *(formerly Q6; owner arbitration)*

**Decision:** Rejected outright. Skill Lens does **no advocacy of any kind, in any release**: no claim-vocabulary proposal, no linter-recognition request, no authoring-skill guidance edits, no external campaigning (vendor PRs, conference talks, marketplace partnerships). This is **not deferred** — there is no roadmap item, no revisit date, no trigger condition, nothing to "keep alive." No agent or contributor schedules work for it, cites it in plans, or carries it forward. Only the owner editing this document reopens it.

**Rationale (owner):** The capability vocabulary is a feature request aimed at Hermes, not a Lens feature. Lens implements nothing against it and has zero dependency on it — claimed-vs-actual extracts claims from what authors already write (frontmatter fields, prose descriptions, tool lists), and undeclared behavior simply scores at full weight via the absence of the `declared` discount. Ecosystem persuasion is out of scope for a detection tool, full stop.

---

### R5 · Coverage-honesty footer: standing, on every artifact including slash renders *(formerly Q7)*

**Decision:** One-line byte-stable footer on every report surface — `· static analysis only — runtime-injected instructions (tool output) are out of scope · lens explain coverage` — full block behind `--limitations`; fast-path lifecycle one-liners exempt.

**Rationale:** Mechanics unchanged from the original recommendation; the reframe doubled the beneficiary. In-session, Lens reports are consumed by the agent itself before it advises the human — a grade-A skill whose danger lives in runtime tool-output injection is maximally dangerous in agentic contexts, and models demonstrably echo salient disclaimers they render. Same ~1-line cost, now paid twice over; nobody else prints their blind spot on every run.

---

### R6 · Naming: **resolved — brand "Hermes Skill Lens," display "Skill Lens"** *(formerly Q8; owner decision 2026-08-23)*

**Decision:** The earlier keep-"Skill X-Ray" recommendation is **superseded by the owner's 2026-08-23 rename call**. The product is **Hermes Skill Lens**, displayed as **Skill Lens**; the metaphor migrates radiology→optics ("A lens, not a bouncer. We show you what's there; you decide."). Identifier map, applied everywhere: repo/install `hermes-skill-lens` (`hermes plugins install owner/hermes-skill-lens`), slash command `/lens`, Python package import `skill_lens`, plugin key `lens` (config at `plugins.entries.lens.settings`), rule-ID prefix `LNS-`, GitHub repo `hermes-skill-lens` with PyPI package name `skill-lens` (reserved for the optional v1.0 console-script), release codenames drawn from optics pioneers (v0.9 Leeuwenhoek, v1.0 Newton, v1.1 Fresnel).

**Accepted collisions:** K8s Lens (the IDE), pi-lens, and Lens Protocol are acknowledged honestly and accepted per owner call — none operate in our space (static analysis of skill packages), host namespaces disambiguate in context, and search noise is a tolerable price for a metaphor that tells the truth about what the tool does.

**Decision history:** Drafted as "Skill X-Ray" through v0.3 (heritage preserved untouched under `.analysis/`). The 2026-08-22 reframe had recommended keeping that name — plugin key `xray`, slash `/xray`, import `xray_plugin`, registries `skill-xray`, a future standalone console alias `sxr` — reasoning that with no compiled binary there was nothing to collide with (AWS X-Ray, Xray-core) and in-host namespaces police themselves (`register_command` rejects built-in conflicts). The owner overrode on 2026-08-23 in favor of the optics identity. The migration is recorded exactly once in the changelog (SPEC Appendix A); all other artifacts carry only current names.

---

### R7 · Relationship to skills_guard: integrated display, strict non-coupling — now a concrete contract *(formerly Q11)*

**Decision:** At the hub quarantine beat, render Lens's full report beside the guard's verdict with explicit role labels (`advisory — skills_guard decides install policy`). Never read or write `INSTALL_POLICY`; never port guard regexes into the pack; dedupe only at render time, by annotation, when both fire on the same fingerprint.

**Rationale:** Ground truth confirmed every limb. The seam exists exactly as imagined (`~/.hermes/skills/.hub/quarantine/`; lockfile provenance resolvable via `trust_level_for`), and the clutter problem is worse than posed — Lens is the *third* opinion at that beat (guard gate + NVIDIA Tier-1 advisory + Lens depth), so labeled integrated display is the only arrangement that doesn't strand users reconciling three verdicts. The fit is complementary, not duplicate: the guard's `agent-created` policy row is permissive and `skills.guard_agent_created` defaults off, so authoring-time writes are structurally unvetted — the `post_tool_call(skill_manage)` beat Lens watches is unique coverage, not the guard's.

---

### R8 · Hub trust level as score modifier: no — provenance annotates, never computes *(surfaced by the reframe, immediately closed)*

**Decision:** Hub provenance/trust (`builtin` / `trusted` / `community`) renders on the patient line (`patient … (@openai/skills · trusted)`) and is stored in the IR — and is excluded from weights, discounts, ceilings, and grades. Permanently.

**Rationale:** Baking provenance into arithmetic would (a) break cross-source determinism — same bytes, different score by birthplace, (b) import the guard's trust politics, including its `TRUSTED_REPOS` list, into Lens's independence claim, and (c) mute exactly the scenario that matters: a compromised trusted repo would scan soft. Annotation preserves the spirit of the original N3 proposal under T2/D-EXPLAIN discipline. Display detail: lifecycle hook payloads carry bounded provenance classes only, so enrich provenance at scan time from hub lockfiles, never from hook kwargs.

---

## Still open — owner arbitration

> **Status note:** each open item below carries my recommendation, and SPEC/PLAN
> *provisionally implement it* so the docs stay buildable. Your answer overrides —
> where you disagree, the change propagates to the cited sections.

Five dials where the evidence narrows the space but cannot turn the knob for you.

### O1 · Rule-pack provenance: how independent is "independent"? *(formerly Q3)*

**Why it's hard:** Arch-review correctly rules that Lens must *own* its core pack — claimed-vs-actual tagging requires our ontology, which upstream engines cannot emit. But it never answered the adjacent question: when authoring those ~30–40 converged v0.9 rules, may we transcribe/adapt pattern logic from Cisco skill-scanner and NVIDIA SkillSpector, both conveniently Apache-2.0 and locally cloned? Transcription closes coverage gaps fast; clean-room authorship protects the "independent second opinion" positioning and avoids inheriting upstream false-positive profiles (Cisco #138 showed packs can cascade). The reframe didn't change the tradeoff — it only made calibration raw material easier to reach (guard regexes and the SkillEvaluator wrapper are locally inspectable for FP-profile study), and R7 confines guard patterns to the study/attribute/recalibrate bucket, never wholesale import.

| Option | Pros | Cons |
| --- | --- | --- |
| **Clean-room only** (derive purely from our taxonomy indicator tables) | Maximum independence claim; FP profile fully ours; no provenance bookkeeping | Slower to coverage; risks repeating upstream blind spots they already fixed |
| **Transcribe freely with attribution** | Fastest path to parity with 68-pattern-class coverage; license-clean; incident citations enrich rule cards | Report must disclose derived lineage or the independence claim becomes dishonest; inherits subtle FP-prone pattern shapes unless recalibrated |
| **Hybrid: own core + attributed ports behind a promotion gate** | Coverage speed *and* control; per-rule `origin:` field keeps reports honest; ports promoted only after passing benign-corpus PR-curve calibration | Most process overhead; needs a written provenance policy on day one |

**Recommendation:** **Hybrid.** Seed the core from our own taxonomy (built to be transcribable into rules); allow Apache-2.0-derived ports tagged `origin: adapted-from <repo@sha>`; require every port to pass the same benign-corpus calibration bar as originals before entering a signed bundle. Attribution lives in `lens explain` rule cards, so honesty is rendered, not promised.
**Confidence:** Medium-high — the mechanism is sound; the *degree* of independence you want to advertise is the value call.

**Owner's answer:** *(Confirmed — hybrid stands exactly as provisionally specified: own core + Apache-2.0-derived ports tagged `origin:`, each passing the benign-corpus calibration gate; `origin:` fields render in rule cards.)*

---

### O2 · How loud is `/lens scan` inside the conversation? *(formerly Q5, narrowed by the reframe)*

**Already settled by the reframe:** terminal TTY keeps the full Balanced rendering; `shell_interpreter = false` stays the shipped default (defaults are what reviewers quote); `doctor` offers the dev preset interactively. What remains open is the default plate for slash-command output.

**Why it's hard:** Slash output lands inside the conversation — paid context tokens the model conditions on, possibly relayed through gateways where wide tables flatten and long messages chunk (Discord splits near 1900 chars). Printing every honestly-declared capability as a diff row nags on most marketplace skills (declared shell+network is normal for dev tooling); hiding them trains users to skim past the claimed-vs-actual story that *is* the product. The corpus target (≥95% benign ≥60) bounds the ceiling on nagging, not the right point under it — and the worst-N cutoff is unvalidated taste.

| Option | Pros | Cons |
| --- | --- | --- |
| **Collapsed summary default** — count line + worst-N findings + pointer to `/lens report` (full panel renders from disk) | Cheap in-context; nothing hidden (the count line *is* the line item); disk-path rendering is required by gateway constraints anyway | Worst-N cutoff is arbitrary; power users retype a command for detail |
| **Full panel always** | Zero information lost mid-chat | Token tax on every scan; gateway chunking/flattening mangles it; nagging on benign skills |
| **Grade-adaptive** — alert/warn render full; notice/clean collapse | Attention flows where risk lives | Non-obvious surface behavior is hardest to golden-test, document, and predict |

**Recommendation:** **Collapsed summary default**, worst-N ≈ 5, count line accounting for every point; `/lens report <id>` serves the full optical panel from `ctx.state.data_dir` (which gateway constraints force us toward anyway).
**Confidence:** Medium — calibrated taste; weeks of dogfooding will tell you if worst-N is wrong.

**Owner's answer:** *(Confirmed by owner: in-session surfaces are stat lines, never clunky summaries — collapsed-by-default worst-5 stands; full panel only on explicit `/lens report`; per-finding explanations stay one consult away. Codified as the Surface Principle, SPEC §1.)*

---

### O3 · Share cards: REJECTED outright *(formerly Q9; owner arbitration)*

**Decision:** The exportable share-card feature is **cut entirely — an overfeature, unnecessary**. No SVG posters, no plates or themes, no `/lens card`, no `--card` flag, no `card_theme` setting — in v0.9 or any release. Lens renders stat lines and reports on its own surfaces; it does not manufacture shareables. (Prior art-direction analysis survives only as archived heritage; FUN.md F-2/F-9 carry cut markers.)

**Owner's answer:** Rejected outright — not deferred, nothing to revisit. Only the owner editing this document revives it.

---

### O4 · Voice pack: how much humor ships in v1? *(formerly Q10)*

**Why it's hard:** The adopted voices are `clinical` (default, byte-identical to plain output) and `microscopy` (dry dictation), protected by data-invariance golden tests; the earlier ideation pass had a campier noir pathologist (*"Time of death: v2.3.1. Cause: unresolved TODO"*). Every extra voice triples golden-file maintenance and enlarges the surface where tone can bleed into facts despite the tests. The reframe added a failure mode those tests *cannot* catch: slash output enters the conversation as context the model conditions on, so a campy register routinely injected mid-session risks bleeding into assistant behavior well outside Lens's replies. Dry understatement is low-bleed by construction; camp is the highest-bleed prose we could ship.

| Option | Pros | Cons |
| --- | --- | --- |
| **Clinical only in v1** | Zero cringe risk; smallest surface; voices arrive polished later | Ships a personality doc and no personality; delays the cheapest delight win |
| **Clinical + microscopy (dry)** in v1; campier registers later, usage-gated | One real alternate voice proves the template-pack mechanism; dry humor survives contact with critical-severity tables; bounded maintenance | Some users will ask "is that all?" — the joke is quiet by design |
| **All three incl. noir camp** | Maximum delight-per-release; covers both comedy registers | Triple golden files; camp voice *will* be screenshotted beside a 0.93 exfil finding eventually — and now bleeds into session context |

**Recommendation:** **Clinical + microscopy in v1**, snapshot test asserting finding-data byte-equality across voices from day one (it's the mechanism that makes later voices safe). Add noir only if usage data shows people actually toggle voices — humor nobody selects is debt, not delight, and in-session it's bleed risk too.
**Confidence:** Medium-high.

**Owner's answer:** *(Confirmed — clinical + microscopy only in v1; noir stays deferred usage-gated.)*

---

### O5 · Fixture corpus: publication posture *(formerly Q12)*

**Why it's hard:** `lens playground` and the calibration lab both need a labeled corpus including Shai-Hulud/nx/postmark-class reproductions. Full-fidelity public fixtures make regression testing honest and help other scanner authors — but they also publish a curated, *tested* playbook for exfiltrating credentials past marketplace previews. Stubbing weakens fidelity claims; splitting adds sync friction and a temptation to let the private half rot. No amount of evidence decides risk appetite — this is a publication-liability call only you can sign. The reframe added conveniences, not arguments: fixtures can be authored directly as categorized-layout SKILL.md bundles (dogfooding the ingest path), the hub's own quarantine dir is a legitimate private-side calibration source under the same legal/provenance review gate, and the playground translates cleanly to `/lens playground`.

| Option | Pros | Cons |
| --- | --- | --- |
| **Public, full fidelity** | Best science; community-wide detection uplift; maximal credibility | Publishes working exfil recipes keyed to real dead-drop techniques; fuels the arms race |
| **Public stubs engineered for identical rule trips** (fake keys shaped like real token grammars, `*.invalid` hosts, echo endpoints) + **private full-fidelity corpus** for lab PR-curves | Safe-by-construction yet exercises every rule deterministically (CI asserts stub/real corpora produce identical fingerprints); private side keeps honest metrics | Two corpora to keep in sync; skeptics can't audit the private half |
| **Private everything** | Zero publication risk | Playground becomes vapor; no community proof; corpus quality unverifiable |

**Recommendation:** **Split, with a parity invariant.** Stubs trip the same rules with the same confidence as their real counterparts — CI-enforced fingerprint equality between stub-corpus and private-corpus runs, so the public suite never silently diverges from what the lab measures. Extend the canary fake-key grammar discipline corpus-wide. Mechanism confidence high; the go/no-go on deriving any fixture from real-world attacks is yours.
**Confidence:** High on mechanism; publication risk acceptance sits with you.

**Owner's answer:** Publish full fidelity — the public corpus ships the real-world-derived fixtures, "no biggie." Publication risk explicitly accepted by owner; no stub/private split, no parity-invariant machinery. The licensing/provenance review gate stays.

---

## Considered and deliberately NOT asked (settled by research)

- **Lab mode ships in v1** — one schema, `street`/`lab` presets (arch-review Q3, D-P1/P2).
- **Choir disposition** — v0.9 ships config + downgrade-only contract stub, zero adapters; upstream-scanner adapters v1.1; LLM adjudicator owner-moved to a **v1.0 promotion eval**: opt-in `/lens second-opinion` (downgrade-only, `llm_touched`, outside canonical envelope), judged against the benign-corpus PR-curve before any default-on. `ctx.llm` only lowered the adapter's future cost, reinforcing the stub (D-FP).
- **Mascots and product renames** — rejected at drafting time; persona-over-puppet. (The naming half was later superseded by the owner's 2026-08-23 rename — see R6.)
- **Grade-band cutoffs and action precedence** — U1/U6, D-SC2.
- **Exit-code contract** — now scoped to CLI verbs only. In-session there is no exit channel (`register_command` handlers return strings; hook returns are discarded), so the **verdict field + `needs_review` flag is THE automation interface everywhere**; "exit 2" moments render as notice text with identical wording so logs stay greppable across surfaces. No invented slash-command error sentinels (X2).
- **Policy auto-load prohibition** — R1/D-P1.
- **Blocking hooks banned** — `pre_tool_call` exists and is blocking-capable (fail-closed block/approve/modify), which makes observer-only abstention a visible, contrastive choice; doctor check asserts zero `pre_tool_call` registrations (T1/D-HOOK).
- **Watch mechanics** — hash-poll default with OS events as accelerator only (D-WATCHPOLL); dies with the host process.
- **Tree-sitter delivery lane** — logistics, not taste: pin manifest `python_dependencies` declaration + doctor "AST engines active/degraded" check + golden-tested line-scanner fallback, else demote AST engines to v1.0 (PLAN Phase 1.5 action, D-PARSE).
- **Windows hooks timing** — v1 scan-only.
- **Multilingual lexicons and captioner promotion gates** — deferred pending eval; model-access posture (second-opinion only, narrator cut outright) is recorded at R2.
