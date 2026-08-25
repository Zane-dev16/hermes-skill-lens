# 06 · DECISION LEDGER — Owner Arbitration Sweep (HARD_QUESTIONS.md rev. 3, 2026-08-23)

**Source of truth:** `/root/hermes-skill-lens/HARD_QUESTIONS.md` (read in full: header, R1–R8 prose,
O1–O5 prose + tables + Owner's answers, settled-exclusions list, closing notes).
**Swept:** SPEC.md (928 lines), PLAN.md (342 lines), FUN.md (360 lines) — every occurrence of
card/plate/film/SVG/poster/share · corpus/fixture/stub/private/parity/fidelity · narrator/--llm/
second-opinion · advocacy/vocabulary/standards · voice names incl. `plain` · worst-N/collapsed/
count-line/stat-line · footer/coverage literals · xray/sxr/radiology · trust/provenance arithmetic ·
`.analysis` references · legacy Q-number citations.

**Status vocabulary:** `NEW` = ruling decided here for the first time · `CONFIRMED` = matches what
SPEC/PLAN provisionally encode · `REVERSED` = the provisional spec encodes the opposite of the
ruling. Each item lists **every** affected location and the required change; ✅ = verified already
conformant (no edit needed); ⚠️ = residue requiring an edit.

---

## D-SHARECARD · Share cards rejected outright (HQ O3)

**Owner ruling (quote):** "The exportable share-card feature is **cut entirely — an overfeature,
unnecessary**. No SVG posters, no plates or themes, no `/lens card`, no `--card` flag, no
`card_theme` setting — in v0.9 or any release. Lens renders stat lines and reports on its own
surfaces; it does not manufacture shareables." Answer: "Rejected outright — not deferred, nothing to
revisit. Only the owner editing this document revives it."

**Status:** REVERSED (provisional spec shipped cards; removal is total, nothing deferred).

**Already conformant (heritage sanctioned by O3's own carve-out "prior art-direction analysis
survives only as archived heritage; FUN.md F-2/F-9 carry cut markers"):**

- ✅ SPEC §12.5 "Share cards — CUT (owner arbitration)" — cut marker + explicit rejection sentence;
  retained body paragraph = sanctioned heritage.
- ✅ SPEC §16 ranked list item 1 — "**Share cards — CUT** … nothing poster-shaped ships in any version."
- ✅ SPEC §16 "Rejected by guardrails" tail unchanged (cards not listed there — correct, they're cut, not guardrail-rejected).
- ✅ SPEC §10 plugin-settings keys (`profile`, `watch.poll`, `discord_spoilers`, `voice`,
  `chat_budget_chars`) — no `card_theme`; §11.2 verb table has no `card` verb; scan flag list has no
  `--card`/`--svg`.
- ✅ PLAN Definition-of-Done — no card acceptance criteria.
- ✅ FUN §4 compliance checklist rows F-2 / F-9 — both carry "⛔ CUT (HQ O3)".
- ✅ FUN §2 feature bodies F-2 (line 107, ⛔ CUT marker, "Retained below as design heritage only") and
  F-9 (line 307, ⛔ CUT) — marked blocks are heritage.

**Residues requiring edits (live text still treating cards as shippable):**

- ⚠️ **SPEC §13, v1.0 bullet:** "optional DeliveryRouter/media-pipeline stretch for proactive gateway
  push **+ inline cards** (both hinge on the same missing plugin push API — elected or rejected by
  owner)" → delete "+ inline cards"; the stretch reduces to proactive gateway push only ("inline
  image embeds"/cards are dead in every release per O3).
- ⚠️ **PLAN §7 DoD deferred list (final parenthetical):** "and the elected-or-rejected
  DeliveryRouter/**media-pipeline** stretch → v1.0" → drop "media-pipeline" (card-lineage vocabulary;
  media pipeline existed to carry inline card/embed output) → "DeliveryRouter proactive-gateway-push
  stretch".
- ⚠️ **PLAN Phase 6, second bullet:** "FUN translation matrix conformance (**F-1..F-6** per 04_ux §6)"
  → range includes cut F-2 → restate as "F-1, F-3–F-6" (F-2 excluded as CUT).
- ⚠️ **FUN §2 build-order line:** "Build order: **F-1 → F-2 → F-6** first … **F-7–F-9** as garnish"
  → remove F-2 and F-9 from the build order (they are never built): e.g. "F-1 → F-6 first …
  F-3, F-5 next … F-4 once watch exists; F-7–F-8 as garnish."
- ⚠️ **FUN §4 Plugin-port note (after checklist):** "F-1, F-5, F-6, **F-9** translate directly to
  `/lens` verbs; **F-2 returns the SVG by path** (chat users attach manually); F-3/F-4 remain
  CLI-TTY-only …" → delete both F-9 and F-2 clauses; port note covers F-1, F-5, F-6 only.
- ⚠️ **FUN §1 Recommendation paragraph:** "film-grain texture **in SVG art only**" and "scales across
  every surface (terminal, **SVG**, docs)" → with cards cut there is no SVG art anywhere; reword to
  drop the SVG-art clause (visual language now lives on terminal/chat renders and docs only).

---

## D-CORPUS · Fixture corpus publishes PUBLIC FULL-FIDELITY (HQ O5)

**Owner ruling (quote):** "Publish full fidelity — the public corpus ships the real-world-derived
fixtures, 'no biggie.' Publication risk explicitly accepted by owner; **no stub/private split, no
parity-invariant machinery**. The licensing/provenance review gate stays."

**Status:** REVERSED (provisional recommendation was stub/public + private split with CI fingerprint-
parity invariant; owner chose the other option outright).

**Already conformant (updated during arbitration pass):**

- ✅ PLAN Phase 3 gate sentence: "(HQ Q12 resolved by owner: corpus publishes full fidelity — no
  stub/private split)" — licensing/provenance review gate BEFORE authoring the ~10 real-world-derived
  fixtures correctly RETAINED.
- ✅ PLAN Phase 3 Exit: "corpus published full-fidelity public (HQ Q12 owner call)".
- ✅ PLAN §3 Testing strategy item 2: "HQ Q12 resolved: corpus publishes full fidelity (owner
  arbitration)."
- ✅ PLAN §7 DoD: "Corpus ≥40 malicious / ≥30 benign all green, published full fidelity (HQ Q12 owner
  call); licensing gate done".
- ✅ No parity-invariant machinery anywhere: grep for parity/stub-split/CI-fingerprint-equality across
  SPEC/PLAN/FUN finds none (only unrelated "stub" uses: choir contract stub — a different, still-valid
  decision). `.analysis` references (SPEC Appx A item 16, PLAN header) are historical audit citations,
  not parity language — keep.
- ✅ SPEC carries no corpus publication posture at all (§15 fixtures are per-rule golden TP/FP
  requirements; publication-neutral) — nothing to reverse in SPEC.

**Residues requiring edits (pre-arbitration posture language contradicting full fidelity):**

- ⚠️ **PLAN Phase 3, sentence after the gate:** "Malicious set models campaigns *from descriptions*,
  **sanitized**;" → the "sanitized/from-descriptions-only" clause is the old risk-mitigated posture;
  under the accepted-risk full-fidelity call it must be conformed (delete "sanitized" or reword to
  "real-world-derived fixtures authored under the licensing/provenance review gate").
- ⚠️ **PLAN §6 Risk-table row 8 mitigation:** "**Fixtures from descriptions, never payloads**; HQ Q12
  resolved — public full fidelity, risk accepted by owner; legal read before authoring derived
  fixtures" → first clause contradicts the ruling it precedes; strike "Fixtures from descriptions,
  never payloads;" keeping "public full fidelity, risk accepted by owner; legal read before authoring
  derived fixtures".

---

## D-SURFACE · Surface Principle codified in SPEC §1 (HQ O2)

**Owner ruling (quote):** "Confirmed by owner: in-session surfaces are stat lines, never clunky
summaries — collapsed-by-default worst-5 stands; full panel only on explicit `/lens report`;
per-finding explanations stay one consult away. Codified as the Surface Principle, SPEC §1."

**Status:** CONFIRMED — SPEC already encodes it, by name.

**Locations verified:**

- ✅ SPEC §1 "Product doctrine — three pillars, one surface principle": pillar 2 "Glanceable stats
  surfaces — in-session output is a *stat line*, never a dump … The full microscopy panel lives
  behind `/lens report`; nothing clunky renders by default."; named paragraph "**Surface principle:**
  *stats at a glance, explanations on consult.* … each entry carries an explanation one step away …
  never walls of prose." — Principle stated by name; no insertion needed.
- ✅ SPEC §11.3 bullet "**Collapsed-by-default**: `/lens scan` returns count-line + worst-N findings +
  pointers"; overflow path writes full report to disk + pointer.
- ✅ SPEC §12.2 chat compact variant; Appendix A items 18 & 34 ("O2 collapsed-stat rendering
  confirmed as owner answer"); PLAN locked-table Surfaces row + Phase 1 collapsed chat variant +
  Day-10 renderer row.

**One conformance tweak:**

- ⚠️ The number 5 is pinned nowhere: SPEC §1 pillar 2 says "verdict, score, **worst finding**, count"
  (singular) and §11.3 says "worst-**N**". Owner pinned worst-**5**. → Set N=5 explicitly in §11.3
  ("worst-5 findings") and align pillar 2 wording ("worst finding(s)") so the confirmed dial is
  reproducible for golden tests.

---

## D-VOICE · Voice pack scope (HQ O4)

**Owner ruling (quote):** "(Confirmed — clinical + microscopy only in v1; noir stays deferred
usage-gated.)"

**Status:** CONFIRMED.

**Locations verified:**

- ✅ SPEC §16 item 2: clinical default + microscopy in v1; "noir deferred usage-gated per Q10's
  tone-bleed rationale"; data-invariance golden test.
- ✅ FUN F-1: `--voice clinical|microscopy` in v1, noir documented-but-deferred usage-gated; cap-at-
  three taste law (a FUN-internal ceiling, not contradicted by the ruling).
- ✅ PLAN Phase 6: "autopsy clinical voice (+ microscopy alternate; noir stays deferred — tone-bleed
  rationale)"; Appendix A item 32/35.

**Residue requiring edits (dangling option the arbitration never contained):**

- ⚠️ **SPEC §11.2 `lens autopsy` row:** "Voices: `clinical` (default), `microscopy` in v1; `noir`
  deferred usage-gated; **`plain` pending owner call (HQ O4)**" → O4 contains no "plain" option and
  the answer confirms clinical+microscopy only; delete the "`plain` pending owner call" clause.
- ⚠️ **SPEC §16 item 2 tail:** "**`plain` ships only if the owner elects it (HQ O4).**" → same defect;
  delete (or the owner must separately elect it — currently unarbitrated text presenting itself as an
  open HQ hook).

---

## D-HYBRID · Rule-pack provenance: hybrid confirmed (HQ O1)

**Owner ruling (quote):** "(Confirmed — hybrid stands exactly as provisionally specified: own core +
Apache-2.0-derived ports tagged `origin:`, each passing the benign-corpus calibration gate; `origin:`
fields render in rule cards.)"

**Status:** CONFIRMED.

**Locations verified / tweaks:**

- ✅ SPEC §15 "**Origin attribution**: patterns studied from external scanners … enter only via
  clean-room transcription with `origin:` attribution and the benign-corpus promotion gate — never
  wholesale import (Q3/Q11 non-coupling)."
- ⚠️ Minor harmonization inside that bullet: O1's confirmed form is transcription/**adaptation tagged
  `origin: adapted-from <repo@sha>`**, while §15 says only "clean-room transcription" (clean-room and
  attributed-adaptation are different postures; the owner confirmed attribution-bearing ports).
  Reword to "attributed transcription/adaptation (`origin: adapted-from <repo@sha>`)". Also add the
  confirmed rendering limb: "`origin:` fields render in `explain-rules` rule cards" (currently implied
  via D-EXPLAIN, not stated in §15).

---

## D-NARRATOR · Offline posture: narrator cut; second-opinion is sole model access (HQ R2)

**Owner ruling (quote):** "**Owner arbitration: the `--llm` narrator is cut outright.** Lens generates
no explanatory prose in any version … The LLM layer is therefore exactly one thing:
`/lens second-opinion` … the LLM layer is a **core product pillar** (SPEC §1, pillar 3) … Core ≠
default-on … v0.9 = deterministic base whose zero-egress/deterministic claims are the launch
marketing, v1.0 = `/lens second-opinion` delivered over the host lane behind its promotion gate."
Claim restated as "zero *direct* egress".

**Status:** CONFIRMED — fully encoded; zero edits found necessary.

**Locations verified:**

- ✅ SPEC §1 pillar 3 (semantic-review-only; "no explanatory prose, ever"; core-not-garnish; v1.0 over
  ctx.llm; "Core ≠ always-on" phasing); T4 ("second-opinion only — no narrator", zero **direct**
  egress); N5 ("Sole model access, ever"); §4 Choir paragraph (HQ R2 citation, downgrade-only,
  llm_touched, outside canonical envelope); §13 v1.0 promotion eval "the *only* model access in any
  version (narrator cut by owner arbitration)"; §14 standing note ("no narrator exists");
  D-PRIVACY ("zero *direct* egress … not 'no network path exists'"); G1 wording; Appendix A item 34.
- ✅ PLAN locked-table Privacy row ("narrator cut by owner arbitration", promotion eval Q2/R2);
  Detection-core row (HQ R2); DoD deferred list ("the only model access — narrator cut").

---

## D-LANG · Pure-Python Hermes plugin (R1) — CONFIRMED

**Ruling (quote):** "Pure-Python Hermes plugin (SPEC §4, D-LANG rev. 2). The retired Rust-vs-Go
analysis stays retired unless a v1.x standalone compiled CLI ever ships."
✅ Encoded: SPEC header PACKAGE, §4 Language-choice note, D-LANG rev. 2, §13 roadmap, PLAN locked
table + Distribution row + Phase 0. No edits.

## D-REGEXDEFER · `re:` allowlists deferred (R3) — CONFIRMED

**Ruling (quote):** "Defer `re:` allowlists to v1.1; globs + PSL + deny-wins ship; the unstable flag
is never shipped."
✅ Encoded: SPEC §10 "Deliberately absent: user-authored `re:` regex allowlists — deferred again …
Globs + PSL + deny-wins cover observed cases"; no unstable flag exists anywhere (correct absence);
PLAN locked-table Rules-storage row (Q4 defer). No edits. (Cross-ref label: see hygiene note.)

## D-ADVOCACY · Advocacy rejected outright (R4)

**Ruling (quote):** "Rejected outright. Skill Lens does **no advocacy of any kind, in any release**:
no claim-vocabulary proposal, no linter-recognition request, no authoring-skill guidance edits, no
external campaigning … This is **not deferred** — there is no roadmap item, no revisit date, no
trigger condition … Only the owner editing this document reopens it."

**Status:** CONFIRMED (rejection is what the docs now encode).

**Locations:**

- ⚠️→✅ **SPEC Appendix A item 31** is the ONLY advocacy text left in any artifact: it records the
  channel discovery ("claim-vocabulary proposals *could* publish through Hermes's own standards
  machinery …") then closes with "**Superseded by owner arbitration: advocacy rejected outright** —
  the vocabulary is a Hermes feature request, not a Lens feature; Lens does no advocacy of any kind in
  any release (HQ R4)." → Compliant as a historical changelog entry with explicit supersession (same
  convention as O3 heritage); no forward-looking advocacy survives in SPEC body, PLAN, or FUN (grep
  verified: advocacy/vocabulary/standards-machinery/linter-recognition appear nowhere else). Optional
  cosmetic trim of item 31's first sentence; not required.
- ✅ PLAN/FUN: zero occurrences — nothing to remove.

## D-FOOTER · Coverage-honesty footer standing on every artifact incl. slash renders (R5)

**Ruling (quote):** "One-line byte-stable footer on every report surface — **`· static analysis only —
runtime-injected instructions (tool output) are out of scope · lens explain coverage`** — full block
behind `--limitations`; fast-path lifecycle one-liners exempt."

**Status:** CONFIRMED (stance encoded everywhere) — but the **literal string is materialized
nowhere**.

**Locations:**

- ✅ Stance encoded: SPEC N6 ("appears in every report, every surface, slash renders included"), §11.3
  final bullet ("The coverage footer (§12) appears on slash renders too"), Appendix A item 18; PLAN
  Phase 5 ("coverage-honesty footer copy byte-frozen — it renders on every surface including slash
  output"); PLAN DoD ("coverage-honesty footer on every surface").
- ⚠️ **SPEC §12.1 / §12.2 mockups and normative rules:** the byte-stable footer literal appears in NO
  file (grep "runtime-injected": 0 hits). §11.3 points to §12 for the footer, yet §12's TTY and chat
  mockups show only the advisor line. → Add the exact R5 literal (plus the `--limitations` full-block
  and fast-path-one-liner exemption) as a normative subsection in §12 (e.g. §12.6 "Coverage footer"),
  and append the one-liner to the §12.1/§12.2 example renders so golden tests have a byte target.

## D-NAMING · Brand "Hermes Skill Lens", display "Skill Lens" (R6) — CONFIRMED

**Ruling (quote):** "The product is **Hermes Skill Lens**, displayed as **Skill Lens** … repo/install
`hermes-skill-lens` … slash command `/lens`, Python package import `skill_lens`, plugin key `lens`
… rule-ID prefix `LNS-`, GitHub repo `hermes-skill-lens` with PyPI package name `skill-lens`
(reserved for the optional v1.0 console-script), release codenames drawn from optics pioneers …
The migration is recorded exactly once in the changelog (SPEC Appendix A); all other artifacts carry
only current names."

- ✅ Identifier map verified across all three files: zero `xray`/`sxr`/X-Ray identifiers remain
  (only historical mentions inside HARD_QUESTIONS R6 itself and SPEC Appx A item 33 — the single
  sanctioned changelog record). Tagline migrated to optics ("A lens, not a bouncer."). Codenames
  Leeuwenhoek/Newton/Fresnel consistent (FUN F-8 ↔ R6). PyPI squat recorded (PLAN wk-1 track).
- ⚠️ **FUN §3 "Explicitly Rejected" list:** "**Product renames** — identity churn, zero payoff." —
  stale drafting-era rule contradicted by the owner's 2026-08-23 rename (HARD_QUESTIONS settled-list
  itself notes "The naming half was later superseded by the owner's 2026-08-23 rename — see R6").
  → Annotate the row: "*(naming half superseded by owner rename 2026-08-23 — HQ R6; mascot half
  stands)*".

## D-GUARD · skills_guard relationship: integrated display, strict non-coupling (R7) — CONFIRMED

**Ruling (quote):** "At the hub quarantine beat, render Lens's full report beside the guard's verdict
with explicit role labels (`advisory — skills_guard decides install policy`). Never read or write
`INSTALL_POLICY`; never port guard regexes into the pack; dedupe only at render time, by annotation,
when both fire on the same fingerprint."
✅ Encoded: SPEC §11.7 (third-opinion framing, role-label block, latency contract — fast-path line in
beat, full report via worker + `/lens report`, which implements "render beside the verdict" without
delaying y/N), hard non-coupling rules incl. study/attribute/recalibrate bucket; SPEC §7 render-time
dedupe-by-annotation; D-BEAT; PLAN locked-table Detection-core row, Phase 4 hub view, DoD. No edits.
(Cross-ref label: see hygiene note.)

## D-TRUST · Hub trust level annotates, never computes (R8) — CONFIRMED

**Ruling (quote):** "Hub provenance/trust … renders on the patient line (`patient … (@openai/skills ·
trusted)`) and is stored in the IR — and is excluded from weights, discounts, ceilings, and grades.
Permanently." Display detail: "lifecycle hook payloads carry bounded provenance classes only, so
enrich provenance at scan time from hub lockfiles, never from hook kwargs."
✅ Encoded: SPEC N3, D-PROV, D-STREETLAB (third-profile rejection), §5.1 bounded hook classes +
lockfile enrichment, §8 ceilings untouched by provenance, §11.6, §12.1 patient-line format; PLAN
Triggers/Surfaces rows, Phase 0/Phase 4, DoD ("provenance rendered as annotation-only"). No edits.

---

## Closing-notes cross-check (settled-exclusions list — read, verified, no rulings missed)

Choir disposition (contract stub v0.9 / adapters v1.1 / second-opinion eval v1.0) ✅ matches SPEC §13
- PLAN; exit-code scoping to CLI verbs + verdict-as-interface ✅ (SPEC §18/D-SURF, PLAN X2 row);
blocking-hook ban + doctor check #5 ✅; watch hash-poll mechanics ✅ (D-WATCHPOLL, PLAN watcher rows);
tree-sitter delivery lane ✅ (D-PARSE, PLAN Phase 1.5); policy auto-load prohibition ✅ (absence
verified — no auto-load text anywhere); multilingual lexicons/captioner gates deferred ✅ (lexicon v1
only); Windows hooks timing "v1 scan-only" — no contrary encoding exists (topic simply absent from
SPEC/PLAN; acceptable, nothing reverses). Legacy `.analysis/01_platform|02_decisions|04_ux` citations
are audit-provenance references, not parity machinery — retain.

## Global hygiene note (editorial, not an owner ruling)

All artifacts still cite retired question numbers (Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12) —
~25 sites across SPEC (lines 237, 277, 493, 621, 757, 768, 788, 801, 806, 921, 923, 925), PLAN (lines
26, 28, 31, 62, 84, 142, 157, 211, 221, 258, 302, 318, 323), FUN (lines 75, 111). HARD_QUESTIONS rev. 3
relabeled them R1–R8/O1–O5 with "(formerly QN)" bridges. Recommended mechanical pass: Q2→R2, Q3→O1,
Q4→R3, Q5→O2, Q6→R4, Q7→R5, Q8→R6, Q9→O3, Q10→O4, Q11→R7, Q12→O5. Not blocking; do in the same
editing pass as the residues above.

---

# CHANGE-ORDER CHECKLIST

## SPEC.md (numbered, in document order)

1. §1 pillar 2 — pluralize/align "worst finding" so the worst-**5** default is stated (with §11.3 carrying the number). *(D-SURFACE)*
2. §11.2 `lens autopsy` row — delete "`plain` pending owner call (HQ O4)". *(D-VOICE)*
3. §11.3 collapsed-by-default bullet — pin "worst-**5** findings". *(D-SURFACE)*
4. §12.1 + §12.2 — append the byte-stable coverage-footer literal to both mockup renders; add normative footer subsection (new §12.6 or equivalent) stating the exact R5 string, the `--limitations` full block, and the fast-path one-liner exemption. *(D-FOOTER)*
5. §13 v1.0 bullet — delete "+ inline cards" from the DeliveryRouter/media-pipeline stretch; stretch is proactive gateway push only. *(D-SHARECARD)*
6. §15 Origin-attribution bullet — reword "clean-room transcription" → attributed transcription/adaptation with `origin: adapted-from <repo@sha>`; add "`origin:` fields render in `explain-rules` rule cards". *(D-HYBRID)*
7. §16 item 2 — delete "`plain` ships only if the owner elects it (HQ O4)". *(D-VOICE)*
8. Appendix A item 31 — leave as-is (explicitly superseded historical record); optionally trim the descriptive first sentence. *(D-ADVOCACY, optional)*
9. Mechanical: retire Q-number citations (see hygiene map above). *(hygiene)*

## PLAN.md (numbered, in document order)

1. Phase 3 — conform the post-gate sentence: remove "*from descriptions*, sanitized" posture; real-world-derived fixtures proceed under the retained licensing/provenance review gate at full fidelity. *(D-CORPUS)*
2. Phase 3 Exit — already reads "corpus published full-fidelity public"; no change (verify only). *(D-CORPUS ✅)*
3. Phase 5 — footer copy already byte-frozen per R5; once SPEC gains the literal, reference the frozen string. *(D-FOOTER)*
4. Phase 6 — fix FUN translation-matrix range "F-1..F-6" → "F-1, F-3–F-6" (F-2 CUT). *(D-SHARECARD)*
5. §3 Testing strategy item 2 — already conformed; verify only. *(D-CORPUS ✅)*
6. §6 Risk table row 8 — strike "Fixtures from descriptions, never payloads;"; keep "public full fidelity, risk accepted by owner; legal read before authoring derived fixtures". *(D-CORPUS)*
7. §7 DoD deferred list — change "DeliveryRouter/media-pipeline stretch" → "DeliveryRouter proactive-gateway-push stretch" (drop card-lineage "media-pipeline"). *(D-SHARECARD)*
8. Mechanical: retire Q-number citations. *(hygiene)*

## FUN.md (numbered, in document order)

1. §1 Recommendation — drop the "film-grain texture **in SVG art only**" clause and the "SVG" entry in the surfaces list (no SVG art exists post-O3). *(D-SHARECARD)*
2. §2 build-order line — remove F-2 and F-9 from the build order (never built): F-1 → F-6 first; F-3, F-5 next; F-4 after watch; F-7–F-8 garnish. *(D-SHARECARD)*
3. §2 F-1 — no change needed (noir documented-but-deferred usage-gated matches O4); verify only. *(D-VOICE ✅)*
4. F-2 / F-9 bodies — retain verbatim as cut-marked heritage (sanctioned by O3). *(D-SHARECARD ✅)*
5. §3 "Product renames — identity churn, zero payoff." — annotate as superseded-in-part by the owner's 2026-08-23 rename (HQ R6). *(D-NAMING)*
6. §4 compliance checklist — F-2/F-9 rows already carry ⛔ CUT markers; verify only. *(D-SHARECARD ✅)*
7. §4 Plugin-port note — delete the F-9 clause and the "F-2 returns the SVG by path" sentence; port note covers F-1, F-5, F-6 (+ inert-on-slash F-3/F-4, sober F-7). *(D-SHARECARD)*

---
*Ledger generated from a complete read of HARD_QUESTIONS.md rev. 3 against SPEC/PLAN/FUN current
text; every quoted ruling is verbatim from the owner's arbitration document.*
