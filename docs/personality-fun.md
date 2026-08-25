> ⚠️ **HISTORICAL IDEATION — superseded.** Share cards were rejected outright by owner
> arbitration (HARD_QUESTIONS O3, 2026-08-23); all naming here predates the Skill Lens rename
> (R6). Retained for provenance only. Current truth: [`../FUN.md`](../FUN.md) + [`../SPEC.md`](../SPEC.md).

# Personality, Creativity & Fun — Ideation

**Phase:** Scoring, policy, and UX refinement · **Label:** personality fun
**Constraint (spec):** optional modules may carry themes; **default UX stays normal.**
**Grounding:** `architecture.md` (crates, golden-file CI, `choir` naming precedent, §8 explain narration), `arch-review.md` (D-PRIV redaction, §8.4 ANSI discipline, advisor-not-gate posture), `hook-and-watch.md` (§6 silent-until-result, no progress theater), `threat-taxonomy.md` (canary tokens, L3 tracer txns, incident corpus).

---

## 0. House theory of taste

X-Ray earns its personality the way SSL Labs and Scorecard earn theirs: **through precision, not decoration.** The existing personality budget is already correct — one 🩻, parenthetical timings `(412ms)`, dry imperatives, `choir` as a stage name. Everything below either (a) extends that register into *opt-in* surfaces, or (b) protects it.

Working definition of taste risk (used in rankings):

| Axis | Question |
| --- | --- |
| Trust cost | Does it make the scanner less credible next to a 0.93 exfil finding? |
| Sobriety bleed | Can it leak into default text / JSON / SARIF? |
| Cringe half-life | Will it embarrass us in two years? |
| Surface cost | New rendering/test burden, or free? |

**Global invariants every idea must obey:** determinism (no wall-clock/randomness in generated artifacts; timestamps only from stamped provenance), redaction pass extended to *every* emitted artifact including SVG (D-PRIV), ANSI law (no cursor-positioning ever; framed banners fine), facts immutable by theme (numbers, grades, severities, finding messages identical across all themes — diffable), and the sobriety guarantee enforced mechanically: **golden-byte CI on default text/JSON/SARIF fails if any theme work bleeds into the default render path.**

---

## 1. Brainstorm sweep

| # | Idea | Lives in | Default UX affected? | Taste risk | Verdict |
| --- | --- | --- | --- | --- | --- |
| N1 | Rename product "X-Ray Vision" | n/a (brand) | n/a | Med — toy-store suffix, weakens searchability, adds nothing | **Reject** |
| N2 | Rename product "BoneScan" | n/a | n/a | High — joke name, obscures the tool | **Reject** |
| N3 | Keep **X-Ray**, adopt controlled radiology glossary: *artifact* (dual meaning: imaging artifact / supply-chain artifact — genuinely apt), *plate*, *exposure*, *reading*, *contrast*, *phantom*, *tracer* | `docs/glossary.md` + naming of optional modules | No | Low — words only, published deliberately | **Adopt** |
| M1 | Skeleton mascot | share cards, docs | Must stay out | High — Halloween energy beside a critical-severity table is tone-deaf; mascots date badly | **Reject** |
| M2 | Radiologist persona as narrator | explain/report themes | No (opt-in voice) | Med — viable only as dry prose register, never a character with a face | Conditional (see V1) |
| M3 | Canary bird emblem, scoped to the canary subsystem only | canary module, fixtures | No | Low — canary-in-the-coal-mine is a *serious* security metaphor already in the taxonomy | **Adopt** (C1) |
| E1 | Konami codes, date-triggered greetings, hidden `xray fluoroscopy` verb | cli | Must stay out | High — exclusionary, dated, clock-coupling smell, docs confusion | **Reject** |
| E2 | Honest delights: `xray scan --self` (scanner runs its own secrets rules over its own binary/ruleset); `explain` near-miss ID suggestions (already specced §8.4); rule self-test count line | cli, rules | No | Low — a real trust feature wearing an easter-egg costume | **Adopt** (F5) |
| S1 | Share cards `--svg` with fixed poster "plates": **Radiograph** (dark film, findings as bright opacities), **Phosphor** (green CRT), **Print** (halftone newsprint) | `xray-report` svg renderer | No (explicit flag; text/json/sarif untouched) | Low-Med — gamification pull ("flex your A+"); mitigated by stamping `formula_version`/`ruleset_version` on every plate and refusing celebratory F-grades | **Adopt** (F2) |
| S2 | Randomized/seasonal poster variants | report | No | High — breaks determinism-by-construction, seasonal kitsch | **Reject** |
| V1 | Narration **voices** for `xray scan --explain`: `clinical` (default = today's exact copy), `radiology` ("opacity detected at scripts/upload.js:102 — recommend excision"), `case-file` | `xray-score` breakdown narration + text renderer | No — default voice emits byte-identical current output; JSON/SARIF ignore voice entirely | Med — the easiest place to slide into cringe; contained by: voice may rewrite only generator-owned connective prose/headers, never rule messages (they come from YAML data), numbers, or severities; golden file per voice | **Adopt** (F3) |
| V2 | Full "autopsy" narrative mode implying the skill is dead | report | No | High — wrong metaphor: advisor-not-gate means nothing died; autopsy language presumes execution and guilt | **Reject** — renamed to "readings" (V1) |
| C1 | **Canary program**: group canary-token sandbox checks + (future L3) testnet tracer txns under `xray canary`; fixture skills named `canary-*` with planted fake keys; one-paragraph lore (coal mine → tracer study) | engines/docs now, `xray-lab`/protocol for L3 | No — naming/doc organization; behavior unchanged | Low | **Adopt** (F4) |
| R1 | **Rehearsal playground as radiology "phantoms."** Real radiography QA uses *phantoms* — calibration objects imaged to prove an imaging system works. Map exactly onto our malicious/benign fixture corpora: `xray rehearse` runs the phantom suite through the loaded ruleset and prints the detection matrix | `fixtures/` + small cli verb + `xray-lab` PR curves | No (new verb) | Low — accurate, professional, delightful once known; fiction kept restrained (case numbers like `phantom 2026-0117-a3`, no ARG, no fictional-org LARP — that erodes trust) | **Adopt** (F1) |
| W1 | Watch-mode animations: spinners, pulsing daemon TUI | watch | Yes by construction — violates §6 (no placeholders, no progress theater) and §8.4 ANSI law (host renderers fight in-place redraws) | High | **Reject** in animated form |
| W2 | Static "heartbeat" status line, re-rendered only per invocation: `watchdog: awake · 4 projects · last sweep 2s · queue 0` with a pulse glyph chosen by last-sweep age band | `xray watch status` | No — status verb only; daemon itself stays silent | Low — satisfies the animation itch within the law | **Adopt** (F6) |
| G1 | Grade-reveal drama: countdown, drumroll, delayed grade | cli | Yes — delays information, violates print-after-completion and CI latency budgets; drama that withholds findings is anti-security | High | **Reject** categorically |
| G2 | Typographic drama instead of temporal: grade plate rendered with visual weight (heavy frame, inverted letter), grade **I** plate reads "PARTIAL EXPOSURE — incomplete scan" | svg plates only; text stays as specced | No | Low-Med — honest drama only; never celebrate an F | Fold into F2 |

Cross-cutting note on L-tier flavor (docs-only, zero UI): L1 = radiograph, L2 = fluoroscopy/CT, L3 = nuclear medicine (inject tracer, watch it move — which is precisely what a canary token *is*). Permitted inside `xray explain` rule cards and docs; nowhere else.

---

## 2. Recommended build list (ranked)

### F1 — Phantom Suite + `xray rehearse` ★ build first

**Module:** `fixtures/{malicious,benign}` + tiny CLI verb + `xray-lab` PR curves. **Default UX impact:** none (additive verb). **Taste risk:** Low.
Turns the loader's mandatory rule self-tests and golden fixtures into a user-facing proof of detection power: `xray rehearse` prints a matrix — each phantom case, legs fired, whether the loaded ruleset catches it. Doubles as onboarding, marketing asset, and regression harness. The radiology-phantom framing is factually precise, which is what makes it charming rather than cute.

### F2 — Share plates: `xray report --svg [--plate radiograph|phosphor|print]`

**Module:** `xray-report` (new svg renderer). **Default UX impact:** none. **Taste risk:** Low-Med.
Three fixed, hand-designed themes; summary statistics only (grade, score, top penalty groups, counts, `snapshot_id` prefix, formula/ruleset versions) — **never snippets**, extending the D-PRIV redaction pass to SVG. Deterministic generation, no clock. Version stamps keep the flex honest; F-plates get a heavier frame, never confetti. Precedent: Scorecard badges proved shareable artifacts drive adoption without softening the rubric.

### F3 — Explain narration voices

**Module:** `xray-score` narration + text renderer. **Default UX impact:** none (`voice=clinical` is byte-identical to today; machine formats immune). **Taste risk:** Medium — the containment rules are the feature: voices touch only generator-owned connective prose and section headers; findings text, numbers, severities, gates are invariant across voices; golden file per voice; a test asserts extracted data equality across all voices.

### F4 — Canary sub-brand + `xray canary`

**Module:** docs + engine organization now; `xray-lab`/protocol crate when L3 tracers land. **Default UX impact:** none. **Taste risk:** Low.
Gives the hardest detection tier a memorable, serious name; `canary-*` fixtures make the mitigation concrete; one paragraph of lore (coal mine → tracer study) earns the emblem. Scoped strictly: the canary belongs to the canary subsystem, not to X-Ray at large.

### F5 — `xray scan --self`

**Module:** cli + rules verify. **Default UX impact:** none. **Taste risk:** Low.
The scanner audits its own binary and signed ruleset with its own secrets rules. It is simultaneously the only sanctioned "easter egg" and a genuine supply-chain trust display — the tool subjecting itself to its own redaction/discipline rules is the joke and the proof in one.

### F6 — Watch heartbeat status line

**Module:** `xray watch status` only. **Default UX impact:** none (daemon and hooks stay fully silent per §6). **Taste risk:** Low.
Static per-invocation line, pulse glyph banded by last-sweep age, no cursor addressing, no background animation. Gives the "watch mode animation" instinct a legal outlet.

### F7 — House-style page + rejected-ideas ledger

**Module:** `docs/style.md`. **Default UX impact:** none (it guards the default). **Taste risk:** None.
Codifies: the glossary (N3), the humor ceiling for defaults (one emoji, timings, dry imperatives — do not add), and the public rejection list (skeleton mascot, konami, countdown reveals, autopsy framing). Publishing what we refused *is* the personality; it signals taste better than any feature and protects every item above from future drift.

---

## 3. Enforcement mechanics

1. **Sobriety CI:** existing golden-byte tests on default `text|json|sarif` are the hard tripwire — any bleed from theme work fails the build. Theme renderers live behind their own golden files.
2. **Data-equality test:** for every theme/voice pair, parse rendered output back to data and assert equality with the canonical `ScanDocument` view.
3. **Redaction uniformity:** the D-PRIV self-scan pass runs over every emitter (text, md, svg) before write.
4. **ANSI audit:** grep-grade CI rule — no cursor-positioning escapes anywhere in `xray-report` or hook output, themed or not.

## 4. Summary judgment

The strongest fun available to X-Ray is *precision with a memory* — names drawn from real radiology practice (plates, phantoms, readings, tracers) that map one-to-one onto things the tool actually does. Mascotry, temporal drama, and hidden gimmicks all fail the trust test and are rejected in writing. Build order: F1 → F2 → F3 are the high-value core; F4–F7 are cheap brand reinforcement.
