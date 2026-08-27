# Phase 6 Gate Report — surfaces polish + opt-in personality

**Auditor:** orchestrator gate audit (direct completion + independent evidence after
subagent-lane outage; the P6 implementation lane died mid-flight on a provider outage —
its landed work was audited file-by-file, repaired where needed, and finished here).
**Date:** 2026-08-27 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.7`

## Verdict: **PASS** · all exit criteria re-executed

Authoritative numbers at the audited tree: **pytest 1162 passed · 0 failed**, **ruff clean**
("All checks passed!"), **vectors A–G byte-exact**, corpus harness green (≥40 malicious /
≥30 benign, both-way complete), **perf budgets strict-PASS inside the fake lifecycle
dispatch after repair** (see below).

## Criterion (a) — snapshot tests prove JSON/SARIF/effect-free identical with every fun flag on/off ✅

`tests/test_fun_invariance.py` (25 passed): per-combo run-to-run stability PLUS
cross-combo equality enforced over the committed goldens in `tests/golden/fun/`
(`envelope-*.sha256`, `sarif-*.sha256`, `exit-*.json`, `events-*.golden.json`) — one unique
digest per artifact family across ALL combos (voice unset/clinical/microscopy × spoilers),
matrix documented in `tests/golden/fun/README.md`. Automation surfaces stay sober even with
fun ON (grep + runtime probes inside the suite). O3 guard: `tests/test_fun_guard.py`
(9 passed) asserts NO card/poster/theme codepath exists.

## Criterion (b) — map renders categorized layout correctly ✅

`tests/test_map_verb.py` (10 passed) over synthetic categorized trees incl.
hub-provenance annotation rendering (annotation-only); live dogfood over the maintainer's
REAL `~/.hermes/skills` tree captured read-only in `build-state/dogfood.md`
(categorized layout, hub lockfile provenance annotations, no state mutation).

## Criterion (c) — chat outputs within 1200/1800 budgets, fence-safe chunking ✅

`tests/test_budget_chunking.py` (16 passed): pathological-input budget ladder for
map/autopsy/bones renders + fence-safe split behavior; `skill_lens/chunking.py`.
NO_COLOR/`--plain` honored across slash + CLI lanes: `tests/test_no_color_audit.py`
(25 passed); Discord spoilers flag default-OFF pinned in settings defaults + tests.

## Voices shipped (FUN.md conformance)

autopsy clinical voice + microscopy alternate (`tests/test_autopsy_voices.py`, 12 passed;
settings-selectable, deterministic templates only, kill-switch keys per FUN.md/04_ux §6);
bones/self-scan gag in fenced slash form; F-1, F-3–F-6 verified; F-2/F-9 ABSENT (O3/O4 law);
noir deferred. `skill_lens/fun.py`, `mapview.py` wired through the shared slash dispatch
with CLI parity (`tests/test_cli_exit_codes.py`, grammar parity tests from P4 pattern).

## PERF BUDGET REPAIR (D-056)

Cold p95 had silently drifted past the ≤400 ms budget BEFORE this phase's tree
(clean HEAD measured 442–457 ms; regression introduced post-P3-corpus-growth outside any
single commit boundary). Repaired honestly INSIDE E2 with three provably output-identical
optimizations (duplicate clean-view skip when no strippable codepoints exist; pure-function
`skeleton()` memoization; mixed-script predicate reordering). Post-repair strict-PASS:
**cold p95 ≈ 344 ms (max sample 354 ms) · cached p95 ≈ 5.3 ms** —
`python3 scripts/perf_check.py --strict --write` exit 0, `build-state/perf-baseline.txt`
refreshed. Budgets never weakened; vectors/corpus byte-exact throughout.

## Session-context notes

The prior attempt's mid-flight death left coherent partial work which was audited line-by-line,
completed (budget/chunking + guard tests finalized), and put through this gate. The perf red
that motivated D-056 was proven NOT caused by those changes (clean-HEAD A/B) — recorded so the
history shows the regression predates Phase 6.

## Gate: **PASS**
