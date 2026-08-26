# Phase 2 Gate Report — Policy, baselines, explain-rules, diff, worker/coalescing

**Auditor:** Phase 2 gate audit & commit (independent re-run of PLAN §1 Phase-2 exit criteria)
**Date:** 2026-08-25 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.5`
**Scope audited:** all Phase 2 deliverables landed uncommitted by four build tasks —
`skill_lens/policy.py` (D-041), `baseline.py` (D-042), `explain.py`+`diff.py`+`cli.py` (D-043),
`jobs.py` + queue-first slash wiring (D-044), plus their integration edits to
`report.py`/`render.py`/`slash.py`/`bootstrap.py` and golden-test updates.
This audit re-executed every exit criterion itself before committing anything.

## Verdict: **PASS — 6/6 exit criteria** · Nothing committed until after this report

Authoritative gates at HEAD, re-run by the auditor:
**pytest 639 passed, 0 failed/skipped** (three consecutive runs, 16–17 s each — identical count),
**ruff clean** (`ruff check .` → "All checks passed!"), **vectors A–G byte-exact**
(`tests/test_vectors_golden.py`: 14 passed). Corpus tree untouched by the audit (all hand-checks
ran on /tmp copies; `git status` shows zero corpus entries).

New-test census reconciles exactly: policy 54 + baseline 32 + explain 16 + diff 10 + jobs 21
= **133 new tests** = 639 total − 506 at Phase 1.5 gate.

---

## Criterion (a) — Baseline round-trip suppresses EXACTLY the baselined findings ✅

Tests re-run green: `test_baseline_round_trip_end_to_end`, `test_apply_suppresses_exactly_matching_findings`,
`test_slash_baseline_round_trip_and_scan_json`, `test_expired_entries_resurface_loudly` (+ full
`tests/test_baseline.py`, 32/32).

**Independent hand spot-check** (auditor script `/tmp/gate_spotcheck_a.py`, vectors copied into a
categorized home under /tmp — corpus never mutated): for real vector bundles **B, C, C-prime**
(A is clean-by-design per the §8.3 oracle): scanned fresh → collected baseline records from every
finding → wrote `<bundle>/.lens/baseline.toml` → rescanned:

| vector | findings | baselined | suppressed set == baselined set | bundle hash stable | score after |
| --- | --- | --- | --- | --- | --- |
| B | 3 | 3 | exact | yes | 100 |
| C | 3 | 3 | exact | yes | 100 |
| C-prime | 2 | 2 | exact | yes | 100 |

Every suppressed row keeps `suppressed_by`; store write is hash-invisible (dot-entry walk, D-011);
scorer prices suppressed findings nothing.

## Criterion (b) — Settings-layer precedence unit-tested against ctx.get_config fakes ✅

Full `tests/test_policy.py` re-run: **54/54**. The fake (`tests/conftest.py::FakePluginContext`)
is genuinely `get_config`-shaped (host PluginContext seam, plugin-relative keys per
`hermes_cli/plugins.py::get_config`). Pinned by `test_full_chain_settings_file_flags`
("PLAN exit criterion" docstring): settings name `lab`, project file supplies values, explicit
flag wins last — plus `test_settings_present_but_file_supplies_values`, layer-by-layer naming
tests, and provenance coverage with line numbers (`test_provenance_covers_every_layer_with_line_numbers`).

HARD_QUESTIONS boundary verified end-to-end in-suite: weights/caps/ceilings are unreachable from
user-reachable policy — `[score]` tamper ⇒ `LNS-POLICY-SCORE-TAMPER` diagnostic + ignored;
`test_scoring_math_identical_under_tamper_attempt` proves scoring `to_dict` equality under tamper;
severity_override touches `effective_severity` display only while pricing keeps reading rule-assigned
severity (override CRITICAL→LOW still scores its full weight).

## Criterion (c) — Diff survives a 10-line shift without flagging drift ✅

`tests/test_diff.py` 10/10 incl. `test_ten_line_insertion_produces_zero_drift` (re-run solo:
PASS) — fixture scanned, 10 lines inserted above evidence, rescanned, diffed: zero drift while
every script location provably moved +10; classification keyed on fingerprints only, material-field
moves (severity/effective_severity/suppressed/declared/static_only) are what count as "changed".

## Criterion (d) — Malformed policy: exit 2 on CLI lane, one-line notice in-session ✅

Tests green: `test_cli_malformed_policy_exits_two` (CLI dispatch returns POLICY_EXIT_CODE=2,
stderr starts `lens: policy error`), its mirror `test_slash_lane_same_fault_renders_one_line_notice`,
plus the PolicyError lane unit tests (invalid TOML / unreadable file / single-line notice /
exit-code constant).

**Independent hand drive** (`/tmp/gate_spotcheck_d.py`, broken `.lens/policy.toml`
`[rules\nbroken = yes`):

- CLI lane: `dispatch(scan <bundle>)` → **code=2**, stderr one line:
  `lens: policy error (/tmp/gate-d-spot/sk/.lens/policy.toml): invalid TOML …`
- Slash lane: handler answer is **exactly 1 line**, same wording (greppable across surfaces).
- Missing files stay silent (absent layer); only existing-but-broken config takes the error lane.

## Criterion (e) — Two concurrent triggers ⇒ exactly ONE scan job ✅

Repo test re-run green: `test_two_concurrent_triggers_produce_exactly_one_scan_job` (barrier-raced
pair shares one job id, runner executes once, jobs.json records one row per hash).

**Independent stress** (`/tmp/gate_stress_e.py`, three shapes NOT identical to the repo test,
5 consecutive stable runs):

| shape | load | result (every run) |
| --- | --- | --- |
| S1 | 16 barrier-synced threads, same hash, gated slow runner | 1 unique job id · 1 fresh + 15 coalesced · **1 execution** |
| S2 | 4 distinct hashes × 8 shuffled threads | 4 unique jobs · **exactly 1 execution per hash** · every job saw fresh+coalesced decisions |
| S3 | default REAL pipeline runner, 12 threads on a live mini-bundle | 1 job id · 1 `jobs.json` entry for the hash · all 12 reached READY · shared cache filled for all |

Audit honesty note: three intermediate stress FAILs were **harness bugs, not product bugs** —
(a) comparing a `Counter` object to `1` instead of `.count`, (b) probing the fast-path cache with
the coalescing `bundle_hash` instead of the actual key contract `key_for_ir(canonical IR bytes)`
(the worker's `run_scan` scans without a categorized home, which changes canonical IR bytes —
verified directly), (c) keying result samples by job_id, which collides when all triggers share
one job (the very property under test). After harness fixes: PASS ×5, no flakes. `_execute`
ordering verified by read: READY flips strictly AFTER the runner returns, so cache-populate
precedes ready-witness.

## Criterion (f) — pytest + ruff + vectors green ✅

`python3 -m pytest -q` → **639 passed**, exit 0 (×3 runs); `ruff check .` → "All checks passed!";
vectors A–G suite → 14 passed byte-exact oracle comparisons. Rerun after ALL auditor activity
(no source changes were made by the audit) as final pre-commit check.

---

## Artifacts

- Modules: `skill_lens/policy.py` (1162 L) · `baseline.py` (563) · `explain.py` (302) ·
  `diff.py` (307) · `cli.py` (175) · `jobs.py` (707)
- Tests: `tests/test_{policy,baseline,explain,diff,jobs}.py` (133 tests)
- Integration diffs: `report.py` (baseline_entries/report_date kwargs, defaults byte-identical),
  `render.py` (conditional suppressed-count line; zero-suppression renders unchanged),
  `slash.py` (dispatch table scan|report|baseline|explain-rules|diff|help; queue-first scan;
  banner accounting), `bootstrap.py` (defensive CLI registration), golden-test updates
  (queue-first-aware byte-stability test; sidecar-exclusion note)
- Decision rows D-041..D-044; scratch scripts in /tmp (not committed)

## Escalations / observations (non-blocking)

1. **Cache-key vs home context (observation, by design):** fast-path keys are `key_for_ir` over
   canonical IR bytes; scanning the same bundle with vs without a categorized home yields
   different IR identity and therefore different keys. Each surface is internally consistent
   (slash lane always scans home-less). Flagging so the Phase 3 determinism CI pins it explicitly.
2. **Interim CLI adapter** routes via `shlex.join` token reconstruction + fail-prefix heuristics
   (documented in cli.py + D-043); native §11.2 argparse spec replaces it in P4/P5. Recorded, not open.
3. **Expiry semantics reconciliation** (policy severity_override mandatory-expires vs machine-written
   baseline optional expiry) resolved per SPEC text and pinned in D-042 — owner-reviewed, closed.

No blocking escalations. Advisor-not-gate laws hold everywhere audited: observer hooks only,
callbacks never raise into host (defensive registration both surfaces), success-shaped answers,
no network imports introduced (suite runs under pytest-socket).

## Commits (this gate)

1. `feat(policy)` — layered §10 policy engine + settings layer + host lists + tamper guard (D-041)
2. `feat(baseline)` — canonical `.lens/baseline.toml` store + suppression stage in build_report (D-042)
3. `feat(jobs)` — worker thread, coalescing, jobs.json/events.ndjson state machine (D-044)
4. `feat(cli)` — explain-rules + diff verbs, dual-surface CLI lane, queue-first slash wiring (D-043)
5. `docs` — phase-2 gate report + status ledger

Ordering keeps every intermediate commit importable/green: policy and jobs lazy-import their
seams; baseline lands before the slash rewrite that consumes it.
