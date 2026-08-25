# Phase 1 Gate Report — Claims, first engines, scoring v2, slash

**Auditor:** Phase 1 gate audit & commit (independent re-run of PLAN §1 exit criteria)
**Date:** 2026-08-25 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.2` (checksum `sha256:23b42495…`)

## Verdict: **PASS — 5/5 criteria**

Every criterion was re-executed independently by the auditor (not taken from prior summaries).
Authoritative gates at HEAD: **pytest 335 passed, 0 failed/skipped/xfail** (`python3 -m pytest -q`,
exit 0) and **ruff clean** (`ruff check .` → "All checks passed!"). Note: the engine-absence
xfail class from earlier in the phase is now empty — all four engines shipped, so the sanctioned
xfails resolved into real passes.

---

## Criterion (a) — Golden vectors A–G reproduce EXACTLY ✅

- Suite `tests/test_vectors_golden.py` (14 tests, all green) runs the eight §8.3 fixture bundles
  under `corpus/vectors/{A,B,C,C-prime,D,E,F,G}` through the LIVE pipeline
  (`scan_bundle` → `build_report`: ingest → claims → engines → fingerprint dedup → scoring) and
  asserts `(score, grade, verdict, needs_review)` byte-exact against the committed machine oracle
  `corpus/vectors/expected.toml` (D-028), plus exact fired-rule sets and applied ceilings.
  Reproduced outcomes: A=100/A·clean · B=91/A·notice · C=25/F·alert · C′=40/D·warn·needs_review ·
  D(lab)=85/B·notice · E=80/C·warn · F=83/B·notice · G=70/C·warn.
- Independent end-to-end spot-check (auditor script, fresh temp home, direct
  `scan_bundle(...)`+`build_report(...)` invocation, no test fixtures reused):
  **vector C tuple = (25, 'F', 'alert', False)**; fired rules
  `{LNS-NET-011, LNS-NET-012, LNS-SHL-002}`; ceiling applied `confirmed-critical` — matches the
  §8.3 oracle exactly. Documented shape deltas vs the hand narrative are recorded in D-028; the
  tuples are the oracle and they match.

## Criterion (b) — Every core rule TP-covered, benign-silent ✅

Corpus harness `tests/test_corpus.py`: **39 passed**. The auditor recomputed coverage independently
(direct `run_case` over all fixtures, bypassing the test assertions):

- Core pack: **17 active rules**, fixtures **13 malicious / 13 benign**.
- Malicious coverage: every rule fires on ≥1 malicious fixture — MAN-001×1, MAN-002×1,
  MAN-003×1, MAN-004×8, MAN-005×1, MAN-007×1, NET-011×2, NET-012×1, NET-013×1, SEC-001×1,
  SEC-002×1, SHL-001…SHL-006 ×1 each. **UNCOVERED = none.**
- Benign silence: **zero** core-pack findings across all 13 benign fixtures
  (**BENIGN VIOLATIONS = none**) — including lookalikes (pentest-lab declared-offensive,
  hex-docs/uuid entropy traps, webhook notifier, pinned tarball installer).
- §15 bidirectional contract enforced by `test_bidirectional_rule_fixture_contract`
  (every active rule declares ≥1 positive + ≥1 negative fixture on disk).

## Criterion (c) — Raising test engine changes neither results nor UX ✅

Both isolation tests green:

- `test_registered_raising_engine_changes_neither_outcomes_nor_ux` — registering `TestEngine`
  alongside real engines leaves every vector's canonical envelope byte-identical.
- `test_raising_engine_with_bound_rules_is_contained` — even with pack rules bound to the crashing
  engine: exactly ONE synthetic `LNS-ENG-000` finding ("engine 'test_boom' failed: RuntimeError"),
  all other findings survive byte-identically, report still builds and renders compact chat output.

## Criterion (d) — `/lens scan --json` byte-stable ✅

Auditor harness invoked the real slash handler (`make_handler`) on vector A from two separate
processes with a fixed input path:

- In-process: cold == cache-hit == `--no-cache` outputs identical (702-byte fenced envelope).
- Cross-process: `cmp` of the two runs' outputs → **identical bytes**.
- (First attempt differed only because the auditor's own random tempdir leaked into
  `path_as_given`; fixed-path rerun is byte-stable — an input change, not nondeterminism.)

## Criterion (e) — pytest + ruff green ✅

See header: 335 passed / 0 failed; ruff clean. Determinism law spot-holds: canonical envelopes
carry no wall-clock (`_meta` sidecar separation per D-009); integer-point scoring; sorts keyed
`(rule_id, path, start_line)`.

---

## Artifacts & evidence index

| Item | Location |
| --- | --- |
| Vector oracle | `corpus/vectors/expected.toml` (+ 8 bundle dirs) |
| Vector suite | `tests/test_vectors_golden.py` (14 tests) |
| Corpus fixtures | `corpus/fixtures/{malicious×13, benign×13}` with `expected.toml` |
| Corpus harness | `skill_lens/corpus.py`, `tests/test_corpus.py` (39 tests) |
| Engines E1/E3/E6/E7 | `skill_lens/engines/` (+ base protocol, isolation, ScanContext) |
| Scoring v2 | `skill_lens/scoring.py` (+ hypothesis properties) |
| Report/render/slash/cache | `report.py`, `render.py`, `slash.py`, `cache.py`, wired via `bootstrap.py` |
| Decision log | DECISIONS.md rows **D-012 … D-032** (rule schema, corpus contract, pack calibration, claims mapping, overreach semantics, engine details, secretscan redaction, MAN-005 static_only flip, NET-011 confidence grading, occurrence indexing fix, overflow-artifact sanitization) |

## Commits & push

Atomic conventional commits in dependency order (identity repo-local `Irell Zane
<itsirellzane@gmail.com>`, verified via `git config` and `git log --format="%h %an <%ae>"`);
pushed to `origin main`. Per-commit trees were smoke-verified during sequencing; HEAD is the
authoritative green state.

## Escalations / open questions for owner

**None.** No blocking defects found at gate. Two informational notes, both already governed by
recorded decisions rather than open questions: (1) rule-pack version moved 2026.08.1→2026.08.2 when
LNS-MAN-004 landed (§15 patch bump, D-020); (2) cross-process JSON stability requires a stable
input path — `path_as_given` is part of the deterministic envelope by design (SPEC §12), so
byte-compare jobs must hold the path fixed (relevant to the Phase 3 determinism CI job).
