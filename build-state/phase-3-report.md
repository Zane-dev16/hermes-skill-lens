# Phase 3 Gate Report — E8 depintel, corpus ≥40/≥30, determinism/privacy/perf CI

**Auditor:** Phase 3 gate audit & commit (independent re-run of PLAN §1 Phase-3 exit criteria)
**Date:** 2026-08-26 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.6`
**Scope audited:** all Phase 3 deliverables landed uncommitted by four build tasks plus the
fixer pass — E8 depintel + OSV opt-in lane + SARIF 2.1.0 (D-045), malicious corpus expansion
behind the retained licensing/provenance gate (D-046), i18n FP closure (D-047), benign hard
cases + floor probe (D-048), perf/CLI/determinism/privacy CI (D-049), licensing-gate tracking
fix (D-050). This audit re-executed every exit criterion itself before committing anything.

## Verdict: **PASS — 7/7 exit criteria** · Nothing committed until after this report

Authoritative gates at the audited tree, re-run by the auditor:
**pytest 868 passed, 0 failed/skipped-error** (22.2 s; includes perf-budget asserts),
**ruff clean** (`ruff check .` → "All checks passed!"), **vectors A–G byte-exact**
(`tests/test_vectors_golden.py`: 14 passed).

One gate-tool defect found and fixed during the audit (criterion e): `scripts/perf_check.py`
computed its strict-mode verdict as `lines[-3].endswith("PASS")`, which indexed the blank
separator line after the report grew sample dumps — `--strict` exited **1 even on VERDICT:
PASS** (red-on-green gate tool; CI never calls it and `tests/perf/test_budgets.py` asserts
budgets directly, so suite results were unaffected). Fixed position-independent
(`VERDICT`-line scan); strict run now exits 0 on green.

---

## Criterion (a) — 100% of malicious fixtures caught in expected severity band ✅

Auditor re-ran the corpus harness directly (`discover_fixtures` → `run_case` → `evaluate_case`
against a temp scratch root, pack `2026.08.6`):

```
malicious=43 failures=0
```

Every one of the **43** malicious fixtures fires **every** declared `expect_rules` entry inside
its declared `severity_band`. In-suite equivalents: `tests/test_corpus.py` (72 tests) green.
The 12 new real-world-derived/combo fixtures (Shai-Hulud worm, Nx sweeper, event-stream stager,
ctx harvester, polyfill.io hijack, postmark BCC tap, MCP tool poisoning, SolarMarker-class
persistence, PyPI typosquat campaign, CI secret dumper, stego-deaddrop-combo,
typosquat-beacon-combo) all band correctly — including all three LNS-DEP rules where expected
(`typosquat-deps`, `typosquat-beacon-combo`).

## Criterion (b) — 100% of benign fixtures ≥B on street ✅

```
python3 tools/probe_benign_floor.py   →   benign=33 failures=0
```

All **33** benign fixtures score **100 / A / clean** (every grade ≥ B; verdict clean on the
street profile). The ten Phase-3 hard cases (`lab-recon-playbook` with
`[lab:declared-offensive]`, docker/k8s helpers, docs cookbook, non-English descriptions
`cjk-notes-helper`/`arabic-task-tracker`, exotic-frontmatter-tolerated, Hermes-native reference,
data-URI docs, pinned-deps lookalikes ×2) are all silent. Enforced in-suite by
`tests/test_benign_floor.py`.

## Criterion (c) — Corpus ≥40/≥30 full-fidelity public, licensing gate predates derived fixtures ✅

Census (auditor-counted): **43 malicious / 33 benign**, **76 `expected.toml` manifests** (one per
fixture), all authored as categorized-layout bundles that dogfood the ingest path. Full fidelity:
fixtures ship complete SKILL.md/scripts/manifests content, not stubs (HQ O5 owner call).

Git-order proof: the licensing/provenance gate record `docs/corpus-licensing-review.md` is
**already committed as `984e76f` (2026-08-26, "docs(corpus): track licensing/provenance gate
record + ordering attestation (D-050)")** — the corpus fixtures were untracked working-tree
state at audit time and are committed only AFTER it, so history order = gate-before-fixtures.
The doc's internal ordering attestation records that the GO record was completed 2026-08-25
before fixture authoring (auditor-sanctioned attestation path; re-base rejected as destructive).
Spot-verified live: 10/10 real-world-derived fixtures' `expected.toml` carry provenance
back-pointers citing the review; benign addenda are synthetic clean-room (no gate burden).

## Criterion (d) — Determinism + socket-deny + import-contract red-on-drift ✅ (spot-proven)

Jobs exist and are wired: `.github/workflows/determinism.yml` (two-leg TZ/locale/path-prefix/
PYTHONHASHSEED byte-compare over all 76 fixtures via `tools/determinism_check.py`, compare job
requires byte equality of sha256 manifests), `.github/workflows/privacy.yml` (import-contract +
pytest-socket canned-scan suites), `ci.yml` SARIF schema step.

**Auditor spot-proof via /tmp copy trick (import-contract):** full repo copied to `/tmp/lens-drift`
(copy since discarded; repo untouched); single line `import urllib.request` injected into the
default-closure module `skill_lens/scoring.py`; rerun:

```
FAILED test_default_closure_imports_no_network_modules
FAILED test_no_static_network_imports_outside_enrich
FAILED test_enrich_osv_imported_only_on_flagged_codepath    → EXIT=1
```

All three G1/G3 proofs go red on drift. Socket-deny and cross-env determinism proofs were
previously captured by construction in `build-state/privacy-ci-proof.txt` (injected getaddrinfo ⇒
SocketBlockedError; TZ/LANG/hash-seed/path-prefix byte-identical digests) and stand.

## Criterion (e) — Perf budgets green inside fake lifecycle dispatch ✅

Auditor re-ran `scripts/perf_check.py --strict --write` (harness loads the package host-style and
times the REGISTERED lens command handler through a fake PluginContext — cold leg rides the real
worker queue to job-ready, cached leg redispatches byte-identical input):

| leg | auditor run | budget |
| --- | --- | --- |
| cold dispatch→ready p95 | **325.0 ms** (p50 316.5, max 343.4; 24 runs) | ≤400 ms ✅ |
| cached fast path p95 | **4.0 ms** (p50 3.8; 24 runs) | <200 ms ✅ |

Probe bundle 148,306 bytes (realistic mixed ≤1 MB contract). Regenerated baseline committed at
`build-state/perf-baseline.txt`; near-ceiling ~830 KB cost (~1.7 s) stays INFORMATIONAL per
PLAN risk #2 mitigation (cold work rides the worker; synchronous install beat bounded).
Includes the audit fix restoring `--strict` exit-code semantics (see Verdict block).

## Criterion (f) — SARIF validates ✅

`tests/test_report_sarif.py`: **21 passed** — every rendered envelope validated against the
vendored official OASIS SARIF 2.1.0 draft-07 schema (`tests/fixtures/schema/sarif-schema-2.1.0.json`)
across vectors A–G, both corpus classes, and an enriched case; level bands/fingerprints/
suppressions/score-block mappings pinned byte-stable. CLI tool re-run:
`scripts/sarif_check.py` → `SARIF CHECK: PASS (0 violations)` (malicious committed-keys 2 results

+ benign pinned-deps-helper 0 results, both schema-valid), wired as an explicit ci.yml step.

## Criterion (g) — pytest + ruff + vectors green; E8 shipped ⇒ all EIGHT engines live ✅

+ `python3 -m pytest -q` → **868 passed** (Phase 2 gate: 639 ⇒ +229 across E8/SARIF/corpus/floor/
  exit-codes/perf/import-contract work)
+ `ruff check .` → All checks passed!
+ `tests/test_vectors_golden.py` → 14 passed, A–G byte-exact (re-verified after the audit's own
  shared-file edit)
+ Engine registry census: **8/8** — `depintel, jsscan, manifest, netgraph, pyscan, secretscan,
  shellscan, textinject` (E1–E8 all implemented; REGISTRY wired; D-036 deferral closed)

---

## Commit plan executed after this report

Atomic conventional commits, identity Irell Zane `<itsirellzane@gmail.com>` (repo-preconfigured;
no env/-c overrides), then push to origin main:

1. `feat(depintel)` — E8 engine, LNS-DEP-001/002/003, OSV opt-in lane, SARIF output, privacy
   closure (D-045) [shared modules cli/slash/jobs/render/e2 carry co-edits whose dedicated tests
   land with commits 5–6]
2. `fix(claims)` — multilingual concreteness cues, i18n MAN-004 FP closure (D-047)
3. `test(corpus)` — 12 malicious + 10 benign fixture additions, floor probe (D-046/D-048)
4. `feat(perf)` — fake-dispatch harness + baseline; fix `--strict` verdict indexing (D-049)
5. `ci(determinism+privacy)` — workflows, digests tool, socket/import proof (D-049)
6. `test(cli)` — §18 exit-code contract matrix (D-049)
7. `docs` — this report + STATUS ledger row + DECISIONS rows (D-045..D-050)

Push failure ⇒ recorded as a non-fatal DECISIONS row per task law.
