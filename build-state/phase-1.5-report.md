# Phase 1.5 Gate Report — AST engines + lexicon claims

**Auditor:** Phase 1.5 gate audit & commit (independent re-run of PLAN §1 exit criteria)
**Date:** 2026-08-25 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.5` (checksum `sha256:e8702428…`)
**Scope audited:** parse-lane substrate (`parsing.py` + vendored wheels), E4 pyscan, E5 jsscan,
E2 textinject, lexicon claim extractor, AST-vs-regex benchmark — all landed uncommitted by five
Phase 1.5 sub-tasks; this audit re-executed every exit criterion itself before committing.

## Verdict: **PASS — 5/5 criteria** · Delivery-lane outcome: **HOLDS — no demotion**

Every criterion was re-executed independently by the auditor (not taken from prior summaries).
Authoritative gates at HEAD: **pytest 506 passed, 0 failed/skipped** (`python3 -m pytest`, 9.9 s)
and **ruff clean** (`ruff check .` → "All checks passed!").

---

## Criterion (a) — AST evidence beats regex on the FP corpus at equal TP ✅

Reran `tools/bench_ast_vs_regex.py` **twice** → `build-state/ast-benchmark.txt` (exit 0 both runs):

- Corpus: **52 fixtures (30 malicious / 22 benign)** through `corpus.run_case`; ast mode = live
  ParserGateway, regex mode = grammar import forced unavailable rebound in EVERY loaded
  `skill_lens.*` module holding the gateway (so the comparison hits the engines' actual seam).
- **TP(ast)=45 ≥ TP(regex)=42: OK · FP(ast)=0 < FP(regex)=4: OK → VERDICT: PASS.**
- Honest judgment of the exit math: the advantage is *structural, not tuned*. The 3 TPs regex
  cannot see are exactly the D-039 obfuscation shapes (`py-getattr-exec` getattr→eval resolution,
  `py-aliased-eval` aliased-import tail matching, `py-stringattr-shell` static-string-concat callee)
  which are AST-only true positives by construction; the 4 FPs are sink-shaped STRING LITERALS plus
  prose in the benign `lint-blocked-pattern-docs` lookalike that the comment-stripping line scanner
  flags (PYS-001×2, PYS-003×2) while the AST correctly treats string contents as data. Both exit
  clauses hold strictly, not marginally-equal.
- Determinism: the table (rows, totals, disagreements, verdict) is **byte-identical across both
  runs** excluding the labeled advisory latency columns; no wall-clock in the table proper.

## Criterion (b) — unicode-stego fixture caught ✅

`corpus/fixtures/malicious/unicode-stego` (innocent paragraph carrying ZWSP/ZWNJ + Tags-encoded
"Ignore previous instructions…") is wired into the rule YAML fixtures both ways and gated by the
corpus harness: 3 stego-scoped tests green — TXT-001 fires escalated (Tags payload decodes to an
instruction-bearing ASCII channel) plus the TXT-004 ghost-view hit; benign twin
`emoji-rich-i18n-notes` (CJK + Arabic + ZWJ-family/rainbow-flag/keycap emoji) stays silent.

## Criterion (c) — Degraded mode golden-identical when grammar absent OR fails ✅

Two independent proofs:

1. Repo goldens: `tests/test_parsing_golden.py` **9/9 green** — for each engine slot
   (e4_pyscan/e5_jsscan/e3_shellscan_bash) the serialized engine-facing surface (mode + full
   `line_tokens()` stream + statuses + failure counters) is byte-for-byte identical under an
   ImportError loader (both lanes absent) vs a loads-but-`Language()`-explodes loader; reason codes
   are deliberately excluded from the golden and separately asserted to differ.
2. Auditor force-degraded proof (fresh subprocesses, script outside the test suite): grammar
   import blocked at the gateway seam vs module present but `language()` raising — degraded token
   streams byte-identical (python 3 lines + javascript 2 lines), health counters consistent,
   WHY-reason codes differ as designed. Engine-level parity goldens
   (`e4_findings_pyscan`/`e5_findings_jsscan`) additionally pin the post-D-038 finding surface
   byte-exactly. Degradation is first-class, provably cause-independent.

## Criterion (d) — Fuzzer green over the grammar corpora ✅

`tests/fuzz/test_grammar_fuzz.py` **8/8 green**: hypothesis adversarial bytes (binary soup ≤2048 B,
zero-width/bidi/Tags-block/astral unicode alphabets, nested/malformed constructs, truncations of
valid programs) through python/javascript/bash grammars — asserts no exception escapes, mode/reason
well-formedness, per-parse wall-clock <5 s, health-counter consistency.

## Criterion (e) — Vectors A–G exact · pytest+ruff green ✅

`tests/test_vectors_golden.py` **14/14**: live pipeline reproduces the §8.3 oracle byte-exact —
A=100/A·clean · B=91/A·notice · C=25/F·alert · C′=40/D·warn·needs_review · D(lab)=85/B·notice ·
E=80/C·warn · F=83/B·notice · G=70/C·warn. Full suite **506 passed / 0 failed**, ruff clean.
Zero-network-import law unchanged (pytest-socket + import-contract inside the suite).

---

## Lane disposition (D-PARSE)

Both lanes verified on this machine (CPython 3.13.5, Linux x86_64): pip install clean
(tree-sitter 0.26.0 cp313 manylinux + python/javascript/bash grammar wheels cp310-abi3) and the
same four wheels vendored under `wheels/`, SHA256-pinned in `parsing.py::_WHEEL_SHA256`
(vendor tests fail CI on swap/mismatch; hash-mismatched wheels skipped, never executed). Manifest
`python_dependencies` is declaration-seam-only (host validates/warns, never auto-installs).
**AST engines stay v0.9 — no demotion filed; the QUESTIONS_FOR_OWNER.md demotion note is therefore
NOT drafted (condition not met).**

## Artifacts

- `build-state/ast-benchmark.txt` — committed bench output (auditor rerun #2)
- `tools/bench_ast_vs_regex.py` — deterministic exit-math tool (CI-adoptable exit codes)
- `tests/golden/degraded/*.golden.json` — gateway-level ×3 + engine-findings ×2 goldens
- `build-state/phase-1.5-report.md` — this report · DECISIONS rows D-033..D-040 · STATUS ledger

## Escalations

None blocking. Recorded-not-open items (each already carries its own DECISIONS row): dedicated
TypeScript grammar deferred honestly — `.ts` rides the JS grammar lane per §4 row E5 scope
(D-036); doctor active/degraded reporting lands in Phase 4 per plan (health() telemetry already
shipped); subprocess parse-isolation remains the documented v1.0 escape hatch (D-PROC caveat).

## Commits (atomic conventional series)

1. `feat(parsing)` — ParserGateway dual-lane delivery + degradation goldens + grammar fuzz [D-033, D-034]
2. `feat(claims)` — lexicon v1 verb-object extractor + declared-discount wiring [D-038]
3. `feat(engines)` — E4 pyscan + E5 jsscan + E2 textinject wave, pack 2026.08.5 [D-035..D-037, D-039]
4. `feat(tools)` — AST-vs-regex evidence benchmark + committed artifact [D-040]
5. `docs(gate)` — this report + STATUS ledger + decision rows
