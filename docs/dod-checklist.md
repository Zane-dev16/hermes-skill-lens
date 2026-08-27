# Definition-of-Done checklist — Hermes Skill Lens v0.9

Audit of PLAN §7 against this tree at tag time (`2026-08-27`, plugin 0.9.0, pack
`core` `2026.08.7`). Each item: status + where the evidence lives.

| # | DoD item | Status | Evidence |
| --- | ---------- | -------- | ---------- |
| 1 | `hermes plugins install <tag>` end-to-end; enable/disable clean; malformed input → structured diagnostics | ✅ | build-state/release-drill.md (fresh-install-from-tag doctor-green); P0 scratch-home loop |
| 2 | All eight engines E1–E8 shipped; tree-sitter dual-lane resolved honestly; degradation golden-proven | ✅ | skill_lens/engines/ (E1 manifest, E2 textinject, E3 shellscan, E4 pyscan, E5 jsscan, E6 netgraph, E7 secretscan, E8 depintel); ParserGateway active/degraded + byte-golden fallback tests; fuzz corpus green |
| 3 | Claims subsystem complete (field-direct + lexicon, overreach templates, LNS-MAN-004) | ✅ | skill_lens/claims.py; tests/test_claims.py, test_lexicon_claims.py |
| 4 | Core pack 30–40 rules, corpus-tested both ways | ✅* | **41 rules** in skill_lens/rules/core/rules/ — one over the stated budget band; coverage complete both ways (43 malicious / 33 benign fixtures). Deviation escalated in QUESTIONS_FOR_OWNER.md rather than dropping working detection |
| 5 | Rubric v2 exact; SPEC §8.3 vectors A–G reproduced exactly; rubric documented | ✅ | tests/test_vectors_golden.py (14 pass, byte-exact tuples); scoring-property suite |
| 6 | Triggers live + host-contract tested; observers only, zero blocking registrations asserted | ✅ | skill_lens/triggers.py; docs/host-contract.md (verbatim emit sites); doctor check 5 negative proofs |
| 7 | Async UX complete: fast-path one-liners, jobs.json state machine, coalescing, delivered results, events.ndjson mirror | ✅ | skill_lens/jobs.py; tests/test_jobs.py; H13 print-seam absence documented (docs/limitations.md L1) |
| 8 | Watcher covers out-of-band drift: always-on sweep + opt-in polling + gap replay once | ✅ | skill_lens/watcher.py; churn/restart-replay tests + live spot-checks |
| 9 | Hub quarantine view at confirm beat, role-labeled, rmtree-tolerant, INSTALL_POLICY untouched | ✅ | skill_lens/hubview.py; /lens hub; guard non-coupling tests |
| 10 | Doctor: nine checks incl. synthetic-event self-test, blocking-wiring audit, AST health, network-isolation self-test | ✅ | skill_lens/doctor.py; negative-proof tests (broken state + injected pre_tool_call ⇒ loud FAIL) |
| 11 | street/lab profiles + TOML & settings layers + merge semantics + severity_overrides; --fail-on on CLI verbs; verdict = automation interface | ✅ | skill_lens/policy.py; tests per P2/P3 gates; §18 exit-code matrix tests |
| 12 | Baseline round-trip via .lens/baseline.toml; suppressed machine-visible; diff shift-stable | ✅ | skill_lens/baseline.py, diff.py; 10-line-shift test |
| 13 | --json envelope + _meta sidecar; SARIF schema-validated; byte-determinism CI across environments | ✅ | determinism.yml two-leg TZ/locale/path compare; vendored OASIS 2.1.0 validation |
| 14 | Corpus ≥40 malicious / ≥30 benign, full-fidelity public; licensing gate done | ✅ | 43 mal / 33 ben with expected.toml provenance back-pointers; docs/corpus-licensing-review.md committed BEFORE derived fixtures (984e76f order attestation D-046/D-050) |
| 15 | Privacy G1–G6 test-enforced (socket-deny + import-contract red-on-drift); perf budgets inside fake dispatch | ✅ | privacy.yml proofs (build-state/privacy-ci-proof.txt); perf-baseline strict PASS cold p95 ≈344 ms / cached 5.3 ms |
| 16 | Signed packs (YYYY.MM.N); PR→published automated; downgrade pins matching pack | ✅ | packsec/packver; rule-pack.yml; drill §8–§10 incl. tamper + downgrade evidence |
| 17 | Choir stub present (contract + config, zero adapters); provenance annotation-only | ✅ | policy.py `choir.enabled=False` lane (downgrade-only per HQ R2); S7/R8 annotation law tests |
| 18 | Per-profile stance documented; verified in a second scratch profile | ✅ | PLAN §0 profiles row → README/limitations wording; multi-home drills used independent HERMES_HOMEs throughout |
| 19 | Fun strictly opt-in, snapshot-proven data-invariance; NO_COLOR/--plain respected; coverage footer everywhere | ✅ | tests/golden/fun cross-combo equality; test_no_color_audit; R5 footer pinned by render tests |
| 20 | Docs complete (README quickstart, rule-author guide, threat-model & limitations statement); dogfooded on maintainer's tree | ✅ | docs/{rule-author-guide,threat-model,key-ceremony,limitations,fp-regression}.md; mandated statement verbatim in threat-model.md; build-state/dogfood.md |

Deferred to roadmap homes exactly as PLAN §7 states (v1.0/v1.1 columns): cross-file taint,
subprocess parse isolation, community SHA-pin loading, PyPI console-script CLI, GitHub Action +
SARIF upload, `/lens second-opinion` promotion eval, proactive gateway push.

## Result

**20/20 criteria satisfied** (one owner-visible deviation flagged inline in #4).
Budget contract items never cut: advisor stance, determinism, scoring-v2 contracts,
non-blocking host contract, privacy guarantees.
