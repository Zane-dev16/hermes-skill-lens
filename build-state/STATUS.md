# Build status ledger — Hermes Skill Lens v0.9

Format: one line per milestone. Newest at bottom. Phases per PLAN §1.

- [2026-08-25] BOOT: repo prepared (D-001..D-004). Phase 0 (spine) queued.
- [2026-08-25] PHASE 0 GATE: PASS (4/4) — real-home scan byte-identical ×2 (sha256 e6e63059…, 95 bundles); scratch-home /tmp/lens-dev load/enable/disable clean under real PluginManager; quarantine-vanish test exists + green; pytest 80 passed, ruff clean. Gate report: build-state/phase-0-report.md.
- [2026-08-25] PHASE 1 GATE: PASS (5/5) — vectors A–G exact via live pipeline (spot C=(25,F·alert)); corpus 17/17 rules TP-covered, benign ×13 silent; raising-engine isolation inert; /lens scan --json byte-stable ×2 processes; pytest 335 passed, ruff clean. Gate report: build-state/phase-1-report.md.
- [2026-08-25] PHASE 1.5 E4 PYSCAN: engine shipped — 8 LNS-PYS rules (exec/eval, decode-chains, shell sinks, sensitive→send flow, persona/cron/config+skill-tree state writes, outside deletes), AST mode via ParserGateway with fingerprint-equal degraded parity (regex evidence @0.72 cap) + engine-level degraded golden; pack 2026.08.3; 11 fixtures wired; vectors A–G exact; pytest 388 green, ruff clean. DECISIONS D-035.
- [2026-08-25] PHASE 1.5 GATE: PASS (5/5) — bench rerun ×2 byte-deterministic: TP(ast)=45 ≥ TP(regex)=42, FP(ast)=0 < FP(regex)=4 (ast-only TPs = D-039 obfuscation shapes; regex FPs = string-literal docs fixture); unicode-stego caught (TXT-001 escalated + TXT-004); degraded goldens absent≡fail-load byte-identical + independent subprocess force-degraded proof; grammar fuzz 8/8; vectors A–G exact; pytest 506 passed, ruff clean; pack 2026.08.5; both delivery lanes hold — no demotion filed. Gate report: build-state/phase-1.5-report.md.
