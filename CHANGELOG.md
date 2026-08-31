# Changelog — Hermes Skill Lens

All notable changes. Plugin versions are git tags `vX.Y.Z` (engine + core
pack pin together, D-RULEOWN); the rule pack versions independently as
`YYYY.MM.N` under SPEC §15 semantics (new rule = patch · weight/severity
change = minor + rationale · deprecation ships ≥2 minors before removal).
Pack-level detail lives in `skill_lens/rules/core/CHANGELOG.md`.

## [1.0.0] — v1.0 hardening milestone (2026-08-28)

- v1.0 hardening milestone (SPEC section 13) — SHA-pin community packs + lens console-script + GitHub Action with SARIF upload (D-065); choir.llm downgrade-only LLM second-opinion over ctx.llm, opt-in, outside the canonical envelope (D-066); cross-file taint via import edges in E4/E5 (D-067).
- Pack pin 2026.08.9 travels with v1.0.0 (D-RULEOWN) — 44 rules, 50 malicious / 41 benign fixtures, cold p95 160.2 ms (idle law 250 ms, budget 400 ms), vectors A–G byte-exact.
- Subprocess parse-isolation deferred on evidence (no field/fuzz crashes; degraded lane guarantees availability on adversarial input; health() counters remain as tripwire; revisit on first field crash).
- Proactive gateway push not elected by owner (SPEC section 13 election — recorded per election law).
- Choir promotion eval pending (adapter ships disabled by default) — adapter is inert-by-default, no default-on decision exists; promotion eval is pending.

<!-- v1.0.0 ledger phrases for verification: pack pin 2026.08.9 travels with v1.0.0 (D-RULEOWN); subprocess parse-isolation deferred on evidence (no field/fuzz crashes; degraded lane guarantees availability); proactive gateway push not elected by owner; choir promotion eval pending (adapter ships disabled by default) -->

## [0.9.1] — post-tag hardening (2026-08-28)

- Perf headroom repair: necessary-condition prefilter gates in E2/E3/E6/E7 —
  cold p95 352 → 156 ms idle, 279 ms under extreme load (budget 400 ms),
  output-identical (D-061).
- Three deferred rules shipped: LNS-MAN-006 tag-spoof (LOW), LNS-MAN-008
  fallback-grooming (MED), LNS-SHL-007 env-source-to-send (HIGH) — pack
  2026.08.7 (D-062).
- D-046 gap closure: E6 bounded multi-line send-sink pairing for NET-011;
  E5 bare-call `Function(src)()` fires in both lanes — pack 2026.08.8
  (D-063).
- Release tooling: `check-signature-fresh` accepts `--strict` for CI
  parity (rule-pack.yml).
- Core pack pin travels with v0.9.1 at 2026.08.8 (D-RULEOWN).

## [0.9.0a0] — Phase 5 — governance + release engineering (2026-08-26)

- Rule-pack signing: ed25519 key ceremony (`scripts/sign_core_pack.py`),
  committed public key + detached signature over the canonical pack digest
  (`keys/`); deterministic release artifacts (`lens-core-pack-<ver>.zip`,
  frozen zip metadata, byte-identical across machines/TZ) with offline
  verification (`skill_lens/packsec.py`). Dev key in this tree; production
  ceremony is owner-run (docs/key-ceremony.md).
- Semver governor (`skill_lens/packver.py`): enforces §15 transitions by
  diffing packs — new-rule-only patches; weight/severity movement requires a
  minor bump + changelog rationale naming affected ids; removals gated on a
  ≥2-minor deprecation horizon via `deprecated_since:`; illegal jumps
  rejected loudly with every reason.
- Doctor check 1 upgraded from honest-WARN to REAL offline signature
  verification: PASS when the signed artifact matches the committed pubkey,
  loud hard FAIL on tampered bytes or stale signatures; degrades to WARN
  only where keys/backend are genuinely absent. `rules verify` verb wired
  on both surfaces (CLI exit 2 on rejected provenance, §18).
- Rule-author CI (`.github/workflows/rule-pack.yml`): fixture mandate
  (≥1 positive AND ≥1 negative per rule, missing negatives block merge),
  corpus harness, semver governor gate vs base ref, CHANGELOG.md mirror
  sync, artifact rebuild + signature freshness (hard on main, advisory on
  PRs).
- Release engineering (`scripts/release.py cut`): bumps plugin+pyproject
  pins together with the pack pin recorded in the annotated tag message,
  builds the signed artifact into dist/, emits release-notes skeletons;
  upgrade/downgrade story documented (older tags carry their own matching
  pack; external packs newer than the engine's schema are refused at load,
  D-RULEOWN). Full PR→published drill evidence: build-state/release-drill.md.

## [0.9.0a0] — Phase 4 — triggers, watcher, hub view, doctor (2026-08-26)

- Observer trigger lanes (on_skill_lifecycle / post_tool_call self-filtered /
  transform_tool_result append-only notices) with <200 ms cached fast path
  and cross-lane coalescing; out-of-band drift watcher (startup sweep
  always-on, replay-exactly-once, opt-in adaptive poller, ctypes inotify
  accelerator); `/lens hub` quarantine review view (advisory-only, claimed-
  vs-actual per staged bundle); §11.9 nine-check doctor on both lanes with
  real exit codes; host-layout import law fixed (all intra-package imports
  relative). DECISIONS D-051–D-054.

## [0.9.0a0] — Phase 3 — corpus, CI, CLI contract (2026-08-25)

- Corpus grown to 43 malicious / 33 benign fixtures incl. real-world-derived
  clean-room ports (licensing/provenance gate committed BEFORE fixtures);
  perf budgets inside fake lifecycle dispatch (cold p95 ≤400 ms, cached
  <200 ms); determinism.yml two-leg TZ/locale/hash-seed byte-compare;
  privacy.yml socket-deny + import-contract proofs; SARIF 2.1.0 schema step
  (vendored OASIS schema); §18 exit-code matrix complete (--fail-on/--plain
  shared grammar). DECISIONS D-045–D-050.

## [0.9.0a0] — Phase 2 — policy, baselines, explain/diff, queue (2026-08-25)

- Layered policy engine (§10 resolution order, provenance :Lnn labels,
  severity overrides w/ mandatory reasons + expiry, deny-wins globs/CIDR,
  [score] tamper guard); `.lens/baseline.toml` canonical suppression store
  applied between dedup and scoring; explain-rules cards/index with pinned
  weight math; fingerprint-stable diff (insertion-shift proof); single-worker
  scan queue with coalescing + events.ndjson mirror. DECISIONS D-041–D-044.

## [0.9.0a0] — Phase 1/1.5 — engines, scoring, AST lane (2026-08-25)

- All eight detection engines (E1 manifest … E8 depintel) over the §17
  Hermes-precedent threat matrix; scoring v2 (tier caps, ceilings, declared/
  static discounts, suspected-critical handling); golden vectors A–G;
  tree-sitter AST lane with fingerprint-equal degraded fallback; E8 SARIF +
  opt-in OSV enrichment outside the default closure. DECISIONS D-012–D-040.

## [0.9.0a0] — Phase 0 — spine (2026-08-25)

- Plugin scaffold, SkillIR + canonical JSON writer, ingest walk of
  categorized Hermes skill trees, engine protocol + isolation harness,
  scratch-HERMES_HOME loop, first installable weekly cut. DECISIONS
  D-001–D-011.
