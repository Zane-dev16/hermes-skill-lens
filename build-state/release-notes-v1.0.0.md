# Skill Lens v1.0.0

Core rule pack pin: **2026.08.9** (engine + pack travel together, D-RULEOWN).

## Pack highlights (head changelog entry)

### 2026.08.9 — cross-file taint via import edges (D-067)

- E4 pyscan LNS-PYS-004 and E5 jsscan LNS-JSS-004 widen to cross-file
  import-edge taint (same-bundle, same-language, direct import edge —
  sink imports source). New evidence token family
  xf-flow:<source_kind>:<sink_short>:<src_path>><sink_path> with
  confidence 0.80, tag cross-file-flow, static_only false, AST-only
  (degraded lane unchanged per D-039 parity; parity law intact).
  Token never collapses against same-file sensitive-flow; line-shift
  stable per file; findings sorted by (rule_id, path, start_line) with
  sink as primary location and source attached to locations[].
- Fixtures: malicious py-split-exfil (helpers/grab.py→scripts/run_report.py)
  and js-split-beacon (lib/envcollect.js→index.js) fire HIGH via xf-flow;
  benign split-modules-reporter (co-presence no edge),
  declared-split-uploader (import edge no source),
  cross-lang-co-presence (py env + js fetch) stay silent (grade ≥ B, FP=0).
- No new rule ids, no material (severity/weight/capability/engine/
  evidence_kind/confidence_default) changes; vectors A–G byte-exact,
  existing fixtures byte-identical. Pack 2026.08.9 re-signed at
  keys/core-pack-2026.08.9.sig; CHANGELOG mirror regenerated, governor
  patch-legal.

## v1.0 hardening milestone (SPEC section 13)

- SHA-pin community packs + lens console-script + GitHub Action with
  SARIF upload (D-065): pins at project `<target>/.lens/packs.toml` +
  global `$XDG_CONFIG_HOME/lens/packs.toml` (project later-wins per name);
  malformed/duplicate/bad-hex/ceiling breach ⇒ PackPinError exit-2;
  fail-closed matrix (digest≠pin / loader-reject / missing-sha256 /
  present-but-invalid sig / id-collision ⇒ REJECTED loud LNS-PACK-*);
  governor core-only; id-collision REJECT with
  `community/<pack>/LNS-…` namespacing deferred (major territory);
  street MEDIUM cap (external CRITICAL/HIGH → effective_severity MEDIUM
  + `[street-cap:…]` annotation); ceiling ≤8 (MAX_EXTERNAL_PACKS);
  perf <2 ms with one external pack, cold p95 156.4 ms (idle law 250,
  budget 400) — scan path unaffected.
- Console-script packaging: `lens = skill_lens.console:main` shim reusing
  cli.setup_parser single grammar + build_cli_handler/dispatch_verb shared
  routing (§18 0/1/2 intact); wheel pure-Python py3-none-any grammar-less
  (extras `ast` = tree-sitter, `sig` = cryptography; degraded lane
  byte-identical); sdist ships skill_lens/** + rules/core/* +
  keys/pack-signing.pub.pem; --sarif-out atomic write; publish owner-run
  TestPyPI-first (pypa/gh-action-pypi-publish@SHA-pinned, Trusted
  Publisher/id-token; no tokens on this box per D-064).
- GitHub Action: composite at repo root action.yml (no Docker, pure-Python,
  full-SHA pin law — every third-party uses: pinned to 40-hex SHA and lens
  itself pinned via lens-ref SHA or lens-version PyPI pin; CI greps pins via
  scripts/action_check.py; gate semantics 0/1/2 via continue-on-error capture
  → conditional SARIF upload (skip on 2) → explicit gate step).
- Choir.llm downgrade-only LLM second-opinion over ctx.llm (D-066):
  two-layer clamp (prompt contract + authoritative post-parse clamp with six
  rules; equal-tier downgrade = no-op confirm; Cisco #138 test), D-060
  budgets 5 findings / 600 chars/card / 4000 total / 512 output tokens /
  20 s timeout (code constants not policy), dual opt-in gates (policy
  [choir] enabled + explicit verb), sidecar lens.choir/1 + separate
  choir-events.ndjson ledger, envelope byte-untouched (llm_touched on
  sidecar only), zero scan-path cost (lazy import), doctor check 10,
  adjusted_score deferred to promotion eval, no new-finding action (v1.1
  boundary); inert-by-default, no default-on decision exists.
- Subprocess parse-isolation deferred on evidence (no field/fuzz crashes;
  degraded lane guarantees availability on adversarial input; health()
  counters remain as tripwire; revisit on first field crash) — per
  cross-file-taint.md §8 and D-065.
- Proactive gateway push not elected by owner (SPEC section 13 election —
  recorded per election law).
- Choir promotion eval pending (adapter ships disabled by default) — adapter
  is inert-by-default, no default-on decision exists; promotion eval is
  pending.

## Verification (offline)

- Pack content checksum: `sha256:e0949cdd46020b034b25b0470c0fc8629e52fc0707815a70427775bad7076e3d`
- Release artifact: `lens-core-pack-2026.08.9.zip`
- Artifact SHA256: `7ec88b2fa7bf779ea506ebece24914b236238ae22aa5d34487548eb4cf03fce7`
- Signing key fingerprint: `SHA256:9802d3c8e6ca921b…` (committed at `keys/pack-signing.pub.pem`)
- Verify after install: `hermes lens rules verify`

## Upgrade / downgrade

- Upgrade: `hermes plugins update` then confirm `hermes lens doctor`
  shows the new signed pack (check 1 PASS).
- Downgrade: reinstall the older tag — it carries ITS OWN matching pack
  by construction; external packs whose schema is newer than the engine
  are refused at load (loud diagnostic, never silently enabled).

Advisor, not bouncer: static analysis only; clean scan ≠ safe skill.
