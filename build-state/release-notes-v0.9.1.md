# Skill Lens v0.9.1

Core rule pack pin: **2026.08.8** (engine + pack travel together, D-RULEOWN).

## Pack highlights (head changelog entries)

### 2026.08.8 — D-046 gap closure (D-063)

- E6 netgraph LNS-NET-011 gains an additive bounded multi-line send-sink
  window (8 lines / 400 chars hard caps) behind the untouched per-line
  tier 1 — a multi-line fetch with method: POST + body: now pairs with
  same-file credential sources; curl/wget backslash continuations fold
  the same way. Necessary-condition gates (D-049/D-056/D-061) intact;
  vectors A-G byte-exact.
- E5 jsscan LNS-JSS-001 fires on bare-call Function(x) in BOTH lanes
  (AST identifier-callee branch; degraded regex with the same
  (?<![\w.$]) guard and quoted-literal carve-out), evidence token
  function-constructor unchanged so fingerprints match across modes; new
  Function, member access, and literal-only bodies stay silent. No new
  rules; no material changes. Fixtures: malicious multiline-fetch-exfil
  - bare-function-loader, benign build-metrics-poster +
  literal-function-helper.

### 2026.08.7 — deferred rules shipped (D-062)

- The three D-014-deferred rules land (corpus breadth precondition met;
  D-060): LNS-MAN-006 tag-spoof LOW static 0.90 (clause A reserved
  impersonation tokens + clause B all-tags-divergent n>=3 padding;
  category-name and bare-hermes tags are carve-outs), LNS-MAN-008
  fallback-grooming MED dynamic 0.90 (fallback entry without a
  same-list requires counterpart), LNS-SHL-007 env-source-to-send flow
  HIGH regex 0.85 (E3-internal same-file source→sink pairing:
  dot-source/set -a/export $(cat ...) of .env*/credential*/auth.json
  basenames, then a variable-interpolating curl/wget send in the same
  shell region; 0.70 unknown-var band; redirect reads/@file attaches
  stay NET-011's). Fixtures: malicious tag-spoof-padder/
  fallback-groomer/env-source-exfil + benign honest-multi-tag/
  honest-fallback/env-config-loader twins.

## Engine hardening (D-061)

- Necessary-condition gates repaired the post-2026.08.6 cold-dispatch
  regression: cold p95 352 ms → 155 ms (measured 156.2 ms, p50 151.8 ms,
  24 cold runs) against the 400 ms budget; cached fast path unchanged at
  p95 5.5 ms against the 200 ms budget. Scan semantics unchanged —
  vectors A-G remain byte-exact and the full suite stays green.
- release.py --strict: check-signature-fresh now honors the CI-parity
  flag the rule-pack workflow passes (bebee46).

## Verification (offline)

- Pack content checksum: `sha256:b0eb64c9452346cad1dd35e142bed79bfa59fe6f1ebdc5928da940a8919192b8`
- Release artifact: `lens-core-pack-2026.08.8.zip`
- Artifact SHA256: `0ec34850f3b4647ad2b9eb192b73063f2637ff1f5a2af98f5632d2f05048b673`
- Signing key fingerprint: `SHA256:9802d3c8e6ca921b…` (committed at `keys/pack-signing.pub.pem`)
- Verify after install: `hermes lens rules verify`

## Upgrade / downgrade

- Upgrade: `hermes plugins update` then confirm `hermes lens doctor`
  shows the new signed pack (check 1 PASS).
- Downgrade: reinstall the older tag — it carries ITS OWN matching pack
  by construction; external packs whose schema is newer than the engine
  are refused at load (loud diagnostic, never silently enabled).

Advisor, not bouncer: static analysis only; clean scan ≠ safe skill.
