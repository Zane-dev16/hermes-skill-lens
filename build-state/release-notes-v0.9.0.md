# Skill Lens v0.9.0

Core rule pack pin: **2026.08.6** (engine + pack travel together, D-RULEOWN).

## Pack highlights (head changelog entry)

- Add engine E8 depintel (SPEC §4 row E8 / §17 R8 supply-chain):
- LNS-DEP-001 unpinned-dependency note LOW static (requirements*/
- pyproject.toml incl. Poetry table, package.json dep fields; a spec
- with no version digits and no direct reference floats), LNS-DEP-002
- offline typosquat heuristic MED regex-band 0.72 (bundled top-package
- allowlists; homoglyph via E2 TR39 skeleton D-037, leet collapse,
- Damerau-Levenshtein <=2 near-miss; allowlist members and <4-char
- names exempt), LNS-DEP-003 npm install lifecycle hooks MED dynamic
- (preinstall/install/postinstall execute at install time — D-036
- deferred exactly this here; download-and-execute body refines
- confidence 0.90→0.97, never severity). Capability ontology gains
- supply-chain family (§9.1 growth). Fixtures: malicious typosquat-deps
- x3 rules + benign pinned-deps-helper lookalike. --osv OSV.dev
- enrichment ships as LAZY-imported skill_lens.enrich.osv outside the
- default closure (SPEC §14 G1/G2/G3); findings carry additive detail
- package refs for enrichment/SARIF mapping.

## Verification (offline)

- Pack content checksum: `sha256:58227cb7fb98cb4e120d8aa7a4e7a9d501c4ff50fd0c5aacb7833d319b6f5828`
- Release artifact: `lens-core-pack-2026.08.6.zip`
- Artifact SHA256: `74ce4a0f5bb69a1e5dad7bacbf741e825efed2f1817409e6889de5c0317f80c5`
- Signing key fingerprint: `SHA256:9802d3c8e6ca921b…` (committed at `keys/pack-signing.pub.pem`)
- Verify after install: `hermes lens rules verify`

## Upgrade / downgrade

- Upgrade: `hermes plugins update` then confirm `hermes lens doctor` shows the
  new signed pack (check 1 PASS).
- Downgrade: reinstall the older tag — it carries ITS OWN matching pack by
  construction; external packs whose schema is newer than the engine are
  refused at load (loud diagnostic, never silently enabled).

Advisor, not bouncer: static analysis only; clean scan ≠ safe skill.
