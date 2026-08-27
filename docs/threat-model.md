# Threat model & limitations

Skill Lens is an advisor: it reads skill bundles as static data and reports
what the bytes say. This page states plainly what that means — what is
covered, and, just as important, what is not.

static analysis only — runtime-injected instructions are out of scope · clean != safe

There is no emphasis trick in that sentence. It is the honest boundary of
the tool:

- **Static analysis only.** Skill Lens inspects files: manifests, scripts,
  prose, dependency declarations. It sees the bundle as written, not the
  agent as it runs. Instructions that only exist at runtime — composed
  lures, tool-result injections, content fetched after install, anything a
  live model or channel generates — are invisible to it by construction.
  Conversation-mediated exfiltration with runtime-generated content cannot
  be seen from disk (accepted residual risk for v0.9, SPEC §17).
- **Clean != safe.** A scan with zero findings means the deterministic rule
  pack found nothing it knows to look for. It does not mean the skill is
  benign. Novel techniques below the detection floor, semantic subtlety
  inside plausible-looking prose, and everything in the "residual risk"
  column of the §17 coverage matrix remain open. The coverage-honesty
  footer on every report carries the rule-pack version and checksum so you
  can always know WHICH detection state produced a given verdict.

## What the lens DOES cover

The full threat-to-engine matrix lives in SPEC §17; in brief, eight
deterministic engines cover: hidden Unicode/ghost-text instruction channels
and homoglyph impersonation (E2), shell and interpreter execution sinks,
decode-to-exec chains, outside-root deletes (E3/E4/E5), network egress
shapes and undeclared hosts (E6), committed known-format credentials
(E7), dependency supply-chain heuristics (E8), and Hermes-dialect manifest
abuse — persona/memory writes, skill chaining, metadata.hermes fields,
cron persistence, control-plane tampering, profile escape shapes (E1) plus
claimed-vs-actual capability diffs over every scanned bundle.

## Governance of what ships

Detection logic is itself attack surface, so the pack travels governed
(SPEC §15): YAML data in-repo, `YYYY.MM.N` semver enforced by the governor
(score-visible changes need a minor bump + written rationale; rules retire
through a ≥2-minor deprecation horizon), both-way golden fixtures per rule,
and ed25519-signed pack states verified offline against the committed
public key on every load (`lens doctor` check 1, `lens rules verify`).
Updates are manual-only — nothing fetches rules on its own.

## Standing limitations (v0.9)

1. Delivered-results UX: no host print seam exists for async summaries;
   they surface via events.ndjson + pull banner (docs/limitations.md L1).
2. Cross-bundle chain completion (H3): watch/diff narrows but does not
   close staged loaders.
3. Exotic path-variable tails (H9) and profile-boundary enforcement (H8)
   remain host-side concerns; Skill Lens detects intent-shaped evidence.
4. E6 send-sink regexes are single-line; multi-line `fetch(...)` calls do
   not pair today (recorded gap, D-046).
5. Non-Latin descriptions mint no ClaimRecords — declared discounts stay a
   Latin surface (D-047 records the closure actually shipped).
6. Decode-depth cap of 3 bounds obfuscation peeling (R7).

Each matrix review accompanies a pack minor release; uncovered cells need
a roadmap entry or an explicit accepted-risk note (§17 closing law).
