# Corpus Licensing & Provenance Review — real-world-derived malicious fixtures

Gate required by PLAN §1 Phase 3 (retained after HARD_QUESTIONS O5 owner ruling: the public
corpus ships real-world-derived fixtures at full fidelity; publication risk accepted by owner;
this review gate STAYS). This document is the gate record. Per the phase task order, its content
was completed BEFORE any of the inventoried fixtures below were authored; each fixture's
expected.toml carries a `provenance` note pointing back here.

Scope: the ~10 planned real-world-derived malicious fixtures plus the 2 purely synthetic
cross-engine combo fixtures (listed for completeness; they derive from nothing external).
No benign fixture derives from any real-world incident.

## Provenance classes used

| Class | Meaning |
| --- | --- |
| PUBLIC-INCIDENT | Fixture models a named, publicly documented supply-chain incident (vendor/maintainer disclosures, mainstream security press). |
| PUBLIC-TECHNIQUE | Fixture models a technique family documented in public research/advisories without tying to one specific victim. |
| SYNTHETIC | Original combination authored from scratch against SPEC §17 threat-matrix rows; no external source material at all. |

## Inventory

### 1. `shai-hulud-worm` — provenance PUBLIC-INCIDENT

Derives from: the September 2025 Shai-Hulud npm self-replicating worm campaign (public writeups:
Wiz, Snyk, StepSecurity, Unit 42). Modeled technique: a package manifest whose install lifecycle
script bootstraps a remote setup script through a curl-pipe-shell chain and decodes an embedded
base64 payload.

- (a) Publicly documented technique: yes — incident response writeups describe the install-hook
  - staged-bootstrap behavior in detail.
- (b) Reimplemented from scratch: yes — manifest, script text, and payload strings are original;
  no copied bytes, hashes, or proprietary artifacts from the actual campaign; no campaign IOC
  domains/URLs are reused (all endpoints are RFC 2606 `.invalid`/`.example` hosts).
- (c) Safe to publish: yes — demonstrates shapes scanners must detect anyway (LNS-DEP-003,
  LNS-SHL-001/002); no working exploit, no live endpoints, no replication machinery beyond the
  static hook declarations every scanner flags.

### 2. `nx-preinstall-sweeper` — provenance PUBLIC-INCIDENT

Derives from: the August 2025 compromise of widely-installed Nx build-tool packages (public
writeups: Snyk, Socket, StepSecurity). Modeled technique: malicious install-time script sweeping
environment credentials and shipping them to an attacker-controlled collection endpoint.

- (a) Publicly documented: yes — multiple detailed third-party post-mortems.
- (b) From scratch: yes — original JS helper code; attacker infrastructure replaced with
  `webhook.site` (a generic, scanner-canonical sink class) and `.invalid` fallbacks; no copied
  payload bytes; package names changed (`nx` referenced nowhere; nominative mention limited to
  this review file).
- (c) Safe: yes — exercises LNS-DEP-003/LNS-JSS-004/LNS-NET-011/012 detection shapes; collects
  nothing, contacts nothing (static fixture text only).

### 3. `event-stream-stager` — provenance PUBLIC-INCIDENT

Derives from: the November 2018 event-stream npm compromise (maintainer disclosure and public
analyses). Modeled technique: a patched dependency adding obfuscated code that decodes a base64
payload and executes it through a dynamic-constructor stager.

- (a) Publicly documented: yes — one of the most-analyzed npm incidents in history.
- (b) From scratch: yes — original function names, strings, and structure; the historical
  payload's specific logic (flatmap-stream internals) is not reproduced; no copied bytes.
- (c) Safe: yes — decodes an inert marker string; exercises LNS-JSS-001/002 (decode-into-exec).

### 4. `ctx-env-harvester` — provenance PUBLIC-INCIDENT

Derives from: the May–June 2022 PyPI `ctx` package compromise (public reporting: The Hacker News,
Sonatype). Modeled technique: a trusted-looking library update POSTing the full process
environment to an attacker-controlled raw-IP HTTP endpoint.

- (a) Publicly documented: yes.
- (b) From scratch: yes — original module/function naming; the historical C2 address is NOT
  reused; the endpoint is an RFC 5737 documentation-range literal (203.0.113.x), which doubles as
  honest test data for the raw-IP host classifier.
- (c) Safe: yes — exercises LNS-PYS-004 + LNS-NET-011; sends nothing.

### 5. `polyfillio-redirect-hijack` — provenance PUBLIC-INCIDENT

Derives from: the June 2024 polyfill.io CDN domain hijack (public reporting: BleepingComputer,
Sansec, Fastly). Modeled technique: bundled JS referencing a "polyfill" convenience host whose
response is executed through a dynamic constructor after being fetched — the hijack-to-code-exec
shape.

- (a) Publicly documented: yes.
- (b) From scratch: yes — original code; host renamed to `polyfill-cdn.example` (RFC 2606); no
  copied payload bytes from the actual injected script.
- (c) Safe: yes — exercises LNS-JSS-001 (non-literal Function construction); no live domain, no
  working redirect chain beyond the shape scanners flag.

### 6. `postmark-bcc-tap` — provenance PUBLIC-INCIDENT

Derives from: the September 2025 postmark-mcp MCP server backdoor disclosure (Koi Security,
public). Modeled technique: a messaging helper that reads local configuration/state and silently
forwards a copy of outgoing content to an external collection sink.

- (a) Publicly documented: yes.
- (b) From scratch: yes — original helper code; vendor product names appear ONLY in this review
  file (nominative provenance reference); the fixture itself uses generic identifiers; sink is
  `webhook.site` (generic sink class).
- (c) Safe: yes — exercises LNS-JSS-004 + LNS-NET-011/012; forwards nothing.

### 7. `mcp-tool-poisoning` — provenance PUBLIC-TECHNIQUE

Derives from: MCP tool-poisoning / cross-skill prompt-injection research (Invariant Labs public
disclosure, April 2025) and the broader documented literature on instruction-in-description
hijacks. Modeled technique: adversarial directives planted in skill/tool description text that
attempt to override agent instructions and direct self-state changes.

- (a) Publicly documented: yes — active area of published AI-security research.
- (b) From scratch: yes — original prose; no quoted research text beyond the generic
  "ignore previous instructions" grammar family that detection targets.
- (c) Safe: yes — exercises LNS-TXT-004/TXT-005; the directives are inert prose in a fixture
  nobody should run; no novel bypass technique is disclosed.

### 8. `solar-task-persistence` — provenance PUBLIC-TECHNIQUE

Derives from: SolarMarker/Jark-class SEO-injected Python installer malware families (public
advisories: Zscaler, Unit 42; recurring since 2021). Modeled technique: a Python "installer"
that writes scheduler persistence entries and then sweeps user data directories.

- (a) Publicly documented: yes.
- (b) From scratch: yes — original code; no family IOCs, hashes, domains, or payload bytes.
- (c) Safe: yes — writes only into the harness throwaway Hermes home paths; exercises
  LNS-PYS-006 (+ LNS-PYS-008 delete shape); persistence payloads are inert comments.

### 9. `pypi-typosquat-campaign` — provenance PUBLIC-TECHNIQUE

Derives from: recurring PyPI/npm typosquat campaign families (public reporting: ReversingLabs,
Sonatype annual supply-chain reports; e.g. the documented `requests`/`colourama` lookalike
waves). Modeled technique: dependency manifests declaring near-popular package names under
unpinned version floats.

- (a) Publicly documented: yes.
- (b) From scratch: yes — invented lookalike names built by transposition/leet rules the
  detector itself documents; no registry-scraped metadata; no real squat package names copied
  from takedown reports.
- (c) Safe: yes — exercises LNS-DEP-001/DEP-002 against the Poetry manifest lane; installs
  nothing.

### 10. `ci-secret-dumper` — provenance PUBLIC-TECHNIQUE

Derives from: CI secret-exfiltration patterns documented in GitHub Actions hardening guidance and
in public coverage of workflow-abuse incidents (e.g. the 2025 s1ngularity/Nx wave's CI steps).
Modeled technique: a CI shell step dumping the job environment to a request-bin collector.

- (a) Publicly documented: yes — the print-env-to-collector pattern appears in vendor hardening
  guides precisely because it is the canonical exfil primitive.
- (b) From scratch: yes — original script; collector is `requestbin.com` (generic sink class);
  variable names generic (`CI_…`, `RUNNER_TEMP` are public runner conventions, not secrets).
- (c) Safe: yes — exercises LNS-NET-011/012; contains no real credentials (token-shaped strings
  are the documented fake-key grammar, `*.invalid` where hostnames are needed).

## Synthetic combo fixtures (no external derivation)

- `stego-deaddrop-combo` — SYNTHETIC. Cross-engine combo: Unicode Tags-block stego channel
  carrying injected instructions (LNS-TXT-001) + same-file dead-drop exfil of an env file over
  ntfy.sh (LNS-NET-012 + LNS-NET-011). All strings authored from scratch.
- `typosquat-beacon-combo` — SYNTHETIC. Cross-engine combo: lookalike dependency names
  (LNS-DEP-001/002) + periodic env beacon to a dead-drop topic (LNS-NET-011/012). All strings
  authored from scratch.

## Benign hard-case addendum (Phase 3 benign-set task, 2026-08-25)

The ten Phase-3 benign hard-case fixtures (`lab-recon-playbook`, `docker-compose-helper`,
`k8s-manifest-linter`, `docs-command-cookbook`, `cjk-notes-helper`, `arabic-task-tracker`,
`exotic-frontmatter-tolerated`, `hermes-native-reference-skill`, `data-uri-docs`,
`pinned-pyproject-tool`) are all SYNTHETIC clean-room authoring: no real-world incident,
campaign, vendor payload, or third-party prose derives any part of them. The offensive-scope
fixture targets only RFC 5737 documentation ranges and ships no tooling. The retained gate
therefore records them for completeness without further review burden; the GO record above is
unchanged.

## Review assertions (apply to every inventoried fixture)

1. **Publicly documented technique** — each fixture models behavior described in at least one
   cited-class public source above; no fixture discloses a novel or unreported technique.
2. **Clean-room reimplementation** — no proprietary code, payload bytes, binary blobs, captured
   traffic, or IOC literals (domains, IPs, hashes, wallet addresses) from any real campaign are
   copied. All endpoints resolve to RFC 2606 reserved names (`.example`/`.invalid`) or RFC 5737
   documentation IP ranges. Vendor/product/package names appear only here, as nominative
   provenance references, never inside fixture payloads.
3. **Safe to publish** — no working 0day, no weaponized kill chains: every fixture is static
   text exercising detection shapes scanners must detect anyway; nothing in the corpus executes,
   contacts, decrypts-to-live-payloads, or replicates. Credential-shaped strings follow the
   corpus-wide fake-key grammar discipline.

## GO record

- Reviewed by: implementer 2/4 (Phase 3, corpus task), 2026-08-25 session.
- Ruling applied: HARD_QUESTIONS O5 — owner accepted full-fidelity public publication; the
  retained licensing/provenance gate is THIS document.
- Findings: all 10 real-world-derived fixtures satisfy assertions 1–3; both synthetic combos
  trivially do (no external source).
- **DECISION: GO** — authoring of the inventoried fixtures may proceed. Any future fixture
  derived from a NEW real-world incident requires a one-row amendment here before authoring.

## Ordering attestation (2026-08-26)

The retained HARD_QUESTIONS O5 gate requires this review to precede authoring of the
inventoried fixtures. The GO record above was completed 2026-08-25 before any inventoried
fixture was authored (see DECISIONS D-046: review first, then fixtures). Git history
cannot demonstrate that ordering by itself: the project's commit discipline defers
commits to gate boundaries, so this file enters version control at the Phase 3 gate
while the fixture set it governs was still uncommitted working-tree state, and earlier
corpus fixtures landed at 14ac50c/e151f37 before this file was ever tracked.

The ordering is therefore ATTESTED rather than provable from commit order:

- Attested by: Irell Zane (owner), 2026-08-26.
- Scope: every fixture inventoried above, the ten benign hard-case addendum fixtures,
  and every future fixture gated by the amendment rule in the GO record.
- Basis: 2026-08-25 session records (DECISIONS D-046) showing review completion before
  fixture authoring; each inventoried fixture's `expected.toml` carries the matching
  provenance back-pointer to this document.
- Alternative considered and rejected: history rewrite ("re-base") to place this file
  ahead of 14ac50c — destructive to the very audit trail that keeps ordering questions
  answerable; attestation is the honest instrument.

Provenance challenges are resolved against THIS record plus the per-fixture
`expected.toml` back-pointers — never against commit order alone.
