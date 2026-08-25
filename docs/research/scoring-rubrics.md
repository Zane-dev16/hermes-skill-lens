# Research: Scoring & Policy Design for Security Tools

Phase: Competitive and threat research — task label **scoring rubrics**
Sources: FIRST/CVSS docs, npm/cargo/Semgrep/Snyk/Scorecard/SSL Labs documentation, SARIF v2.1.0 spec, GitHub code-scanning docs, Android/browser-extension/VS Code permission literature.

---

## 1. How existing tools actually score

### CVSS v3.1 / v4.0 — severity per finding, not portfolio

- v3.1: base score 0–10 from AV/AC/PR/UI + C/I/A with Scope modifier. Qualitative bands: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10. Formula is fully deterministic and public.
- v4.0 (Nov 2023): removes Scope; adds Exploit Maturity, subsequent-system requirements, and Supplemental metrics (Safety, Automatable, Recovery, Value Density, Provider Urgency).
- **Key guidance**: FIRST explicitly frames CVSS as *communicating severity characteristics*, not risk; aggregating/averaging CVSS across findings is widely discouraged (NIST IR 7946 catalogs limitations; CISA promotes SSVC for decisions). Top-end compression is real: Snyk reports ~23% of findings they see have CVSS > 8.0, which makes CVSS useless for prioritization without extra context.

### npm audit — curated severity + threshold gating

- Severity (critical/high/moderate/low/none) is **not computed locally**; it comes from GitHub Security Advisories / npm security curation attached to each advisory ID.
- Findings grouped per advisory with all dependency-tree paths listed underneath (root-cause grouping built in).
- Policy layer is separate: non-zero exit if any vuln by default; `--audit-level=<sev>` raises the gate. This exists precisely because "any finding fails CI" proved too noisy.

### cargo-audit / RustSec — taxonomy separation

- Advisory categories: **vulnerability**, **unmaintained**, **unsound**, **notice**. Security bugs are kept distinct from hygiene/quality signals — a deliberate taxonomy choice worth copying.
- Severity taken from CVSS when the advisory carries one. Config: `ignore` list (with reasons), `severity_threshold`, informational-warning toggles; yanked-crate detection; configurable deny/exit behavior.

### Semgrep — two-axis severity × confidence

- Rule severity now Critical/High/Medium/Low (legacy ERROR/WARNING/INFO ≙ High/Medium/Low), author-assigned; Registry security rules assigned via documented likelihood × impact rubric.
- Separate `confidence` metadata describes *the rule's false-positive propensity* (taint-mode rules get HIGH), not the vulnerability.
- Semgrep Supply Chain layers on: **reachability** analysis (is the vulnerable code path called?) and EPSS exploitation-probability bands (High ≥50%, Medium 10–<50%, Low <10%).

### Snyk Priority Score — the main hybrid precedent

- 0–**1000** scale (deliberately not 0–100: users prioritize *across* projects and needed granularity; also forces score distribution away from CVSS-style top-compression — target <5% of issues above 800).
- Factors: CVSS as weighted foundation (~highest single factor), severity policy overrides, exploit maturity, reachable-via-code-path, social trends/publication time, fix availability, transitive-dependency condition, package popularity.
- Explicitly tuned for *distribution*: they validate that scores spread rather than pile up.

### OpenSSF Scorecard — documented weighted aggregate + badge

- Each check scores 0–10 with a published risk weight (Critical/High/Medium/Low per check); **aggregate = weighted mean** Σ(scoreᵢ·wᵢ)/Σwᵢ, formula and per-check criteria fully published in docs/checks.md.
- Checks return pass/fail/partial **with reasons**; deterministic given a repo snapshot; badges derived from aggregate score. Closest open-source example of "explainable 0–N + grade" done credibly.

### SSL Labs — the deepest precedent for 0–100 + letter grade

- Category scores (protocol/key-exchange/cipher) weighted 30/30/40; **any category at zero pushes overall to zero**; numeric→grade table (≥80 A, ≥65 B, ≥50 C, ≥35 D, ≥20 E, <20 F).
- Then a **rule layer on top of arithmetic**: caps (BEAST/CRIME → B, POODLE → C, RC4/weak-DH → B), hard fails (Heartbleed, DROWN, export suites → F), rewards (A+ for exceptional config), and **out-of-scope grades** (T = untrusted cert, M = name mismatch) that override the whole computation because the number would be meaningless.
- History lessons: they removed the numeric score in 2013 because the letter grade was more useful (later restored); grade-rule changes ship with an **early-warning period** (warn, then enforce).

### Local-first CLIs (Trivy, Grype, osv-scanner)

- None produce an aggregate score. Pattern: severity taxonomy inherited from feeds → user policy = threshold flags (`--fail-on`, `--severity CRITICAL,HIGH`) + ignore files with reasons + VEX documents. Finding layer strictly separated from policy layer; exit codes are the contract.

**Landscape conclusion**: nobody credible computes a portfolio score by averaging CVSS. Tools either (a) refuse to aggregate (local CLIs), (b) aggregate with a documented weighted model + caps (Scorecard, SSL Labs), or (c) build a hybrid contextual score with tuned distribution (Snyk). All credible systems keep findings, confidence, and policy as separate concerns.

---

## 2. Claimed-vs-actual permission diff patterns

### Android

- Claims live in AndroidManifest.xml; post-API-23 split into install-time vs runtime-dangerous permissions.
- **PScout (CCS 2012)** produced permission→API-call maps across OS versions, enabling static diffing. **Felt et al., "Android Permissions Demystified" (CCS 2011)** showed a large share of apps were *overprivileged* (declaring permissions never used) using least-privilege analysis.
- Direction asymmetry matters: **claimed-unused** (overprivilege) is common, erodes trust, medium severity. **used-unclaimed** is rare and high-signal — indicates manifest/code drift, dynamic loading, or deception, and often means breakage or hidden capability.
- False-negative source: reflection, native code, dynamic feature delivery can hide real usage → naive "unused" verdicts are wrong. Mitigations: conservative string analysis, runtime instrumentation, requiring multiple evidence kinds before asserting "unused".

### Browser extensions

- manifest.json `permissions` + `host_permissions` vs actual `chrome.*` namespace API calls in the shipped JS bundle. Chrome Web Store review flags declared-but-unused permissions at submission; third-party analyzers do the same AST-level diff.
- Same asymmetry: requesting broad host permissions without using them is the classic trust-reduction finding. Remote-hosted code calling APIs dynamically is the blind spot.

### VS Code extensions

- package.json `contributes` sections (commands, activationEvents, languages…) vs actual `registerCommand` calls and code references. VS Code itself introduced **implicit activation events** (Nov 2022) plus lint warnings for *redundant explicit activationEvents* because declared-but-unused contributions were endemic — i.e., the platform vendor validated the claimed-vs-actual diff as a first-class check.

### Generalized pipeline (transfers directly to auditing any declarative-capability surface)

1. Parse claims from the declarative manifest (cheap, authoritative).
2. Extract evidence of actual use: direct AST match → call graph/taint path → runtime trace (increasing strength).
3. Diff both directions with different severities: overclaim = trust/hygiene (medium, prevalent); underclaim = integrity/deception (high, rare).
4. Evidence kind determines default **confidence**, deterministically: runtime trace > taint-reachable > direct AST > fuzzy/string heuristic.
5. Gate the "unused" assertion behind an evidence threshold; support suppressions with mandatory reasons.

---

## 3. SARIF output standards (what to emit)

SARIF v2.1.0 (OASIS) is the interchange standard; GitHub code scanning consumes it. Fields that matter for scoring/dedup design:

| Field | Use |
| --- | --- |
| `result.level` | enum none/note/warning/error — coarse, maps to UI |
| `result.rank` | 0–100 float for relative priority *within a run* |
| `rule.defaultConfiguration.level` | rule-level default severity |
| `result.partialFingerprints` / `fingerprints` | **dedup identity** — GitHub matches results across uploads via fingerprints to prevent duplicate alerts |
| `result.baselineState` | new/unchanged/absent — triage workflow support |
| `result.suppressions` | status accepted/underReview/rejected — encodes waivers |
| `properties` bag (both rule and result) | free-form custom data — GitHub convention `properties.security-severity` (0–10 string) drives security-alert sorting (≥9 critical, ≥7 high, ≥4 medium, else low) |
| `runs.invocations`, `versionControlProvenance`, `redactionTokens` | reproducibility context, secret scrubbing |

Design implications: compute and emit your own stable `partialFingerprints` (don't rely on consumer-side matching); put the full score breakdown in the properties bag so downstream consumers get explainability for free; keep rank and level consistent with your own taxonomy.

---

## 4. Assessment

### (a) Weighted subtraction vs CVSS-style

- **CVSS-style vector formulas are right per-finding, wrong for portfolios.** FIRST positions CVSS as communication, not decision-making; averaging is discouraged and empirically compresses the top of the scale.
- **Pure weighted subtraction (start 100, subtract per finding)** matches the mental model of Scorecard/Lighthouse, is monotone and banded naturally. Risks: clamping at 0 loses information; arbitrary-looking weights; order-dependence and double-counting if implemented naively; one noisy class can dominate.
- **Recommendation: hybrid, three layers**
  - **L1 finding severity**: fixed rubric matrix over evidence axes (exploitability, exposure, impact, evidence strength) — CVSS-*inspired* but simpler; pass through upstream CVSS/advisory severity verbatim when it exists.
  - **L2 portfolio score**: integer weighted-subtraction with per-category ceilings and diminishing multiplicity (first instance costs most; Nth duplicate of a root cause costs ~nothing). Ceilings prevent any single class from owning the score.
  - **L3 caps/overrides (SSL Labs pattern)**: verified-critical classes cap the grade regardless of arithmetic (e.g., used-unclaimed dangerous permission ⇒ cap C/F); degenerate states get special grades (e.g., "I" incomplete scan, "E" error) instead of a fake low number.
- If you want Snyk-style spread, validate empirically: run against a corpus and check the histogram doesn't pile at extremes; tune weights toward a defensible distribution, and say so publicly.

### (b) Grade band validity

Letter bands are legitimate — SSL Labs, Scorecard badges, Lighthouse all prove adoption — but validity requires:

- Cutoffs tied to **action** ("B means: fix X before shipping"), not round numbers.
- **Always render the exact number beside the grade**; cliff effects (98→A− vs 99→A) are real and resented.
- Caps protect bands from arithmetic nonsense (an A− with Heartbleed destroyed SSL Labs' credibility until caps existed).
- Special/out-of-band grades instead of forced F when the scan itself is untrustworthy.
- Versioned band changes with a warn-then-enforce period (SSL Labs' early-warning system).
- Stability testing: small input perturbations shouldn't flip bands; add a CI check.

### (c) Deduplication strategies

Layered identity, in order:

1. **Content identity**: advisory ID / rule ID + subject (package@version, permission name).
2. **Location identity**: normalized path + symbol/line-region hash — this becomes SARIF `partialFingerprints`; normalize separators, casing, and omit volatile line numbers from the hash so edits don't fork identities.
3. **Root-cause grouping**: one underlying issue, N sites (npm groups advisory → finding paths; cargo groups per crate). Group first, then apply severity-max-wins inside the group for scoring.

- Scoring must consume **groups, not raw findings**, with diminishing multiplicity; otherwise transitive-dependency noise dominates. Deterministic requirement: canonical sort order before any summation, so result order never affects the score.

### (d) Confidence weighting

- Keep severity and confidence **orthogonal axes** (Semgrep's model) — folding confidence silently into a number destroys trust when a "critical" turns out false.
- Derive default confidence deterministically from evidence kind (runtime trace > taint-reachable > direct AST match > heuristic), with author overrides.
- Fold into the score only as a bounded multiplier with a floor (e.g., confirmed 1.0 / probable 0.75 / possible 0.5, floor ~0.25), or better: **gate the headline score on confidence tier** (only ≥probable moves the score) and list lower-confidence items separately as "possible issues".
- Blocking/CI policy should key on (severity, confidence) pairs, never raw score alone.

### (e) Explainability and determinism

- **Score = pure function**(scan snapshot, formula_version). No wall-clock, no network at scoring time; fetch/cache data earlier and stamp timestamps into input.
- Integer or fixed-point arithmetic only; define rounding once, applied at the final step; canonical ordering everywhere; stable serialization for byte-identical output across platforms/runs.
- **Emit the breakdown**: per-finding `{id, severity, confidence, weight, penalty}`, every cap event, every ceiling applied — in the SARIF properties bag and JSON output. The CLI should answer "why is this a B?" in one screen (Scorecard's per-check reasons are the model).
- Publish the formula doc + changelog; `score_version` in every output; weight changes are major versions with a deprecation window.
- Golden-file tests: fixed fixture repos must produce byte-identical scores and reports.

---

## 5. Recommended shape for xray score v1

1. **Per-finding**: severity from rubric matrix (or passthrough advisory severity) × confidence from evidence kind — displayed as two axes, e.g. `HIGH/probable`.
2. **Portfolio**: 0–100 integer = 100 − Σ(group penalties), per-category ceiling, diminishing multiplicity; caps for verified-critical classes; special grades for incomplete scans.
3. **Grade**: letter band rendered *with* the number; band table and caps documented in a versioned formula page.
4. **Output**: SARIF (with partialFingerprints, security-severity property, suppressions, breakdown in properties bag) + plain JSON + human text; all byte-stable.
5. **Policy**: separate from scoring — thresholds, ignore lists with reasons, VEX-style attestations; exit codes keyed on (severity, confidence).
6. **Validation**: corpus-run histograms (distribution check), stability fuzzing (near-duplicate inputs → same grade), golden-file regression suite.

### Source index

- FIRST CVSS user guides & FAQ — first.org/cvss; NIST IR 7946 (CVSS limitations)
- npm audit docs — docs.npmjs.com/cli/commands/npm-audit
- cargo-audit config & RustSec advisory-db — docs.rs/cargo_audit, github.com/rustsec/advisory-db
- Semgrep severities/confidence — docs.semgrep.dev/kb/rules/understand-severities; supply-chain findings + EPSS
- Snyk Priority Score — snyk.io/blog/snyk-priority-score/, docs.snyk.io priority-score
- OpenSSF Scorecard — scorecard.dev, github.com/ossf/scorecard docs/checks.md; badge announcement blog (2022)
- SSL Labs Rating Guide 2009r — github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
- SARIF v2.1.0 — docs.oasis-open.org/sarif/sarif/v2.1.0; GitHub code-scanning SARIF support + fingerprint changelog
- Android: PScout (CCS 2012), Felt et al. "Android Permissions Demystified" (CCS 2011)
- Browser extensions: manifest permissions vs chrome.* API usage analyses; Web Store unused-permission review
- VS Code: implicit activation events + redundant activationEvents lint (microsoft/vscode #170984, Nov 2022 release notes)
