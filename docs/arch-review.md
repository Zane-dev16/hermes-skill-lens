# Skill X-Ray v0.3 — Architecture Critique & Decisions

**Phase:** Spec critique and architectural decisions · **Label:** arch critique
**Reviewer stance:** staff engineer + security reviewer. Opinionated; every section ends in a decision.
**Inputs:** v0.3 product spec (2026-08-22 draft), `docs/threat-taxonomy.md`, `docs/research/scoring-rubrics.md`, NVIDIA SkillSpector source (`docs/ANALYSIS_RESOURCE_BOUNDS.md`, `docs/SUPPRESSION.md`, `src/skillspector/nodes/report.py`), Cisco AI Defense skill-scanner `FEATURE.md` (analyzer composition model).

---

## 0. Verdict

The spec's spine is right: **advisor-not-gate, deterministic rubric, claimed-vs-actual as set difference, LLM demoted to captioner.** These are the four decisions that make X-Ray trustworthy and they should not drift. The weaknesses are all in the seams the spec didn't draw:

| # | Risk | Severity | One-line fix |
| --- | ------ | ---------- | -------------- |
| R1 | **Config/policy injection from the scanned artifact** — nothing prevents a skill shipping its own `.xray.toml` that softens its scan | Critical | Never auto-load any config from the scanned path; policy only from `$XDG_CONFIG_HOME/xray` + explicit `--policy` |
| R2 | **Choir quietly breaks the determinism story** ("the score is deterministic" + "external binaries contribute findings" cannot both be true unconditionally) | High | v1 score excludes choir; when enabled later, choir is recorded input, contract restated precisely |
| R3 | **Finding identity is underspecified** — `--diff` and dedup-by-"normalized id" will produce noise; every edit forks every finding | High | Canonical fingerprint = rule-family + capability + normalized target + path-region hash *without line numbers* |
| R4 | **No resource ceilings** — a pathological package (10k files, zip bomb, 500MB blob) hangs the hook fast path and makes "never holds the install" unenforceable | High | Adopt SkillSpector-style ceilings; partial scans get grade **I**, not a fake number |
| R5 | **Capability set (9 buckets) ≠ engines (8)** — `identity` and `spawn_skills` have no owning engine; lockfiles are ingested but nothing scores them | Medium | Engines become layered parser+rule-family architecture with an explicit ownership matrix |

Everything below elaborates these and answers §10.

---

## 1. Ingestion completeness — what the IR misses

The IR (file tree, decoded views, hashes, extracted strings) is a good skeleton but omits things several downstream stages silently need.

### 1.1 Missing from the IR

1. **Provenance block.** Where the package came from (local dir / git URL + resolved SHA / registry URL), fetch timestamp, `xray_version`, `rule_pack_version`, `formula_version`. Diff and reproducibility (see §5) are impossible without it. *Add it.*
2. **File metadata.** Executable bit, mode, symlink targets. A symlinked `scripts/run.sh → ~/.ssh/` is a different animal than a regular file; executable-bit-on-markdown is itself a mild signal. Cheap to capture now, painful to retrofit.
3. **Decode provenance / coordinate mapping.** Every decoded view must record `{decoder, source_file, original_byte_span}`. Hard contract: **evidence always cites original-file coordinates**, with the view chain shown as a badge. Users must be able to `sed -n '40p' SKILL.md` and see what we flagged, even when the hit was inside a base64 layer. Without this, findings are unverifiable and trust dies.
4. **Decode budget knobs.** Taxonomy normalizer specifies recursion depth ≤ 3 and base64 runs ≥ 40 chars; the spec says neither. Pin: depth ≤ 3, min encoded-run 40 chars, total decoded bytes ≤ 2× source bytes, global decode time slice. Exceeding a budget records a `partial-decode` marker — it is *evidence of evasion*, not silence (per taxonomy: the evasion attempt itself is the signal; emit XR-UNI finding on budget exhaustion).
5. **Frontmatter safety.** YAML alias-bomb / billion-laughs expansion caps; duplicate-key policy (last-wins, but *flag* duplicates — authors hide keys behind parsers' disagreement); invalid-YAML fallback to heading/description parse must be recorded as a finding-grade notice, not swallowed.
6. **Cross-reference audit.** The spec ingests "referenced local files." Two gaps: **dangling references** (SKILL.md points at `scripts/foo.sh` that doesn't exist — broken or bait) and **unreferenced payloads** (executable files present but never mentioned — classic smuggling). Both are cheap set operations over the file tree + reference graph and belong in ingest output, not in an engine.
7. **Nested archives & binaries.** Skills ship `.zip`/`.tgz` inside `assets/`. Policy: expand nested archives one level (budget-capped, counted toward file ceiling); binaries are hashed, hexl-viewed first 64KiB, and marked `binary/unanalyzed` — never silent. A `.pyc` next to a missing `.py` is a known Cisco-scanner concern (bytecode/source mismatch) worth a v1.1 rule.
8. **Canonical path form.** Define relative-path canonicalization (POSIX separators, NFC, case handling note for case-insensitive filesystems) once, in ingest, so hashing and evidence agree.

### 1.2 Decision

> **D-ING:** IR gains `provenance`, per-file `{mode, symlink_target, exec_bit}`, decode `{decoder, span, budget_events}`, cross-reference audit results, and canonical path rules. Ingest emits `partial: bool + reasons[]` whenever any ceiling trips.

---

## 2. Engine boundaries — is 8 the right number?

### 2.1 The real problem: three axes are tangled

The spec's "engine" conflates **(a) where it looks** (markdown text vs code vs manifest), **(b) what it flags** (capability class), and **(c) code module boundaries**. That's why "money" feels odd as an engine (it's a pattern library over the same text/code views the other engines read) and why `curl` in bash is contested territory between Scripts and Network.

Refactor to layers; keep the public-facing families:

```
L0 normalize/decode          ← moves INTO ingest (taxonomy treats it as cross-cutting infra)
L1 views/parsers             ← markdown-text, shell AST, python AST, js AST, frontmatter/manifest,
                               generic-binary hexl   (shared infrastructure, not engines)
L2 rule evaluation           ← rule FAMILIES over views, each rule tagged with ONE capability bucket;
                               families ≈ today's engines: injection, unicode-evasion, override,
                               scripts/exec, network, secrets, money, identity*, spawn_skills*
L3 correlation               ← NEW: multi-leg chain detection (secret-read→encode→egress etc.)
L4 policy/score/report       ← unchanged
```

\* = families the spec forgot. The capability set has nine buckets; engines cover seven-ish. Per the taxonomy: **identity spoofing** (fake role markers, vendor-authority imperatives, ANSI rewrite sequences) and **spawn_skills** (writes to skills dirs, "install more skills", permission-escalation requests) are distinct classes with their own indicators and false-positive profiles. Today `spawn_skills` half-lives inside Override and `identity` half-lives inside Injection/Unicode. Give each a named rule family and an owner in `docs`. This is documentation + rule organization, not new parsing work — most rules already exist in the taxonomy's indicator tables.

**Answer to "is 8 right?":** Eight is wrong as stated (two capabilities homeless, lockfiles orphaned) but eight-to-ten *families* is the right magnitude. Ship **10 families**: the spec's 8 + `identity` + `spawn_skills`, with supply-chain-lite (vendored-manifest lifecycle scripts, unpinned deps in bundled manifests) assigned to Manifest. Do **not** grow past ~10: every family beyond the capability ontology creates overlap pressure and double-count pressure in scoring.

### 2.2 The missing stage: correlation (L3)

Taxonomy §3.1 is emphatic: *multi-leg chains dominate* — secret-read→encode→network = 0.95 confidence while any single leg ≤ 0.7. The v0.3 pipeline has no home for chain logic; each engine would have to hack it in. Add a small correlator between findings and policy: input = finding list, output = composite findings with boosted confidence and merged evidence. v1 chains (from taxonomy): exfil trio, clipboard-watch + address literal, evasion-context escalation (any unicode/TAG/ANSI hit raises sibling confidences +0.15, floor 0.5 for review). This is ~200 lines and it is where X-Ray's detection quality actually comes from — single-leg regexes alone put us below Cisco's static tier.

### 2.3 Overlap policy

Overlaps don't disappear; you *adjudicate* them:

- One finding per (rule, evidence span). A `curl https://o.example` hit legitimately yields a Scripts finding (exec primitive) **and** contributes the host to Network's undeclared-host set — the host-set contribution is not a second finding, it's aggregate data.
- Correlator merges, never multiplies: legs referencing the same evidence spans collapse to one composite finding.

### 2.4 Decision

> **D-ENG:** Layered architecture above; 10 rule families mapped 1:1 onto the 9 capability buckets (+ supply-chain-lite in Manifest); new L3 correlator; overlap adjudicated by "one finding per rule×span; host sets are aggregates, not findings."

---

## 3. False positive handling

The spec's position — "FPs are fixed by changing rules, not by prompting a model" — is correct but incomplete: it makes every user annoyance an upstream bug report. Security tools that survived contact with users (cargo-audit `ignore`, Semgrep baseline, SkillSpector baselines, SARIF `suppressions`) all ship local suppression.

### 3.1 Decisions

1. **User ignore file.** `~/.config/xray/ignore.toml`: entries keyed by finding fingerprint (see §6), each with mandatory `reason` and optional `expiry` (expired entries resurface). Suppressed findings: excluded from score and counts, still rendered (struck-through / `suppressed` section), still emitted in SARIF with `suppressions.status = accepted`. Auditability is the point — suppression is a *record*, not amnesia.
2. **Confidence discipline.** Rule-authored confidence is banned above 0.8 unless the rule matches a very-high-signal signature class (taxonomy's calibration tables give the priors: concealed-channel hits 0.95+, bare imperatives <0.4). Confidence < 0.6 already halves penalties and stays out of the actual-capability set — keep exactly that.
3. **Calibration corpus as CI.** Golden malicious fixtures built from the incidents catalogued in the taxonomy (Shai-Hulud patterns, nx s1ngularity, postmark-style rug-pull, TrapDoor-style zero-width, jqwik-style ANSI protestware) + a benign corpus (top marketplace skills, dev-tooling skills, security-training skills — the known FP magnets). PR curves per family in CI; a rule change that moves precision >2pp must cite corpus numbers. Adopt the taxonomy's FP-attribution rule: >10% of a family's FPs sharing one cause ⇒ split or scope the rule, never lower the threshold globally.
4. **Purpose-vs-behavior exemption** (declared pentest skill may declare shell+network) lives in policy, not engines — engines stay dumb and honest; street/lab decides how loud to shout. This keeps one truth layer.

### 3.2 Decision

> **D-FP:** Fingerprinted user ignore file with reason+expiry; suppressed-but-visible semantics; confidence priors imported from taxonomy calibration tables; corpus-driven PR-curve CI with FP-attribution-driven rule splitting.

---

## 4. Performance — scan-time budget for hook mode

The spec promises hooks "print a warning and return control" and "if the scan is slow, print scanning… and never hold the install," but gives no numbers and no mechanism. Both are needed.

### 4.1 Budgets

| Mode | p50 target | Hard ceiling | Behavior at ceiling |
| --- | --- | --- | --- |
| Hook (async spawn) | n/a — returns instantly | none on installer | Hook exits ≤ 50 ms always (see §8) |
| Hook scan (detached) | < 1.5 s typical skill | 10 s | Report degrades to "partial — rerun `xray scan`" pointer |
| CLI interactive | < 1 s typical | 60 s | Grade **I** (incomplete) + partial reasons |
| `xray scan --installed` (many skills) | amortized | 60 s/skill | Same |

SkillSpector ships nearly identical ceilings (10k entries, depth 64, 16 MiB/file, 64 MiB bundle, 60 s workflow) — adopt the shape wholesale: **ceilings are safety boundaries, not allowlists; tripping one marks the scan partial and reports what was examined.**

### 4.2 Mechanism

- Ingest enforces byte/file/depth ceilings; per-engine watchdog timeout (default 5 s) skips a hung engine and emits `XR-ENG-TIMEOUT` notice — an engine crash or hang is a *finding about the scan*, never a failed install.
- Engines run in-process, parallel across files; tree-sitter parses are error-tolerant so adversarial syntax costs bounded time (grammar-level catastrophic backtracking isn't a thing; hand-rolled regexes need RE2-style linear matching — use linear-time regex everywhere, this is a hard implementation rule).
- The hook never runs the scan inline, ever: it validates args, spawns the detached scan, exits 0. Then "scanning…" placeholder vs instant-print debates vanish — the installer is structurally incapable of being held.

### 4.3 Decision

> **D-PERF:** Ceilings table adopted (10k files / depth 64 / 16 MiB per file / 64 MiB retained / 60 s CLI / 10 s detached-hook scan); partial ⇒ grade **I**; per-engine watchdog; linear-time regexes only; hook = spawn-and-exit, never inline.

---

## 5. Determinism guarantees

"Deterministic" appears five times in the spec without a definition. Define it or lose it:

> **Same (IR bytes + rule-pack version + formula version + engine inventory) ⇒ byte-identical report.**

Consequences, all mechanical:

1. **Score = pure function.** Integer arithmetic only (penalties are integers already — keep them so; ban floats from the entire scoring path), rounding defined once (there is none — keep it that way), canonical ordering by fingerprint bytes before any aggregation, locale-independent sort (never collation-order).
2. **No wall clock, no network at scoring time.** `--follow-remote` fetch happens in ingest and is stamped into IR (URL, sha256, byte count) — the *input* carries the nondeterminism, the function stays pure.
3. **Pinned Unicode version** for NFC/NFKC and confusable tables (normalization output changes across Unicode versions → different hashes → spurious diffs). Record `unicode_version` in provenance.
4. **Byte-stable serializers.** Fixed JSON key order; SARIF/JSON/text golden-file tests assert byte equality on fixture corpora; stability fuzzing (near-duplicate inputs ⇒ same grade) as CI job — straight from scoring-research §4(e)/§5(6).
5. **Choir (R2).** External CLIs version-drift and their outputs change under you. Options: (a) exclude from headline score, show as corroboration rows; (b) include, accept that score depends on installed binaries; (c) pin adapter-schema versions and call that deterministic-enough. **Choose (a) for v1 with (c) as the v1.1 evolution**: `xray scan` default = local engines only, fully self-contained determinism story (matches spec §3.3 "X-Ray's own engines must be good enough alone"); `--choir` adds findings to the *report* and a clearly-labeled secondary `score_with_choir`. When (and only when) adapter mappings stabilize, promote to single-score with recorded engine inventory. Phase-2 timing makes this free — choir doesn't exist in v1 anyway; this decision just stops Phase 2 from silently breaking Phase 0's promise.

### 5.1 Decision

> **D-DET:** Determinism contract as stated; integers only; canonical byte-order sorting; pinned Unicode version; golden-byte CI; choir excluded from headline score in v1 (report-only corroboration), promotion criteria written down now.

---

## 6. Hash & diff design

The spec says per-file SHA-256 + "package hash … this is also how update diffs work." Two underspecified halves.

### 6.1 Package hash

Naïve concatenation hashes break on file order and platform line endings. Use a **Merkle scheme**: sort by canonical relative path (byte order), leaf = SHA-256(`path \0 mode \0 file-sha256`), root over the sorted leaves. Deterministic, incremental, tamper-evident, stable across tarball re-serialization. Store the full leaf list in the IR — `--diff` needs per-file deltas anyway.

### 6.2 Finding identity (R3)

`--diff` quality = fingerprint quality. Line-number-based identities fork on every edit (research §3: omit volatile line numbers). Canonical fingerprint:

```
fp = sha256( rule_family | rule_id | capability | normalized_target | canonical_path_region )
```

where `normalized_target` is the semantic object (host, secret-path glob, capability verb, decoded-payload hash) and `canonical_path_region` is path + coarse region (function name / hunk bucket), **no line numbers**. These double as SARIF `partialFingerprints` (research §3: compute your own; never rely on consumer matching).

### 6.3 State & semantics

- Scan state: `~/.local/state/xray/<name-hash>/history.jsonl` — append-only `{ts, package_root_hash, score, severity, fingerprints[]}`. Keyed by skill *name* (frontmatter name, validated) + install path; collisions append.
- `--diff` renders: score Δ + grade Δ, capability-set Δ (claimed/actual/overreach each), hosts Δ, findings as **new / resolved / persistent** by fingerprint. Persistent-with-content-change (same fp, different evidence span) gets its own marker — rug-pull updates (postmark pattern) look exactly like this: quiet history, then one new fp.
- Renamed-skill reappearance (taxonomy gap: downstream mirrors resurrect blocked skills): exact root-hash match against history ⇒ "this content was previously scanned as NAME." Fuzzy/name-distance matching deferred to v1.1 — note it in docs so nobody assumes v1 catches rebrands.

### 6.4 Decision

> **D-HASH:** Merkle package hash over sorted canonical leaves; fingerprint formula above doubles as SARIF partialFingerprints; append-only state history; diff = set algebra over fingerprints; exact-content resurrection detection in v1, fuzzy deferred.

---

## 7. Privacy — "no exfil" needs enforcement, not vibes

The spec's privacy section is a list of intentions. Make them verifiable:

1. **Zero-network test in CI.** Run the full scan suite under a deny-all network namespace (Linux netns / sandbox-exec); any socket attempt fails the build. This is the only credible way to claim "no skill source leaves the machine" — including the *scanner's own* telemetry, which therefore must be off by default and, if it ever exists, route through the same test.
2. **`--explain` redaction pass (self-referential safeguard).** The explain payload contains snippets; snippets can contain secret-shaped strings (that's often *why* they're flagged). Before sending anything: run the Secrets family's token-shape rules over the outgoing payload itself and replace matches with `[REDACTED:XR-SEC-class]`. Document that `--explain` sends: finding ids, severities, capabilities, redacted snippets, claimed/actual sets. Nothing else. Model unreachable ⇒ report complete (already specced — keep).
3. **`--follow-remote` caps:** max 10 fetches, 2 MiB each, 5 s each; fetched bytes stored locally (hashed into IR), never forwarded anywhere; document that fetching attacker-controlled URLs reveals your IP + fetch time to that host — that's inherent, just say it in `--help`.
4. **Local state hygiene.** State/evidence dirs 0700; evidence snippets persist until `xray cache prune` (add to doctor output); docs state retention plainly: "X-Ray stores findings and snippets locally indefinitely until pruned."

### 7.1 Decision

> **D-PRIV:** Deny-all-network CI test as the enforcement mechanism; redaction pass on the `--explain` payload using X-Ray's own secrets rules; fetch caps; documented retention + prune.

---

## 8. Hook safety — making "cannot cancel the installer" structural

Current design relies on discipline ("hooks print a warning and return control"). Convert to structure:

1. **Observer-only contract, enforced by property tests.** The hook binary/script must, for *any* stdin (closed, `/dev/urandom`, giant), any cwd, any signals (SIGINT/SIGTERM ignored during startup), exit **0 within 50 ms** having written nothing to the installer's stderr. CI fuzzes exactly this. If the contract breaks, hooks ship disabled.
2. **Spawn-and-exit, never inline** (§4.2). The hook's only jobs: locate the changed paths, enqueue the scan (detached process group, `setsid`), exit 0. Even a corrupted scan request cannot slow the installer.
3. **Print-after-completion, never mid-install.** Printing during the installer's progress UI corrupts redraws and — worse — trains users to associate X-Ray output with installer glitches. Print the compact banner after the installer's process tree exits, or append to `$XRAY_REPORT_FILE` when stdout isn't a safe TTY.
4. **ANSI-hygiene of our own output (lesson from our own taxonomy).** jqwik and Trail-of-Bits showed terminal rendering is an attack surface: a malicious installer can cursor-rewrite lines so X-Ray's warning is overwritten before it's read. Mitigations: emit a visually distinctive framed banner, disable cursor-positioning sequences in our own output, and when severity ≥ warn also write the full report to a file and print its path — a pointer that survives redrawing. Never rely on scrollback persistence for the alert.
5. **Lifecycle.** Hooks installed only by `xray doctor` (interactive confirm), checksummed, listed by `doctor`, removable with `xray doctor --uninstall-hooks`. No PATH shims, no wrapper aliases — spec already forbids installer wrapping; keep it a non-goal permanently.

### 8.1 Decision

> **D-HOOK:** Property-tested observer contract (exit 0 ≤ 50 ms under arbitrary conditions); spawn-and-exit; print-after-completion with file-backed pointer for warns+; ANSI-disciplined output; doctor-managed checksummed lifecycle.

---

## 9. Scoring composition (flagged for the stress-test phase)

Not my phase to tune numbers, but three structural defects must be fixed *before* tuning:

1. **Double-count ambiguity.** Is an undeclared wallet-drain finding scored as −25 (critical) *and* −30 (money undeclared)? Spec is silent. Decide: penalties compose along **disjoint dimensions** — (a) per-finding severity × confidence, (b) capability-diff (overreach/undeclared-class), (c) host diff — and a finding may feed at most... no: a finding feeds (a); its capability feeds (b) only if the capability is *newly* established by ≥0.6-confidence findings. Write the rule down; test it.
2. **Ceilings and floors.** Research is unambiguous: weighted subtraction without per-category ceilings lets one noisy class own the score (SSL Labs zero-category rule; Scorecard weights; SkillSpector diminishing multiplicity 1.0/0.5/0.25 and its SC8 floor). Adopt: diminishing multiplicity per rule-id (first occurrence full, second ½, third ¼, rest 0), per-family contribution ceiling, and a **hard floor override** for verified-critical classes (declared-permission-self-grant ⇒ score ≤ 25 regardless of arithmetic — the taxonomy calls permission-allowlist self-authorization "treat as breach").
3. **Grade integrity.** Always render number beside letter (cliff resentment is real); add grade **I** (partial scan — ceilings tripped) instead of a fake low number; band changes ship warn-then-enforce with `score_version` stamped in every report.

---

## 10. §10 Open questions — recommended answers

### Q1. Script-parser completeness in v1: bash + Python only, or JS too?

**Ship bash + Python + JS in v1, all via tree-sitter, intra-procedural taint-lite only.**

Reasoning: the observed incident record is npm-native (Shai-Hulud worm, postmark-mcp, nx s1ngularity all executed through Node ecosystems); skipping JS means skipping the highest-frequency real-world payload language, and MCP servers — a first-class X-Ray subject per the taxonomy — are TypeScript programs. Cost objection is weaker than it looks: tree-sitter grammars for all three are mature and embed uniformly, and tree-sitter's error-tolerance is *load-bearing* here — adversarial and generated files frequently fail strict parses, and a strict-parser design silently goes blind on exactly the inputs you care about. Scope discipline: v1 does call/arg extraction + same-function source→sink pairs (env/secret-read flowing to network/exec sinks); leave cross-function dataflow to v1.1 — the correlator (§2.2) recovers much of the value cheaply. Bash: POSIX-sh subset via tree-sitter-bash, accept imperfect coverage and say so. PowerShell/other: regex-tier rules (Invoke-WebRequest, Invoke-Expression) labeled honestly as lexical-only. Unparseable files get a `parse-failed` marker finding — never silence.

### Q2. Post-install hook vs background watch — which is less surprising?

**Both ship in v1; watch is the default posture, hook is opt-in, async, print-after-completion.**

They're not actually rivals — they answer different moments. Watch covers "already on disk" (the majority reality: packs copied by hand, git clones, `cp -r`) with zero coupling to any installer and zero surprise, because nothing happens unless the user looks. The hook covers "at the moment you care" and its value survives being asynchronous: a banner *after* the installer finishes is arguably better UX than a mid-install print (no redraw corruption, no perceived slowdown). Surprise-ranking: inline-blocking hook ≫ wrapper shim (banned) > mid-install print > post-completion print > watch. Pick the two least surprising; make the riskiest one structurally harmless (§8). For Hermes/OpenCode specifically: directory watchers on their skills paths (inotify/FSEvents via a notify lib where available, 2–5 s polling fallback), hash-dedupe so re-scan prints only on real content change.

### Q3. Should lab mode be a separate policy file?

**One schema, two named presets — but the deeper decision is policy provenance, and that's R1.**

A second file format buys nothing (same keys, different defaults) and costs a second parser and divergent docs. Ship `policy.toml` with `mode = "street"` (default) / `"lab"`, presets shipped as templates (`xray doctor --print-preset lab`). Lab relaxes *how loudly declared* overreach is treated; it never relaxes undeclared-findings reporting — the taxonomy is clear that declaration-vs-behavior mismatch is itself a signal, in both directions. The critical adjacent rule the spec lacks: **policy is never auto-loaded from the scanned directory or the package.** A skill that ships `.xray.toml` saying `allow_hosts = ["*"]` must not soften its own scan. Project-local policy files apply only via explicit `--policy <file>` or an explicit `xray trust <dir>` act recorded in user config. Street defaults live in the binary; user overrides in `$XDG_CONFIG_HOME/xray`.

### Q4. Minimum own rule pack vs wrapping upstream engines earlier?

**Own a compact high-precision core (≈60–100 rules derivable directly from the taxonomy's indicator tables); wrap choir in Phase 2 as planned; version the rule pack like an API.**

Three reasons the core can't be outsourced: (1) claimed-vs-actual — X-Ray's differentiator — requires findings tagged with X-Ray's capability ontology; upstream engines don't emit those tags, so their output can corroborate but cannot feed the diff; (2) the readable-report promise needs evidence coordinates in *our* format with decode badges; (3) determinism and FP attribution require rule provenance we control. The taxonomy's regex tables + confidence calibrations are essentially the seed rule pack — authoring cost is mostly transcription + fixture-writing, not research. Packaging: rule pack is semver'd data (TOML) embedded in the binary, overridable/augmentable from `~/.config/xray/rules/*.toml` (user rules *add*; core is never silently replaced), `--explain-rules <id>` prints the rule + its calibration rationale. Band-affecting formula/rule changes follow SSL Labs' early-warning discipline: announce, warn one minor version, enforce at the major. Choir adapters (Phase 2) map upstream outputs into our Finding schema tagged `source=external`, shown as corroboration rows (§5 item 5).

---

## 11. Decisions beyond §10 the spec still owes

| Topic | Decision | Why now |
| --- | --- | --- |
| Implementation language | **Go, single static binary** (tree-sitter via cgo bindings), distributable additionally as a thin npm package wrapping the binary | Hooks must survive machines with no runtime assumptions; sub-20 ms startup fits the 50 ms hook contract; npx-wrapping meets skill users where they already are. Python-for-shipping is ruled out by hook robustness; TS-core acceptable *only* with the compiled-binary escape hatch, which concedes Go's advantages anyway |
| Exit-code contract | 0 completed (incl. alert), 2 crash, **3 config/policy error**, 4 internal ingest ceiling-abort (still writes partial report) | CI wrappers need to distinguish "found problems" from "scanner broken" from "asked nonsense" |
| Score versioning | `score_version` (formula), `rule_pack_version`, `engine_versions{}` in every report; band changes = major, warn-then-enforce | Determinism contract (§5) and upgrade trust |
| Special grades | **I** = partial (ceiling/timeout); consider **E** later for errored states; never fabricate a low number for an untrustworthy scan | SSL Labs lesson, research §4(b) |
| Report ANSI discipline | Own output: no cursor-positioning, framed banners, file-pointer for warn+ | Terminal-rendering attacks are in our own threat model (jqwik, ToB) |
| Windows support | v1: scan-only (paths, CRLF canonicalization); hooks/watch deferred | Skills ecosystem is Unix-first; don't let NTFS case-folding poison hashing in v1 |

---

## 12. What must not change (explicitly endorsed)

- Advisor-not-gate, including the refusal to wrap installers or veto writes — the whole trust posture depends on it.
- Set-difference claimed-vs-actual with no LLM in the truth path; LLM as evidence-bound captioner, off by default.
- Findings/severity/confidence/policy as orthogonal concerns (research §1: nobody credible folds them).
- Exit 0 on completed scans; CI gating strictly opt-in via `--fail-on`.
- "Every point deducted prints as a line item" — extend to: every cap event, floor override, and suppression prints too.
