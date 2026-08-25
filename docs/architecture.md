# X-Ray Engine Architecture

**Phase:** Spec critique and architectural decisions · **Label:** engine architecture
**Pipeline:** `ingest → static engines → choir → policy → score → report → explain`
**Grounding:** `docs/threat-taxonomy.md` (threat classes 2.1–2.8, detection layers L1/L2/L3, confidence tables) and `docs/research/scoring-rubrics.md` (§4 assessment: layered identity dedup, groups-not-findings scoring, byte-stable outputs, special grades).

---

## 0. Decision record (read this first)

| # | Decision | Choice | One-line rationale |
| --- | ---------- | -------- | -------------------- |
| D1 | Language | **Rust** for the shipped CLI + all first-party engines; Python stays in an offline calibration lab only | Single static binary, linear-time regex (scanner itself must not ReDoS on hostile input), tree-sitter is native, serde gives byte-stable JSON |
| D2 | Engine isolation | **In-process modules** with panic isolation (`catch_unwind` per engine) + a documented **out-of-process stdio protocol** for third-party engines; **WASM rejected for v1** | 90% of process isolation at 10% of the cost; WASM/WASI immaturity and audit-surface cost aren't justified while all engines are first-party |
| D3 | Engine crash semantics | An engine panic/timeout **never** fails the scan: engine marked `failed`, its findings absent, scan flagged **degraded**, grade capped at `I` (incomplete). Exit `2` reserved for orchestrator-level failures only | Matches spec; matches rubrics §4b "special grades instead of fake numbers" |
| D4 | Rule format | **YAML** rules validated against a versioned JSON Schema; rules are *data*, engines are *interpreters* | Rules need multiline regex + nested metadata (TOML is hostile to both); data-driven rules decouple rule velocity from core-language compile cycle |
| D5 | Ruleset distribution | Versioned, **signed ruleset bundles**, append-only preferred, atomic version-dir swap, pinned trust keys | Security tool must have a stronger supply chain than the things it audits |
| D6 | Scoring purity | `score = f(ScanSnapshot, formula_version)` — integer-only math, no clock/network, canonical ordering everywhere | Rubrics §4e determinism requirements |
| D7 | Dedup identity | Layered fingerprint: `rule_id ⊕ normalized-path ⊕ symbol-region ⊕ content-hash(line-insensitive)`; emitted as SARIF `partialFingerprints` | Rubrics §4c; GitHub code-scanning interop |

---

## 1. Pipeline overview

```text
                       ┌────────────────────────────────────────────────┐
 target path/archive    │                   xray scan                    │
 ──────────────────►   │                                                │
                       │  ingest ──► IR ──► ┌ engines (parallel) ┐      │
                       │                    │ text-rules         │      │
                       │                    │ ast-js  ast-py     │      │
                       │                    │ ast-sh             │      │
                       │                    │ manifest  entropy  │      │
                       │                    │ registry (opt.)    │      │
                       │                    └─────┬──────────────┘      │
                       │                          │ Vec<RawFinding>     │
                       │                     choir                      │
                       │        dedup → link → compose → canonicalize   │
                       │                          │ Vec<Finding>        │
                       │                         policy                  │
                       │        suppressions, exemptions, gate           │
                       │                          │ PolicyResult        │
                       │                          score                  │
                       │        pure fn → ScoreResult + breakdown       │
                       │                          │ ScanDocument        │
                       │                         report                 │
                       │        text / json / sarif renderers           │
                       │        (UX contract: docs/report-ux.md)         │
                       └────────────────────────────────────────────────┘
                                │                ▲
                                ▼                │ explain reads ScanDocument
                            exit code        + loaded RuleSet
                         0 / 1 / 2
```

**Stage contract style.** Every stage is a pure transformation `A → B` with no hidden I/O except `ingest` (filesystem) and `registry` (explicitly networked, cached). Everything downstream of `ingest` is deterministic given the IR: same IR ⇒ byte-identical `ScanDocument`. This is the property that makes golden-file testing and reproducible CI possible (rubrics §4e).

---

## 2. Stage-by-stage specification

### 2.1 `ingest`

**Input:** target (directory | `.tar.gz`/`.zip` skill bundle | git ref), `xray.toml` config, ignore rules.
**Output:** `Ir` (see §3.1).

Responsibilities:

1. **Enumeration.** Walk target respecting `.gitignore` + built-in excludes (`.git`, `node_modules`, lockfiles > N MB). Enforce `max_file_bytes` (default 2 MB per file for decode-eligible text; hard cap 20 MB), `max_total_bytes` (default 512 MB), symlink-jail (never follow links outside target root).
2. **Kind detection.** Sniff each file: `markdown`, `manifest-json`, `manifest-toml`, `shell`, `js/ts`, `python`, `other-text`, `binary`. Binary files: hashed, not scanned.
3. **Normalization** (implements taxonomy §1 exactly):
   - NFC/NFKC fold, homoglyph confusable mapping;
   - strip zero-width U+200B–200F, U+2060–206F, U+FEFF — **recording each removal as an event**;
   - extract Unicode TAG block U+E0000–U+E007F into its own layer;
   - extract ANSI/OSC sequences *before* stripping them;
   - recursively decode base64/hex/gzip runs ≥ 40 chars (depth ≤ 3, amplification guard: decoded ≤ 100× encoded chunk and ≤ 1 MB absolute);
   - split-string rejoin detection (`"ig""nore"` fragmentation);
   - each transform emits a `DecodeEvent` and produces a new **text layer**.
4. **Offset fidelity.** Every layer keeps an offset map back to original file spans. A finding that fires in `decode-2` cites the original byte range. Without this, explainability dies at the first base64 blob.
5. **Claims extraction.** Parse declarative surfaces: `SKILL.md` frontmatter (name, description, declared capabilities), `package.json` (+ lifecycle scripts), `requirements.txt`/`pyproject.toml`, MCP config entries, requested permissions/host allowlists. Stored as structured `Claim[]`.
6. **Provenance.** Content hashes (SHA-256) per file and for the whole snapshot; `snapshot_id = hash(sorted file hashes)`.
7. **Registry enrichment (optional, networked).** If enabled, resolve dependency metadata (first-publish date, maintainer history, download curve — taxonomy §2.5) and stamp `fetched_at` into the IR. Scoring/report never touch the network afterwards.

**Failure modes:** unreadable target, oversized input, or IO errors → orchestrator error, **exit 2** (this is an operational failure, not a scan result). Individual undecodable files become `anomalies[]` entries inside a successful IR.

### 2.2 `static engines`

**Input:** `&Ir` (read-only), `&CompiledRuleSet`.
**Output:** `Vec<RawFinding>` per engine + `EngineStatus`.

The universal engine signature:

```rust
pub trait Engine: Send + Sync {
    fn id(&self) -> &'static str;            // "text-rules", "ast-js", ...
    fn applies_to(&self, ir: &Ir) -> bool;   // cheap applicability precheck
    fn run(&self, ir: &Ir, rules: &CompiledRuleSet)
        -> Result<Vec<RawFinding>, EngineFailure>; // panic boundary wraps this
}
```

Engines are **pure functions**: no shared mutable state, no I/O, no clocks. Results may arrive in any order; `choir` canonicalizes.

| Engine | Layer | Implements | Notes |
| --- | --- | --- | --- |
| `text-rules` | L1 | Taxonomy §2 regex suites over selected text layers | Meta-regex / Aho-Corasick prefilter → candidate rules → per-rule confirm. Linear-time regex crate only (no backtracking: hostile input must not DoS the scanner) |
| `ast-js` / `ast-py` / `ast-sh` | L2 | Tree-sitter parse → structural queries + scoped dataflow pairs (§2.2–2.6 signatures: secret-source → encode → sink) | v1 does *scoped* pairing (within function/scope), not full taint; confidence ceiling for heuristic pairs stays honest per taxonomy tables |
| `manifest` | L1/L2 | Claimed-vs-actual capability diff (rubrics §2 generalized pipeline) | Produces both directions: overclaim (medium) and used-unclaimed (high). Needs `Claim[]` + primitive observations tagged by other engines — implemented as a *second-pass* engine consuming a shared observation log |
| `entropy` | L1 | Token shapes + Shannon entropy (taxonomy §2.3) | Feeds candidates; low-confidence alone, high-value when choir links it to egress |
| `registry` | metadata | Supply-chain checks (§2.5) | Off by default in `--offline`; writes into IR at ingest time, engine just evaluates cached facts |

**Two-pass note:** `manifest` depends on observations from other engines. Implementation: engines push primitive observations (`observed_capabilities: [(bucket, site, evidence_kind)]`) into the IR-scoped scratchpad; `manifest` runs last and diffs against `claims[]`. Ordering is orchestrated, not emergent.

### 2.3 `choir` (signal fusion)

Etymology assumption: many detector voices → one harmonized verdict. This stage implements taxonomy §3.1 combination rules and rubrics §4c grouping. Four sub-steps, strictly ordered:

1. **Dedup.** Collapse raw findings sharing a fingerprint (§5). Keep highest-evidence instance; merge `sources: [engine…]` onto the survivor.
2. **Link.** Build **groups** (root cause: same rule + same subject-entity, e.g., same advisory across dep paths) and **chains** (multi-leg attack signatures: legs joined by shared file/subject/dataflow adjacency, e.g., secret-read + encode + egress). Independence check per §3.1 rule 1: three hits on the same string are *one* leg; legs must come from distinct rules *and* distinct sites.
3. **Compose.** Per chain/group: combined confidence via the taxonomy reference points (single leg ≤ 0.7; any-two-legs ≥ 0.8; all-three ≥ 0.95). Evasion uplift: presence of concealment events (zero-width/TAG/ANSI/base64 in sibling layers) adds +0.15 to associated findings, floor 0.5. Declared-purpose exemption: declared capability X observed doing exactly X in scope → severity capped at "review".
4. **Canonicalize.** Sort by `(group_id, finding fingerprint)`; assign sequential IDs `XRY-F-000001…`. From here on, **order is total and content-derived** — nothing downstream iterates a HashMap.

**Output:** `Vec<Finding>` with `severity` (from the rubric matrix or advisory passthrough) and `confidence_tier` (`confirmed ≥0.9 / probable ≥0.75 / possible ≥0.5 / hint`) attached as **orthogonal axes** (Semgrep model, rubrics §4d).

### 2.4 `policy`

**Input:** `Vec<Finding>`, `PolicyConfig` (inline `xray.toml` + `--policy` override + ignore files).
**Output:** `PolicyResult { visible: Vec<Finding>, suppressed: Vec<(Finding, SuppressionReason)>, gate: Gate }`.

- Suppressions are **recorded, never erased**: every ignored finding appears in the report with who/why/expiry (SARIF `suppressions`). Expired suppressions stop suppressing and surface as stale entries.
- Ignore entries require a reason string; wildcard scoping allowed (`rule_id`, path glob, fingerprint).
- Gate decision keyed on **(severity × confidence)** pairs, never raw score alone (rubrics §4d): e.g., default gate fails on any `≥HIGH ∧ ≥probable`. `--fail-on` raises/lowers it. Exit `1` iff gate fails.
- Purpose exemptions from the skill's own declared capabilities are applied here (not in choir) so they're individually visible and toggleable.

### 2.5 `score`

Pure function `(ScanSnapshot, FormulaVersion) → ScoreResult`. Consumes **groups, not raw findings** (rubrics §4c):

- Start 100; subtract per-group penalties with diminishing multiplicity (1st instance full, geometric decay after);
- per-category ceilings (any bucket class can't own the score);
- L3 caps: verified-critical classes cap the letter regardless of arithmetic;
- confidence gating: only `≥ probable` moves the headline number; lower tiers listed separately;
- **degraded scans** (any enabled engine failed/timed out): grade forced to `I` unless `--allow-degraded`;
- integer/fixed-point arithmetic, rounding applied once, at the end;
- emits `ScoreBreakdown { per_group penalties, cap_events, ceiling_events }` — mandatory, feeds `explain` and the SARIF properties bag.

`formula_version` is semver; weight changes are major bumps with a warn-then-enforce window (SSL Labs early-warning pattern, rubrics §4b).

### 2.6 `report`

Renderers over one `ScanDocument`:

| Format | Flag | Notes |
| --- | --- | --- |
| Human text | default on TTY | Grade + number side by side, one-screen "why" (top penalties, caps), findings grouped |
| JSON | `--format json` | Canonical `ScanDocument`; sorted keys, fixed float formatting; **byte-stable across platforms/runs** |
| SARIF 2.1.0 | `--format sarif` | `partialFingerprints`, `rank` consistent with our taxonomy, `properties.security-severity`, breakdown in properties bag, suppressions (rubrics §3 table) |
| Markdown | `--format md` | PR-friendly summary |

All four consume the identical struct; none recomputes anything.

### 2.7 `explain`

Three entry points (details §8):

- `xray explain <RULE_ID>` — rule card from the loaded ruleset;
- `xray scan --explain` — post-scan narrative: why this grade, why this finding fired (layer, pattern, chain legs, confidence derivation);
- `--explain-rules` — attach per-finding explanation payloads to machine-readable output.

No magic: everything rendered is data that already lives in the ruleset or the `ScanDocument`.

---

## 3. File formats

### 3.1 IR JSON schema sketch

```jsonc
{
  "$schema": "https://xray.dev/schemas/ir-v1.json",
  "ir_version": "1.0",
  "target": {
    "kind": "directory",              // directory | archive | git_ref
    "root": "/abs/path",
    "snapshot_id": "sha256:…"          // hash over sorted per-file hashes
  },
  "files": [{
    "path": "skills/foo/scripts/setup.sh",   // target-root-relative, forward slashes
    "kind": "shell",                          // markdown|manifest-json|manifest-toml|
                                              // shell|js|ts|python|other-text|binary
    "size_bytes": 4096,
    "sha256": "…",
    "layers": ["raw", "norm"]                 // layer_ids present for this file
  }],
  "texts": {                                  // keyed by "<path>#<layer_id>"
    "skills/foo/scripts/setup.sh#norm": {
      "content": "…normalized…",
      "offset_map": [[0,0],[17,17]],          // (layer_offset, original_offset) pairs
      "decode_chain": []                       // e.g. ["base64","gzip"] for deeper layers
    }
  },
  "claims": [{                                 // from SKILL.md/package.json/etc.
    "surface": "skill_md_frontmatter",         // | package_json | mcp_config | permissions
    "key": "capabilities",
    "value": ["network:api.github.com"],
    "site": {"path": "SKILL.md", "span": [0, 210]}
  }],
  "observations_scratch": [],                  // filled by engines mid-scan; not persisted
  "decode_events": [{                          // normalization audit trail (taxonomy §1)
    "file": "README.md", "event": "zero_width_strip",
    "count": 14, "layer_from": "raw", "layer_to": "norm"
  }],
  "anomalies": [{"file": "blob.bin", "code": "binary_skipped"}],
  "enrichment": {                              // registry engine cache, stamped
    "fetched_at": "2026-08-24T12:00:00Z",
    "packages": [{"ecosystem":"npm","name":"left-pad","first_publish":"2011-…","…":"…"}]
  }
}
```

### 3.2 Finding schemas (two stages, deliberately distinct)

**RawFinding** (engine → choir). Deliberately dumb: no dedup, no severity math.

```jsonc
{
  "engine": "ast-js",
  "rule_id": "XRY-SECRETS-GITHUB-PAT",
  "subject": {
    "file": "scripts/upload.js",
    "span": [102, 138],                // original-file byte range (via offset map)
    "symbol_scope": "uploadArtifact",  // enclosing fn/class when known
    "entity": "ghp_…"                  // canonical subject when applicable (pkg@ver, perm name)
  },
  "layer": "decode-1",                 // which text layer matched
  "evidence_kind": "taint_reachable",  // runtime|taint_reachable|direct_ast|string_match|heuristic
  "buckets": ["secrets"],
  "message": "GitHub PAT literal flows into fetch() argument",
  "snippet": "const t = \"ghp_…\";",
  "raw_confidence": 0.72,
  "legs": ["secret_source", "network_sink"],   // chain-leg tags for choir
  "extra": {}                           // engine-private payload (schema-validated per engine)
}
```

**Finding** (choir → downstream). Stable identity, orthogonal axes, group membership.

```jsonc
{
  "finding_id": "XRY-F-000014",                        // canonical sequence, content-independent label
  "fingerprint": "sha256:…",                           // §5 identity; == SARIF partialFingerprints["xray/v1"]
  "rule_id": "XRY-SECRETS-GITHUB-PAT",
  "rule_version": "3",
  "engine_sources": ["ast-js", "text-rules"],          // merged survivors
  "group_id": "G-secret-exfil-01",
  "chain": {"role": "leg_of_secret_exfil", "legs": ["secret_source","encode","network_sink"],
             "combined_confidence": 0.95},
  "subject": { /* as above */ },
  "evidence_kind": "taint_reachable",
  "buckets": ["secrets", "network"],
  "threat_class": "2.3",
  "severity": "high",                                   // L1 axis (rubric matrix or advisory passthrough)
  "confidence_tier": "confirmed",                       // L2 axis — orthogonal, never folded silently
  "message": "…", "snippet": "…",
  "explanation": {                                      // powers --explain / SARIF properties bag
    "matched_because": ["pattern AKIA… on layer norm", "pair secret_read→fetch within scope"],
    "confidence_derivation": "base 0.85 (taint pair) ; evasion uplift +0 ; exemption none"
  },
  "status": "visible"                                    // visible | suppressed{reason,by,expires}
}
```

### 3.3 Rule storage shape (YAML)

```yaml
# rules/security/secret-exfil.yaml
schema_version: 1
ruleset: security        # bundle member; see §7 for bundling/signing
rules:
  - id: XRY-SECRETS-GITHUB-PAT
    version: 3
    status: stable            # draft | stable | deprecated (with successor field)
    title: "GitHub personal access token literal"
    threat_class: "2.3"       # taxonomy section
    buckets: [secrets]        # canonical vocabulary from taxonomy §0
    engines: [text-rules, entropy]     # eligible engines; engine may still skip
    layers: [norm, decode-1, decode-2] # which text layers to scan
    match:
      - regex: 'gh[pousr]_[A-Za-z0-9]{36,255}'   # RE2-syntax only; loader rejects backrefs/lookaround
        flags: []              # loader compiles with linear-time engine; case handled in pattern
      - regex: '(?i)github[_-]?token\s*=\s*[''"][A-Za-z0-9]{30,}'
    entropy_check: {min_length: 30, min_entropy: 4.0}   # secondary confirmation
    evidence_kind: string_match           # default; engines may upgrade (AST pair → taint_reachable)
    confidence_base: 0.70
    legs: [secret_source]                 # choir link hints
    chains:                               # what a complete chain looks like (for choir + docs)
      - name: secret-exfil
        with_legs: [encode, network_sink]
        combined_confidence: 0.95
    severity:                             # rubric-matrix shortcut; omit to inherit class defaults
      base: high
      escalate_when: {with_legs: [network_sink], to: critical}
    false_positives:                      # machine-readable mitigation hints for policy/choir
      - test_fixtures                     # sk-test… dummies
      - token_verification_libs
    rationale: |
      Shai-Hulud (Sept 2025) harvested PATs via TruffleHog-style scans; nx s1ngularity
      pushed them to public repos. A PAT literal outside a test fixture is treated as
      exposed-at-rest.
    references:
      - https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
    examples:
      - should_match:  'const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'
        because: direct literal
      - should_not_match: 'process.env.GITHUB_TOKEN'
        because: indirection, not a literal
    deprecated_since: null
    successor: null
```

Loader contract: validate against JSON Schema → reject unknown fields (typo = load error, not silent skip) → compile regexes with the linear-time engine → run embedded `examples` as self-tests (mandatory in CI, `--skip-rule-selftest` escape hatch for air-gapped custom rules) → produce `CompiledRuleSet` keyed by id, with prefilter automaton. Custom rules live in `.xray/rules/**/*.yaml` beside the scanned project; precedence custom > builtin override > builtin; ID collisions are load errors unless the file declares `overrides: builtin`.

Why YAML over TOML: multiline regex literals and deeply nested metadata (`chains`, `examples`) are miserable in TOML; YAML handles them natively and every editor highlights it. The strict-schema loader removes YAML's usual downside (silent misparse).

---

## 4. Engine isolation model

**Requirement (spec):** one engine crashing must not fail the scan; exit `2` only on total crash.

Mechanics (in-process, per D2):

```rust
let handles: Vec<_> = engines.iter().map(|e| {
    let ir = &ir; let rules = &ruleset;
    thread::scope(|s| s.spawn(move || {
        catch_unwind(|| e.run(ir, rules))       // panic boundary
            .unwrap_or(Err(EngineFailure::Panic))
    }))
}).collect();
// join with per-engine wall-clock timeout (channel + recv_timeout);
// on timeout: mark EngineFailure::Timeout, abandon the worker thread (leak-until-exit,
// documented; process exits shortly after so this is bounded).
```

Consequences, stated honestly:

| Failure | Effect on scan | Effect on exit code | Report trace |
| --- | --- | --- | --- |
| Engine panic (bug) | Engine's findings absent; others proceed | Unchanged (0/1) | `engines:[{status:"failed", reason:"panic:<msg>"}]` |
| Engine timeout (hostile input / hang) | Same as panic | Unchanged | `{status:"timeout", budget_ms}` |
| Engine returns Ok but empty | Normal | Unchanged | `{status:"ok", findings:N}` |
| Any enabled engine failed | Scan flagged **degraded** → grade `I` (cap) unless `--allow-degraded` | Still 0/1 by policy | degradation banner + engine table |
| Config invalid, target unreadable, report unwritable, ruleset fails schema validation | No scan | **exit 2** | stderr diagnostic |

Why in-process beats process-per-engine here:

- Engines share the multi-hundred-MB IR; serializing it over pipes per engine is the single biggest perf tax, and v1 engines are pure functions over read-only data — the corruption risk process isolation defends against doesn't exist when nothing mutates shared state.
- Panics are the realistic failure mode (logic bugs, index panics on adversarial input), and `catch_unwind` covers exactly that. True segfault risk concentrates in tree-sitter (C FFI); accepted residual risk, mitigated by fuzzing the ingest/parse boundary (§9) and by the documented out-of-process protocol for anyone who needs harder isolation today.
- Process isolation remains available *opt-in* per engine (`[engines.ast-py] mode="external"` in config) using the stdio protocol below — useful for the Python semantic classifier planned post-v1.

**Out-of-process Engine Protocol (v1.x, documented, versioned):** engine executable reads length-prefixed JSON frames on stdin: `{protocol:1, method:"describe"|"run", params:{ir_uri|ir_inline, rules_subset}}`, replies `{findings:[RawFinding]} | {error:{kind,message}}`. Orchestrator treats it identically: crash/timeout/OOM → `EngineFailure`, scan continues. This is also the seam where WASM would slot in later if a third-party engine ecosystem materializes — the frame format is transport-agnostic.

WASM specifically rejected for v1 because: (a) parse-heavy AST work pays a real perf tax unless grammars are compiled into each module; (b) WASI filesystem abstractions fight our walk-and-layer ingest model; (c) Component Model tooling is still churning; (d) adding a WASM runtime to a security scanner enlarges the very audit surface the tool exists to shrink. Revisit trigger: >3 credible third-party engines wanting distribution.

---

## 5. Dedup logic (fingerprint identity)

Layered identity, cheapest-first (rubrics §4c):

1. **Exact:** `sha256(rule_id ‖ normalized_path ‖ symbol_region ‖ content_hash_line_insensitive)`.
   - `normalized_path`: forward slashes, target-relative, lowercased drive/case-normalized components where FS-insensitive;
   - `symbol_region`: enclosing function/class name when known, else nearest heading/block anchor — **line numbers excluded** so upstream edits don't fork identities;
   - `content_hash_line_insensitive`: whitespace-normalized snippet hash.
2. **Subject fallback:** same rule + same entity (`pkg@version`, permission name) merges across sites into one group with N locations.
3. **Cross-rule collapse:** identical span + equivalent bucket + overlapping pattern provenance (same underlying string hit by literal + entropy rules) → one finding, sources merged. Implemented by comparing match spans on the same layer; ties broken by evidence-kind rank (`runtime > taint_reachable > direct_ast > string_match > heuristic`).

Groups and chains are *above* dedup: dedup collapses copies; grouping collapses instances of one root cause; chaining composes independent legs. Scoring consumes groups; reporting shows group with expandable sites (npm-audit's path-listing UX).

Deterministic tie-breaking everywhere (canonical sort before any merge or summation) so finding arrival order can never perturb output.

---

## 6. Technology choice analysis

| Axis | Rust | Go | TypeScript | Python |
| --- | --- | --- | --- | --- |
| Distribution | ★ static binary, zero deps | ★ static binary (cgo complicates cross-compile w/ tree-sitter) | ✗ Node runtime required | ✗ worst (venvs, pyinstaller fragility) |
| Regex safety on hostile input | ★ `regex` crate: linear-time, no backtracking, UTF-8 by construction | ★ RE2-derived, linear-time | ✗ backtracking → **ReDoS surface in the scanner itself** | ✗ `re` backtracking, worse |
| Tree-sitter (L2 AST) | ★ first-class official bindings | ◑ cgo friction, messier cross-builds | ◑ WASM grammar builds work but slower | ◑ bindings exist, GIL contention |
| Byte-stable JSON | ★ serde + ordered structs | ★ encoding/json (map ordering care needed) | ◑ float/formatting pitfalls | ◑ dict ordering fine, floats worse |
| Concurrency | ★ rayon/threads, no GC pauses | ★ goroutines (simplest) | ◑ worker_threads | ✗ GIL (needs multiprocessing) |
| Rule-author velocity | ◑ data-driven rules mitigate; core changes compile slowly | ◑ fast compile | ★ fastest iteration | ★ fastest |
| Startup latency (pre-install hook!) | ★ ~ms | ★ ~ms | ◑ ~100ms+ | ✗ ~300ms+ |
| Contributor pool | smallest of the three compiled options | large | largest | large |
| Supply-chain credibility | ★ near-zero deps, auditable `Cargo.lock` | ★ good | ✗ hundreds of transitive npm deps for a *supply-chain auditor* is a credibility and attack-surface problem | ✗ similar |
| Calibration/corpus work (offline) | ◑ possible, unpleasant | ◑ | ◑ | ★ pandas/sklearn/PR-curve tooling |

**Decision (D1):** Rust for the shipped artifact. The deciding arguments are the ones unique to this domain: (1) the scanner ingests *hostile* input, so the regex engine must be linear-time by construction — TS/Py regex would make the scanner itself vulnerable to the denial-of-service it should be defending against; (2) pre-install/CI invocation makes startup latency and single-binary distribution functional requirements; (3) a security tool whose own dependency tree is a headline vulnerability undermines its thesis. Go is the runner-up (goroutines are nicer, team-velocity friendlier); choose it instead only if the implementing team is strongly Go-native — the architecture is language-neutral below the engine trait.

**Companion:** `xray-lab/` (Python, separate repo, never shipped): labeled-corpus management, PR curves per taxonomy §3.3, score-distribution histograms, stability fuzzers. Lab outputs feed rule thresholds and weight tuning; the CLI stays deterministic and offline.

---

## 7. Rule versioning & updates

Model: **signed, immutable ruleset bundles**; the resolver picks a version; nothing mutates in place.

- **Bundle** = `{manifest.toml, rules/**/*.yaml, schema hash, ruleset_semver, per-file sha256, ed25519 signature}`. Built by CI from the rules repo; published to a static URL/channel (`stable`, `fast`).
- **Trust:** ed25519 public key pinned in the binary. `xray rules verify <bundle>` checks signatures + hashes. Unsigned local bundles run only with `--trust-local-rules` (loud warning, watermarked reports).
- **Install layout:**

```text
~/.xray/rules/
├── active -> v2026.08.3            # atomic symlink swap
├── v2026.08.3/{manifest.toml, rules/…, manifest.sig}
└── v2026.07.1/…                    # previous versions retained for reproducibility
```

- **Resolution order:** project `.xray/rules/**` (custom) → `overrides:` blocks → active builtin bundle. Every report stamps `{tool_version, ruleset_version, per-rule versions, content hashes}` so a year-old report remains exactly interpretable.
- **Mutation policy:** append-new-rule preferred; modifying a rule bumps its `version`; breaking changes (semantics/severity) bump ruleset minor/major and land in a generated `CHANGELOG`. Deprecated rules keep matching but emit `deprecated` notices pointing at `successor` for one ruleset generation — SSL Labs early-warning discipline (rubrics §4b).
- **Formula coupling:** rule severity defaults are part of the ruleset; the score *formula* has an independent `formula_version`. Compatibility matrix in each release notes ("formula 2.x expects ruleset ≥ 2026.06").
- **Offline-first:** scans never fetch; `xray rules update` is explicit (or CI-scheduled), verifies, swaps atomically, and prints the changelog diff. `--rules-pin <version>` freezes CI to a known bundle.

---

## 8. How `--explain-rules` works

Everything is documentation-as-data; no second brain exists.

1. **Rule cards** — `xray explain <RULE_ID>` renders from the loaded `CompiledRuleSet`: title, status/version/since, buckets/threat-class, what it matches (patterns shown verbatim), evidence-kind ladder and confidence bases, chain roles it participates in, FP profile (`false_positives` + `fp_notes`), rationale with incident references (straight from the YAML), embedded examples with expected outcomes.
2. **Per-finding explanations** — choir already wrote `finding.explanation` (§3.2): which layers/patterns matched, which chain legs contributed and how confidence composed, whether evasion uplift or purpose exemptions applied. `--explain-rules` (JSON/SARIF) embeds these; SARIF gets them free via the properties bag (rubrics §3).
3. **Grade narration** — `xray scan --explain` renders the `ScoreBreakdown`: start 100 → per-group penalties (with diminishing multiplicity shown), ceilings hit, caps applied, final number beside the letter, and the exact gate expression that decided the exit code ("B because: −18 secret-exfil group (3 sites, diminishing), ceiling −4 on money bucket; cap none").
4. **Unknown-ID handling** — `xray explain XRY-FOO` resolves through the same precedence chain as scans and suggests near-miss IDs; if the ID existed in an older installed bundle, it says so and names the bundle (reports carry bundle versions precisely to enable this).

---

## 9. Test strategy

| Level | What | Mechanism |
| --- | --- | --- |
| Unit | Per-function purity, offset-map round-trips, fingerprint stability | Standard `#[test]`, proptest for offset maps (normalize → map-back == original span) |
| Rule self-tests | Every rule's `examples` run against its own patterns | Loader executes at compile; CI gates on it; corpus regressions add cases per FP attribution |
| Golden files | Fixture targets → byte-identical JSON/SARIF/text | `fixtures/{benign,malicious}/*` snapshots; any diff requires conscious regeneration + review. Covers determinism (rubrics §4e) |
| Stability fuzz | Near-duplicate inputs (line shifts, comment churn, re-encoding) must not flip fingerprints, groups, or grade bands | Property tests + scheduled corpus runs; implements rubrics §4b "stability testing" |
| Score distribution | Histogram over benign corpus must not pile at extremes | Lab job; guards Snyk-style spread requirement (rubrics §4a) |
| Crash drills | Injected panics/timeouts per engine; assert scan completes, engine table correct, exit ∈ {0,1}, grade capped `I` | Fault-injection harness behind a `cfg(test)` engine wrapper |
| Parser fuzz | cargo-fuzz/afl over ingest normalizer + each tree-sitter grammar with hostile corpora (deep nesting, billion-laughs YAML, zip bombs, base64 bombs) | Continuous OSS-Fuzz-style job; bounds tested: decode depth/amplification, IR size caps |
| Corpus PR curves | Precision/recall per detector family on labeled malicious/benign sets; FP attribution reason codes | `xray-lab` (Python); quarterly recalibration cadence per taxonomy §3.3 |
| Cross-platform byte-stability | Same snapshot scanned on linux/macOS/arm64 → identical bytes | CI matrix comparing SHA-256 of outputs |
| Exit-code contract | Table-driven: clean / gate-fail / engine-crash / bad-config / unreadable-report | Integration tests asserting exact codes (spec requirement) |

---

## 10. Directory layout

```text
xray/
├── Cargo.toml                     # workspace
├── crates/
│   ├── xray-cli/                  # bin: arg parsing, orchestration, exit codes, config load
│   ├── xray-core/                 # pipeline traits, Ir/Finding/RawFinding types, error taxonomy
│   ├── xray-ingest/               # walker, normalizer, offset maps, claims extractor, archive support
│   ├── xray-engines/
│   │   ├── text-rules/            # L1 interpreter + prefilter
│   │   ├── ast/                   # shared tree-sitter infra
│   │   ├── manifest/              # claims-vs-observation diff (second pass)
│   │   ├── entropy/
│   │   └── registry/              # evaluates cached enrichment facts
│   ├── xray-choir/                # dedup, linker, composer, canonicalizer
│   ├── xray-policy/
│   ├── xray-score/                # formula v2 impl, caps, ceilings, breakdown
│   ├── xray-report/               # text/json/sarif/md renderers (docs/report-ux.md)
│   ├── xray-rules/                # YAML loader, JSON-Schema validation, compiler, precedence
│   └── xray-protocol/             # out-of-process engine protocol (frames, client, supervisor)
├── rules/                         # builtin rulesets (source of truth; CI signs bundles from here)
│   ├── security/*.yaml
│   ├── hygiene/*.yaml
│   └── CHANGELOG.md
├── schemas/                       # ir-v1.json, finding-v1.json, rule-v1.json, report-v1.json
├── fixtures/                      # golden-input targets
│   ├── benign/                    # legit skills w/ known-tricky patterns
│   ├── malicious/                 # reproductions of taxonomy incidents (redacted)
│   └── golden/                    # expected outputs (byte-exact)
├── docs/                          # this file, taxonomy, rubrics, formula.md, rule-authoring.md
├── xray-lab/                      # SEPARATE repo in practice: python calibration tooling
└── xray.toml                      # default config template
```

Crates split along pipeline seams so each stage's invariants are type-enforced at the boundary (`RawFinding` can't leak past choir; `ScoreResult` is constructible only inside `xray-score`).

## 11. CLI structure

```text
xray scan [PATH]                    # primary verb; PATH defaults to cwd
  --format text|json|sarif|md       # repeatable; text implicit on TTY
  -o, --output FILE                 # else stdout
  --policy FILE                     # extra policy layer atop xray.toml
  --fail-on "high+probable"         # gate expression (severity × confidence)
  --min-severity low|medium|high|critical
  --ignore FILE                     # suppressions with reasons
  --engine +name/-name              # enable/disable specific engines
  --rules-pin VERSION | --rules DIR
  --offline                         # forbid registry enrichment
  --explain                         # narrate grade + gate on stdout
  --explain-rules                   # embed per-finding explanations (json/sarif)
  --allow-degraded                  # force numeric grade despite failed engines
  --timeout-scan SECS --timeout-engine SECS
  --json-diagnostics                # machine-readable engine/status/errors on stderr

xray explain <RULE_ID>              # rule card (§8)
xray rules list|show|lint|update|verify|pin
xray init                           # scaffold xray.toml + .xray/rules/
```

**Exit codes (contract, tested):** `0` scan completed, gate passed · `1` scan completed, gate failed · `2` operational failure (bad config, unreadable target, unwritable report, ruleset validation failure). Engine crashes never produce `2` — that's the spec's isolation guarantee, now enforced by construction and by test.

---

## 12. Spec gaps noticed during design (feedback upstream)

1. **Degraded-scan semantics unspecified.** Spec says crashes don't fail scans, but not what grade a partially-scanned target earns. Proposed: `I` grade cap (D3), `--allow-degraded` override — needs spec blessing.
2. **Score input ambiguity.** Spec's pipeline implies score follows policy; rubrics require groups. Resolved: score consumes choir groups *after* policy visibility filtering — worth stating explicitly in the spec.
3. **Ruleset trust model absent.** Nothing in the spec prevents a malicious "rules update" from becoming the attack vector (a scanner that runs attacker-chosen regexes over your files). §7's signed-bundle model should be promoted into spec requirements.
4. **`explain` underspecified.** Is it scan-time narration or standalone lookup? Proposed: both (§8); spec should name the three entry points.
5. **Registry engine network posture.** Spec doesn't say whether scans may touch the network. Default `--offline`-safe with explicit opt-in keeps CI hermetic; needs confirmation.
