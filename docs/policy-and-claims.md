# Claims Extraction & Policy Design — X-Ray v1

**Phase:** Scoring, policy, and UX refinement · **Label:** policy design
**Grounding:** `docs/threat-taxonomy.md` §0/§3 (buckets, declared-purpose rule, action bands), `docs/arch-review.md` (D-FP, R1 policy provenance, Q3 one-schema-two-presets, §9 double-count rule), `docs/research/scoring-rubrics.md` §2 (claimed-vs-actual precedent, direction asymmetry).
**Interface contracts:** scoring phase owns penalty *numbers*; this doc owns the sets, labels, and policy semantics they consume. No LLM anywhere in the truth path.

---

## 0. Decisions (read this first)

| # | Decision | One-line rationale |
| D-C1 | Claims come from **three evidence tiers** — structural fields, verb–object lexicon, tool anchors — plus **negative claims** (disavowals); outcome/marketing language grants nothing | Android/browser lesson: structured surfaces are authoritative; prose needs a conservative, auditable lexicon, not an oracle |
| D-C2 | Vague copy ("helper", "supercharges your workflow") ⇒ **empty claim contribution + `XR-META-VAGUE` hygiene finding + `claim_specificity = low`**, which relabels diffs as *undeclared*, never *overreach* | Two failure directions are asymmetric: missing a deceptive skill is costly, accusing a vague-but-honest one is costly too — separate the words so each gets its own weight |
| D-C3 | Ontology = **9 buckets (scored, frozen) × ~29 facets (descriptive, danger-classified)**; bucket-level claims sanction routine+sensitive facets only; **critical-class facets always require an explicit facet claim** | Facets carry granularity without fragmenting scores/fingerprints; the critical-facet rule kills the "claims everything" gaming vector |
| D-C4 | Diff outcomes are five-valued: **sanctioned / unused-claim / undeclared / overreach / violation**; overreach requires an *affirmative scope statement narrower than reality*; a disavowal ("fully offline") contradicted by behavior is **violation**, weighted above overreach | Matches research §2 direction asymmetry (used-unclaimed ≫ claimed-unused); gives scoring five disjoint inputs instead of one muddy "overreach" |
| D-P1 | **One `policy.toml` schema, two shipped presets** (`street` default, `lab`); layers = builtin ← `$XDG_CONFIG_HOME/xray/policy.toml` ← explicit `--policy` (ordered, last-wins per key, exempt-lists append); **never auto-loaded from the scanned path** — untrusted project policies print a one-line notice and are ignored unless `xray trust`-ed | Arch-review R1/Q3 verbatim; predictable merge beats clever merge |
| D-P2 | Lab mode relaxes **only** the loudness of sanctioned/declared behavior; **undeclared, overreach, and violation labels are byte-identical across modes** | The declaration-vs-behavior mismatch is the signal (taxonomy §3.1 rule 3); lab exists so red-team arsenals don't drown users in sanctioned-behavior warns |
| D-P3 | Host allowlists use **domain globs with one-label `*`**, apex-inclusive `*.`, and opt-in Public Suffix List matching; `re:` regex is a documented escape hatch validated at load (bad pattern ⇒ exit 3); **deny beats allow everywhere** | Glob semantics must be precise enough to reason about security; PSL breadth is a footgun worth an explicit flag |
| D-P4 | Explanations are **template-rendered from deterministic slots** (claim quote+coords, finding fingerprint+snippet, facet verb-phrase, why-uncovered rule, remedy options); template strings are versioned data, golden-tested | "Every point deducted prints as a line item" extended to every diff verdict; byte-stable without a model |
| D-P5 | Terminology fix: manifest-declared tools feed **claimed**; code/config-observed primitives (imports, spawned binaries) feed **actual** as *weak members* (notes only, never penalties alone) | Current spec conflates the two; "declared tools ⇒ actual" inverts the evidence direction |

---

## 1. Claim model

### 1.1 Surfaces (where claims live)

| Surface | Fields | Tier |
| SKILL.md frontmatter | `name`, `description`, native capability fields: Claude Code `allowed-tools`, proposed `capabilities: [...]`, `tools: [...]`, `permissions.hosts` | T1 structural |
| Package manifests | `package.json` (`bin`, `scripts`, `dependencies`), `pyproject.toml`, MCP config `mcpServers` (server command + tool defs) | T1 structural |
| Prose | SKILL.md body intro, README first ~80 lines, tool descriptions in MCP defs | T2 lexical |
| Embedded config | requested host allowlists, permission asks, `.xray`-style metadata found in bundle (recorded, never executed) | T1 structural |

Union across surfaces: a capability is *claimed* if **any** surface claims it (users may have read any of them). Exception: negative claims (§1.4) — if surfaces conflict, the negative claim wins and the conflict itself becomes a finding-grade notice (`XR-CLAIM-CONFLICT`).

### 1.2 Data model

```rust
struct Claim {
  capability: Bucket,            // 9-bucket enum, frozen
  facet: Option<Facet>,          // e.g. net:fetch; None = bucket-wide
  polarity: Pos | Neg,
  tier: Structural | ExplicitVerb | ToolAnchor,
  scope: Option<ScopeGlob>,      // "within ./src", "*.sql only"
  surface, source_span, quote,   // original coordinates; evidence cites these
}
```

Every claim keeps `quote + file:span` — the explanation renderer (§6) quotes it verbatim. This is what makes no-LLM explanation possible: the claim *is* a citation.

### 1.3 Lexicon (T2) — shape and seed

Data file `rules/claims/lexicon-{version}.toml`, versioned like the rule pack, embedded + user-extensible (`~/.config/xray/claims/*.toml` **adds** rows, never overrides core). Matching: lowercase, lemma-normalized, ≤ 6 tokens window between verb head and object head; each hit emits a claim at tier `ExplicitVerb`.

Seed rows (illustrative, full pack ~150 rows):

```toml
[[verb]]
verbs = ["read", "scan", "parse", "inspect", "analyze", "index"]
objects = ["file", "files", "code", "repo", "repository", "directory", "project"]
claim = { capability = "read", facet = "r:workspace" }

[[verb]]
verbs = ["fetch", "download", "call", "query", "hit", "curl"]
objects = ["api", "url", "endpoint", "web", "website", "service", "host"]
claim = { capability = "network", facet = "net:fetch" }

[[verb]]
verbs = ["search", "browse", "look up"]
objects = ["web", "internet", "online", "the web"]
claim = { capability = "network", facet = "net:fetch" }

[[verb]]
verbs = ["install", "add", "pull"]
objects = ["package", "dependency", "module", "library", "plugin"]
claim = { capability = "spawn_skills", facet = "spn:install" }

[[verb]]
verbs = ["send", "post", "upload", "push", "publish", "sync"]
objects = ["data", "results", "file", "report", "content"]
claim = { capability = "network", facet = "net:upload" }

[[verb]]
verbs = ["run", "execute", "invoke", "launch"]
objects = ["command", "commands", "shell", "script", "process"]
claim = { capability = "shell", facet = "sh:interpreter" }

[[verb]]
verbs = ["pay", "charge", "purchase", "swap", "transfer", "transact"]
objects = []
claim = { capability = "money", facet = "mon:transact" }   # objectless verbs allowed for hot verbs

[[verb]]
verbs = ["edit", "modify", "update", "write", "create"]
objects = ["file", "files", "config", "configuration"]
claim = { capability = "write", facet = "w:workspace" }     # scope qualifier may upgrade target class
```

Guardrails: a row fires only on **verb+object co-occurrence** (except whitelisted objectless hot verbs); "manages your workflow files" ⇒ write, "manages your workflow" ⇒ nothing. Ambiguous objects ("your data") resolve to the *nearest* facet only when a second signal (tool anchor, structural field) corroborates; alone they count toward specificity but grant no facet.

### 1.4 Negative claims (disavowals) — the highest-value prose

Patterns: `offline`, `air-gapped`, `works without network`, `no network access`, `no telemetry`, `nothing leaves your machine`, `reads only`, `never writes`, `does not execute`, `local only`, `sandboxed`.

A negative claim produces `Claim{polarity: Neg}` covering its facet set. Effects:

1. Behavior matching a disavowed facet ⇒ **violation** verdict (§3) — weighted above overreach, because the author *pre-answered* the question wrongly.
2. Disavowals also **narrow the claimed set**: "reads only project files" ⇒ claimed = {r:workspace}, everything else actual is at best undeclared.
3. Cross-surface conflict (README: "fully offline", frontmatter `tools: [curl]`) ⇒ `XR-CLAIM-CONFLICT` notice; negative wins for diff purposes (strict-to-author; authors who write disavowals are making a promise).

### 1.5 Marketing copy: the vagueness protocol (answers "how to handle *helper*/*supercharges*")

Hard rule (**D-C2**): **capability claims require a capability verb, a tool anchor, or a structural field. Outcome language, praise adjectives, and role nouns grant nothing.**

Hyperbole/outcome stoplist (never claims): `supercharges`, `boost`, `10x`, `blazing`, `magical`, `effortlessly`, `unlock`, `transform`, `turbocharge`, `revolutionize`, `next-level`, `game-changer`, `powerful` (+ `helper`, `assistant`, `companion` as role nouns — no capability content).

But zero-claim descriptions are themselves reported, not silently forgiven:

```
specificity = 3·(#T1 fields) + 2·(#T2 verb-object hits) + 1.5·(#tool anchors) + 2·(#scope qualifiers), per 50 words
  < 1.0        → vague      : XR-META-VAGUE (notice) · claim_specificity = low
  1.0 – 3.0    → normal     : standard labeling
  > 3.0        → rich       : claims quoted prominently in report header
```

Consequences of `low`: actual−claimed differences are labeled **undeclared (description unclear)** — notice band in street mode, never the word "overreach", never overreach-weight penalties. The skill isn't accused of deception; it's accused of *silence*, which is exactly what happened. Honesty preserved, accusation calibrated. Non-English descriptions hit the vague path until the lexicon gains translations (documented limitation; fails loud-ish, not silent).

Broad hyperbole that *names powers* ("full control of your system", "can execute anything") **is** honored — as broad claims. The report then displays an alarming claim set, which is the honest outcome: the skill told on itself.

### 1.6 Tool anchors (T3)

Bundled table `rules/claims/tools-{version}.toml`: known tool/binary/import names → capability sets. Sample: `gh` → {sh:interpreter, net:fetch}; `npm|pip|cargo install` → {spn:install, net:fetch}; `curl|wget` → {net:fetch}; `jq` → {r:workspace}; `docker` → {sh:interpreter}; `git` → {sh:interpreter}; `crontab|systemctl --user` → {sh:persistence}; `security find-generic-password|xcrun altool` → {sec:read}. Anchors fire only on unambiguous tokens (word-boundary match against the table keys); versioned and calibrated against the benign corpus like any rule.

---

## 2. Capability ontology — 9 buckets × 29 facets

**Answer to "are 8 enough?"** The taxonomy settled 9 (arch-review D-ENG: families map 1:1). Eight was wrong (identity/spawn_skills homeless); going past 9 buckets is also wrong — every added bucket creates overlap pressure and double-count pressure in scoring (research §1: nobody credible folds orthogonal axes, and nobody scores 15 permission classes). **Freeze buckets; put granularity in facets.**

**Answer to "should network split fetch vs exfiltrate?"** Yes — as *facets*, not buckets. Facets are descriptive, carried by findings/claims, rendered in reports, and classified into three **danger classes** that scoring keys on:

| Class | Meaning in scoring | Label band (street) |
| routine | ubiquitous in benign skills | clean/notice |
| sensitive | needs a reason to exist | warn if undeclared |
| critical | near-certain malice or breach-grade if undeclared | alert; hard-floor eligible |

Full facet table (authoritative; `X` = requires explicit facet claim even if bucket claimed):

| Bucket | facet (class) | | Bucket | facet (class) |
| --- | --- | --- | --- | --- |
| read | `r:workspace` (routine) | | money | `mon:display` (routine) |
| | `r:dotfiles` (sensitive) | | | `mon:transact` (X, critical) |
| | `r:credentials` (X, critical) | | | `mon:mine` (X, critical) |
| | `r:system` (sensitive) | | | `mon:clipboard` (X, critical) |
| write | `w:workspace` (routine) | | spawn | `spn:manage` (routine, own scope) |
| | `w:outside_workspace` (sensitive) | | | `spn:install` (sensitive) |
| | `w:exec_bit` (sensitive) | | | `spn:replicate` (X, critical) |
| | `w:agent_instructions` (X, critical) | | | `spn:escalate` (X, critical) |
| | `w:skill_dirs` (X, critical) | | identity | `id:role_forge` (sensitive) |
| shell | `sh:interpreter` (sensitive) | | | `id:vendor` (sensitive) |
| | `sh:remote_exec` (X, critical) | | | `id:approval_spoof` (X, critical) |
| | `sh:persistence` (X, critical) | | | `id:authorship` (sensitive) |
| network | `net:fetch` (routine) | | override | `ovr:injection` (critical) |
| | `net:upload` (sensitive) | | | `ovr:self_grant` (X, critical) |
| | `net:raw_socket` (X, critical) | | | `ovr:harness_config` (X, critical) |
| | `net:dns_tunnel` (X, critical) | | | |
| secrets | `sec:detect` (sensitive — scanners legitimately) · `sec:read` (X, critical) · `sec:transmit` (X, critical) | | | |

Notes: `w:agent_instructions` and `ovr:harness_config` overlap deliberately (dual-tagged findings dedupe by fingerprint; both buckets get fed per arch-review §9 disjoint-dimension rule). Exfiltration is **not** a facet — it is a correlator composite (sec:read/transmit × net:upload) whose legs already carry facets; composing at the facet layer would double-count.

Claim syntax: `capabilities = ["network", "write:w:workspace"]` or bare `["network:fetch"]` (bucket prefix elided when unambiguous). Unknown facet in a claim ⇒ parse warning + treated as bucket-wide claim (generous-to-author direction avoids punishing typos with accusation-grade labels).

---

## 3. Actual set and the five-valued diff

### 3.1 Admission to `actual` (refines "findings ≥ 0.6")

1. Any finding with `confidence ≥ 0.6` ⇒ its `{bucket, facet}` is a **full member** (drives penalties).
2. Correlator composites ⇒ members, inheriting strongest leg's facet.
3. **Weak members**: primitive observations (AST call sites, imports) with no ≥0.6 finding ⇒ printed in the capability table, drive *nothing* numeric. They exist so reviewers see "this skill touches `os.environ` but no rule fired."
4. Lexical-only evidence caps at 0.5 by D-FP ⇒ can never constitute `actual` alone. Runtime (L3, v1.x) outranks everything when it lands.

Terminology fix (**D-P5**): what the current spec calls "declared tools" feeding *actual* splits cleanly — manifest-declared tools ⇒ **claimed** (§1.6 anchors apply symmetrically: declaring `gh` claims its capability set); code-observed primitives ⇒ weak members of **actual**.

### 3.2 Diff algebra

For each actual member `c`:

| Condition | Verdict | Street default |
| --- | --- | --- |
| negative claim covers c | **VIOLATION** | alert; violation-class penalty; hard-floor eligible (scoring phase decides numbers) |
| claimed(c), c's facet not `X` | **SANCTIONED** | printed, severity capped at review (taxonomy §3.1 rule 3); lab mode drops to notice |
| claimed(c) but facet is `X` | **UNDECLARED (critical-facet)** | alert — bucket claims never launder critical facets (D-C3) |
| ¬claimed, description affirmed narrower scope | **OVERREACH** | warn; alert if facet critical |
| ¬claimed, claim_specificity = low | **UNDECLARED (vague)** | notice |
| ¬claimed, otherwise | **UNDECLARED** | notice (routine) / warn (sensitive) / alert (critical) |

And for each claimed-but-unused capability: **UNUSED CLAIM** — hygiene note (Android overprivilege analog; medium-low; feeds "trust erosion" section, not the security score). Overreach definition is now precise and mechanical: *∃ affirmative scope statement S ∧ actual ⊄ S*. No scope statement ⇒ no overreach, only undeclared. This is what makes the word trustworthy.

---

## 4. `policy.toml` — schema v1

### 4.1 Provenance & merge (R1 restated as mechanics)

```text
layers (lowest→highest):  builtin preset  ←  $XDG_CONFIG_HOME/xray/policy.toml  ←  --policy FILE (repeatable, ordered)
merge: scalars/enums last-wins; lists REPLACE; [[purpose.exempt]] / [[assumptions]] entries APPEND
trust: project-local policy files load ONLY if recorded via `xray trust add <dir>`; otherwise
       report prints: "ignored untrusted project policy: .xray/policy.toml (xray trust add to enable)"
provenance: report stamps policy_layers: [{source, sha256, mode}] — report stays f(IR, rules, policy)
errors: schema violations, unknown keys, bad globs/regex ⇒ exit 3 (config error), never silent skip
```

### 4.2 Schema with comments

```toml
schema_version = 1
mode = "street"                    # "street" (default) | "lab"

[gate]                             # CI contract; advisor defaults are all no-ops
fail_on = ""                       # "" = never fail. e.g. ">=warn", "alert", "score<=70",
                                   # "violation|overreach", "severity>=high && confidence>=probable"
max_report_findings = 0            # 0 = unlimited; >0 fails if table exceeds (CI noise valve)

[purpose]                          # who is allowed to do what — the declared-purpose exemption,
                                   # enforced HERE (policy), not in engines (arch-review D-FP)
[[purpose.exempt]]
match.name = ["pentest-*", "*-redteam"]       # glob on validated skill name, OR
match.tags  = ["security-testing"]            # frontmatter tags, OR
match.hash  = "sha256:…"                      # exact snapshot pin (strongest)
allow   = ["shell:*", "network:net:fetch", "secrets:sec:detect"]
scope.home = false                            # exemption refuses r:credentials/r:dotfiles regardless
note = "internal red-team pack"               # MANDATORY; printed wherever the exemption fires

[hosts]
deny  = ["*.webhook.site", "requestbin.*", "pastebin.com", "*.telegram.org", "*.onion"]
allow = ["api.github.com", "*.githubusercontent.com"]
public_suffix = false              # true ⇒ bare "github.io" style entries match any private suffix member
                                   # (PSL bundled, version-stamped); keep false unless you mean it

[paths]
allow_write = []                   # extra writable roots beyond workspace, glob: "~/sandboxes/**"
allow_read  = []                   # e.g. "~/datasets/**" (stops undeclared r:dotfiles-class noise, narrowly)

[assumptions]                      # environment-wide baselines; each silences ONE facet class, loudly
# shell_interpreter = true         # "I accept any skill spawning local processes" — prints once per report
# network_fetch = false            # default: no blanket assumptions

[labels]                           # per-verdict loudness overrides (rarely touched; presets set these)
# overreach    = "warn"            # notice|warn|alert
# undeclared   = "auto"            # "auto" = danger-class table (§3.2)
# unused_claim = "notice"
```

### 4.3 Presets

**street (default)** — §3.2 table verbatim. Sanctioned behavior still prints (capped at review): users should *see* what a skill does even when it confessed. Gate off; exit 0 unless `--fail-on`.

**lab** — for auditing your own arsenal / red-team packs:

```toml
# xray doctor --print-preset lab
schema_version = 1
mode = "lab"
[labels]
undeclared   = "auto"    # UNCHANGED from street — the whole point (D-P2)
overreach    = "auto"    # UNCHANGED
violation    = "alert"   # UNCHANGED
sanctioned   = "silent"  # the ONLY relaxation: confessed behavior stops printing
unused_claim = "silent"
```

Lab is intentionally tiny: three label flips. It cannot touch gates for undeclared/overreach/violation, cannot widen `purpose.exempt`, cannot edit host denies. A future `lab-plus` preset may relax more, behind a new schema_version and a changelog entry — never by editing street.

### 4.4 Worked example — user policy for a pentest shop

```toml
schema_version = 1
mode = "street"

[gate]
fail_on = "violation || overreach || (undeclared && class==critical)"

[[purpose.exempt]]
match.tags = ["security-testing"]
allow = ["shell:*", "network:net:fetch", "network:net:raw_socket", "secrets:sec:detect"]
scope.home = false
note = "eng-approved offensive-tooling skills; credential READS still flagged"

[hosts]
deny  = ["*.webhook.site", "pastebin.com"]
allow = ["api.github.com", "*.internal.corp"]
public_suffix = false
```

Effect: `nmap-helper` (tags security-testing, opens sockets to lab ranges) → sanctioned, silent in lab mode, one-line in street. Same skill hitting `pastebin.com` → undeclared net:upload + host-deny corroboration → alert regardless of mode or exemption (deny beats everything; exemptions never authorize denied hosts).

---

## 5. Allowlist UX

**Domains (hosts).** Semantics, precisely: entry matches one hostname or a wildcard; `*` spans **exactly one label** (`*.githubusercontent.com` matches `raw.githubusercontent.com`, not `a.b.githubusercontent.com`); `**.` spans many (`**.corp` matches `a.b.corp`); apex form `example.com` is exact-host only; `psl:github.io` (or `public_suffix = true`) matches every member of a public suffix — flagged as broad in `xray policy lint`. `re:` prefix enables anchored regex, compiled with the linear-time engine, rejected at load on invalid patterns (exit 3), and rendered in reports as `re:…` verbatim (regexes are audit surfaces too). **Order-independence: deny wins.** Matching happens against the finding's normalized host; port stripped; IDNA-canonicalized (reuse ingest's NFC/confusable pass — punycode lookalikes of allowlisted hosts do NOT match, and the mismatch is itself a finding).

**Paths.** Glob with `~` expansion against the *user's* home (never the skill's), `**` recursive, canonicalized per ingest rules; symlink-jail respected (an allow for `~/datasets/**` does not admit `~/datasets/link → ~/.ssh`).

**Names/tags (purpose.exempt).** Globs on the validated skill `name`; tags come from frontmatter `tags` (proposed convention) — note tags are author-controlled, so `hash` pins exist for real enforcement; docs say plainly: name/tag matches are convenience, hash pins are guarantees.

**Ergonomics.** `xray policy lint` validates + prints effective merged policy + simulates: `--simulate <finding.json>` answers "would this be suppressed?"; `xray doctor --print-preset street|lab` emits commented starter files. Suppressions-with-reasons stay in `ignore.toml` (D-FP) — policy expresses *what is acceptable in general*, ignore expresses *"this specific fingerprint, until expiry"*; the report renders both, distinctly.

---

## 6. Explaining overreach without an LLM

Explanations assemble from **deterministic slots** — no generation, only selection + interpolation. Template catalog is versioned data (`templates/explain-{version}`), so outputs are golden-testable bytes.

Slots: (1) verdict + facet + danger class; (2) the claim quote with coordinates (or the explicit no-claim statement); (3) finding fingerprint, rule id, snippet with decode badges, confidence + evidence kind; (4) the *why-uncovered* clause selected from a closed rule set; (5) remedies.

Why-uncovered clauses (closed set — this is the epistemic core):

| Situation | Clause |
| facet is `X`-class, only bucket claimed | "Bucket-level declaration cannot cover critical-class capability `w:agent_instructions`; an explicit facet declaration is required." |
| scope narrower than actual | "Description restricts scope to `*.sql` (SKILL.md:4); observed write target `~/.zshrc` lies outside it." |
| disavowal contradicted | "Description states 'fully offline' (README.md:8); finding XR-NET-004 observes an HTTP client constructing a request." |
| no claims at all (vague) | "Description makes no capability statements (specificity 0.4, below 1.0). All observed capabilities are therefore undeclared — this is a description-quality issue, not proof of intent." |
| negative claim conflict | "Surfaces disagree: frontmatter declares `allowed-tools: Bash`, README states 'no shell access'. The stricter claim governs." |

Rendered example (default voice; the personality module owns optional voices):

```text
⚠ OVERREACH — write:w:agent_instructions (critical)
  claim    "Formats and lints SQL files in your project"  (SKILL.md:4)
           declares: none · scope: *.sql only
  evidence scripts/setup.sh:18 — printf '%s\n' 'export PATH=…' >> ~/.zshrc
           XR-OVR-002 · conf 0.82 · direct AST match
  why      Description affirms a scope (*.sql) narrower than observed behavior;
           instruction-file writes are critical-class and cannot inherit from
           an unrelated or absent declaration.
  options  fix the description + declare capabilities · suppress w/ reason
           (fingerprint 9f2a…) · remove skill
```

And the honest vague case:

```text
· UNDECLARED (description unclear) — network:net:fetch
  claim    no capability statements found (specificity 0.3) — "A helpful
           assistant that supercharges your workflow" (SKILL.md:4)
  evidence src/index.js:88 — fetch(`https://${cfg.telemetry}/v1`, …)
           XR-NET-001 · conf 0.71
  why      Vague descriptions earn benefit of the doubt on *intent*, not on
           *reporting*: undeclared stays visible at notice level.
  options  declare capabilities in frontmatter · suppress w/ reason
```

LLM captioner boundary: if enabled, its paraphrase lands as an `[ai-note]` line beneath the template block — never in `claimed`, never in the score, stamped in provenance. Off by default (unchanged posture).

---

## 7. Worked micro-cases (calibration anchors)

| Skill | Description | Observed | Diff outcome |
| --- | --- | --- | --- |
| `sql-formatter` | "Formats and lints SQL files in your project" | parses `*.sql`, writes `*.sql` back | sanctioned (w:workspace, r:workspace); appends `export PATH=` to `~/.zshrc` ⇒ **OVERREACH** (scope narrower than reality) + critical facet ⇒ alert |
| `workflow-helper` | "A helper that supercharges your workflow" | fetches `cfg.telemetry` host | **UNDECLARED (vague)** net:fetch, notice + XR-META-VAGUE; had it POSTed `process.env` ⇒ correlator composite ⇒ undeclared critical ⇒ alert despite vagueness (vagueness softens *wording*, never the critical class) |
| `offline-notes` | "Works fully offline, stores notes locally" | zero network, writes `~/notes/` | sanctioned; claimed−actual = {} ; clean |
| `pentest-nmap` (tags security-testing, user §4.4 policy) | "Port-scans targets you specify" | sockets, raw packets to lab CIDRs | sanctioned via purpose.exempt (net:raw_socket explicitly allowed); hits `scan.io` (denied? no — allowed list only affects *suppression*; undeclared host finding still fires) ⇒ undeclared net:fetch warn in street, silent sanctioned-row in lab |
| `postmark-style mailer` v1.0.15 | "Sends email via Postmark API" | `api.postmarkapp.com` only | sanctioned (net:fetch + net:upload to declared host family) — history clean; v1.0.16 adds BCC header to attacker domain ⇒ host Δ + net:upload undeclared ⇒ alert + rug-pull diff marker (quiet-history-then-new-fingerprint) |

Case 2 is the crux: vagueness changes the *label*, never the *class*. Deception hiding behind mush still reaches alert through facet danger class + correlator composites.

---

## 8. Interfaces & handoffs

- **Scoring phase:** consumes the five verdicts + danger classes as disjoint dimensions (arch-review §9). Numbers theirs; this doc guarantees: violation > overreach > undeclared ordering, sanctioned capped-at-review, vague-undeclared floors at notice, unused-claim out of the security score.
- **Report UX:** capability table columns `{bucket, facet, claimed?, actual, verdict}`; claim quotes in header block; `[ai-note]` line spec'd here.
- **Fun/personality:** explanation templates are data — alternate voices swap the template pack, never the slots.
- **HARD_QUESTIONS candidates:** (a) promote `capabilities:`/`tags:` frontmatter as an ecosystem convention (upstream PRs to skill authors?) — cheap trust win, slow burn; (b) default `[assumptions] shell_interpreter` on/off for developer audiences; (c) ship `re:` regex allowlists in v1 or defer (escape hatch now vs audit-surface discipline).
- **Lexicon governance:** lexicon + tool-table versions stamped in reports beside `rule_pack_version`; additions cite benign-corpus PR numbers (same bar as rules).

Open items deferred: multilingual lexicons (v1.1, community data files); LLM captioner promotion criteria (needs eval showing ≥ human-agreement on claim extraction without hallucinated grants — until then D-C2 stands); runtime L3 evidence joining `actual` at highest tier (v1.x, slot already reserved in §3.1).
