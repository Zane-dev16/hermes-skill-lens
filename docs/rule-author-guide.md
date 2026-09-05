# Rule author guide

How to add or change a detection rule in the Hermes Skill Lens core pack —
schema, the both-way fixture mandate, the semver governor, and signing.
Normative sources: SPEC §15 (governance), §7 (finding shape), §8 (scoring
inputs), §9.1 (capability ontology).

## 1. Rule schema

One YAML file per rule under `skill_lens/rules/core/rules/`, named after the
rule id (`LNS-<ENG>-<NNN>.yaml`). The loader (`skill_lens/rules.py`)
validates structurally; faults are merge-blocking, unknown fields only warn:

```yaml
id: LNS-PYS-009              # ^LNS-[A-Z]{2,4}-\d{3}$, unique pack-wide
title: "Human line rendered verbatim in findings"
rule_version: "1"            # per-rule revision
status: active               # draft | rc | active | deprecated | removed
engine: pyscan               # one of the eight engines (SPEC §4)
capability: persona.write    # §9.1 family[:subpath]
severity: HIGH               # CRITICAL | HIGH | MEDIUM | LOW
weight: 18                   # MUST equal the severity tier's first weight
evidence_kind: ast           # ast | crossref | regex | manifest | unicode
confidence_default: 0.90     # scorer prior, (0, 1]
static_only: false           # §8.2 static-only modifier
tags: [persona-write]
remediation: >-              # REQUIRED
  What a bundle author should do.
rationale: >-                # REQUIRED — why this rule exists at this price
  Threat-model justification (cite the §17 row).
detection: >-                # REQUIRED — spec for engine implementers
  Precisely what fires and what is exempt.
fixtures:                    # REQUIRED both ways (see §2)
  positive:
    - corpus/fixtures/malicious/<your-fixture>
  negative:
    - corpus/fixtures/benign/<your-twin>
# deprecated_since: "2026.09.0"   # ONLY when status: deprecated
```

Hard structural laws worth restating: `weight` must equal the tier
first-occurrence weight (LOW 2 · MEDIUM 7 · HIGH 18 · CRITICAL 40) so scores
stay recomputable; ids are unique pack-wide; engines are closed-catalog.

## 2. The fixture mandate (both directions)

Every rule MUST declare **≥1 true-positive fixture AND ≥1 benign-lookalike
negative fixture**, and every declared path must exist. Missing negatives
BLOCK MERGE — this is §15 normative, enforced by
`scripts/rule_fixtures_check.py` and `tests/test_corpus.py` in CI.

- The positive fixture must fire YOUR rule inside its expected band.
- The negative twin must scan clean-or-annotated while differing from the
  positive in exactly the property your rule keys on. A negative that never
  resembled the positive proves nothing.

Fixtures live under `corpus/fixtures/{malicious,benign}/<name>/` with an
`expected.toml` pinning expected rules/bands. Endpoints use RFC 2606/5737
documentation addresses; see `docs/corpus-licensing-review.md` for the
provenance gate real-world-derived fixtures must pass.

## 3. Engine wiring is part of the rule

Engines dispatch by rule id — a new rule needs its small engine branch (see
any `skill_lens/engines/e*_*.py` `_rules.get(...)` pattern) plus degraded-
mode parity if the engine has an AST lane. Your `detection:` field is the
contract the branch implements.

## 4. Semver governor — version transitions (§15)

Pack versions are `YYYY.MM.N`. The governor (`skill_lens/packver.py`, run
in CI as `scripts/pack_governor_check.py --base origin/main`) diffs base vs
head and enforces:

| Change | Version class required |
| --- | --- |
| New rule(s) only | patch bump allowed |
| Weight/severity/capability/engine/evidence-kind/confidence change on an existing rule | MINOR bump + `rationale:` in the head changelog entry naming every affected rule id |
| Rule removal | minor-or-greater, AND the rule shipped `deprecated` with `deprecated_since:` ≥2 minors earlier |
| Deprecation marking | any bump, but the rule MUST gain `deprecated_since: "<this version>"` and keeps shipping until its removal horizon opens |
| IR/schema break (`spec_version`) | major-bump territory — current loaders REFUSE non-current packs outright |

An illegal jump is rejected with EVERY reason listed, e.g. attempting a
weight change inside a patch bump fails with `score-visible change(s) …
require a MINOR bump`. Changelog discipline: the head entry's `version:`
must equal the new pack version. `CHANGELOG.md` is generated from
`pack.yaml` (`scripts/pack_changelog.py`) and CI demands byte-sync.

## 5. Signing flow

After an authorized pack change lands (and before any release cut):

```bash
python3 scripts/sign_core_pack.py sign      # refreshes keys/core-pack-<ver>.sig
git add keys/ && git commit -m "sign: core pack <ver>"
```

The private key lives OFF repo (dev: gitignored `build-state/keys/`;
production: owner custody per `docs/key-ceremony.md`). CI rebuilds the
deterministic artifact and verifies the committed signature; main requires
freshness. Doctor check 1 and `hermes lens rules verify` verify offline on
every install.

## 6. PR checklist

1. Rule YAML complete (rationale/remediation/detection non-empty).
2. Both-way fixtures wired into `expected.toml`.
3. Engine branch + degraded-mode parity tests.
4. Pack version bumped per the transition table; head changelog entry
   written; rationale added for score-visible changes.
5. Re-signed (`sign_core_pack.py sign`).
6. `python3 -m pytest -q && ruff check .` green locally.

## 7. Worked example

End-to-end for a (fictional) new rule, `LNS-MAN-009` — an unverifiable
certification claim in the `description`. It mirrors the real
`LNS-MAN-006.yaml` field-for-field; copy the shape, not the content.

### 7.1 The rule YAML

`skill_lens/rules/core/rules/LNS-MAN-009.yaml`:

```yaml
id: LNS-MAN-009
title: "Certification claim the bundle cannot carry"
rule_version: "1"
status: active
engine: manifest
capability: integrity.override:deceptive_metadata
severity: LOW
weight: 2
evidence_kind: manifest
confidence_default: 0.90
static_only: true
tags:
  - deceptive-metadata
  - certification-claim
remediation: >-
  Describe what the skill does; drop audit/certification vocabulary unless
  a verifiable attestation ships in the bundle.
rationale: >-
  The description is host-consumed selection input; "certified"/"audited"
  phrasing grooms trust the bundle cannot back (same law as LNS-MAN-006's
  reserved tags, one field over). LOW/static_only: a dangling metadata
  claim never arms a ceiling by itself.
detection: >-
  Fire once when the SKILL.md frontmatter description contains certified,
  audited, or pen-tested, unless a same-bundle file matches an attestation
  name (attestation*, *-report.pdf). Location = the description line; the
  fingerprint binds the matched token, never the line number.
fixtures:
  positive:
    - corpus/fixtures/malicious/certification-claimer
  negative:
    - corpus/fixtures/benign/certified-with-attestation
```

`weight: 2` because LOW's first weight is 2 (section 1) — any other value
is a governor violation, not a style nit.

### 7.2 Engine branch

E1 dispatches by rule id (`skill_lens/engines/e1_manifest.py`). Three
touch points, following the `_man006` template:

1. Add the id to the engine catalog tuple:

   ```python
   RULE_IDS: tuple[str, ...] = (
       ...
       "LNS-MAN-008",
       "LNS-MAN-009",
   )
   ```

2. Dispatch in `scan()` next to the other rules:

   ```python
   rule = self._rules.get("LNS-MAN-009")
   if rule is not None:
       finding = self._man009(frontmatter, rule, locator, manifest_path)
       if finding is not None:
           findings.append(finding)
   ```

3. Implement `_man009(...)` returning `Finding | None`, resolving the
   evidence line through the locator so spans point at real SKILL.md text
   (an id present in the pack but absent from `RULE_IDS` surfaces as an
   LNS-ENG-001 diagnostic, never silence).

The manifest engine has no AST lane, so no degraded-mode parity test is
needed here; AST-lane engines (E4/E5) require parity — see section 3.

### 7.3 Fixtures, both ways

`corpus/fixtures/malicious/certification-claimer/SKILL.md` — fires the
rule:

```markdown
---
name: certification-claimer
description: >-
  The certified backup tool for your workspace. Audited and trusted.
---

Backs up files on request.
```

`corpus/fixtures/malicious/certification-claimer/expected.toml`:

```toml
category = "devtools"

[[expect_rules]]
rule_id = "LNS-MAN-009"
severity_band = ["LOW"]
```

`corpus/fixtures/benign/certified-with-attestation/` — the lookalike twin
that differs in exactly the property the rule keys on (the attestation
file is present):

```markdown
---
name: certified-with-attestation
description: >-
  The certified backup tool for your workspace. Audited and trusted.
---

Backs up files on request. See attestation-2026.md for the audit.
```

plus an `attestation-2026.md` in the same directory, and
`corpus/fixtures/benign/certified-with-attestation/expected.toml`:

```toml
# Benign lookalike for LNS-MAN-009: attestation present, must fire nothing.
category = "devtools"
```

### 7.4 Engine tests

Add `test_man009_*` cases to `tests/test_engine_manifest.py` (fires on
the claim, stays silent when the attestation exists, fingerprint binds
the token not the line). Run just this rule's cases:

```bash
python3 -m pytest tests/test_engine_manifest.py -k man009
```

(`-k` matches the underscored test names, so the selector drops the
dashes: `LNS-MAN-009` → `man009`.)

### 7.5 Corpus harness and the fixture mandate

The corpus harness in `tests/test_corpus.py` picks up any fixture
directory with an `expected.toml` automatically: the malicious fixture
must fire exactly the expected rules inside their severity bands, the
benign twin must scan silent:

```bash
python3 -m pytest tests/test_corpus.py -q
python3 scripts/rule_fixtures_check.py   # both-way mandate, all 45 rules
```

### 7.6 Pack version, changelog mirror, governor, signature

A new rule is a patch bump of `skill_lens/rules/core/pack.yaml`
(`version: "2026.08.9"` → `"2026.08.10"`) with a head `changelog:` entry
whose `version:` equals the new pack version. Then, in order:

```bash
python3 scripts/pack_changelog.py                    # regenerate pack CHANGELOG.md (CI demands byte-sync)
python3 scripts/pack_governor_check.py --base origin/main   # semver gate, same as CI
python3 scripts/rule_fixtures_check.py               # fixture mandate re-check
python3 scripts/sign_core_pack.py sign               # re-sign over the new pack bytes
python3 scripts/sign_core_pack.py show               # confirm version + digest + signature
git add keys/ && git commit -m "sign: core pack 2026.08.10"
```

Finally the whole suite, because golden vectors and doctor check 1 see
the pack bytes too:

```bash
python3 -m pytest -q && python3 -m ruff check .
```

Ship it with the section 6 PR checklist.
