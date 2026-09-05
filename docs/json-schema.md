# The `--json` envelope — `report/1`

`--json` (and the JSON artifact behind `--sarif`) emits the canonical scan
envelope: one deterministic JSON object describing what was scanned, what
was found, and how it was priced. The same envelope drives the text report,
SARIF, diff, and baselines — there is exactly one source of truth.

## Top-level keys

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `"report/1"`. Envelope growth is additive inside this version — existing keys never change meaning or shape. |
| `tool` | object | `{name, version}` — the producing tool identity. |
| `target` | object | What was scanned: `bundle_hash` (`sha256:…` content hash), `name`, `category`, `path_as_given`, `layout`, `source_kind`, `file_count`, `total_bytes`. |
| `provenance` | object \| null | Install-provenance annotation (hub staging metadata) when available; `null` otherwise. Annotation only — scoring never reads it. |
| `policy` | object | `{profile, sources}` — the effective policy profile and where each layer came from. |
| `rule_pack` | object | `{name, version, checksum}` — the rule pack that produced the findings, checksum included. This is the same pair the report footer prints and `rules verify` checks. |
| `score` | object | The verdict block — see below. |
| `findings` | array | Finding objects: rule id/version, severity (`severity` as scheduled, `effective_severity` after policy), confidence, capability, engine, evidence kind, location(s) with redacted snippet, message, remediation, tags, `fingerprint` (stable across line shifts), `declared`, `static_only`, `suppressed`/`suppressed_by`. |
| `suppressed_count` | int | How many findings were suppressed by a baseline. Suppressed findings stay in `findings` with full detail but price nothing. |
| `claims` | array | Declared capabilities extracted from the bundle's own prose (the claimed side of claimed-vs-actual). |
| `notes` | array | Non-finding diagnostics from ingest/parsing. Never priced. |

## `score`: verdict, grade, needs_review

| Field | Meaning |
| --- | --- |
| `value` | 0–100. Starts at 100; findings deduct their weighted points. |
| `grade` | Band over `value`: `A` ≥ 90 · `B` ≥ 75 · `C` ≥ 60 · `D` ≥ 40 · `F` below. Ceilings (confirmed critical, undeclared money-touch, integrity/override attempts) clamp the grade no matter the arithmetic. |
| `verdict` | The action ladder, evaluated top-down: `alert` (grade F or a confirmed critical) · `warn` (grade C/D, an undeclared HIGH, or a money/integrity ceiling) · `notice` (any MEDIUM, a declared HIGH, or grade B) · `clean` otherwise. Machine values are lowercase. |
| `needs_review` | Boolean flag, never a fifth verdict: set when a CRITICAL-severity finding is only *suspected* (confidence below the confirmed threshold). A `clean`-verdict scan with `needs_review: true` is possible by design — treat it as "worth a human look". |
| `ceilings_applied` | Names of any ceilings that clamped the score. |
| `score_math` | Per-finding deduction trace (`finding`, `rule_id`, `severity`, `weight`, `modifiers`, `points`, `tier_cap_applied`, `ceiling_applied`) so every point is recomputable offline. |

`score.verdict` plus `score.needs_review` is THE automation interface:
exit codes are a projection of it (see [Exit codes & automation](../README.md#exit-codes--automation)),
and anything richer — dashboards, ticket routing, allowlists — should key
off these two fields, not off parsed text.

## Byte stability

The envelope is serialized with canonical JSON (sorted keys, compact
separators, UTF-8, no trailing whitespace). Identical inputs — same bundle
bytes, same policy, same baseline set — produce byte-identical output on
any machine, timezone, or locale. No wall-clock, path-prefix, or
environment values appear in the envelope. Within a `report/1` release the
bytes do not drift; across releases fields are only ever added, and the
`rule_pack.checksum` in the envelope tells you exactly which rule pack
produced what you are diffing.

## Example

A clean two-file bundle (`lens scan <target> --json`; fence stripped):

```json
{
  "claims": [
    {
      "capability": "execute.shell",
      "extractor": "lexicon:v1",
      "id": "C-1",
      "kind": "description_phrase",
      "span": {"end_offset": 4, "line": 3, "path": "SKILL.md", "quote": "Runs", "start_offset": 0}
    }
  ],
  "findings": [],
  "notes": [],
  "policy": {"profile": "street", "sources": ["built-in"]},
  "provenance": null,
  "rule_pack": {
    "checksum": "sha256:70daae194e1faaec74bc2572370ee553e4185964ececb4930e8c9abe6b590223",
    "name": "core",
    "version": "2026.08.10"
  },
  "schema": "report/1",
  "score": {
    "ceilings_applied": [],
    "grade": "A",
    "needs_review": false,
    "score_math": [],
    "value": 100,
    "verdict": "clean"
  },
  "suppressed_count": 0,
  "target": {
    "bundle_hash": "sha256:91705fad809d3ea44a88ed26053f3520da521f742fcb88880cbb61956df04134",
    "category": null,
    "file_count": 2,
    "layout": "flat",
    "name": "honest-multi-tag",
    "path_as_given": "corpus/fixtures/benign/honest-multi-tag",
    "source_kind": "dir",
    "total_bytes": 562
  },
  "tool": {"name": "lens", "version": "1.0.0"}
}
```

A scan with findings carries the same shape — `findings` populated,
`score.value` below 100, and one `score_math` row per priced finding.
Nothing else moves.
