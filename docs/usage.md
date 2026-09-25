# Usage

## Exit codes

One rule holds for `scan`, `report`, `doctor`, and `rules verify`. Exit 0 is the advisor default and findings alone never change it. Exit 1 happens only on an explicit `--fail-on` breach. Exit 2 signals a total error such as a malformed policy, an unresolvable target, a failed doctor check, or a rejected pack.

The `--json` surface carries the same judgment for automation: `score.verdict` (`CLEAN`, `NOTICE`, `WARN`, `ALERT`) plus the boolean `score.needs_review`.

```bash
hermes lens scan <path-or-name> --json
hermes lens scan <path-or-name> --fail-on alert
lens scan ./my-skill --fail-on notice --sarif-out lens-results.sarif
```

## CI

The composite GitHub Action scans a path, writes SARIF, and gates only on the `fail-on` input. The supported pin is a full 40-hex commit SHA.

```yaml
- uses: Zane-dev16/hermes-skill-lens@v1
  with:
    path: ./skills
    fail-on: notice
    lens-source: git
    lens-ref: <full 40-hex commit SHA>
```

Self-check when anything looks off:

```bash
hermes lens doctor
hermes lens rules verify
```
