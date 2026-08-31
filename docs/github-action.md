# GitHub Action — Skill Lens in CI (v1.0)

The repository ships a **composite** GitHub Action at the repo root
(`action.yml`). Consumers scan their skill bundles in CI, get a canonical
SARIF 2.1.0 artifact for GitHub code scanning, and gate on the SPEC §18
exit-code contract — 0 pass, 1 `--fail-on` threshold breach, 2 total
error. There is no Docker and no new runtime: the action installs the
pure-Python `lens` package and runs it (cold p95 156.2 ms idle, well
under GitHub step ceilings; no network in the scan itself — the upload
step's network is GitHub's, not lens's).

## Consumer example

```yaml
name: skill-lens
on: [push, pull_request]
jobs:
  lens:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: Zane-dev16/hermes-skill-lens@v1
        with:
          path: ./skills
          fail-on: notice
          lens-source: git
          lens-ref: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b # full commit SHA
```

Consumers SHOULD pin their `uses:` line to the full commit SHA of the
release they audit (or a major tag like `v1` for convenience) — the same
supply-chain symmetry lens demands of its own dependencies: every
third-party step inside `action.yml` is pinned to a full 40-hex SHA, and
the repo's CI (`python3 scripts/action_check.py`) fails on any tag pin.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | scan target inside the consumer repo |
| `fail-on` | `notice` | verdict level that exits 1 (§8.4). `notice` is the documented CI stance; set `''` to restore the advisor stance (never gates; findings report only) |
| `lens-source` | `git` | `git` or `pypi` |
| `lens-ref` | — | **REQUIRED for `git`**: full 40-hex commit SHA of `Zane-dev16/hermes-skill-lens` — the supported pin (reproducible bytes) |
| `lens-version` | — | **REQUIRED for `pypi`**: exact `skill-lens` version (available after the first PyPI publish) |
| `python-version` | `3.12` | forwarded to `actions/setup-python` |
| `sarif-file` | `lens-results.sarif` | where the scan writes raw canonical SARIF (`--sarif-out`) |
| `upload-sarif` | `true` | set `false` for fork/private repos without code scanning |

## Outputs

| Output | Meaning |
| --- | --- |
| `verdict` | the envelope verdict string (`clean | notice | warn | alert`) |
| `exit-code` | the §18 code: `0` pass · `1` fail-on breach · `2` total error |

## How the gate works (and why it is split)

- The **scan step** runs with `continue-on-error: true` and captures the
  exit code (`steps.scan.outputs.exit-code`). Splitting scan and gate is
  what keeps the gate from eating the SARIF upload.
- The **upload step** is guarded:
  `if: steps.scan.outputs.exit-code != '2' && inputs.upload-sarif == 'true'`.
  Exit 2 means total error (malformed policy, unresolvable target) — the
  SARIF file may be missing or partial, and uploading it would lie.
  Code scanning maps CRITICAL/HIGH → error, MEDIUM → warning, LOW → note
  (the §12.4 mapping); `partialFingerprints.lensPrimaryFingerprint`
  gives stable baseline matching.
- The **gate step** honors 0/1/2 exactly: pass on 0, fail on 1
  (threshold breach, §8.4 CI contract) and on 2 (total error, loud),
  echoing the verdict into the job step summary.

Lens itself is installed with the `cryptography` backend so offline
signature verification (D-055) is active in CI; the scan itself never
touches the network (SPEC §14 G1/G3 hold on the consumer's runner).

## Self-dogfood (post-publish)

After the first PyPI publish, a repo-owned workflow consumes this action
with `lens-source: pypi` and `lens-version` set to the released version —
gated behind the owner-credential setup described in
`build-state/release-publish-kit.md`.
