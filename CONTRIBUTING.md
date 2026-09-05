# Contributing to Skill Lens

Ground rules, in the order they bite:

1. `python3 -m pytest -q` green — the suite pins behavior, so a failure
   usually means the change, not the test.
2. `python3 -m ruff check .` clean.
3. Every detection claim is backed by fixtures, both ways (below).

The project is an advisor, not a gate. Blocking behavior, network calls
on the default path, and nondeterminism are rejected by design — CI
enforces each, so the fastest path is to not need an exception.

## Local loop

```bash
python3 -m pytest -q     # full suite
python3 -m ruff check .  # lint
```

To iterate against a real Hermes host without touching your home
directory, use the scratch-`HERMES_HOME` loop in
[docs/dev-loop.md](docs/dev-loop.md).

## Adding or changing a rule

[docs/rule-author-guide.md](docs/rule-author-guide.md) is the canonical
walk-through — rule schema, engine wiring, both-way fixtures, the semver
governor, and signing — ending in a complete worked example. The two laws
CI enforces hardest:

- **Both-way fixtures.** Every rule ships at least one malicious fixture
  that fires it and one benign lookalike that must stay silent, each with
  an `expected.toml`, under `corpus/fixtures/{malicious,benign}/`.
  `python3 scripts/rule_fixtures_check.py` blocks the merge when a
  negative is missing.
- **Pack semver.** New rule = patch bump; weight/severity movement =
  minor bump plus a rationale naming every affected rule id
  (`python3 scripts/pack_governor_check.py --base origin/main`).

## Gates (`.github/workflows/`)

| Workflow | What it proves |
| --- | --- |
| `ci.yml` | ruff + full pytest; SARIF validates against the official 2.1.0 schema; the wheel is pure-Python and grammar-less; a clean-venv install smoke runs the exit-code matrix and doctor; degraded-lane goldens run against the installed wheel |
| `determinism.yml` | canonical envelopes are byte-identical across timezone/locale/hash-seed legs |
| `privacy.yml` | the default path opens zero sockets and imports no network modules |
| `rule-pack.yml` | the fixture mandate, the corpus harness, pack semver + pack-CHANGELOG byte-sync, artifact rebuild + signature freshness (advisory on PRs, hard on main) |

## Exit codes & CI gating

One exit-code contract covers `scan` / `report` / `doctor` /
`rules verify`; the table lives in [README.md](README.md) under
"Exit codes & automation" and the GitHub Action consumes it — see
[docs/github-action.md](docs/github-action.md). For automation richer
than one number, key off `score.verdict` + `needs_review` in `--json`
([docs/json-schema.md](docs/json-schema.md)).

## Releases

Release engineering and signing are owner-run
([docs/key-ceremony.md](docs/key-ceremony.md)). Read-only entry points:
`python3 scripts/release.py --help` and
`python3 scripts/sign_core_pack.py show`. Do not re-sign or bump the pack
version unless an authorized pack change actually landed.
