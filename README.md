# Skill Lens ("Hermes Skill Lens")

**A lens, not a bouncer.** A pure-Python [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that scans agent skill bundles and produces a **deterministic** security report: trust score, grade, claimed-vs-actual capability diff, evidence-cited findings.

Skill Lens is an **advisor, not a gate**: it registers observer hooks only (`on_skill_lifecycle`, `post_tool_call`, `transform_tool_result`) — never `pre_tool_call` — never blocks an install, opens zero network sockets in its default path, and requires no LLM. static analysis only — runtime-injected instructions are out of scope · clean != safe

## Quickstart

1. **Install** (Hermes plugin; flat directory, discovered from your plugins dir):

   ```bash
   hermes plugins install Zane-dev16/hermes-skill-lens
   # or from a checkout:
   ln -s "$PWD/hermes-skill-lens" "$HERMES_HOME/plugins/lens"
   ```

2. **Enable**:

   ```bash
   hermes plugins enable lens
   hermes plugins doctor lens        # runtime load proof (registration lines are expected)
   ```

3. **First scan** — either lane:

   ```bash
   /lens scan <skill-name>           # in-session; queue-first, answers inline on cache hits
   hermes lens scan <path-or-name> --json   # CLI; add --fail-on alert for CI gates
   ```

4. **Reading reports**: `/lens report [name]` renders the full report (verdict line,
   findings with evidence citations, score/grade); `--json` and `--sarif` give machine
   surfaces whose `score.verdict` (+ `needs_review`) is THE automation interface. Every
   surface ends with a coverage-honesty footer naming the rule-pack version + checksum.
   A clean verdict means "nothing detected", not "safe" — see docs/threat-model.md.

5. **Self-check** when anything looks off: `hermes lens doctor` (nine checks incl.
   offline signature verification of the rule pack).

Rule packs travel signed and version-pinned with the plugin (`YYYY.MM.N`,
SPEC §15). Verify provenance any time: `hermes lens rules verify`. Updates
are manual-only by design. Community packs are opt-in and SHA-pinned via
`.lens/packs.toml` (local-path-only, fail-closed; see `lens rules list`).

## Standalone CLI (PyPI)

The same engine ships as a zero-dependency pure-Python package with a
`lens` console script (one grammar, one §18 exit-code law with the host
lane; the wheel degrades to the golden-tested line-scanner lane without
grammars — that is the honest contract):

```bash
pip install skill-lens[sig]      # + [ast] for the AST grammar lane
lens scan ./my-skill --json
lens scan ./my-skill --fail-on notice --sarif-out lens-results.sarif
```

## CI (GitHub Action)

```yaml
- uses: Zane-dev16/hermes-skill-lens@v1   # pin the release SHA to audit
  with:
    path: ./skills
    fail-on: notice
    lens-source: git
    lens-ref: <full 40-hex commit SHA>   # the supported pin
```

Writes canonical SARIF, uploads to code scanning (guarded on exit 2), and
gates on the §18 contract. See `docs/github-action.md`.

## Status

v0.9.0a0 — Phases 0–4 gated PASS; Phase 5 (governance + release engineering)
landed per `PLAN.md` §1. See `CHANGELOG.md`.

## Development

```bash
python3 -m pytest -q     # tests
python3 -m ruff check .  # lint
python3 scripts/release.py --help        # release engineering
python3 scripts/sign_core_pack.py show   # pack signature status
```

See `docs/dev-loop.md` (scratch-HERMES_HOME loop), `docs/rule-author-guide.md`
(adding rules), `docs/key-ceremony.md` (signing).
