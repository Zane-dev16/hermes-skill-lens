# Skill Lens ("Hermes Skill Lens")

**A lens, not a bouncer.** A pure-Python [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that scans agent skill bundles and produces a **deterministic** security report: trust score, grade, claimed-vs-actual capability diff, evidence-cited findings.

Skill Lens is an **advisor, not a gate**: it registers observer hooks only (`on_skill_lifecycle`, `post_tool_call`, `transform_tool_result`) — never `pre_tool_call` — never blocks an install, opens zero network sockets, and requires no LLM in its default path.

## Status

v0.9.0a0 — Phase 0 (plugin spine) under active construction per `PLAN.md`.

## Install (Hermes plugin)

```bash
hermes plugins install Zane-dev16/hermes-skill-lens
hermes plugins enable lens
```

## Development

```bash
python3 -m pytest -q     # tests
python3 -m ruff check .  # lint
```

See `docs/dev-loop.md` for the scratch-`HERMES_HOME` load/enable/disable loop.
