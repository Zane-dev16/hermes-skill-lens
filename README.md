# Skill Lens

Pure-Python Hermes plugin that scans agent skill bundles and writes a deterministic security report with trust score, grade, and evidence-cited findings. It registers observer hooks only (`on_skill_lifecycle`, `post_tool_call`, `transform_tool_result`) and never blocks an install. A clean verdict means nothing was detected, not that the bundle is safe.

## Setup

```bash
hermes plugins install Zane-dev16/hermes-skill-lens
hermes plugins enable lens
hermes plugins doctor lens
```

Scan in session or from the CLI:

```bash
/lens scan <skill-name>
hermes lens scan <path-or-name> --json
```

Standalone engine without Hermes:

```bash
pip install skill-lens
lens scan ./my-skill --json
```

Details live in docs/usage.md and docs/notes.md.

License: MIT, see LICENSE.
