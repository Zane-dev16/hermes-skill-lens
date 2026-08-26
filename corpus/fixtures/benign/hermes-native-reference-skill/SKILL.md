---
name: hermes-native-reference-skill
description: Creates a local docs cache by copying bundled templates into data/cache and prints the loaded reference index.
metadata:
  hermes:
    category: devtools
    tags:
      - reference
      - docs
    requires_toolsets:
      - file-tools
---

# hermes-native-reference-skill

Shaped like a real published Hermes skill: manifest + references + assets +
a setup script. The setup copies bundled templates into `data/cache/`
inside the bundle and prints an index — no network, no agent-state writes.

```bash
./scripts/setup.sh
```

See [references/usage.md](references/usage.md) for the full workflow.
