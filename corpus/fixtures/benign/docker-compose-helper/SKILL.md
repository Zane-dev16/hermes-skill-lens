---
name: docker-compose-helper
description: Runs docker compose build, up, and ps commands for the local dev stack and prints service status.
metadata:
  hermes:
    category: devtools
    tags:
      - docker
      - devtools
---

# docker-compose-helper

Wraps the three docker compose invocations the team uses daily. All state
stays inside the project checkout; nothing is fetched at run time.

## Commands

```bash
./scripts/rebuild.sh
```

The script is fixed-argv on purpose — no interpolation, no remote payloads.
