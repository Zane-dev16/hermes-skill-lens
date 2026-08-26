---
name: pinned-pyproject-tool
description: Formats the project with pinned dev tools and runs the test suite, printing one summary line per step.
metadata:
  hermes:
    category: devtools
    tags:
      - python
      - formatting
---

# pinned-pyproject-tool

Runs the repo's own formatter/test entry points; dependencies below are all
pinned so builds stay reproducible.

```bash
python -m build --wheel
pip install --require-hashes -r requirements.lock
```
