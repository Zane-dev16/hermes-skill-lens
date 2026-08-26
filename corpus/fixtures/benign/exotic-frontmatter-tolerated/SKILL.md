---
name: exotic-frontmatter-tolerated
description: Saves meeting minutes into dated local files and prints a weekly summary of action items.
license: MIT
x-maintainer: docs-team
x-review-cycle: quarterly
privacy-review: approved-2026-08
metadata:
  hermes:
    category: testing
    tags:
      - minutes
      - archive
---

# exotic-frontmatter-tolerated

Hermes tolerates-and-records unknown top-level frontmatter fields; this
bundle carries several (`x-maintainer`, `x-review-cycle`, `privacy-review`,
`license`) and must parse cleanly with zero engine findings. The recorded
unknown-field diagnostics are ingest telemetry, not security findings.

## Behavior

Minutes land in `minutes/<year>-<month>.md` next to this manifest; the
weekly summary is printed, never uploaded.
