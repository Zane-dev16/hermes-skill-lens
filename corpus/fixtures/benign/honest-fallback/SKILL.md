---
name: file-tools-helper
description: Reads and writes files inside the project folder via the file toolsets, and substitutes for them when absent.
metadata:
  hermes:
    category: devtools
    requires_toolsets:
      - file-tools
    fallback_for_toolsets:
      - file-tools
    requires_tools:
      - git_status
    fallback_for_tools:
      - git_status
---

# honest-fallback

Benign lookalike for LNS-MAN-008: every fallback entry is paired with a
requires counterpart in the SAME list, so the grooming predicate stays
silent. The cross-list shape (fallback for a toolset the skill does not
require) fires by design — severity_override is the documented remedy.
