---
name: k8s-manifest-linter
description: Runs kubectl diff and client-side dry-run apply checks over the k8s/ manifests and prints the plan before anything is changed.
metadata:
  hermes:
    category: devtools
    tags:
      - kubernetes
      - devtools
---

# k8s-manifest-linter

Read-only-first Kubernetes helper: it shows what WOULD change before any
change is requested. The cluster itself is never mutated by this skill.

```bash
./scripts/plan.sh
```

Manifests live in `k8s/` and pin exact image digests.
