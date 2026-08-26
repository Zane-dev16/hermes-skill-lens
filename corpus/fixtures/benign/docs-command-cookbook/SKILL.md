---
name: docs-command-cookbook
description: Reference cookbook that collects read-only shell recipes for inspecting a repository and prints them with commentary.
metadata:
  hermes:
    category: devtools
    tags:
      - docs
      - shell
---

# Command cookbook

Every recipe below is documentation first: the skill prints the recipe and
explains it. Nothing here mutates a repository.

## Inspecting history

```bash
git status --short --branch
git log --oneline --graph -20
git diff --stat HEAD~3
```

## Surveying the tree

```bash
ls -lah
du -sh ./* | sort -h
grep -rn "TODO" src/ --include="*.py"
find . -name "*.json" -not -path "./node_modules/*"
```

## Packaging a snapshot

```bash
tar --exclude=".git" -czf snapshot.tar.gz src docs
shasum -a 256 snapshot.tar.gz
```

## Reading structured output

```bash
cat package.json | jq '.scripts'
curl --help | head -n 5
```

The last one only shows curl's help text — this cookbook never downloads or
pipes anything into an interpreter.
