# Release publish kit — owner runbook (2026-08-28)

The SSH tag push is the release (owner ruling, D-064). What remains is
attaching the signed artifacts as GitHub Release assets for both cuts.
This box has **no GitHub API token**, so these commands are owner-run.

Artifact names are deterministic: `dist/lens-core-pack-<packver>.zip` plus
`.zip.sig` (see `scripts/release.py`). The 2026.08.8 zip appears only after
the v0.9.1 cut; it is referenced here by its deterministic name.

## Prerequisite (one-time)

```sh
gh auth login          # or: export GH_TOKEN=<personal access token>
```

## v0.9.0 — pack 2026.08.6 (tag exists: d64d1f6)

```sh
gh release create v0.9.0 \
  dist/lens-core-pack-2026.08.6.zip \
  dist/lens-core-pack-2026.08.6.zip.sig \
  --title "Skill Lens v0.9.0" \
  --notes-file build-state/release-notes-v0.9.0.md
```

## v0.9.1 — pack 2026.08.8 (after `scripts/release.py cut --plugin-version 0.9.1`)

```sh
gh release create v0.9.1 \
  dist/lens-core-pack-2026.08.8.zip \
  dist/lens-core-pack-2026.08.8.zip.sig \
  --title "Skill Lens v0.9.1" \
  --notes-file build-state/release-notes-v0.9.1.md
```

`release.py cut` emits the v0.9.1 notes skeleton
(`dist/release-notes-v0.9.1.md` by default — move or point
`--notes-file` at wherever it lands).

## curl-API alternative (if gh CLI is unavailable)

```sh
export GH_TOKEN=<personal access token>
TAG=v0.9.1
NOTES_FILE=build-state/release-notes-v0.9.1.md

# 1. create the release object (tag must already be pushed)
curl -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  https://api.github.com/repos/<owner>/<repo>/releases \
  -d "$(jq -n --arg tag "$TAG" --rawfile body "$NOTES_FILE" \
        '{tag_name:$tag, name:("Skill Lens " + $tag), body:$body}')"

# 2. attach the artifact + detached signature (upload_url from step 1)
UPLOAD_URL=$(curl -s -H "Authorization: Bearer $GH_TOKEN" \
  https://api.github.com/repos/<owner>/<repo>/releases/tags/$TAG | jq -r .upload_url | sed 's/{.*}//')
curl -X POST -H "Authorization: Bearer $GH_TOKEN" \
  -H "Content-Type: application/zip" \
  --data-binary @dist/lens-core-pack-2026.08.8.zip \
  "$UPLOAD_URL?name=lens-core-pack-2026.08.8.zip"
curl -X POST -H "Authorization: Bearer $GH_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @dist/lens-core-pack-2026.08.8.zip.sig \
  "$UPLOAD_URL?name=lens-core-pack-2026.08.8.zip.sig"
```

Repeat with `TAG=v0.9.0`, pack `2026.08.6`, and
`build-state/release-notes-v0.9.0.md` for the earlier cut.

## Verification after attaching

```sh
gh release view v0.9.0 --json assets --jq '.assets[].name'
gh release view v0.9.1 --json assets --jq '.assets[].name'
```

Each release should list exactly two assets: the pack zip and its `.sig`.
Asset SHA256 must match the value recorded in the annotated tag message
(`git tag -v` / `git cat-file tag v0.9.1`).
