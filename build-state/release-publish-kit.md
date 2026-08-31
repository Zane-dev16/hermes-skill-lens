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

## PyPI publish — TestPyPI-first (v1.0, owner-run, SHA-pinned)

This box holds **no PyPI or GitHub tokens** (D-064 posture) — publishing is
owner-run. The package name `skill-lens` and the console script `lens` MUST be
checked for collisions on TestPyPI **before** any real publish.

### Name-collision pre-check

```sh
# PyPI project name availability (TestPyPI first, then PyPI)
curl -s https://test.pypi.org/simple/skill-lens/ | head -n 20
curl -s https://pypi.org/simple/skill-lens/ | head -n 20
# If either returns 200 with content, the name is taken.

# Console-script collision (TestPyPI wheel install in a clean venv)
python -m venv /tmp/lens-publish-check
/tmp/lens-publish-check/bin/pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ skill-lens --dry-run 2>&1 | head -n 20
# Search https://test.pypi.org/project/skill-lens/ for an existing console_script `lens`.
```

### Publish workflow (SHA-pinned, Trusted Publisher)

Tag-triggered workflow (`.github/workflows/publish.yml`, owner-maintained) uses
the SHA-pinned action:

```yaml
- uses: pypa/gh-action-pypi-publish@67fea6c8c4b9bec66d6d4759856e03bf7f3a082ae  # v1.13.0
  with:
    repository-url: https://test.pypi.org/legacy/  # TestPyPI first
```

1. Owner stores a **TestPyPI API token** as repository secret `TEST_PYPI_API_TOKEN`
   (or project-scoped trusted publisher) — this token never touches the
   build box.
2. On annotated tag push `v1.0.0` (cut by `scripts/release.py` which bumps
   plugin.yaml + pyproject.toml together — single-source version law), the
   workflow builds sdist+wheel (`python -m build`) and publishes to TestPyPI
   via the SHA-pinned action.

### TestPyPI smoke (owner-run, clean venv)

```sh
python -m venv /tmp/lens-testpypi-smoke
/tmp/lens-testpypi-smoke/bin/pip install --upgrade pip
/tmp/lens-testpypi-smoke/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  skill-lens
/tmp/lens-testpypi-smoke/bin/lens --help
/tmp/lens-testpypi-smoke/bin/lens scan corpus/fixtures/benign/pinned-deps-helper --json >/dev/null
python -m twine check dist/*   # already gated in ci packaging job
```

If the smoke passes (exit-code matrix 0/1/2 as in ci `packaging` job, degraded
goldens byte-exact without `[ast]` extras), proceed to PyPI.

### PyPI (Trusted Publisher, no long-lived secret)

Once the TestPyPI artifact is verified, the project is registered on PyPI
(`skill-lens` ownership claimed). Publishing then switches to
**Trusted Publisher (OIDC)** — no long-lived secret stored:

```yaml
# PyPI Trusted Publisher — uses id-token, no api-token secret
permissions:
  id-token: write
  contents: read
- uses: pypa/gh-action-pypi-publish@67fea6c8c4b9bec66d6d4759856e03bf7f3a082ae
  # no repository-url → defaults to https://upload.pypi.org/legacy/
```

Configure the publisher at https://pypi.org/manage/account/publishing/ with
repository `Zane-dev16/hermes-skill-lens`, workflow `publish.yml`, environment
`pypi`. After that, the same tag push publishes to PyPI with an ephemeral
`id-token` — owner-run, no token material on any developer box.

### Order of record

1. `scripts/release.py cut --plugin-version 1.0.0` (single-source bump, signed
   artifact `dist/lens-core-pack-YYYY.MM.N.zip` unchanged by packaging).
2. `git push origin v1.0.0` (SSH tag push is the release per D-064).
3. Publish workflow → TestPyPI (SHA-pinned action).
4. Clean-venv smoke from TestPyPI (above).
5. Re-run workflow targeting PyPI (or re-tag with Trusted Publisher) — first
   PyPI version is `1.0.0`.

### Post-publish self-dogfood

After the first PyPI publish, enable the repo-owned dogfood workflow that
consumes `action.yml` with `lens-source: pypi` and `lens-version: 1.0.0`
(gated behind the owner credential setup above).
