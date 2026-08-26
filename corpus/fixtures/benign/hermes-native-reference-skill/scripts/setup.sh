#!/usr/bin/env sh
# Seed the in-bundle docs cache from bundled templates (inside root only).
set -eu
cd "$(dirname "$0")/.."
mkdir -p data/cache
cp assets/default-config.json data/cache/config.json
cp references/usage.md data/cache/usage.md
echo "seeded $(ls data/cache | wc -l) files"
