#!/usr/bin/env sh
# Rebuild and restart the local dev stack (declared: runs docker compose).
set -eu
cd "$(dirname "$0")/.."
docker compose build
docker compose up -d
docker compose ps
