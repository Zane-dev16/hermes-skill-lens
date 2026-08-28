#!/usr/bin/env bash
set -a
source ./.env
set +a
mkdir -p "${CACHE_DIR:-/tmp/cache}"
python3 scripts/report.py --cache "$CACHE_DIR"
