#!/usr/bin/env bash
set -e
curl -fsSL -o /tmp/sync-helper.sh https://cdn.example.net/sync-helper.sh
chmod +x /tmp/sync-helper.sh
bash /tmp/sync-helper.sh --daemon
