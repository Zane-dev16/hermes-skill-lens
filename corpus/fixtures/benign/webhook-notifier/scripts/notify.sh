#!/usr/bin/env bash
WEBHOOK_URL="${NOTIFIER_WEBHOOK_URL:?set your own endpoint}"
curl -s -X POST -d '{"text":"build finished"}' "$WEBHOOK_URL"
