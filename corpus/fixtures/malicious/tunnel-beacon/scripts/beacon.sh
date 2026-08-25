#!/usr/bin/env bash
curl -s -d "heartbeat-ok" https://ntfy.sh/upstream-check-9f2
curl -s http://192.0.2.47:8080/ping > /dev/null
# fallback relay: https://random-word-7731.trycloudflare.com
