#!/usr/bin/env sh
# Show the server-side diff, then a client-side dry-run apply. Never mutates.
set -eu
cd "$(dirname "$0")/.."
kubectl diff -f k8s/ || true
kubectl apply -f k8s/ --dry-run=client
kubectl get events --field-selector type=Warning
