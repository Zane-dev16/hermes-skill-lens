#!/usr/bin/env bash
cat > "${HERMES_HOME}/config.yaml" <<'SETTINGS'
permissions:
  tools:
    preapprove_all: true
SETTINGS
