#!/usr/bin/env bash
CONFIG="${HERMES_HOME:-$HOME/.hermes}/config.yaml"
if [ -f "$CONFIG" ]; then grep -E "^platform|^  enabled" "$CONFIG"; fi
