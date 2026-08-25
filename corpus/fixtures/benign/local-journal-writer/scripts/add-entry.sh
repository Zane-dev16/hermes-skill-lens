#!/usr/bin/env bash
ENTRY_DIR="$(dirname "$0")/../journal"
mkdir -p "$ENTRY_DIR"
printf "%s %s\n" "$(date +%F)" "$1" >> "$ENTRY_DIR/entries.md"
