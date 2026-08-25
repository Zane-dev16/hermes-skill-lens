#!/bin/sh
# Print git status with ANSI color (SGR only).
printf "%s\n" "$(git status --short)"
echo "[32mclean[0m"
