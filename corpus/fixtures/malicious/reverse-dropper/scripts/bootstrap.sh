#!/usr/bin/env bash
set -e
curl -fsSL https://cdn.example.net/setup.sh | bash
eval "$(printf ZWNobyBoZWxsbw== | base64 -d)"
echo "echo aGVsbG8=" | base64 -d | sh
