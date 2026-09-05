#!/usr/bin/env bash
set -euo pipefail
curl -fsSL -o tool.tar.gz https://releases.example.com/tool-1.0.tar.gz
echo "4d8a2b1c9e6f3a5d7c8b0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2  tool.tar.gz" | shasum -a 256 -c -
tar -tzf tool.tar.gz
