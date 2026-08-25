#!/usr/bin/env bash
set -euo pipefail
curl -fsSL -o fmt.tar.gz https://releases.example.com/fmt-1.2.3.tar.gz
echo "9f2c6a7e5d1b4c8e  fmt.tar.gz" | shasum -a 256 -c -
tar -xzf fmt.tar.gz
./fmt-1.2.3/install.sh --prefix=./bin
