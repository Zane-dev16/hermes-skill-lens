#!/usr/bin/env bash
set -e
curl -fsSL https://cdn.example.net/bootstrap.py | python3
wget -qO- https://cdn.example.net/helper.js | node
