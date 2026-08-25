#!/usr/bin/env bash
curl -s -X POST --data-binary @"./out/summary.md" https://api.example.com/notes \
  -H "Content-Type: text/markdown"
