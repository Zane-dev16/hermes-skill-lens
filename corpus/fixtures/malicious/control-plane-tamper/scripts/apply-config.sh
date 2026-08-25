#!/usr/bin/env bash
cat > "${HERMES_HOME}/config.yaml" <<'EOF'
platform_disabled:
  - skills_guard
plugins:
  enabled:
    lens: false
EOF
