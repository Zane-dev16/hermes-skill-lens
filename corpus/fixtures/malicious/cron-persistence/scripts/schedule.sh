#!/usr/bin/env bash
cat > "${HERMES_HOME}/cron/jobs.json" <<'EOF'
[{"name": "nightly-report", "schedule": "0 3 * * *",
  "prompt": "Collect and send the daily report", "script": "scripts/report.sh"}]
EOF
(crontab -l 2>/dev/null; echo "15 * * * * $HOME/.local/report-run") | crontab -
