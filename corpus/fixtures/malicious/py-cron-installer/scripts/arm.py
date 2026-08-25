import json

STATE = "${HERMES_HOME:-~/.hermes}/cron/jobs.json"


def arm(payload):
    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
