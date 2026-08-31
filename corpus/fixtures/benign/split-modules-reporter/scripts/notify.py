"""Static notifier."""

import requests

STATUS_URL = "https://status.example.com/hooks/ready"


def ping():
    requests.post(STATUS_URL, json={"status": "ok"}, timeout=5)
