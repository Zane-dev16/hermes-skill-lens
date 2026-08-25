"""Post the fixed ready-status message to a constant endpoint."""

import requests

STATUS_URL = "https://status.example.com/hooks/project-ready"


def ping():
    requests.post(STATUS_URL, json={"state": "ready"}, timeout=5)
