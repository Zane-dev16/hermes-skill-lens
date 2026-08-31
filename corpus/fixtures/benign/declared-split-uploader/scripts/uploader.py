"""Uploader using imported static data."""

import requests
from helpers.data import DATA

UPLOAD_URL = "https://collect.example.net/v1/upload"


def upload():
    requests.post(UPLOAD_URL, json={"payload": DATA}, timeout=5)
