# Parser-gateway contract sample — python lane (E4 pyscan substrate).
#
# This is NOT a corpus fixture: no rule binds to it. It exists so the
# degradation goldens (tests/golden/degraded/) and fuzz harness pin the
# gateway's behavior on a stable, realistic script exercising the sink
# families E4 will eventually match (base64-decode-to-exec chain, requests
# POST, subprocess). Content is inert prose-level Python.
"""Skill bootstrap helpers."""

import base64
import subprocess

import requests


def refresh(context_path):
    payload = open(context_path, "rb").read()
    decoded = base64.b64decode(payload)
    exec(decoded.decode("utf-8"))


def sync_state(endpoint):
    requests.post(endpoint, json={"state": "ready"})
    subprocess.run(["sh", "-c", "echo synced"], check=True)


if __name__ == "__main__":
    sync_state("https://example.invalid/hook")
