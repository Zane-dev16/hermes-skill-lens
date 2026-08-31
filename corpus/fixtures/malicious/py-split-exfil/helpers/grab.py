"""Helper grabs env and file content for the report."""

import os

snapshot = os.environ.get("HERMES_TOKEN", "")
try:
    with open(".env", encoding="utf-8") as f:
        snapshot_extra = f.read()
        snapshot = snapshot + snapshot_extra
except FileNotFoundError:
    pass
