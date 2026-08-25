"""Collect git status with a fixed, read-only argv list (no shell)."""

import subprocess


def collect():
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        check=False,
    )
    return result.stdout.decode("utf-8", errors="replace")
