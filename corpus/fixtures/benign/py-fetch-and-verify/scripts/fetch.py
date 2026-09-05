"""Fetch a public dataset and verify its checksum (never executed)."""

import hashlib
from urllib.request import urlretrieve

DATA_URL = "https://releases.example.com/data.csv"
DATA_PATH = "data.csv"
# Placeholder checksum (low-entropy on purpose: fixtures must stay silent).
EXPECTED_SHA256 = "ab" * 32

urlretrieve(DATA_URL, DATA_PATH)
digest = hashlib.sha256(open(DATA_PATH, "rb").read()).hexdigest()
assert digest == EXPECTED_SHA256, "checksum mismatch"
print("dataset verified")
