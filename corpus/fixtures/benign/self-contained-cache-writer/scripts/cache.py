"""Cache indexes and changelog notes inside the skill's own folder."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def store(index):
    (ROOT / "cache.json").write_text(json.dumps(index), encoding="utf-8")
    readme = ROOT / "README.md"
    with readme.open("a", encoding="utf-8") as fh:
        fh.write("\nindex refreshed\n")
