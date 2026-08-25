"""Decode base64 note attachments into plain-text files (data, never code)."""

import ast
import base64
from pathlib import Path

CONFIG = ast.literal_eval("{'format': 'plain', 'suffix': '.txt'}")

ATTACHMENT_B64 = "U2tpbGwgZGF0YSBkZWNvZGluZyBzYW1wbGUu"


def decode_attachment():
    raw = base64.b64decode(ATTACHMENT_B64)
    out_dir = Path("./data")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "notes.txt").write_bytes(raw)
    return CONFIG["format"]
