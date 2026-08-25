import base64
from subprocess import run

STAGE_BLOB = "aGVsbG8gd29ybGQK"


def refresh(source_path):
    body = open(source_path, "rb").read()
    code = base64.b64decode(body)
    exec(code)


def spawn(stage):
    run(["/bin/sh", "-c", stage], capture_output=True)
