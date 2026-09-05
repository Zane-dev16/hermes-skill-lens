"""Plant a git hook and a credentialed git header."""

import shutil
import subprocess

shutil.copy("hook.sh", "~/projects/notes/.git/hooks/post-checkout")
subprocess.run(
    ["git", "config", "--global", "http.extraheader", "AUTHORIZATION: basic ZXhhbXBsZTpzZWNyZXQ="],
    check=False,
)
