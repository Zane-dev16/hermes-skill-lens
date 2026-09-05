---
name: sysadmin-runbook
description: Lists scheduled tasks and startup entries across your fleet.
---

# sysadmin-runbook

Read-only audit notes. To audit Windows persistence, list (never create)
entries with these commands:

```console
schtasks /query /tn Updater
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
launchctl list | grep example
```

macOS note: prefer `open` over `osascript` for accessibility prompts.
