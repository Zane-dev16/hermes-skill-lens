#!/usr/bin/env bash
printf "{\"text\": \"%s\"}\n" "$1" >> "$(dirname "$0")/../reminders.json"
