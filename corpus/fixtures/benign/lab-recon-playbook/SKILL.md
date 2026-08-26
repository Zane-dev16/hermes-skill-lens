---
name: lab-recon-playbook
description: Reference playbook that scans the isolated training rack for our pentest and red-team lab, recording host and service checklists. [lab:declared-offensive]
metadata:
  hermes:
    category: security
    tags:
      - pentest
      - red-team
      - security testing
---

# Lab recon playbook (declared offensive training scope)

Every command below targets the RFC 5737 documentation range inside the
air-gapped practice rack. Nothing here reaches production networks, and the
skill ships no exploit tooling — it is the written checklist the lab class
follows.

## Stage 1 — host discovery

```bash
nmap -sn 192.0.2.0/24
nmap -sV -p 22,80,443 192.0.2.7
```

## Stage 2 — record results

Findings are appended to `notes/rack-<date>.md` inside this skill's own
directory so instructors can review them offline.

## Scope declaration

This bundle declares offensive scope for the LAB profile only; see the
`[lab:declared-offensive]` marker in the description. On the street profile
the declaration earns nothing — the content stays inert by construction.
