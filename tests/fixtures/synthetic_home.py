"""Synthetic categorized Hermes home builder shared by ingest test suites.

Deterministic contents: ≥3 categories, ≥5 categorized bundles (one with
``metadata.hermes``, one malformed SKILL.md, one name/dirname mismatch, one
with non-UTF-8 assets), a flat bundle, variable-depth hub-quarantine bundles,
a quarantined zip target, and a hub lock.json with provenance entries.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

FULL_FRONTMATTER = """\
---
name: web-design-guidelines
description: Ship accessible interfaces with design-system tokens.
allowed-tools: [read_file, bash]
compatibility: Hermes >= 0.20
version: 1.4.0
metadata:
  hermes:
    tags: [design, web]
    related_skills: [plain-helper]
    category: tools
    requires_tools: [read_file]
    fallback_for_tools: [browser]
    config:
      palette: default
  vendor-note: future-metadata-sibling
---

# Web Design Guidelines

Use tokens; never hardcode hex values.
"""

PLAIN_FRONTMATTER = """\
---
name: plain-helper
description: Helps with small chores.
---
Body text only.
"""

MISMATCHED_FRONTMATTER = """\
---
name: sketch
description: Draws sketches on canvas.
---
Draw it.
"""

BROKEN_FRONTMATTER = """\
---
name: broken-skill
description: [unclosed, list
  bad_indent: ::::
---
This frontmatter is deliberately malformed YAML.
"""


def _bundle(
    skills: Path,
    category: str,
    name: str,
    skill_md: str,
    extra: dict[str, bytes] | None = None,
) -> None:
    root = skills / category / name
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(skill_md, encoding="utf-8")
    for rel, data in (extra or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def make_synthetic_home(home: Path) -> Path:
    """Populate *home* with the full deterministic fixture tree.

    Returns the home path for chaining. Byte-identical contents on every
    call — safe to rebuild across runs for golden comparisons.
    """
    skills = home / "skills"

    _bundle(
        skills,
        "tools",
        "web-design-guidelines",
        FULL_FRONTMATTER,
        {"scripts/sync.sh": b"#!/bin/sh\necho sync\n", "references/guide.md": b"# Guide\n"},
    )
    _bundle(skills, "tools", "plain-helper", PLAIN_FRONTMATTER)
    _bundle(skills, "creative", "sketchy-dir", MISMATCHED_FRONTMATTER)
    _bundle(skills, "creative", "broken-skill", BROKEN_FRONTMATTER)
    # Non-UTF-8 asset (latin-1 bytes) + nested script for encoding coverage.
    _bundle(
        skills,
        "devops",
        "deployer",
        "---\nname: deployer\ndescription: Deploys things safely.\n---\nRunbook.\n",
        {
            "scripts/deploy.sh": "#!/bin/sh\necho d\xe9ploy\n".encode("latin-1"),
            "assets/logo.bin": bytes(range(256)) * 4,
        },
    )

    flat = skills / "flat-root-skill"
    flat.mkdir()
    (flat / "SKILL.md").write_text(
        "---\nname: flat-root-skill\ndescription: Category optional.\n---\n", encoding="utf-8"
    )

    quarantine = skills / ".hub" / "quarantine"
    staged = quarantine / "staged-one"
    staged.mkdir(parents=True)
    (staged / "SKILL.md").write_text(
        "---\nname: staged-one\ndescription: Awaiting confirmation.\n---\n", encoding="utf-8"
    )
    deep = quarantine / "team" / "nested-deep" / "another"
    deep.mkdir(parents=True)
    (deep / "SKILL.md").write_text(
        "---\nname: another\ndescription: Variable depth bundle.\n---\n", encoding="utf-8"
    )
    zip_path = quarantine / "packed.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "packed/SKILL.md",
            "---\nname: packed\ndescription: Zipped staging target.\n---\n",
        )
        zf.writestr("packed/scripts/run.sh", "#!/bin/sh\necho packed\n")

    lock_path = skills / ".hub" / "lock.json"
    lock_path.write_text(
        json.dumps(
            {
                "version": 1,
                "installed": {
                    "web-design-guidelines": {
                        "source": "github",
                        "identifier": "vercel-labs/agent-skills/web-design-guidelines",
                        "trust_level": "trusted",
                        "scan_verdict": "clean",
                        "content_hash": "sha256:" + "11" * 32,
                        "install_path": "tools/web-design-guidelines",
                        "files": ["SKILL.md"],
                        "metadata": {},
                        "scan_provenance": {"gate": "skills_guard", "verdict": "allow"},
                    },
                    "staged-one": {
                        "source": "clawhub",
                        "identifier": "clawhub/staged-one",
                        "trust_level": "community",
                        "content_hash": "sha256:" + "22" * 32,
                        "install_path": ".hub/quarantine/staged-one",
                        "files": ["SKILL.md"],
                        "metadata": {},
                        "scan_provenance": {},
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return home
