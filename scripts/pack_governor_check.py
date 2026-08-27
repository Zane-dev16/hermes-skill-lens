#!/usr/bin/env python3
"""Pack semver governor gate — CI job 2 of rule-pack.yml.

Diffs the rule pack between a BASE git ref and the working tree (HEAD) via
:func:`skill_lens.packver.enforce`, then regenerates CHANGELOG.md and
demands byte-sync with pack.yaml. An illegal transition (patch bump carrying
a weight/severity change, removal inside the deprecation horizon, missing
rationale, …) fails LOUDLY with every reason listed.

Usage: pack_governor_check.py [--base REF] (default origin/main; "HEAD"
compares last commit vs working tree).

Exit 0 = transition legal · exit 1 = violations · exit 2 structural.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

PACK_REL = Path("skill_lens") / "rules" / "core"


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _export_pack(ref: str, out_dir: Path) -> None:
    """Materialize skill_lens/rules/core from *ref* into *out_dir*."""
    listing = _git("ls-tree", "-r", "--name-only", ref, str(PACK_REL))
    for rel in listing.splitlines():
        if not rel.strip():
            continue
        content = _git("show", f"{ref}:{rel}")
        dest = out_dir / rel[len(str(PACK_REL)) + 1 :]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="base git ref to diff against")
    args = parser.parse_args()

    try:
        _git("rev-parse", "--verify", args.base + "^{commit}")
    except RuntimeError as exc:
        print(f"error: base ref {args.base!r} unavailable ({exc})", file=sys.stderr)
        return 2

    from skill_lens.packver import PackVerError, enforce
    from skill_lens.rules import RulePackError, load_pack

    with tempfile.TemporaryDirectory(prefix="lens-governor-") as tmp:
        # _export_pack writes the pack ROOT (pack.yaml + rules/) directly
        # under <tmp>/old, so that directory itself is what we load.
        old_dir = Path(tmp) / "old"
        try:
            _export_pack(args.base, Path(tmp) / "old")
            old_pack = load_pack(old_dir)
        except (RuntimeError, RulePackError) as exc:
            print(f"error: cannot load pack at {args.base}: {exc}", file=sys.stderr)
            return 2
        new_pack = load_pack(REPO_ROOT / PACK_REL)

        print(f"governor: {old_pack.version} → {new_pack.version} (base {args.base})")
        try:
            report = enforce(old_pack, new_pack)
        except PackVerError as exc:
            print("GOVERNOR REJECTED THE TRANSITION:")
            for reason in exc.violations:
                print(f"  - {reason}")
            return 1
        print(f"transition legal: {report.summary_line()}")

    # Changelog mirror sync.
    regen = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "pack_changelog.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    if regen.returncode != 0:
        print(f"error: changelog regeneration failed: {regen.stderr}", file=sys.stderr)
        return 2
    dirty = _git("status", "--porcelain", str(PACK_REL / "CHANGELOG.md")).strip()
    if dirty:
        print(
            "CHANGELOG.md out of sync with pack.yaml — run "
            "`python3 scripts/pack_changelog.py` and commit the result"
        )
        return 1
    print("changelog mirror in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
