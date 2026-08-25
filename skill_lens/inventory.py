"""Whole-tree inventory — scan every bundle under a Hermes home.

The Phase 0 exit artifact: :func:`scan_inventory` walks
``<home>/skills`` (categorized layout + hub quarantine corridor via
:mod:`skill_lens.ingest`) and produces ONE canonical envelope whose bytes
are identical across runs for identical inputs (DETERMINISM LAW). The
envelope nests each bundle's ``SkillIR.canonical_dict()`` under
``inventory.bundles`` (sorted by relative path); discovery-level
diagnostics that belong to no single bundle live at the top level.

Dogfood CLI::

    python3 -m skill_lens.inventory [HOME] [--json]

prints the stable text inventory over the real skills tree (default home:
``$HERMES_HOME`` else ``~/.hermes``), tolerating absence gracefully.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skill_lens.canonical import canonical_dumps
from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.ingest import (
    DEFAULT_CEILINGS,
    BundleRef,
    Ceilings,
    discover_bundles,
    load_bundle,
    read_hub_lock,
)
from skill_lens.ir import (
    IR_SPEC_VERSION,
    TOOL_NAME,
    SkillIR,
    render_inventory,
    tool_version,
)


def default_home() -> Path:
    """Active Hermes home: ``$HERMES_HOME`` when set, else ``~/.hermes``."""
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".hermes"


@dataclass(frozen=True)
class InventoryResult:
    """Everything one tree scan produced (IRs kept for human rendering)."""

    home_label: str
    bundles: tuple[SkillIR, ...]
    envelope: dict[str, Any]
    diagnostics: DiagnosticsCollector


def build_inventory(
    home: Path | str,
    *,
    ceilings: Ceilings = DEFAULT_CEILINGS,
) -> InventoryResult:
    """Discover and ingest every bundle under *home* (deterministic order)."""
    diags = DiagnosticsCollector()
    refs = discover_bundles(home, ceilings=ceilings, diagnostics=diags)
    lock = read_hub_lock(home, diagnostics=diags)
    irs: list[SkillIR] = []
    for ref in sorted(refs, key=_ref_sort_key):
        irs.append(
            load_bundle(
                ref.path,
                home=home,
                ceilings=ceilings,
                provenance_lock=lock,
            )
        )

    # The root identifier is the caller's form of the home (as-given),
    # mirroring BundleIdentity.path semantics; every bundle below it is a
    # $HERMES_HOME-normalized '~/' label, so no machine-derived expansion
    # is invented here.
    home_lbl = str(home)
    envelope: dict[str, Any] = {
        "spec_version": IR_SPEC_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "inventory": {
            "home_label": home_lbl,
            "bundle_count": len(irs),
            "bundles": [ir.canonical_dict() for ir in irs],
        },
        "diagnostics": [diag.to_dict() for diag in diags.snapshot()],
    }
    return InventoryResult(
        home_label=home_lbl,
        bundles=tuple(irs),
        envelope=envelope,
        diagnostics=diags,
    )


def scan_inventory(home: Path | str, *, ceilings: Ceilings = DEFAULT_CEILINGS) -> dict[str, Any]:
    """Canonical inventory envelope for *home* — byte-stable across runs."""
    return build_inventory(home, ceilings=ceilings).envelope


def _ref_sort_key(ref: BundleRef) -> tuple[str, str]:
    """Byte-stable bundle ordering for the envelope (label then name)."""
    return (ref.label, ref.name)


__all__ = [
    "InventoryResult",
    "build_inventory",
    "default_home",
    "main",
    "scan_inventory",
]


# ---------------------------------------------------------------------------
# Dogfood CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """``python3 -m skill_lens.inventory [HOME] [--json]`` entry point."""
    parser = argparse.ArgumentParser(
        prog="python3 -m skill_lens.inventory",
        description="Skill Lens deterministic skills-tree inventory (advisor, offline).",
    )
    parser.add_argument(
        "home",
        nargs="?",
        default=None,
        help="Hermes home directory (default: $HERMES_HOME or ~/.hermes)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the canonical JSON envelope instead of the text inventory",
    )
    args = parser.parse_args(argv)

    raw_home = args.home if args.home else str(default_home())
    home = Path(raw_home).expanduser()
    if not (home / "skills").is_dir():
        print(f"skill_lens: no skills tree under {raw_home}/skills; nothing to scan.")
        return 0

    result = build_inventory(home)
    if args.json:
        print(canonical_dumps(result.envelope))
        return 0

    for index, ir in enumerate(result.bundles):
        if index:
            print()
        print(render_inventory(ir), end="")
    total_diags = len(result.diagnostics)
    print(f"inventory: {len(result.bundles)} bundle(s), {total_diags} discovery diagnostic(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
