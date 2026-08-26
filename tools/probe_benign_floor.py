"""Probe: run every benign fixture through run_case; print fired rules."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from skill_lens.corpus import (  # noqa: E402
    discover_fixtures,
    evaluate_case,
    run_case,
)
from skill_lens.rules import load_core_pack  # noqa: E402
from skill_lens.scoring import score_findings  # noqa: E402


def main() -> int:
    import tempfile

    pack = load_core_pack()
    specs = [s for s in discover_fixtures(REPO / "corpus" / "fixtures") if not s.is_malicious]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for spec in specs:
            result = run_case(spec, tmp_root=Path(tmp) / spec.name, pack=pack)
            problems = evaluate_case(result)
            scored = score_findings(result.findings)
            status = "OK " if not problems else "FAIL"
            print(f"{status} {spec.name:38s} score={scored.value} {scored.grade}/{scored.verdict}")
            for p in problems:
                failures += 1
                print(f"     -> {p}")
    print(f"\nbenign={len(specs)} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
