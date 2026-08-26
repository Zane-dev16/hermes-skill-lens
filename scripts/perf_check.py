#!/usr/bin/env python3
"""Regenerable perf-baseline tool (PLAN §1 Phase 3 deliverable).

Runs the SAME measurement as ``tests/perf/test_budgets.py`` — one shared
implementation in :mod:`tests.perf.harness` — outside pytest:

    python3 scripts/perf_check.py                 # print report
    python3 scripts/perf_check.py --strict        # exit 1 on budget breach
    python3 scripts/perf_check.py --write         # refresh build-state/perf-baseline.txt
    python3 scripts/perf_check.py --ceiling-probe # add informational ~900 KB numbers

Exit codes: 0 budgets green (or --strict unset), 1 budget breach under
--strict, 2 harness correctness failure.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
#: The plugin package's absolute ``skill_lens.*`` imports resolve against the
#: repo root — required before any harness/plugin module executes.
sys.path.insert(0, str(REPO_ROOT))


def _load_harness():
    """Load tests/perf/harness.py by path — one shared implementation, no
    package-import requirement outside pytest (the harness module is
    self-contained; test_budgets.py imports the same file as tests.perf.harness)."""
    path = REPO_ROOT / "tests" / "perf" / "harness.py"
    spec = importlib.util.spec_from_file_location("_lens_perf_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


def _fmt(stats: dict) -> list[str]:
    return [
        f"probe bundle     : {stats['bundle_bytes']} bytes "
        f"(target {harness.PROBE_TARGET_BYTES}, ceiling contract <=1 MB)",
        f"runs             : {stats['cold_runs']} cold / {stats['fast_runs']} cached",
        f"cold  dispatch->ready : p50 {stats['cold_p50_ms']:7.1f} ms   "
        f"p95 {stats['cold_p95_ms']:7.1f} ms   max {stats['cold_max_ms']:7.1f} ms",
        f"cached fast path      : p50 {stats['fast_p50_ms']:7.1f} ms   "
        f"p95 {stats['fast_p95_ms']:7.1f} ms   max {stats['fast_max_ms']:7.1f} ms",
        f"budgets          : cold p95 <= {harness.COLD_P95_BUDGET_MS:.0f} ms · "
        f"cached p95 < {harness.FAST_P95_BUDGET_MS:.0f} ms",
        (
            "VERDICT          : PASS"
            if stats["cold_p95_ms"] <= harness.COLD_P95_BUDGET_MS
            and stats["fast_p95_ms"] < harness.FAST_P95_BUDGET_MS
            else "VERDICT          : FAIL"
        ),
        "",
        "cold samples(ms) : " + " ".join(f"{x:.0f}" for x in stats["cold_ms"]),
        "cache samples(ms): " + " ".join(f"{x:.1f}" for x in stats["fast_ms"]),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="exit 1 on budget breach")
    parser.add_argument(
        "--write",
        nargs="?",
        const=str(REPO_ROOT / "build-state" / "perf-baseline.txt"),
        metavar="PATH",
        help="write the report to PATH (default build-state/perf-baseline.txt)",
    )
    parser.add_argument(
        "--ceiling-probe",
        action="store_true",
        help="also measure a ~900 KB bundle (informational; NOT gated)",
    )
    args = parser.parse_args()

    lines: list[str] = [
        "Skill Lens perf baseline — fake lifecycle dispatch (PLAN §1 Phase 3)",
        "tool: scripts/perf_check.py · harness: tests/perf/harness.py",
        "",
    ]
    try:
        stats = harness.measure(repo_root=REPO_ROOT)
    except harness.PerfFailure as exc:
        print(f"harness correctness failure: {exc}", file=sys.stderr)
        return 2
    lines += _fmt(stats)
    # Position-independent: find the VERDICT line itself (lines[-3] was the
    # blank separator — --strict used to exit 1 even on PASS).
    verdict_ok = any(
        line.startswith("VERDICT") and line.endswith("PASS") for line in lines
    )

    ceiling_block: list[str] | None = None
    if args.ceiling_probe:
        try:
            ceiling = harness.ceiling_probe(repo_root=REPO_ROOT)
        except harness.PerfFailure as exc:
            print(f"ceiling probe failure: {exc}", file=sys.stderr)
            return 2
        ceiling_block = [
            "INFORMATIONAL near-ceiling probe (NOT gated by the budget test):",
            f"  bundle {ceiling['bundle_bytes']} bytes · {ceiling['runs']} runs · "
            f"p50 {ceiling['p50_ms']:.0f} ms · max {ceiling['max_ms']:.0f} ms",
            "  Current engine throughput does not hold 400 ms at the 1 MB ceiling;",
            "  the synchronous install beat stays bounded because cold work rides",
            "  the worker thread (§11.5 queue-first). Flagged as Phase 4/5 follow-up.",
        ]

    report = "\n".join(lines + ([""] + ceiling_block if ceiling_block else [])) + "\n"
    print(report)
    if args.write:
        path = pathlib.Path(args.write)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        print(f"written: {path}")
    if args.strict and not verdict_ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
