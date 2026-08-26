"""Phase 3 perf-budget gate — measured INSIDE a fake lifecycle dispatch.

PLAN §1 Phase 3 (normative budgets):
- p95 cold ≤ 400 ms on a ≤1 MB bundle;
- cached fast path < 200 ms;
- both through the REGISTERED callback wired by ``register()`` — never a
  bare pipeline call.

Set ``LENS_SKIP_PERF=1`` to skip gracefully on slow CI runners (the budget
numbers still regenerate locally via ``scripts/perf_check.py``); the escape
is a skip-with-reason, not a silent pass.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.perf import harness

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    bool(os.environ.get("LENS_SKIP_PERF")),
    reason=(
        "LENS_SKIP_PERF is set — perf budgets are asserted only on dedicated "
        "runners; regenerate numbers with scripts/perf_check.py"
    ),
)


def test_perf_budgets_inside_fake_dispatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stats = harness.measure(repo_root=REPO_ROOT)

    # Human-readable evidence lands in the pytest output (-ra/-s) and in
    # build-state/perf-baseline.txt via scripts/perf_check.py --write.
    cold_line = (
        f"cold  p50 {stats['cold_p50_ms']:7.1f} ms · p95 {stats['cold_p95_ms']:7.1f} ms"
        f" · max {stats['cold_max_ms']:7.1f} ms"
        f"   (budget: p95 ≤ {harness.COLD_P95_BUDGET_MS:.0f})\n"
    )
    fast_line = (
        f"cache p50 {stats['fast_p50_ms']:7.1f} ms · p95 {stats['fast_p95_ms']:7.1f} ms"
        f" · max {stats['fast_max_ms']:7.1f} ms"
        f"   (budget: p95 < {harness.FAST_P95_BUDGET_MS:.0f})"
    )
    print(
        f"\nperf probe bundle: {stats['bundle_bytes']} bytes "
        f"({stats['cold_runs']} cold runs / {stats['fast_runs']} cached runs)\n"
        + cold_line
        + fast_line
    )
    capsys.readouterr()  # keep pytest's own summary clean

    assert stats["cold_p95_ms"] <= harness.COLD_P95_BUDGET_MS, (
        f"cold dispatch→ready p95 {stats['cold_p95_ms']:.1f} ms exceeds the "
        f"{harness.COLD_P95_BUDGET_MS:.0f} ms PLAN budget inside the fake lifecycle dispatch"
    )
    assert stats["fast_p95_ms"] < harness.FAST_P95_BUDGET_MS, (
        f"cached fast-path p95 {stats['fast_p95_ms']:.1f} ms exceeds the "
        f"{harness.FAST_P95_BUDGET_MS:.0f} ms PLAN budget"
    )
