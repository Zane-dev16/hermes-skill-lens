"""AST-vs-regex evidence benchmark — PLAN §1 Phase 1.5 exit proof.

Runs the golden corpus twice through the production pipeline:

1. ``ast``   — :class:`~skill_lens.parsing.ParserGateway` active (tree-sitter
   grammars loaded through their normal delivery lanes);
2. ``regex`` — grammar import FORCED unavailable (every engine takes its
   golden-tested line-scanner fallback).

For each mode it collects:

- **TP** — malicious-fixture expected rule ids (expected.toml) that fired;
- **FP** — findings on benign fixtures (must be zero in a healthy corpus);
- **p95 scan ms** — per-fixture wall-clock, reported ADVISORY only (the
  determinism law keeps wall-clock out of findings; it appears here solely
  as latency telemetry and varies run to run).

Exit clause under test: AST evidence demonstrably beats regex at EQUAL-or-
better TP — aggregate ``TP(ast) >= TP(regex)`` AND strictly fewer benign
false positives. The verdict is computed from real numbers; this tool never
massages them. Exit code 0 = gate PASS, 1 = gate FAIL (escalate honestly),
2 = environment problem (corpus/pack missing).

Repo tool, NOT shipped package (pyproject packages = skill_lens only).
Deterministic output: sorted tables, no timestamps anywhere in the table;
only the latency columns differ between runs by nature.
"""

from __future__ import annotations

import argparse
import math
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

try:
    from skill_lens.corpus import FixtureSpec, discover_fixtures, find_corpus_root, run_case
    from skill_lens.parsing import ParserGateway
    from skill_lens.rules import RulePack, load_core_pack
except ModuleNotFoundError:  # direct execution from outside the repo root
    sys.path.insert(0, str(REPO_ROOT))
    from skill_lens.corpus import FixtureSpec, discover_fixtures, find_corpus_root, run_case
    from skill_lens.parsing import ParserGateway
    from skill_lens.rules import RulePack, load_core_pack

MODE_AST = "ast"
MODE_REGEX = "regex"

RULE_WIDTH = 14


def _absent_import(module_name: str) -> object:
    raise ImportError(f"[bench] grammar delivery forced unavailable: {module_name!r}")


def _gateway_holders() -> list[tuple[str, Any]]:
    """Every loaded ``skill_lens`` module binding a ``GATEWAY`` attribute.

    Engines import the process gateway BY NAME (``from skill_lens.parsing
    import GATEWAY``), so forcing degradation must rebind each holder's own
    reference — patching only ``skill_lens.parsing`` would leave engines on
    the live gateway. Sorted by module name: deterministic.
    """
    holders = []
    for name in sorted(sys.modules):
        if not name.startswith("skill_lens."):
            continue
        module = sys.modules[name]
        if getattr(module, "GATEWAY", None).__class__ is ParserGateway:
            holders.append((name, module))
    return holders


def _force_gateway(gateway: ParserGateway) -> list[tuple[str, Any]]:
    """Install *gateway* everywhere; return the originals for restore."""
    originals: list[tuple[str, Any]] = []
    for name, module in _gateway_holders():
        originals.append((name, module.GATEWAY))
        module.GATEWAY = gateway
    return originals


def _restore_gateways(originals: list[tuple[str, Any]]) -> None:
    by_name = dict(originals)
    for name, module in _gateway_holders():
        original = by_name.get(name)
        if original is not None:
            module.GATEWAY = original


@dataclass
class ModeTally:
    """Per-mode aggregation over one full corpus sweep."""

    tp_total: int = 0
    fp_total: int = 0
    tp_per_rule: dict[str, tuple[int, int]] = field(default_factory=dict)  # caught/expected
    fp_per_rule: dict[str, int] = field(default_factory=dict)
    fired_by_fixture: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    scan_ms: list[float] = field(default_factory=list)


def sweep_mode(
    mode: str,
    specs: tuple[FixtureSpec, ...],
    pack: RulePack,
) -> ModeTally:
    """Run every fixture once under *mode*'s gateway, tallying evidence."""
    forced = ParserGateway(import_fn=_absent_import) if mode == MODE_REGEX else ParserGateway()
    originals = _force_gateway(forced)
    tally = ModeTally()
    try:
        for spec in specs:
            with tempfile.TemporaryDirectory(prefix="lens-bench-") as td:
                started = time.perf_counter()
                result = run_case(spec, tmp_root=td, pack=pack)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
            fired = result.fired_rule_ids()
            key = (spec.klass, spec.name)
            tally.fired_by_fixture[key] = frozenset(fired)
            tally.scan_ms.append(elapsed_ms)
            if spec.is_malicious:
                caught_wanted = {e.rule_id for e in spec.expects} & fired
                tally.tp_total += len(caught_wanted)
                for rule_id in sorted({e.rule_id for e in spec.expects}):
                    seen, total = tally.tp_per_rule.get(rule_id, (0, 0))
                    tally.tp_per_rule[rule_id] = (
                        seen + (1 if rule_id in caught_wanted else 0),
                        total + 1,
                    )
            else:
                tally.fp_total += len(result.findings)
                for finding in result.findings:
                    rule_id = str(finding.get("rule_id"))
                    tally.fp_per_rule[rule_id] = tally.fp_per_rule.get(rule_id, 0) + 1
    finally:
        _restore_gateways(originals)
    return tally


def _percentile_ms(values: list[float], quantile: float) -> float:
    """Nearest-rank percentile over per-case wall-clock (advisory)."""
    ordered = sorted(values)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def _engine_for_rule(pack: RulePack) -> dict[str, str]:
    return {rule.id: rule.engine for rule in pack.rules}


def _disagreement_lines(
    specs: tuple[FixtureSpec, ...],
    ast: ModeTally,
    regex: ModeTally,
) -> list[str]:
    """Sorted fixture-level notes where the two modes' evidence differs."""
    lines = ["Fixture-level disagreements", "-" * 78]
    rows: list[str] = []
    for spec in specs:
        key = (spec.klass, spec.name)
        fired_ast = ast.fired_by_fixture.get(key, frozenset())
        fired_rx = regex.fired_by_fixture.get(key, frozenset())
        label = f"{spec.klass}/{spec.name}"
        if spec.is_malicious:
            wanted = {e.rule_id for e in spec.expects}
            got_ast, got_rx = wanted & fired_ast, wanted & fired_rx
            if got_ast == got_rx:
                continue
            notes = []
            if got_ast - got_rx:
                notes.append("ast-only: " + ",".join(sorted(got_ast - got_rx)))
            if got_rx - got_ast:
                notes.append("regex-only: " + ",".join(sorted(got_rx - got_ast)))
            rows.append(f"{label:<44} {'; '.join(notes)}")
        else:
            if fired_ast == fired_rx:
                continue
            rows.append(
                f"{label:<44} ast={sorted(fired_ast) or '[]'} regex={sorted(fired_rx) or '[]'}"
            )
    lines.extend(rows if rows else ["(modes agree on every fixture)"])
    return lines


def build_report(
    specs: tuple[FixtureSpec, ...],
    pack: RulePack,
    ast: ModeTally,
    regex: ModeTally,
) -> tuple[str, bool]:
    """Render the deterministic benchmark table; return (text, gate_pass)."""
    engines = _engine_for_rule(pack)
    malicious = sum(1 for s in specs if s.is_malicious)
    benign = len(specs) - malicious
    expected_total = sum(expected for _, expected in ast.tp_per_rule.values())
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("AST vs regex evidence benchmark - Hermes Skill Lens Phase 1.5 exit")
    lines.append("=" * 78)
    lines.append(
        f"fixtures : {len(specs)} total ({malicious} malicious / {benign} benign), "
        f"core pack {pack.name} {pack.version}"
    )
    lines.append("modes    : ast   = tree-sitter grammars loaded (delivery lanes normal)")
    lines.append("           regex = grammar import forced unavailable (line-scanner fallback)")
    lines.append("")
    lines.append("Per-rule true positives (malicious expected-rule hits vs expected.toml)")
    lines.append("-" * 78)
    lines.append(
        f"{'engine':<12} {'rule_id':<{RULE_WIDTH}} {'expected':>8} {'ast':>6} {'regex':>6}"
    )
    for rule_id in sorted(ast.tp_per_rule):
        seen_ast, expected_n = ast.tp_per_rule[rule_id]
        seen_rx, _ = regex.tp_per_rule.get(rule_id, (0, expected_n))
        lines.append(
            f"{engines.get(rule_id, '?'):<12} {rule_id:<{RULE_WIDTH}} "
            f"{expected_n:>8} {seen_ast:>6} {seen_rx:>6}"
        )
    lines.append(
        f"{'TOTAL':<12} {'':<{RULE_WIDTH}} {expected_total:>8} "
        f"{ast.tp_total:>6} {regex.tp_total:>6}"
    )
    lines.extend(_disagreement_lines(specs, ast, regex))
    lines.append("")
    lines.append("False positives on benign fixtures (deduped finding counts)")
    lines.append("-" * 78)
    lines.append(f"{'engine':<12} {'rule_id':<{RULE_WIDTH}} {'ast':>6} {'regex':>6}")
    fp_rules = sorted(set(ast.fp_per_rule) | set(regex.fp_per_rule))
    if fp_rules:
        for rule_id in fp_rules:
            lines.append(
                f"{engines.get(rule_id, '?'):<12} {rule_id:<{RULE_WIDTH}} "
                f"{ast.fp_per_rule.get(rule_id, 0):>6} {regex.fp_per_rule.get(rule_id, 0):>6}"
            )
    else:
        lines.append("(no benign fixture fired any core-pack rule in either mode)")
    lines.append(f"{'TOTAL':<12} {'':<{RULE_WIDTH}} {ast.fp_total:>6} {regex.fp_total:>6}")
    lines.append("")
    lines.append("Scan latency per fixture (advisory telemetry; wall-clock varies by run)")
    lines.append("-" * 78)
    lines.append(f"{'mode':<10} {'p95-ms':>10} {'median-ms':>10} {'max-ms':>10}")
    for name, tally in ((MODE_AST, ast), (MODE_REGEX, regex)):
        lines.append(
            f"{name:<10} {_percentile_ms(tally.scan_ms, 0.95):>10.1f} "
            f"{_percentile_ms(tally.scan_ms, 0.50):>10.1f} {max(tally.scan_ms):>10.1f}"
        )
    lines.append("")
    tp_ok = ast.tp_total >= regex.tp_total
    fp_ok = ast.fp_total < regex.fp_total
    gate_pass = tp_ok and fp_ok
    lines.append("Exit math (PLAN §1 Phase 1.5: AST evidence must beat regex on the")
    lines.append("FP corpus at equal TP):")
    lines.append(
        f"  TP(ast)={ast.tp_total} >= TP(regex)={regex.tp_total}: " + ("OK" if tp_ok else "FAIL")
    )
    lines.append(
        f"  FP(ast)={ast.fp_total} <  FP(regex)={regex.fp_total}: " + ("OK" if fp_ok else "FAIL")
    )
    lines.append("")
    if gate_pass:
        lines.append("VERDICT: PASS - AST evidence beats regex at equal-or-better TP.")
    else:
        lines.append(
            "VERDICT: FAIL - gate does NOT hold on these numbers. Do not fake it:"
            " improve AST precision with dataflow-gated suppression of"
            " regex-only FPs, or record honestly that the corpus needs more"
            " fixtures, and escalate via QUESTIONS_FOR_OWNER.md."
        )
    return "\n".join(lines) + "\n", gate_pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AST-vs-regex corpus benchmark (Phase 1.5 exit proof)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "build-state" / "ast-benchmark.txt",
        help="report destination (default: build-state/ast-benchmark.txt)",
    )
    args = parser.parse_args(argv)

    corpus_root = find_corpus_root(REPO_ROOT)
    if corpus_root is None:
        print("environment error: corpus/fixtures not found above", REPO_ROOT)
        return 2
    pack = load_core_pack()
    specs = discover_fixtures(corpus_root)
    if not specs:
        print("environment error: no fixtures discovered under", corpus_root)
        return 2

    ast_tally = sweep_mode(MODE_AST, specs, pack)
    regex_tally = sweep_mode(MODE_REGEX, specs, pack)
    report, gate_pass = build_report(specs, pack, ast_tally, regex_tally)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    sys.stdout.write(f"\nwritten: {args.output}\n")
    return 0 if gate_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
