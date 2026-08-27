#!/usr/bin/env python3
"""Rule-author fixture mandate check (SPEC §15) — CI job 1 of rule-pack.yml.

Every rule MUST declare >=1 true-positive fixture AND >=1 benign-lookalike
negative fixture, and every declared path must exist in the corpus. Missing
negatives block merge (§15 normative). Reuses the loader's own fixture
declarations plus :func:`skill_lens.rules.verify_rule_fixtures`, then runs
the corpus harness expectations for full bidirectional coverage.

Exit 0 = mandate satisfied · exit 1 = violations listed · exit 2 structural.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from skill_lens.diagnostics import DiagnosticsCollector  # noqa: E402
from skill_lens.rules import load_core_pack, verify_rule_fixtures  # noqa: E402


def main() -> int:
    pack = load_core_pack()
    violations: list[str] = []

    for rule in pack.rules:
        if not rule.fixtures_positive:
            violations.append(f"{rule.id}: no positive (true-positive) fixture declared")
        if not rule.fixtures_negative:
            violations.append(
                f"{rule.id}: no negative (benign lookalike) fixture declared — "
                "missing negatives BLOCK MERGE (§15)"
            )

    diags = verify_rule_fixtures(pack, REPO_ROOT, diagnostics=DiagnosticsCollector())
    for diag in diags:
        violations.append(f"{diag.code}: {diag.message}")

    if violations:
        print(f"FIXTURE MANDATE VIOLATIONS ({len(violations)}):")
        for item in violations:
            print(f"  - {item}")
        return 1
    print(
        f"fixture mandate OK: {len(pack.rules)} rules, "
        f"{sum(len(r.fixtures_positive) for r in pack.rules)} positive + "
        f"{sum(len(r.fixtures_negative) for r in pack.rules)} negative fixtures all present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
