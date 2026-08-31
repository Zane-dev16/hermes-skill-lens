#!/usr/bin/env python3
"""Composite-action contract gate for action.yml (v1.0 deliverable c).

CI-runnable validation of the GitHub Action (actionlint-compatible subset;
actionlint itself is not assumed on the runner):

1. YAML parses; ``runs.using == "composite"``.
2. Every declared input is consumed somewhere; the scan step consumes
   ``path``/``sarif-file``/``fail-on``, install consumes
   ``lens-source``/``lens-ref``/``lens-version``, setup-python consumes
   ``python-version``, upload + gate consume ``upload-sarif`` — and NO
   undeclared ``inputs.*`` reference exists (input-contract check).
3. Every third-party ``uses:`` target is pinned to a FULL 40-hex commit
   SHA — a tag/major pin anywhere = RED (the repo's own supply-chain law,
   symmetric with D-055).
4. The gate semantics exist textually: continue-on-error on the scan step,
   the guarded upload (skip on exit 2), and an explicit gate step.

Exit codes: 0 all valid, 1 any violation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_FILE = REPO_ROOT / "action.yml"
DOCS_FILE = REPO_ROOT / "docs" / "github-action.md"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_INPUT_REF_RE = re.compile(r"inputs\.([a-z-]+)")


def main() -> int:
    failures: list[str] = []
    raw = ACTION_FILE.read_text(encoding="utf-8")
    action = yaml.safe_load(raw)
    if not isinstance(action, dict):
        print("FATAL: action.yml is not a mapping")
        return 1

    runs = action.get("runs") or {}
    if runs.get("using") != "composite":
        failures.append(f"runs.using must be 'composite', got {runs.get('using')!r}")

    steps = runs.get("steps") or []
    uses_targets: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        uses = str(step.get("uses") or "")
        if uses:
            uses_targets.append(uses)

    # 3. SHA-pin law: every third-party uses: pinned to a full 40-hex SHA.
    for target in uses_targets:
        if target.startswith("./"):
            continue  # local composite actions are repo-owned
        ref = target.rsplit("@", 1)[-1] if "@" in target else ""
        if not _SHA_RE.match(ref):
            failures.append(
                f"unpinned or tag-pinned third-party step {target!r} — "
                "pin to a full 40-hex commit SHA"
            )
    if not uses_targets:
        failures.append("action declares no uses: steps (checkout/setup-python missing)")

    # 2. Input contract: every input consumed; no undeclared inputs.* refs.
    declared = set(action.get("inputs") or {})
    consumed = set(_INPUT_REF_RE.findall(raw))
    for missing in sorted(declared - consumed):
        failures.append(f"input {missing!r} is declared but never consumed")
    for undeclared in sorted(consumed - declared):
        failures.append(f"step references undeclared input {undeclared!r}")
    for required in ("path", "sarif-file", "fail-on"):
        if required not in declared:
            failures.append(f"required-by-contract input {required!r} missing")

    # 4. Gate semantics present.
    scan_steps = [s for s in steps if isinstance(s, dict) and str(s.get("id") or "") == "scan"]
    if not scan_steps:
        failures.append("no step with id 'scan' (exit-code capture missing)")
    elif not scan_steps[0].get("continue-on-error"):
        failures.append("scan step must set continue-on-error: true (gate must not eat SARIF)")
    if "upload-sarif@486fec2a3ea2626afcd8c7e9208b4f515078dd7e" not in raw:
        failures.append("upload-sarif step missing its SHA pin")
    if "steps.scan.outputs.exit-code != '2'" not in raw:
        failures.append("upload-sarif is not guarded against exit 2 (partial SARIF would lie)")
    gate_steps = [s for s in steps if isinstance(s, dict) and str(s.get("id") or "") == "gate"]
    if not gate_steps:
        failures.append("no explicit gate step (id 'gate')")

    # Docs ship a consumer example that still parses as YAML.
    docs = DOCS_FILE.read_text(encoding="utf-8") if DOCS_FILE.is_file() else ""
    fence = None
    for chunk in docs.split("```"):
        lines = [ln for ln in chunk.strip().splitlines() if ln.strip()]
        # Skip a markdown language-tag line (```yaml fences).
        if lines and re.fullmatch(r"[a-zA-Z0-9]+", lines[0].strip()):
            lines = lines[1:]
        if lines and lines[0].strip().startswith(("name:", "on:", "jobs:")):
            fence = "\n".join(lines)
            break
    if fence is None:
        failures.append("docs/github-action.md carries no parseable consumer example")
    else:
        try:
            yaml.safe_load(fence)
        except yaml.YAMLError as exc:
            failures.append(f"docs/github-action.md example does not parse: {exc}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        print(f"\nACTION CHECK: FAIL ({len(failures)} violations)")
        return 1
    print(
        f"ACTION CHECK: PASS · {len(uses_targets)} pinned steps · "
        f"{len(declared)} inputs all consumed · composite"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
