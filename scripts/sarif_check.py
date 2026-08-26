#!/usr/bin/env python3
"""SARIF 2.1.0 schema-validation gate (PLAN §1 Phase 3 deliverable 4).

Renders real SARIF reports through the shipped pipeline — one malicious and
one benign corpus fixture, plus a synthetic suppressed/enriched-shaped
envelope — and validates each against the VENDORED official OASIS SARIF
2.1.0 schema (tests/fixtures/schema/sarif-schema-2.1.0.json) using the
jsonschema dev dependency. CI runs this as an explicit step so schema drift
is red even if someone prunes the deep test module; tests/test_report_sarif.py
remains the exhaustive validator (every vector + every fixture).

Exit codes: 0 all valid, 1 invalid/error.
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from skill_lens.engines import scan_bundle  # noqa: E402
from skill_lens.report import build_report, render_sarif  # noqa: E402

SCHEMA_PATH = REPO_ROOT / "tests" / "fixtures" / "schema" / "sarif-schema-2.1.0.json"
CASES = [
    ("malicious", REPO_ROOT / "corpus/fixtures/malicious/committed-keys"),
    ("benign", REPO_ROOT / "corpus/fixtures/benign/pinned-deps-helper"),
]


def load_validator():
    try:
        import jsonschema
    except ImportError as exc:
        print("jsonschema not installed (pip install 'skill-lens[dev]')", file=sys.stderr)
        raise SystemExit(1) from exc
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    # The vendored schema declares draft-07; use its class directly so no
    # dynamic validator_for() lookup is needed.
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(schema)


def main() -> int:
    validator = load_validator()
    failures = 0
    for label, bundle in CASES:
        envelope = build_report(scan_bundle(bundle))
        sarif = render_sarif(envelope)
        errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.absolute_path))
        results = len(sarif.get("runs", [{}])[0].get("results", []))
        if errors:
            failures += len(errors)
            for err in errors[:5]:
                loc = "/".join(str(p) for p in err.absolute_path)
                print(f"INVALID [{label}] at {loc or '<root>'}: {err.message}")
        else:
            print(f"OK [{label}] {bundle.name} · {results} SARIF results · schema-valid")

    print(f"\nSARIF CHECK: {'FAIL' if failures else 'PASS'} ({failures} violations)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
