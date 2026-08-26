#!/usr/bin/env python3
"""Canonical-envelope determinism digests over the corpus (PLAN §1 Phase 3).

Scans every corpus fixture bundle, serializes each ``report/1`` envelope with
the canonical dumps law (sort_keys, compact separators), and emits a sorted
``{fixture: sha256}`` manifest plus a total digest. The envelope EXCLUDES the
volatile ``_meta`` sidecar BY CONSTRUCTION (report.py never embeds it; the
sidecar is a separate artifact) — that exclusion is central here: nothing
wall-clock-, locale-, TZ-, or path-dependent may enter the compared bytes.

Used by BOTH legs of ``.github/workflows/determinism.yml`` (differing
TZ / LANG / checkout-path prefix / hash seed); the workflow byte-compares
the two manifests and fails the job on ANY drift. Each invocation also scans
every fixture TWICE in-process and fails on internal mismatch, so intra-leg
nondeterminism is caught even before the cross-leg compare.

Usage: python3 tools/determinism_check.py [OUTPUT.json]  (default: stdout)

Exit codes: 0 identical, 1 drift or error.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from skill_lens.canonical import canonical_dumps  # noqa: E402
from skill_lens.engines import scan_bundle  # noqa: E402
from skill_lens.report import build_report  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "corpus" / "fixtures"


def fixture_bundles() -> list[Path]:
    """Every corpus fixture directory (sorted; both classes)."""
    bundles = [
        p.parent
        for p in sorted(CORPUS_ROOT.rglob("SKILL.md"))
        if (p.parent / "expected.toml").is_file()
    ]
    return sorted(bundles)


def envelope_digest(bundle: Path) -> str:
    """sha256 over the canonical envelope bytes of one fresh scan."""
    result = scan_bundle(bundle)
    envelope = build_report(result)
    if "_meta" in envelope:  # paranoia guard: exclusion is central to this check
        raise RuntimeError(f"{bundle.name}: volatile _meta leaked into envelope")
    payload = canonical_dumps(envelope).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_manifest() -> dict[str, object]:
    """Scan every fixture twice; return the digest manifest or raise."""
    digests: dict[str, str] = {}
    for bundle in fixture_bundles():
        rel = bundle.relative_to(REPO_ROOT).as_posix()
        first = envelope_digest(bundle)
        second = envelope_digest(bundle)
        if first != second:
            raise RuntimeError(f"intra-leg drift: {rel} scanned twice, digests differ")
        digests[rel] = first
    ordered = {key: digests[key] for key in sorted(digests)}
    total = hashlib.sha256(
        canonical_dumps(ordered).encode("utf-8"),
    ).hexdigest()
    return {
        "schema": "lens.determinism-digests/1",
        "fixtures": len(ordered),
        "digests": ordered,
        "total_sha256": total,
    }


def main() -> int:
    try:
        manifest = build_manifest()
    except Exception as exc:  # noqa: BLE001 — CI tool: report and fail cleanly
        print(f"DETERMINISM CHECK ERROR: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    out_path = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"fixtures={manifest['fixtures']} total_sha256={manifest['total_sha256']}")
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
