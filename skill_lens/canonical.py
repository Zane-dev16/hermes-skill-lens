"""Canonical JSON emission — the DETERMINISM LAW made code.

Two artifacts per scan output directory:

- ``report.json``  — the deterministic envelope: ``SkillIR.canonical_dict()``
   serialized with :func:`canonical_dumps`. Same input bundle + same rule
   pack ⇒ byte-identical bytes across runs, machines, TZ and locale.
- ``report.meta.json`` — the ``_meta`` sidecar (SPEC §12.3): every volatile
   observation (``generated_at``, per-stage ``durations_ms``, run-time
   interpreter versions) lives ONLY here. It exists for humans/debugging and
   is never hashed or compared; nothing inside the envelope may embed
   timestamps or environment-dependent values.

Serialization form is pinned in DECISIONS D-007: ``json.dumps(...,
sort_keys=True, separators=(",", ":"), ensure_ascii=False)``, written UTF-8
with LF newlines.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skill_lens.ir import SkillIR

ENVELOPE_FILENAME = "report.json"
SIDECAR_FILENAME = "report.meta.json"


def canonical_dumps(obj: Any) -> str:
    """Byte-stable JSON text for *any* JSON-safe object.

    Sorted keys (insertion order can never leak), compact separators,
    non-ASCII kept as literal UTF-8 rather than escaped. Pure function.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class WrittenReport:
    """Paths of the two files :func:`write_report` produced."""

    report_path: Path
    meta_path: Path


def build_meta_sidecar(
    *,
    durations_ms: Mapping[str, float] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the volatile ``_meta`` object (SPEC §12.3).

    ``now`` defaults to the real wall clock (UTC, millisecond ISO-8601);
    tests inject a fixed instant. ``durations_ms`` keys are sorted so even
    this sidecar renders stably apart from its time-varying values.
    """
    moment = (now if now is not None else datetime.now(UTC)).astimezone(UTC)
    generated_at = moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    durations = {key: durations_ms[key] for key in sorted(durations_ms)} if durations_ms else {}
    return {
        "generated_at": generated_at,
        "durations_ms": durations,
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        },
    }


def write_report(
    ir: SkillIR,
    out_dir: str | Path,
    *,
    durations_ms: Mapping[str, float] | None = None,
    now: datetime | None = None,
) -> WrittenReport:
    """Write the deterministic envelope plus the ``_meta`` sidecar.

    Creates ``out_dir`` when missing. The envelope contains ONLY the IR's
    canonical payload; all volatility goes to the sidecar file. IO errors
    propagate to the caller (this is a library entry point, not a host hook
    — containment happens one layer up).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / ENVELOPE_FILENAME
    meta_path = out / SIDECAR_FILENAME

    envelope_text = canonical_dumps(ir.canonical_dict())
    meta_text = canonical_dumps({"_meta": build_meta_sidecar(durations_ms=durations_ms, now=now)})

    report_path.write_text(envelope_text, encoding="utf-8", newline="\n")
    meta_path.write_text(meta_text, encoding="utf-8", newline="\n")
    return WrittenReport(report_path=report_path, meta_path=meta_path)
