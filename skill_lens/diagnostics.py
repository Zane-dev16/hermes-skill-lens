"""Structured diagnostics for Skill Lens.

Law: every parse/walk/IO failure inside the pipeline becomes a
:class:`Diagnostic` record — nothing raises out to callers, and nothing is
swallowed silently. Records are ordered by occurrence (stable: same input
plus same execution path yields the same record sequence) and carry a
machine-readable ``code``, a ``severity``, an optional ``path`` (bundle or
file the record is about), a human ``message``, and a JSON-safe ``detail``
mapping.

Codes are dotted-free stable strings; subsystems use their own namespaces
(e.g. ``LNS-DIAG-INTERNAL`` here, ingest/engine codes arrive with those
subsystems). Wall-clock timestamps are deliberately NOT recorded here:
deterministic payloads never embed wall-clock data (they belong in the
``_meta`` sidecar only).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

SEVERITY_DEBUG = "debug"
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"

#: All recognized severities, in ascending order of urgency.
SEVERITIES: tuple[str, ...] = (
    SEVERITY_DEBUG,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    SEVERITY_ERROR,
)

#: Code used when building a Diagnostic itself fails (paranoia tier).
CODE_INTERNAL = "LNS-DIAG-000"


@dataclass(frozen=True)
class Diagnostic:
    """One structured, evidence-cited problem report."""

    code: str
    severity: str
    path: str | None
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe mapping (canonical dumps apply ``sort_keys=True``)."""
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
            "detail": dict(self.detail),
        }


class DiagnosticsCollector:
    """Thread-safe, append-only list of :class:`Diagnostic` records."""

    def __init__(self) -> None:
        self._records: list[Diagnostic] = []
        self._lock = threading.Lock()

    def record(
        self,
        code: str,
        message: str,
        *,
        severity: str = SEVERITY_WARNING,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Diagnostic:
        """Append one record and return it. Never raises."""
        try:
            diag = Diagnostic(
                code=str(code),
                severity=str(severity),
                path=None if path is None else str(path),
                message=str(message),
                detail=dict(detail) if detail else {},
            )
        except Exception:  # noqa: BLE001 — even construction must not raise.
            diag = Diagnostic(
                code=CODE_INTERNAL,
                severity=SEVERITY_ERROR,
                path=None,
                message=f"diagnostic construction failed for code={code!r}: message={message!r}",
                detail={},
            )
        with self._lock:
            self._records.append(diag)
        return diag

    # Convenience wrappers keep call sites terse and severity-consistent.
    def info(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Diagnostic:
        return self.record(code, message, severity=SEVERITY_INFO, path=path, detail=detail)

    def warning(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Diagnostic:
        return self.record(code, message, severity=SEVERITY_WARNING, path=path, detail=detail)

    def error(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Diagnostic:
        return self.record(code, message, severity=SEVERITY_ERROR, path=path, detail=detail)

    # -- read side ---------------------------------------------------------------

    def snapshot(self) -> tuple[Diagnostic, ...]:
        """Stable copy of all records so far (insertion order)."""
        with self._lock:
            return tuple(self._records)

    def by_severity_at_least(self, minimum: str) -> tuple[Diagnostic, ...]:
        """Records whose severity rank is >= *minimum*'s rank."""
        if minimum not in SEVERITIES:
            return ()
        floor = SEVERITIES.index(minimum)
        return tuple(d for d in self.snapshot() if _severity_rank(d) >= floor)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __iter__(self) -> Iterator[Diagnostic]:
        return iter(self.snapshot())

    def clear(self) -> None:
        """Drop all records (tests and long-lived sweeps only)."""
        with self._lock:
            self._records.clear()


def _severity_rank(diag: Diagnostic) -> int:
    try:
        return SEVERITIES.index(diag.severity)
    except ValueError:
        # Unknown severity ranks above everything so it can't be filtered out.
        return len(SEVERITIES)
