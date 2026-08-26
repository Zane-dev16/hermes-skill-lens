"""``lens diff`` — shift-stable report comparison (SPEC §11.2, D-HASH).

Compares two ``report/1`` envelopes keyed on FINDING FINGERPRINTS — the
D-HASH identity binds ``(rule_id ‖ capability ‖ normalized-evidence)`` and
deliberately excludes line numbers, so a 10-line insertion above the
evidence shifts every location yet changes NO fingerprint. The classifier
exploits exactly that:

- **new**       fingerprint in B, absent in A;
- **fixed**     fingerprint in A, absent in B;
- **persisted** fingerprint in both — line moves are NOT drift and never
  flagged; a persisted pair counts as **changed** only when a MATERIAL
  field moved (severity / effective_severity / suppressed / declared /
  static_only). Confidence micro-drift is not material.

Pure core (:func:`diff_reports`) + chat renderer
(:func:`render_diff`) under the §11.3 budgets with the same collapse
ladder as every other surface: over soft ⇒ condensed rows; over hard ⇒
summary + persisted full text under ``<plugin-data>/reports/``. The
byte-frozen coverage footer rides on every render (§12.6).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skill_lens.render import (
    ADVISOR_LINE,
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
)

_FENCE = "```"

#: Field set whose movement makes a persisted fingerprint "changed".
MATERIAL_FIELDS: tuple[str, ...] = (
    "severity",
    "effective_severity",
    "suppressed",
    "declared",
    "static_only",
)

_ROW_CLIP = 72
_STEM_MAX = 48

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _severity_rank(severity: str) -> int:
    return _SEV_ORDER.index(severity) if severity in _SEV_ORDER else len(_SEV_ORDER)


def _row_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    eff = str(finding.get("effective_severity") or finding.get("severity") or "")
    location = finding.get("location") or {}
    start = location.get("start_line")
    return (
        _severity_rank(eff),
        str(finding.get("rule_id", "")),
        str(location.get("path", "")),
        start if isinstance(start, int) else 0,
    )


# ---------------------------------------------------------------------------
# Core comparison (pure)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiffReport:
    """Classified outcome of one fingerprint-keyed comparison."""

    subject: str
    added: tuple[dict[str, Any], ...]
    removed: tuple[dict[str, Any], ...]
    persisted: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    changed: tuple[tuple[dict[str, Any], dict[str, Any]], ...]

    @property
    def drift_free(self) -> bool:
        """No new, no fixed, no material change — pure line-shift territory."""
        return not self.added and not self.removed and not self.changed

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe summary (machine consumers; rows stay envelope-shaped)."""
        return {
            "subject": self.subject,
            "new": len(self.added),
            "fixed": len(self.removed),
            "persisted": len(self.persisted),
            "changed": len(self.changed),
            "drift_free": self.drift_free,
            "new_findings": [dict(f) for f in self.added],
            "fixed_findings": [dict(f) for f in self.removed],
            "changed_pairs": [[dict(a), dict(b)] for a, b in self.changed],
        }


def _material_delta(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    deltas: list[str] = []
    for field in MATERIAL_FIELDS:
        old_value = old.get(field)
        new_value = new.get(field)
        if old_value != new_value:
            deltas.append(f"{field} {old_value!r}→{new_value!r}")
    return deltas


def diff_reports(
    envelope_a: Mapping[str, Any],
    envelope_b: Mapping[str, Any],
    *,
    subject: str | None = None,
) -> DiffReport:
    """Classify findings between two envelopes. Pure; deterministic.

    Junk shapes degrade safely: non-dict/missing fingerprints are compared
    under a synthesized per-envelope key so they can never collide across
    reports.
    """
    index_a = _by_fingerprint(envelope_a)
    index_b = _by_fingerprint(envelope_b)

    added = tuple(sorted((index_b[k] for k in index_b if k not in index_a), key=_row_sort_key))
    removed = tuple(sorted((index_a[k] for k in index_a if k not in index_b), key=_row_sort_key))
    shared = sorted(set(index_a) & set(index_b))
    persisted: list[tuple[dict[str, Any], dict[str, Any]]] = []
    changed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for key in shared:
        old = index_a[key]
        new = index_b[key]
        if _material_delta(old, new):
            changed.append((old, new))
        else:
            persisted.append((old, new))

    if subject is not None:
        name = subject
    else:
        target = envelope_b.get("target") or {}
        name = str(target.get("name") or (envelope_a.get("target") or {}).get("name") or "?")
    return DiffReport(
        subject=name,
        added=added,
        removed=removed,
        persisted=tuple(persisted),
        changed=tuple(changed),
    )


def _by_fingerprint(envelope: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Index one envelope's findings by fingerprint.

    Findings WITHOUT a fingerprint are excluded: there is no stable identity
    to compare across reports, and synthesizing one (position/message) would
    manufacture false new/fixed pairs. They remain visible inside their own
    reports — diff simply cannot track what has no identity.
    """
    index: dict[str, dict[str, Any]] = {}
    for finding in envelope.get("findings", ()) or ():
        if not isinstance(finding, Mapping):
            continue
        key = str(finding.get("fingerprint") or "").strip()
        if not key:
            continue
        # First member wins (mirrors pipeline dedup survivor choice).
        index.setdefault(key, dict(finding))
    return index


# ---------------------------------------------------------------------------
# Rendering (§11.3 budgets; fenced; ANSI-free)
# ---------------------------------------------------------------------------


def _score_line(side: str, envelope: Mapping[str, Any] | None) -> str:
    if envelope is None:
        return f"{side}: (none)"
    score = envelope.get("score") or {}
    target = envelope.get("target") or {}
    hash_text = str(target.get("bundle_hash") or "?")
    if hash_text.startswith("sha256:") and len(hash_text) > len("sha256:") + 7:
        hash_text = f"sha256:{hash_text[7:11]}…{hash_text[-4:]}"
    return (
        f"{side}: {hash_text} · {score.get('grade', '?')} "
        f"{score.get('value', '?')}/100 · {str(score.get('verdict', '?')).upper()}"
    )


def _finding_row(prefix: str, finding: Mapping[str, Any]) -> str:
    eff = str(finding.get("effective_severity") or finding.get("severity") or "?")
    location = finding.get("location") or {}
    where = str(location.get("path", ""))
    if location.get("start_line") is not None:
        where += f":{location['start_line']}"
    message = _clip(str(finding.get("message") or finding.get("title", "")), _ROW_CLIP)
    return f"{prefix} {finding.get('rule_id', '?')} {eff} {where} {message}"


def _changed_row(old: Mapping[str, Any], new: Mapping[str, Any]) -> str:
    deltas = _material_delta(old, new)
    eff_old = str(old.get("effective_severity") or old.get("severity") or "?")
    eff_new = str(new.get("effective_severity") or new.get("severity") or "?")
    head = f"~ {new.get('rule_id', '?')} {eff_old}→{eff_new}"
    extras = [d for d in deltas if not d.startswith(("severity ", "effective_severity "))]
    if extras:
        head += " · " + "; ".join(extras)
    location = new.get("location") or {}
    where = str(location.get("path", ""))
    if location.get("start_line") is not None:
        where += f":{location['start_line']}"
    return f"{head} {where} {_clip(str(new.get('message') or ''), _ROW_CLIP)}"


def _clip(text: str, width: int) -> str:
    value = " ".join(text.split())
    return value if len(value) <= width else value[: width - 1] + "…"


def _persist_diff(diff: DiffReport, plugin_data_dir: Path | str | None, text: str) -> str | None:
    if plugin_data_dir is None:
        return None
    shard = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in diff.subject)[:_STEM_MAX]
    path = Path(plugin_data_dir) / "reports" / f"{safe or 'diff'}-diff-{shard}.txt"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8", newline="\n")
    except OSError:
        return None
    return str(path)


def render_diff(
    diff: DiffReport,
    *,
    plugin_data_dir: Path | str | None = None,
    old_envelope: Mapping[str, Any] | None = None,
    new_envelope: Mapping[str, Any] | None = None,
) -> str:
    """Chat-collapsed diff render. Never raises; footer law honored."""
    header = [
        f"lens diff · {_clip(diff.subject, 60)}",
        _score_line("old", old_envelope),
        _score_line("new", new_envelope),
    ]

    counts = (
        f"new({len(diff.added)}) fixed({len(diff.removed)}) "
        f"persisted({len(diff.persisted)}) changed({len(diff.changed)})"
    )

    detail: list[str] = []
    for finding in diff.added:
        detail.append(_finding_row("+ NEW  ", finding))
    for finding in diff.removed:
        detail.append(_finding_row("- FIXED", finding))
    for old, new in diff.changed:
        detail.append(_changed_row(old, new))

    tail: list[str] = []
    if diff.drift_free:
        tail.append(
            f"drift: none · {len(diff.persisted)} fingerprints persisted "
            "(line shifts are not findings)"
        )
    else:
        tail.append(f"= {len(diff.persisted)} unchanged fingerprints")

    body = "\n".join([*header, counts, "", *detail, *tail])
    text = _finish(body)

    if len(text) <= CHAT_SOFT_BUDGET:
        return text

    condensed = [c for c in (counts, *detail[:8], *tail)]
    hidden = max(0, len(detail) - 8)
    if hidden:
        condensed.append(f"… {hidden} more rows in the full diff")
    pointer = _persist_diff(diff, plugin_data_dir, body)
    if pointer:
        condensed.append(f"full diff: {pointer}")
    text = _finish("\n".join(condensed))

    if len(text) > CHAT_HARD_BUDGET:
        minimal = [*header, counts, *tail]
        if pointer is None:
            pointer = _persist_diff(diff, plugin_data_dir, body)
        if pointer:
            minimal.append(f"full diff: {pointer}")
        text = _finish("\n".join(minimal))
    return text


def _finish(body: str) -> str:
    inner = body.rstrip("\n") + "\n" + ADVISOR_LINE + "\n" + COVERAGE_FOOTER
    return f"{_FENCE}\n{inner}\n{_FENCE}\n"


__all__ = ["MATERIAL_FIELDS", "DiffReport", "diff_reports", "render_diff"]
