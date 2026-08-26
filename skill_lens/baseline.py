"""Baseline store + suppression stage (SPEC §10/§11.2; D-FP layer 3).

Baselines are the third false-positive-control layer: a fingerprint set with
a REQUIRED reason and OPTIONAL expiry, written by ``/lens baseline <name>
--reason "…" [--expires DATE]`` into the canonical store
``<target>/.lens/baseline.toml``, merged with any hand-authored ``[[baseline]]``
tables from the §10 policy layers (:mod:`skill_lens.policy`).

Division of labor between the two readers (DECISIONS D-042):

- policy-layer ``[[baseline]]`` tables (hand-authored overlays): ``expires``
  is MANDATORY there (SPEC §10's own comment; enforced by the policy loader);
- the canonical store (machine-written by this module): ``expires`` is
  OPTIONAL — SPEC §11.2's normative verb grammar brackets the flag. An entry
  without expiry simply never expires.

Suppression application is PURE and MACHINE-VISIBLE (PLAN exit criterion):
matched findings stay in the findings list with ``suppressed=true`` and
``suppressed_by="<fingerprint> · <reason>"`` — the fingerprint IS the entry
id (entries are keyed by fingerprint), so the pointer greps straight back to
the store line. Nothing is ever silently dropped; scoring prices suppressed
findings nothing via the existing wire field (the scorer's ``_is_active``
filter), so scores stay a deterministic function of
(bundle bytes, policy, baseline set, report date).

DETERMINISM LAW: expiry evaluation takes the report date as a PARAMETER
(``report_date=``) exactly like :mod:`skill_lens.policy`; wall-clock enters
only at the surface boundary (the slash verb injects ``date.today()``).
Iteration is sorted; stable sorts throughout; zero network.

Store grammar (canonical, written by :func:`write_baseline`)::

    # lens baseline store — …
    [[baseline]]
    fingerprint = "sha256:9c41…"
    reason = "docs example, not executed"
    rule_id = "LNS-SHL-001"     # optional context, advisory only
    path = "scripts/sync.sh"    # optional context, advisory only
    expires = 2027-01-15        # omitted ⇒ never expires

The store lives INSIDE the scanned bundle directory, which is safe: ingest
skips dot-entries (D-011 walk policy), so writing it never changes the
bundle hash (test-enforced).
"""

from __future__ import annotations

import hashlib
import os
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.policy import BaselineEntry, PolicyError

#: Stable diagnostic/store constants.
CODE_BASELINE_EXPIRED = "LNS-BASELINE-EXPIRED"
BASELINE_DIRNAME = ".lens"
BASELINE_FILENAME = "baseline.toml"

#: The D-CRASH isolation finding is a BREAKAGE marker, not behavior — it is
# excluded from what ``/lens baseline`` records (masking crashes forever
# would hide engine failures behind a stale suppression). Kept as a local
# literal (baseline stays import-light) and drift-checked against
# ``skill_lens.engines.base.CODE_ENGINE_FAILURE`` by the suite.
ENGINE_ISOLATION_RULE_ID = "LNS-ENG-000"

_STORE_HEADER = (
    "# lens baseline store — canonical suppression set (SPEC §10/§11.2)\n"
    "# written by 'lens baseline'; hand-edit with care (malformed stores\n"
    "# surface as configuration errors, never silent misses).\n"
    "# Fingerprints are line-shift stable (D-HASH); duplicate fingerprints\n"
    "# keep the earlier expiry; entries without expires never expire.\n"
)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineRecord:
    """One stored suppression: keyed by fingerprint, reason REQUIRED.

    ``rule_id``/``path`` are advisory context captured from the finding at
    write time — they NEVER participate in matching (fingerprints do).
    """

    fingerprint: str
    reason: str
    expires: date | None = None
    rule_id: str | None = None
    path: str | None = None

    def sort_key(self) -> tuple[Any, ...]:
        """Canonical ordering: fingerprint, then earliest expiry, then reason."""
        return (self.fingerprint, self.expires or date.max, self.reason)

    def expired_on(self, report_date: date | None) -> bool:
        """Deterministic expiry check (boundary inclusive, like policy)."""
        if self.expires is None or report_date is None:
            return False
        return report_date > self.expires

    def to_entry(self) -> BaselineEntry:
        """Project onto the policy-layer entry type (shared vocabulary)."""
        return BaselineEntry(fingerprint=self.fingerprint, reason=self.reason, expires=self.expires)


def record_from_baseline_entry(entry: BaselineEntry) -> BaselineRecord:
    """Convert a policy-layer ``[[baseline]]`` entry to a store record."""
    return BaselineRecord(fingerprint=entry.fingerprint, reason=entry.reason, expires=entry.expires)


def normalize_record(value: Any) -> BaselineRecord:
    """Accept either record flavor; anything else is a caller bug."""
    if isinstance(value, BaselineRecord):
        return value
    if isinstance(value, BaselineEntry):
        return record_from_baseline_entry(value)
    raise TypeError(f"not a baseline record: {type(value).__name__}")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def baseline_path_for(target_dir: str | Path) -> Path:
    """Canonical store location: ``<target>/.lens/baseline.toml``."""
    return Path(target_dir) / BASELINE_DIRNAME / BASELINE_FILENAME


# ---------------------------------------------------------------------------
# TOML writing (manual canonical writer — tomllib is read-only stdlib;
# no third-party TOML writer is imported, keeping the dependency closure
# stdlib-only per the privacy/import laws. DECISIONS D-042.)
# ---------------------------------------------------------------------------


def _toml_escape(text: str) -> str:
    """Escape *text* as a TOML basic string body."""
    out: list[str] = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return "".join(out)


def render_baseline_toml(records: Sequence[BaselineRecord]) -> str:
    """Deterministic store text: sorted records, fixed key order.

    Key order inside an entry: fingerprint, reason, rule_id?, path?,
    expires?. Sorting is by :meth:`BaselineRecord.sort_key` (stable).
    """
    parts: list[str] = [_STORE_HEADER]
    for record in sorted(records, key=BaselineRecord.sort_key):
        lines = ["[[baseline]]", f'fingerprint = "{_toml_escape(record.fingerprint)}"']
        lines.append(f'reason = "{_toml_escape(record.reason)}"')
        if record.rule_id:
            lines.append(f'rule_id = "{_toml_escape(record.rule_id)}"')
        if record.path:
            lines.append(f'path = "{_toml_escape(record.path)}"')
        if record.expires is not None:
            lines.append(f"expires = {record.expires.isoformat()}")
        parts.append("\n".join(lines) + "\n")
    return "\n".join(parts)


def write_baseline(path: str | Path, records: Sequence[BaselineRecord]) -> None:
    """Atomically write the canonical store (tmp file + os.replace).

    Creates parent directories. Raises :class:`PolicyError` (configuration
    seam) when the write itself fails; callers map that to exit-2/notice.
    """
    store = Path(path)
    text = render_baseline_toml(records)
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        tmp = store.with_name(store.name + ".tmp")
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, store)
    except OSError as exc:
        raise PolicyError(f"cannot write baseline store: {exc}", path=str(store)) from exc


# ---------------------------------------------------------------------------
# Reading (strict — the store is a configuration seam like policy files)
# ---------------------------------------------------------------------------

_ENTRY_KEYS = ("fingerprint", "reason", "rule_id", "path", "expires")


def _parse_iso_date(value: Any, *, where: str) -> date:
    parsed = value if isinstance(value, date) else None
    if parsed is None:
        try:
            parsed = date.fromisoformat(str(value).strip())
        except (ValueError, TypeError) as exc:
            raise PolicyError(
                f"baseline entry has unparsable expires {value!r} ({where})", path=where
            ) from exc
    return parsed


def parse_baseline_document(data: Mapping[str, Any], *, source: str) -> tuple[BaselineRecord, ...]:
    """Parse the ``[[baseline]]`` array of a loaded store document.

    STRICT: structural problems (missing fingerprint/reason, unknown keys,
    wrong shapes) raise :class:`PolicyError` — a corrupt suppression set must
    surface loudly, never silently stop suppressing.
    """
    raw = data.get("baseline")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError("baseline store must contain a [[baseline]] array", path=source)
    records: list[BaselineRecord] = []
    for index, row in enumerate(raw, start=1):
        where = f"{source}#[[{baseline_label(index)}]]"
        if not isinstance(row, Mapping):
            raise PolicyError("baseline entry must be a table", path=where)
        unknown = sorted(str(key) for key in row if str(key) not in _ENTRY_KEYS)
        if unknown:
            raise PolicyError(f"baseline entry has unknown key(s) {', '.join(unknown)}", path=where)
        fingerprint = str(row.get("fingerprint") or "").strip()
        reason = str(row.get("reason") or "").strip()
        if not fingerprint:
            raise PolicyError("baseline entry lacks required fingerprint", path=where)
        if not reason:
            raise PolicyError(
                "baseline entry lacks required reason (suppressions must justify themselves)",
                path=where,
            )
        rule_id = str(row.get("rule_id") or "").strip() or None
        path_field = str(row.get("path") or "").strip() or None
        expires_raw = row.get("expires")
        expires = _parse_iso_date(expires_raw, where=where) if expires_raw is not None else None
        records.append(
            BaselineRecord(
                fingerprint=fingerprint,
                reason=reason,
                expires=expires,
                rule_id=rule_id,
                path=path_field,
            )
        )
    return tuple(records)


def baseline_label(index: int) -> str:
    """Display token for error paths (store entries carry no names)."""
    return f"baseline:{index}"


def read_baseline(path: str | Path) -> tuple[BaselineRecord, ...]:
    """Read one store strictly; MISSING file ⇒ ``()`` (absent layer).

    Existing-but-broken stores raise :class:`PolicyError` (exit-2 on CLI
    verbs / one-line notice in-session — the A1 seam contract).
    """
    store = Path(path)
    if not store.is_file():
        return ()
    try:
        raw = store.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read baseline store: {exc}", path=str(store)) from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in baseline store: {exc}", path=str(store)) from exc
    return parse_baseline_document(data, source=str(store))


# ---------------------------------------------------------------------------
# Merging (SPEC §10: duplicate fingerprints resolve to the EARLIER expiry)
# ---------------------------------------------------------------------------


def _expiry_rank(record: BaselineRecord) -> date:
    """Expiry comparison rank; ``None`` sorts LAST (never-expiring is the
    longest-lived suppression, so an expiring duplicate beats it)."""
    return record.expires if record.expires is not None else date.max


def merge_records(
    *layers: Iterable[BaselineRecord] | Iterable[BaselineEntry],
) -> tuple[BaselineRecord, ...]:
    """Merge record layers (earlier arguments = lower precedence).

    Per fingerprint the survivor is the record with the EARLIER expiry
    (SPEC §10 comment law; ties — including both-permanent — let the LATER
    layer win so refreshed reasons propagate). Output is canonically sorted.
    """
    winners: dict[str, BaselineRecord] = {}
    for layer in layers:
        for record in layer:
            record = normalize_record(record)
            incumbent = winners.get(record.fingerprint)
            if incumbent is None:
                winners[record.fingerprint] = record
                continue
            old_rank = _expiry_rank(incumbent)
            new_rank = _expiry_rank(record)
            if new_rank < old_rank:
                winners[record.fingerprint] = record
            elif new_rank == old_rank:
                winners[record.fingerprint] = record  # later layer refreshes
    return tuple(sorted(winners.values(), key=BaselineRecord.sort_key))


# ---------------------------------------------------------------------------
# Record collection from a fresh scan (the write verb's input)
# ---------------------------------------------------------------------------


def collect_baseline_records(findings: Iterable[Mapping[str, Any]]) -> list[BaselineRecord]:
    """One record per current finding fingerprint, canonically ordered.

    Excludes the D-CRASH isolation finding (``LNS-ENG-000``): a crash marker
    is breakage telemetry, not bundle behavior, and must resurface on every
    scan until the engine fault is fixed. Findings without a fingerprint are
    skipped (nothing stable to key on).
    """
    records: list[BaselineRecord] = []
    seen: set[str] = set()
    for finding in findings:
        if str(finding.get("rule_id")) == ENGINE_ISOLATION_RULE_ID:
            continue
        fingerprint = str(finding.get("fingerprint") or "").strip()
        if not fingerprint or fingerprint in seen:
            continue
        seen.add(fingerprint)
        location = finding.get("location") or {}
        reason = str(finding.get("message") or finding.get("title") or "baselined finding")
        records.append(
            BaselineRecord(
                fingerprint=fingerprint,
                reason=" ".join(reason.split())[:200],
                rule_id=str(finding.get("rule_id")) or None,
                path=str(location.get("path")) or None,
            )
        )
    records.sort(key=BaselineRecord.sort_key)
    return records


# ---------------------------------------------------------------------------
# Application (PURE — the suppression stage of the report pipeline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineStats:
    """Outcome summary of one :func:`apply_baselines` pass."""

    suppressed: int = 0
    already_suppressed: int = 0
    expired_entries: int = 0
    unmatched_entries: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "suppressed": self.suppressed,
            "already_suppressed": self.already_suppressed,
            "expired_entries": self.expired_entries,
            "unmatched_entries": self.unmatched_entries,
        }


def suppressed_by_marker(record: BaselineRecord) -> str:
    """Machine-visible pointer: "<fingerprint> · <reason>" (entry id + reason)."""
    return f"{record.fingerprint} · {record.reason}"


def apply_baselines(
    findings: Iterable[Mapping[str, Any]],
    entries: Iterable[Any],
    *,
    report_date: date | None = None,
    diag: DiagnosticsCollector | None = None,
) -> tuple[list[dict[str, Any]], BaselineStats]:
    """Mark baseline-suppressed findings; PURE; input dicts never mutated.

    - Expired entries (``expires`` < report_date) suppress NOTHING and
      resurface loudly as an info diagnostic (SPEC §10: "expired entries
      resurface loudly").
    - Matches set ``suppressed=true`` + ``suppressed_by`` and STAY in the
      list — machine-visible per the PLAN exit criterion.
    - Findings already suppressed (policy ``allow_matched`` ran earlier in
      the pipeline) keep their first explanation — first writer wins.

    Duplicate fingerprints within *entries*: earlier expiry wins (same rule
    as :func:`merge_records`; callers normally pass merged records).
    """
    collector = diag if diag is not None else DiagnosticsCollector()

    effective: dict[str, BaselineRecord] = {}
    expired = 0
    for value in entries:
        record = normalize_record(value)
        if record.expired_on(report_date):
            expired += 1
            collector.info(
                CODE_BASELINE_EXPIRED,
                f"baseline entry {record.fingerprint[:16]}… expired "
                f"({record.expires.isoformat() if record.expires else '?'}) "
                "and no longer suppresses",
            )
            continue
        incumbent = effective.get(record.fingerprint)
        if incumbent is None or _expiry_rank(record) < _expiry_rank(incumbent):
            effective[record.fingerprint] = record

    applied: list[dict[str, Any]] = []
    matched: set[str] = set()
    newly_suppressed = 0
    already_suppressed = 0
    for finding in findings:
        row = dict(finding)
        fingerprint = str(row.get("fingerprint") or "")
        record = effective.get(fingerprint)
        if record is not None:
            matched.add(fingerprint)
            if row.get("suppressed"):
                already_suppressed += 1
            else:
                row["suppressed"] = True
                row["suppressed_by"] = suppressed_by_marker(record)
                newly_suppressed += 1
        applied.append(row)

    stats = BaselineStats(
        suppressed=newly_suppressed,
        already_suppressed=already_suppressed,
        expired_entries=expired,
        unmatched_entries=len(set(effective) - matched),
    )
    return applied, stats


# ---------------------------------------------------------------------------
# Effective-set resolution (what a scan actually suppresses) + cache folding
# ---------------------------------------------------------------------------


def resolve_baseline_entries(
    *,
    view: Any = None,
    target_dir: str | Path | None = None,
    extra_files: Sequence[str | Path] = (),
    global_path: str | Path | None = None,
    report_date: date | None = None,
    diag: DiagnosticsCollector | None = None,
) -> tuple[BaselineRecord, ...]:
    """Full effective baseline set for one target (STRICT config lane).

    Layers, later wins: canonical store at ``<target_dir>/.lens/baseline.toml``
    then every policy-layer ``[[baseline]]`` table (settings/global/project/
    extras) resolved via :func:`skill_lens.policy.load_policy`. Raises
    :class:`PolicyError` for broken configuration (verbs map that to exit-2 /
    one-line notice — malformed suppression metadata must never silently
    stop suppressing).
    """
    from skill_lens.policy import load_policy

    collector = diag if diag is not None else DiagnosticsCollector()
    store_records: tuple[BaselineRecord, ...] = ()
    if target_dir is not None:
        store_records = read_baseline(baseline_path_for(target_dir))

    policy = load_policy(
        ctx=view,
        project_dir=target_dir,
        extra_files=extra_files,
        global_path=global_path,
        report_date=report_date,
        diag=collector,
    )
    policy_records = tuple(record_from_baseline_entry(e) for e in policy.baseline_entries)
    return merge_records(store_records, policy_records)


def effective_fingerprints(
    entries: Iterable[Any], *, report_date: date | None = None
) -> tuple[str, ...]:
    """Sorted fingerprints that actively suppress given the report date."""
    active = {
        normalize_record(record).fingerprint
        for record in entries
        if not normalize_record(record).expired_on(report_date)
    }
    return tuple(sorted(active))


def baseline_cache_suffix(entries: Iterable[Any], *, report_date: date | None = None) -> str:
    """Cache-key suffix folding the EFFECTIVE suppression set.

    Empty effective set ⇒ "" (byte-identical historical keys — golden and
    byte-stability tests keep their exact cache behavior). Otherwise
    ``":bl:" + 16 hex`` over the sorted ``(fingerprint, expires)`` pairs, so
    adding/expiring a suppression invalidates fast-path answers that were
    rendered under a different suppression set. Reasons deliberately do NOT
    participate: they never change suppression outcomes, only explanations.
    """
    pairs = []
    for record in sorted(
        (normalize_record(value) for value in entries),
        key=BaselineRecord.sort_key,
    ):
        if record.expired_on(report_date):
            continue
        expires_text = record.expires.isoformat() if record.expires else ""
        pairs.append(f"{record.fingerprint}\x00{expires_text}")
    if not pairs:
        return ""
    digest = hashlib.sha256("\n".join(pairs).encode("utf-8")).hexdigest()
    return f":bl:{digest[:16]}"


__all__ = [
    "CODE_BASELINE_EXPIRED",
    "BASELINE_DIRNAME",
    "BASELINE_FILENAME",
    "BaselineRecord",
    "BaselineStats",
    "ENGINE_ISOLATION_RULE_ID",
    "apply_baselines",
    "baseline_cache_suffix",
    "baseline_path_for",
    "collect_baseline_records",
    "effective_fingerprints",
    "merge_records",
    "normalize_record",
    "parse_baseline_document",
    "read_baseline",
    "render_baseline_toml",
    "resolve_baseline_entries",
    "suppressed_by_marker",
    "write_baseline",
]
