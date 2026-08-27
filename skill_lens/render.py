"""Surface renderers — chat compact (slash), one-liners, terminal panel.

Three renderers live here, kept strictly apart because their contracts
differ (SPEC §11.3/§11.4/§12.1/§12.2):

- :func:`render_chat_compact` — the ``/lens`` collapsed variant: fenced,
  surface-neutral (NO ANSI, no pipe tables), count line + worst-5 findings
  + pointers; soft budget 1200 / hard budget 1800 chars; overflow spills to
  ``<plugin-data>/reports/<name>-<hash8>.txt`` with a path pointer.
- :func:`render_fast_line_*` — §11.4 normative one-liners: single line,
  sober only, ≤160 chars, ASCII punctuation, fixed field order, ends with a
  pull pointer. These are STATUS lines, not reports — exempt from the
  coverage-footer law (§12.6).
- :func:`render_terminal_panel` — the CLI-side box-drawing panel (a later
  phase wires it through Rich on the CLI verbs; never the slash path).

The byte-frozen coverage footer (§12.6, R5) renders on every REPORT surface
including slash output; only the fast-path status lines are exempt.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .canonical import canonical_dumps
from .report import report_hash8

#: Byte-frozen coverage footer (SPEC §12.6 — golden tests assert this exact
#: text; do not rewrap, re-punctuate, or "fix" the middle dots).
COVERAGE_FOOTER = (
    "· static analysis only — runtime-injected instructions "
    "(tool output) are out of scope · lens explain coverage"
)

#: G2 enriched marker (SPEC §14: any network feature is opt-in, named, and
#: logged in-report). Appended to the footer ONLY when the envelope carries
#: an ``enrichment`` block (i.e. the user explicitly passed --osv); the bare
#: footer stays byte-frozen for every default-path render.
ENRICHMENT_MARKER = " · osv-enriched (--osv network opt-in active)"


def envelope_enriched(envelope: Mapping[str, Any]) -> bool:
    """True when this envelope went through an opt-in enrichment pass."""
    return bool((envelope.get("enrichment") or {}).get("provider"))


#: Chat budgets (§11.3 normative): soft target, hard ceiling.
CHAT_SOFT_BUDGET = 1200
CHAT_HARD_BUDGET = 1800

#: §11.4 one-liner hard cap.
FAST_LINE_MAX_CHARS = 160

#: Worst-N findings shown in the default collapsed render / over-budget fall.
WORST_N_DEFAULT = 5
WORST_N_OVER_BUDGET = 3

#: Sober advisor line rendered above the pointers (§12.2).
ADVISOR_LINE = "advisor only — lens never blocks installs. clean scan ≠ safe skill."

#: Bundle names are host-controlled strings; both derived surfaces must stay
#: bounded so §11.3's pointer contract and §12.2's hard budget hold for ANY
#: input. Display clip mirrors the §12.2 ~80-col snippet discipline with
#: headroom for the surrounding fixed fields.
_DISPLAY_NAME_MAX = 96

#: Overflow-artifact stem clip: ``<stem>-<hash8>.txt`` stays ≤77 bytes, safe
#: under every host filesystem's 255-byte NAME_MAX. Uniqueness rides the
#: hash8 shard, never the name (D-032).
_FILENAME_PART_MAX = 64

_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

_FENCE = "```"


def _display_name(name: str) -> str:
    """Clip an untrusted bundle name for inline rendering (hard-budget guard)."""
    if len(name) <= _DISPLAY_NAME_MAX:
        return name
    return name[: _DISPLAY_NAME_MAX - 1] + "…"


def _safe_filename_stem(name: str) -> str:
    """Filename-safe stem for overflow artifacts (D-032).

    Rewrites everything outside ``[A-Za-z0-9._-]`` (including path
    separators and control bytes) and clips to :data:`_FILENAME_PART_MAX`
    so the write can never fail on NAME_MAX or escape the reports dir.
    Two different bundles can share a stem; the ``-<hash8>`` shard keeps
    artifacts distinct.
    """
    cleaned = _FILENAME_UNSAFE.sub("_", name.strip())
    return cleaned[:_FILENAME_PART_MAX] or "report"


#: Display labels per severity tier (sober; glyph+word per §12.1/§12.2).
SEVERITY_LABELS: dict[str, str] = {
    "CRITICAL": "! ALERT",
    "HIGH": "! WARN",
    "MEDIUM": "○ NOTE",
    "LOW": "○ NOTE",
}

#: Family abbreviations used by the caps line (§12.1 house style).
FAMILY_ABBREV: dict[str, str] = {
    "credentials.read": "creds.read",
    "execute.code": "exec.code",
    "execute.shell": "exec.shell",
    "filesystem.outside": "fs.outside",
    "filesystem.read": "fs.read",
    "filesystem.write": "fs.write",
    "integrity.override": "integrity",
    "network.read": "net.read",
    "network.send": "net.send",
    "persona.write": "persona",
    "spawn.agent": "spawn",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    return order.index(severity) if severity in order else len(order)


def worst_findings(envelope: Mapping[str, Any], count: int) -> list[Mapping[str, Any]]:
    """The *count* most severe active findings, deterministic within band.

    Order: effective severity descending, then ``(rule_id, path, line)``
    ascending — the DETERMINISM LAW key inside each severity band.
    """
    active = [f for f in envelope.get("findings", ()) if not f.get("suppressed", False)]

    def key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
        eff = str(finding.get("effective_severity") or finding.get("severity") or "")
        location = finding.get("location") or {}
        start = location.get("start_line")
        return (
            _severity_rank(eff),
            str(finding.get("rule_id", "")),
            str(location.get("path", "")),
            start if isinstance(start, int) else 0,
        )

    return sorted(active, key=key)[:count]


def _finding_counts(envelope: Mapping[str, Any]) -> dict[str, int]:
    """Active-finding counts keyed by §11.4 display class."""
    counts = {"alert": 0, "warn": 0, "note": 0, "low": 0}
    for finding in envelope.get("findings", ()):
        if finding.get("suppressed", False):
            continue
        eff = str(finding.get("effective_severity") or finding.get("severity") or "")
        counts[{"CRITICAL": "alert", "HIGH": "warn", "MEDIUM": "note"}.get(eff, "low")] += 1
    return counts


def counts_phrase(envelope: Mapping[str, Any]) -> str:
    """§11.4 count fragment, e.g. ``1 alert 2 warn`` (zero classes omitted)."""
    labels = (("alert", "alert"), ("warn", "warn"), ("note", "note"), ("low", "low"))
    counts = _finding_counts(envelope)
    parts = [f"{counts[key]} {label}" for key, label in labels if counts[key]]
    return " ".join(parts) if parts else "0 findings"


def capability_line(envelope: Mapping[str, Any]) -> str:
    """``caps`` row: observed families + declared fraction (deterministic)."""
    families: list[str] = []
    for finding in envelope.get("findings", ()):
        family = str(finding.get("capability", "")).partition(":")[0]
        if family and family not in families:
            families.append(family)
    shown = [FAMILY_ABBREV.get(family, family) for family in sorted(families)]
    declared_total = len(envelope.get("claims", ()) or ())
    suffix = ""
    if declared_total:
        suffix = f" (declared {declared_total})"
    return " · ".join(shown) + suffix if shown else "none observed" + suffix


def _patient_line(envelope: Mapping[str, Any]) -> str:
    provenance = envelope.get("provenance") or {}
    name = _display_name(str((envelope.get("target") or {}).get("name", "?")))
    bits = [str(provenance[key]) for key in ("identifier", "trust_level") if provenance.get(key)]
    annotation = f" ({' · '.join(bits)})" if bits else ""
    return f"patient : {name}{annotation}"


def _bundle_line(envelope: Mapping[str, Any]) -> str:
    target = envelope.get("target") or {}
    hash_text = str(target.get("bundle_hash") or "unhashed")
    if hash_text.startswith("sha256:") and len(hash_text) > len("sha256:") + 4:
        hash_text = f"sha256:{hash_text[7:10]}…{hash_text[-3:]}"
    kb = max(1, round(int(target.get("total_bytes") or 0) / 1024))
    policy = str((envelope.get("policy") or {}).get("profile", "street"))
    return (
        f"bundle  : {hash_text} · {target.get('file_count', 0)} files · {kb} KB · policy {policy}"
    )


def _finding_block(finding: Mapping[str, Any]) -> list[str]:
    eff = str(finding.get("effective_severity") or finding.get("severity") or "LOW")
    label = SEVERITY_LABELS.get(eff, "○ NOTE")
    message = str(finding.get("message") or finding.get("title", ""))
    if len(message) > 80:  # §12.2: snippet/message columns cap near 80 cols
        message = message[:79] + "…"
    head = f"{label} {finding.get('rule_id', '?')} {message}"
    lines = [head[:200]]
    location = finding.get("location") or {}
    where = str(location.get("path", ""))
    if location.get("start_line") is not None:
        where += f":{location['start_line']}"
    declared_word = "declared" if finding.get("declared") else "UNDECLARED"
    detail = (
        f"      {where} — {finding.get('capability', '')}"
        f" · {declared_word} · conf {float(finding.get('confidence', 0.0)):.2f}"
    )
    lines.append(detail)
    return lines


# ---------------------------------------------------------------------------
# Chat compact variant (slash; §11.3 + §12.2)
# ---------------------------------------------------------------------------


def spoiler_wrap(text: str) -> str:
    """Discord spoiler wrap ``||…||`` (§11.3; opt-in via discord_spoilers).

    Courtesy, not redaction (G4 applies underneath): wrapped content stays
    fully present in every machine format — only chat prose hides it behind
    a tap. Default OFF everywhere.
    """
    return f"||{text}||"


def render_chat_compact(
    envelope: Mapping[str, Any],
    *,
    plugin_data_dir: Path | str | None = None,
    worst_count: int = WORST_N_DEFAULT,
    spoilers: bool = False,
) -> str:
    """Collapsed fenced chat render (never raises; never emits ANSI).

    Budget ladder (§11.3): full worst-N render targets the soft budget;
    over soft ⇒ collapse to top-3 + pointer; still over hard ⇒ count line +
    pointer only. When *plugin_data_dir* is supplied, every degraded render
    persists the FULL text under ``<dir>/reports/<name>-<hash8>.txt`` and
    appends the file pointer line.

    *spoilers* (default False) wraps finding detail rows in Discord spoiler
    markers — an opt-in display courtesy that changes chat bytes only;
    machine formats and default renders are untouched.
    """
    body = _chat_body(envelope, worst_count, spoilers=spoilers)
    pointer: str | None = None

    if len(body) > CHAT_SOFT_BUDGET:
        pointer = _persist_full(envelope, plugin_data_dir)
        body = _chat_body(envelope, WORST_N_OVER_BUDGET, extra_pointer=pointer, spoilers=spoilers)

    if len(body) > CHAT_HARD_BUDGET:
        pointer = pointer or _persist_full(envelope, plugin_data_dir)
        body = _chat_body(envelope, 0, extra_pointer=pointer, spoilers=spoilers)

    return body


def _chat_body(
    envelope: Mapping[str, Any],
    worst_count: int,
    *,
    extra_pointer: str | None = None,
    spoilers: bool = False,
) -> str:
    score = envelope.get("score") or {}
    rule_pack = envelope.get("rule_pack") or {}
    tool = envelope.get("tool") or {}

    header_lines = [
        f"SKILL LENS {tool.get('version', '?')} · pack {rule_pack.get('version', '?')}",
        _patient_line(envelope),
        _bundle_line(envelope),
        f"grade   : {score.get('grade', '?')} {score.get('value', '?')}/100"
        f" · verdict {str(score.get('verdict', '?')).upper()}",
        f"caps    : {capability_line(envelope)}",
    ]
    flag_line = None
    if score.get("needs_review"):
        flag_line = "flag    : needs_review — low-confidence HIGH+ evidence; triage first"

    finding_lines: list[str] = []
    active = [f for f in envelope.get("findings", ()) if not f.get("suppressed", False)]
    suppressed_total = sum(1 for f in envelope.get("findings", ()) if f.get("suppressed", False))
    if active:
        finding_lines.append(f"findings: {counts_phrase(envelope)}")
        for finding in worst_findings(envelope, worst_count):
            block = _finding_block(finding)
            if spoilers and len(block) > 1:
                # Wrap ONLY the evidence detail row (location · capability ·
                # confidence); the severity/rule head stays visible so the
                # reader knows there is something behind the tap.
                block[1] = "      " + spoiler_wrap(block[1].lstrip())
            finding_lines.extend(block)
        hidden = len(active) - min(worst_count, len(active))
        if hidden > 0:
            finding_lines.append(f"… {hidden} more in the full report")
    else:
        finding_lines.append("findings: none")
    if suppressed_total:
        # Machine visibility law (PLAN Phase 2 exit): suppressed findings are
        # never silently dropped — chat shows the count, the JSON record
        # keeps every suppressed finding with its suppressed_by pointer.
        finding_lines.append(
            f"suppressed: {suppressed_total} by policy/baseline (full record in --json)"
        )

    tail_lines = [ADVISOR_LINE]
    name = _display_name(str((envelope.get("target") or {}).get("name", "")))
    next_bits = []
    if name:
        next_bits.append(f"/lens report {name} (full)")
    next_bits.append("/lens help")
    tail_lines.append("next: " + " · ".join(next_bits))
    if extra_pointer:
        tail_lines.append(f"full report: {extra_pointer}")

    sections = ["\n".join(header_lines)]
    if flag_line:
        sections.append(flag_line)
    sections.append("\n".join(finding_lines))
    sections.append("\n".join(tail_lines))

    inner = "\n\n".join(section.strip("\n") for section in sections)
    inner += "\n" + COVERAGE_FOOTER
    if envelope_enriched(envelope):
        inner += ENRICHMENT_MARKER
    return f"{_FENCE}\n{inner}\n{_FENCE}\n"


def _persist_full(envelope: Mapping[str, Any], plugin_data_dir: Path | str | None) -> str:
    """Write the full canonical JSON report to disk; return its path.

    Overflow artifacts carry the CANONICAL envelope (machine-auditable),
    matching the §11.3 "reports persist under <plugin-data>/lens/reports/"
    contract. Unwritable dirs degrade to an inline notice instead of a path.
    Filename keeps the HISTORICAL ``<stem>-<hash8>.txt`` shape — pinned by
    the D-032 tests; newer surfaces namespace via :func:`persist_full_text`.
    """
    stem = _safe_filename_stem(str((envelope.get("target") or {}).get("name", "report")))
    shard = report_hash8(envelope)
    if plugin_data_dir is None:
        return "(report too large for chat; run /lens scan --json for the full envelope)"
    reports_dir = Path(plugin_data_dir) / "reports"
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{stem}-{shard}.txt"
        path.write_text(canonical_dumps(dict(envelope)) + "\n", encoding="utf-8", newline="\n")
        return str(path)
    except OSError:
        return "(report too large for chat; full report could not be persisted)"


def persist_full_text(
    plugin_data_dir: Path | str | None,
    kind: str,
    envelope: Mapping[str, Any],
    text: str,
    *,
    shard: str | None = None,
) -> str:
    """Persist an overflow artifact (any human surface) and return its path.

    Shared by the personality/map surfaces (autopsy narratives, map trees):
    same directory discipline as :func:`_persist_full` — sanitized stem,
    hash8 shard for uniqueness, inline-notice degradation when unwritable.
    *kind* namespaces the artifact (``report``/``map``/``autopsy``).
    """
    stem = _safe_filename_stem(str((envelope.get("target") or {}).get("name", kind)))
    if shard is None:
        shard = report_hash8(envelope)
    if plugin_data_dir is None:
        return f"(render too large for chat; run /lens scan --json — {kind} overflow)"
    reports_dir = Path(plugin_data_dir) / "reports"
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{stem}-{kind}-{shard}.txt"
        path.write_text(text, encoding="utf-8", newline="\n")
        return str(path)
    except OSError:
        return f"(render too large for chat; {kind} could not be persisted)"


# ---------------------------------------------------------------------------
# Fast-path one-liners (§11.4 normative formats; sober only)
# ---------------------------------------------------------------------------


def _clip_fast_line(line: str) -> str:
    if len(line) <= FAST_LINE_MAX_CHARS:
        return line
    return line[: FAST_LINE_MAX_CHARS - 1] + "…"


def fast_line_ok(
    *,
    name: str,
    grade: str,
    value: int,
    verdict: str,
    counts: str,
    cached_seconds: int | None = None,
) -> str:
    """Format A — cache hit."""
    age = f" · cached {max(0, int(cached_seconds))}s ago" if cached_seconds is not None else ""
    return _clip_fast_line(
        f"lens ok {name} · {grade} {value}/100 · {verdict}"
        + (f" · {counts}" if counts else "")
        + f"{age} · /lens report"
    )


def fast_line_scan_queued(*, name: str, hash8: str) -> str:
    """Format B — cold scan queued (interim inline scans reuse this shape)."""
    return _clip_fast_line(
        f"lens scan queued: {name} · sha256 {hash8} · p95 400ms · /lens report {name} when ready"
    )


def fast_line_skip(*, name: str, last_examined: str) -> str:
    """Format C — coalesced; *last_examined* is a pre-rendered HH:MM:SS tag."""
    return _clip_fast_line(f"lens skip {name} · unchanged since last exam ({last_examined})")


def fast_line_coalesced(*, name: str, hash8: str) -> str:
    """Format C sibling for an in-flight duplicate trigger (§11.4 ``skip``).

    The watcher's own unchanged-since-last-exam wording stays in
    :func:`fast_line_skip`; this variant covers the queue coalescing case —
    a scan for this exact bundle hash is already queued/running, so this
    trigger folds onto it (same job id, no second scan).
    """
    return _clip_fast_line(
        f"lens skip {name} · scan already in progress ({hash8}) · /lens report {name} when ready"
    )


def fast_line_fail(*, name: str, reason: str) -> str:
    """Format D — engine/orchestrator error; wording matches CLI stderr."""
    reason = " ".join(str(reason).split())
    return _clip_fast_line(f"lens fail {name} · {reason} · /lens doctor")


# ---------------------------------------------------------------------------
# Terminal panel (CLI-only; separate function, never wired to slash)
# ---------------------------------------------------------------------------


def render_terminal_panel(envelope: Mapping[str, Any]) -> str:
    """Box-drawing TTY panel (§12.1 layout, ASCII-safe fallback content).

    Color arrives with the CLI verbs phase via Rich; this function stays
    ANSI-free so ``NO_COLOR``/--plain audits hold by construction. Not
    wired to slash surfaces — §11.3 forbids anything but the compact fence
    there.
    """
    score = envelope.get("score") or {}
    target = envelope.get("target") or {}
    width = 80
    title = " SKILL LENS "

    def row(text: str) -> str:
        return f"│ {text.ljust(width - 4)} │"

    lines = [
        f"┌{title.center(width - 2, '─')}┐",
        row(_patient_line(envelope).replace("patient :", "patient  ")),
        row(_bundle_line(envelope).replace("bundle  :", "bundle   ")),
        f"├{'─' * (width - 2)}┤",
        row(
            f"GRADE {score.get('grade', '?')} {score.get('value', '?')}/100"
            f"      VERDICT: {str(score.get('verdict', '?')).upper()}"
        ),
        row(f"capabilities {capability_line(envelope)}"),
        f"├{'─' * (width - 2)}┤",
    ]
    for finding in worst_findings(envelope, 12):
        lines.extend(row(line) for line in _finding_block(finding))
    autopsy = _display_name(str(target.get("name", "")))
    lines += [
        f"├{'─' * (width - 2)}┤",
        row(ADVISOR_LINE),
        row(f"next: lens autopsy {autopsy} · lens explain-rules"),
        f"└{'─' * (width - 2)}┘",
        COVERAGE_FOOTER,
    ]
    return "\n".join(lines)


__all__ = [
    "ADVISOR_LINE",
    "CHAT_HARD_BUDGET",
    "CHAT_SOFT_BUDGET",
    "COVERAGE_FOOTER",
    "FAST_LINE_MAX_CHARS",
    "FAMILY_ABBREV",
    "SEVERITY_LABELS",
    "WORST_N_DEFAULT",
    "WORST_N_OVER_BUDGET",
    "capability_line",
    "counts_phrase",
    "fast_line_fail",
    "fast_line_coalesced",
    "fast_line_ok",
    "fast_line_scan_queued",
    "fast_line_skip",
    "persist_full_text",
    "render_chat_compact",
    "render_terminal_panel",
    "spoiler_wrap",
    "worst_findings",
]
