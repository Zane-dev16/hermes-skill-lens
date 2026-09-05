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

import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .canonical import canonical_dumps
from .claims import BASIS_NO_CLAIMS_MADE
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

#: Fixed verdict glosses — one per :data:`skill_lens.scoring.VERDICTS` enum,
#: never derived from data (determinism law). The clean gloss obeys the
#: "clean ≠ safe" honesty law: it points at the coverage footer and NEVER
#: says "safe".
VERDICT_GLOSS: dict[str, str] = {
    "alert": "examine before installing",
    "warn": "review before installing",
    "notice": "worth a skim",
    "clean": "nothing detected — see coverage footer",
}

#: Score-bar geometry: 10 cells, filled count a pure function of score.value.
_BAR_CELLS = 10

#: --plain/NO_COLOR fallback for the bar glyphs (kept OUT of cli._BOX_CHARS,
#: which this module must not grow; the mapping lives here instead).
_BAR_ASCII = str.maketrans({"█": "#", "░": "-"})


def score_bar(value: Any, *, plain: bool = False) -> str:
    """Ten-cell bar for a 0–100 score — a pure function of *value*.

    58/100 fills 6 cells (round-half-up); junk degrades to an empty bar.
    ``plain`` swaps the block glyphs for ``#``/``-`` so --plain/NO_COLOR
    lanes render ``[######----]`` without touching cli.py's box table.
    """
    try:
        clipped = max(0, min(100, int(value)))
    except (TypeError, ValueError):
        clipped = 0
    # Exact round-half-up in integer arithmetic: float widows (0.15 sits at
    # 1.4999… in binary) would otherwise land scores like 15 a cell short.
    filled = max(0, min(_BAR_CELLS, (clipped * _BAR_CELLS + 50) // 100))
    bar = "█" * filled + "░" * (_BAR_CELLS - filled)
    if plain:
        bar = bar.translate(_BAR_ASCII)
    return f"[{bar}]"


def plain_lane(explicit: bool | None = None) -> bool:
    """--plain/NO_COLOR detection for glyphs OUTSIDE cli._BOX_CHARS.

    Box drawing is translated post-hoc by ``cli.to_ascii_box``; bar and
    direction glyphs need their ASCII fallback resolved at render time.
    Reads only env/flag — never target content (§12.1 color-channel law).
    """
    if explicit is not None:
        return explicit
    if os.environ.get("NO_COLOR"):
        return True
    return "--plain" in sys.argv[1:]


#: Worst-finding headline clip: keeps the fused headline inside the §12.2
#: ~80-col discipline with room for the fixed prefixes.
_WORST_MESSAGE_CLIP = 48


def _worst_headline(envelope: Mapping[str, Any]) -> str | None:
    """``worst :`` headline line for the worst active finding, or None.

    Uses :func:`worst_findings` (the DETERMINISM LAW comparator) — no new
    ordering; None when there are zero active findings, so headline counts
    stay true totals.
    """
    worst = worst_findings(envelope, 1)
    if not worst:
        return None
    finding = worst[0]
    eff = str(finding.get("effective_severity") or finding.get("severity") or "LOW")
    label = SEVERITY_LABELS.get(eff, "○ NOTE")
    message = " ".join(str(finding.get("message") or finding.get("title", "")).split())
    if len(message) > _WORST_MESSAGE_CLIP:
        message = message[: _WORST_MESSAGE_CLIP - 1] + "…"
    location = finding.get("location") or {}
    where = str(location.get("path", ""))
    if location.get("start_line") is not None:
        where += f":{location['start_line']}"
    return f"worst : {label} {finding.get('rule_id', '?')} {message} — {where}"


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


def overreach_line(envelope: Mapping[str, Any]) -> str:
    """``overreach`` header row: undisclosed-capability count + names.

    Always rendered (Wave C): the zero case — ``overreach: 0 undisclosed`` —
    is itself the signal that every observed capability was declared.
    Names ride in envelope order (sorted by capability, DETERMINISM LAW).
    """
    records = [
        record for record in (envelope.get("overreach") or ()) if isinstance(record, Mapping)
    ]
    if not records:
        return "overreach: 0 undisclosed"
    caps = ", ".join(str(record.get("capability", "")) for record in records)
    return f"overreach: {len(records)} undisclosed — {caps}"


#: Diagnostic severities loud enough for human surfaces (info records stay
#: in the JSON ``diagnostics`` mirror only — they already surface as
#: findings where they matter, e.g. LNS-ING-001 for dot-file skips).
_LOUD_DIAGNOSTIC_SEVERITIES = ("error", "warning")

#: Max diagnostic rows before the overflow pointer (fixed: determinism).
_DIAGNOSTIC_ROW_CAP = 5

#: Diagnostic message clip (§12.2 snippet discipline).
_DIAGNOSTIC_CLIP = 100


def diagnostics_lines(envelope: Mapping[str, Any], *, cap: int = _DIAGNOSTIC_ROW_CAP) -> list[str]:
    """First-class ingest/engine diagnostic rows (DX law: never clean-looking).

    A bundle whose manifest is missing (``LNS-ING-MANIFEST``) or whose
    walk hit ceilings/encodings must read as degraded in human output —
    never as a clean bill. Each row names code + severity + message + path.
    """
    loud = [
        record
        for record in (envelope.get("diagnostics") or ())
        if isinstance(record, Mapping)
        and str(record.get("severity", "")).lower() in _LOUD_DIAGNOSTIC_SEVERITIES
    ]
    rows: list[str] = []
    for record in loud[:cap]:
        message = " ".join(str(record.get("message", "")).split())
        if len(message) > _DIAGNOSTIC_CLIP:
            message = message[: _DIAGNOSTIC_CLIP - 1] + "…"
        text = (
            f"diag    : {record.get('code', '?')} "
            f"{str(record.get('severity', '')).lower()} — {message}"
        )
        where = str(record.get("path") or "")
        if where:
            text += f" [{where}]"
        rows.append(text)
    if len(loud) > cap:
        rows.append(f"… {len(loud) - cap} more diagnostics in --json")
    return rows


def _overreach_panel_lines(envelope: Mapping[str, Any]) -> list[str]:
    """§9.3 explanation blocks for the terminal panel (Wave C).

    Reuses the envelope's pre-rendered ``explanation`` slots — the exact
    human text --json consumers get, with zero recomputation so panel and
    machine bytes can never drift. Empty when nothing is undisclosed.
    Rows are clipped to the panel interior by the caller (``cell``).
    """
    records = [
        record for record in (envelope.get("overreach") or ()) if isinstance(record, Mapping)
    ]
    rows: list[str] = []
    for record in records:
        explanation = str(record.get("explanation") or "")
        if explanation:
            rows.extend(explanation.splitlines())
        else:  # honest skeleton when the template slot is absent
            rows.append(f"OVERREACH: {record.get('capability', '?')} ({record.get('basis', '?')})")
    return rows


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
    try:
        total_bytes = int(target.get("total_bytes") or 0)
    except (TypeError, ValueError):
        total_bytes = 0  # junk size degrades, never raises
    kb = max(1, round(total_bytes / 1024))
    policy = str((envelope.get("policy") or {}).get("profile", "street"))
    return (
        f"bundle  : {hash_text} · {target.get('file_count', 0)} files · {kb} KB · policy {policy}"
    )


#: Row clips for the finding block (§12.2 ~80-col snippet/message discipline):
#: the evidence snippet stays ≤76 chars; remediation is author guidance, so
#: it gets a wider column but still clips with a greppable ellipsis.
_EVIDENCE_CLIP = 76
_REMEDIATION_CLIP = 100

#: Fix-suggestion row clip: mirrors the remediation column (the §6 template
#: line — fix + suppress-with-fingerprint + remove — runs ~100 chars).
_OVERREACH_OPTIONS_CLIP = 100


def _overreach_options_row(finding: Mapping[str, Any]) -> str | None:
    """``options:`` fix-suggestion row for overreach findings, else None.

    Keys off the additive ``overreach_basis`` slot report.py stamps on
    findings evidencing an undeclared capability (policy-and-claims §6
    template, per-instance): fix wording depends on the basis — vague
    bundles get the frontmatter-declaration ask, contradicted claims get
    the description fix + capability name — then the deterministic
    suppress-with-fingerprint and remove-skill closes. Findings without
    the slot render no row, so non-overreach bytes stay byte-identical.
    Pure function of finding fields (capability, basis, fingerprint) —
    no wall-clock, no randomness; clipped with a greppable ellipsis.
    """
    basis = finding.get("overreach_basis")
    if not basis:
        return None
    capability = str(finding.get("capability") or "").strip()
    fingerprint = str(finding.get("fingerprint") or "")
    if fingerprint.startswith("sha256:") and len(fingerprint) > len("sha256:") + 4:
        short = fingerprint[len("sha256:") :][:4] + "…"
    else:
        short = fingerprint[:8] or "?"
    if str(basis) == BASIS_NO_CLAIMS_MADE or not capability:
        fix = "declare capabilities in frontmatter"
    else:
        fix = f"fix the description + declare {capability}"
    text = f"options: {fix} · suppress w/ reason (fingerprint {short}) · remove skill"
    if len(text) > _OVERREACH_OPTIONS_CLIP:
        text = text[: _OVERREACH_OPTIONS_CLIP - 1] + "…"
    return f"      {text}"


def _finding_block(finding: Mapping[str, Any], *, with_evidence: bool = False) -> list[str]:
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
    try:
        confidence = float(finding.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0  # junk confidence degrades, never raises
    detail = (
        f"      {where} — {finding.get('capability', '')} · {declared_word} · conf {confidence:.2f}"
    )
    lines.append(detail)
    if with_evidence:
        # The worst block only: quote the evidence the pipeline already
        # carried home (envelope `location.snippet`) — never a fresh read.
        snippet = " ".join(str(location.get("snippet", "")).split())
        if snippet:
            if len(snippet) > _EVIDENCE_CLIP:
                snippet = snippet[: _EVIDENCE_CLIP - 1] + "…"
            lines.append(f"      reads : {snippet}")
    remediation = " ".join(str(finding.get("remediation", "")).split())
    if remediation:
        # Author-facing fix row: every finding carries remediation from the
        # rule pack; dropping it here used to waste the single most useful
        # field for skill authors. Label column matches the reads/where rows.
        if len(remediation) > _REMEDIATION_CLIP:
            remediation = remediation[: _REMEDIATION_CLIP - 1] + "…"
        lines.append(f"      fix   : {remediation}")
    options_row = _overreach_options_row(finding)
    if options_row is not None:
        lines.append(options_row)
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
    ]
    # Headline fusion: the single worst active finding rides in the header
    # (count lines stay true totals; suppressed-only scans show no worst).
    worst = _worst_headline(envelope)
    if worst is not None:
        header_lines.append(worst)
    header_lines.append(f"caps    : {capability_line(envelope)}")
    # Wave C: the claimed-vs-actual diff is a first-class header row — the
    # zero case ("overreach: 0 undisclosed") is itself the signal that
    # every observed capability was declared.
    header_lines.append(overreach_line(envelope))
    # DX #11: ingest/engine validation errors must never read as a clean
    # scan — loud diagnostics ride the header; the full deterministic
    # mirror stays in the envelope ``diagnostics`` key (--json).
    header_lines.extend(diagnostics_lines(envelope))
    flag_line = None
    if score.get("needs_review"):
        flag_line = "flag    : needs_review — low-confidence HIGH+ evidence; triage first"

    finding_lines: list[str] = []
    active = [f for f in envelope.get("findings", ()) if not f.get("suppressed", False)]
    suppressed_total = sum(1 for f in envelope.get("findings", ()) if f.get("suppressed", False))
    if active:
        finding_lines.append(f"findings: {counts_phrase(envelope)}")
        for index, finding in enumerate(worst_findings(envelope, worst_count)):
            # Evidence snippet rides ONLY the first (worst) block — every
            # block would blow the chat budget for repetitive bundles.
            block = _finding_block(finding, with_evidence=index == 0)
            if spoilers and len(block) > 1:
                # Wrap ONLY the evidence detail row (location · capability ·
                # confidence) plus the worst block's snippet row; the
                # severity/rule head stays visible so the reader knows there
                # is something behind the tap.
                block[1] = "      " + spoiler_wrap(block[1].lstrip())
                if index == 0 and len(block) > 2 and block[2].lstrip().startswith("reads :"):
                    block[2] = "      " + spoiler_wrap(block[2].lstrip())
            finding_lines.extend(block)
        hidden = len(active) - min(worst_count, len(active))
        if hidden > 0:
            finding_lines.append(f"… {hidden} more in the full report")
    else:
        # Clean-scan nudge: a clean slide is worth filing — make the next
        # action copy-pasteable while the literal `findings: none` prefix
        # stays byte-exact (tests pin it).
        name = _display_name(str((envelope.get("target") or {}).get("name", "")) or "?")
        finding_lines.append(f'findings: none · lock it in: /lens baseline {name} --reason "…"')
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
    try:
        age_seconds: int | None = (
            max(0, int(cached_seconds)) if cached_seconds is not None else None
        )
    except (TypeError, ValueError):
        age_seconds = None  # junk age degrades, never raises
    age = f" · cached {age_seconds}s ago" if age_seconds is not None else ""
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


def render_terminal_panel(envelope: Mapping[str, Any], *, plain: bool | None = None) -> str:
    """Box-drawing TTY panel (§12.1 layout, ASCII-safe fallback content).

    Color arrives with the CLI verbs phase via Rich; this function stays
    ANSI-free so ``NO_COLOR``/--plain audits hold by construction. Not
    wired to slash surfaces — §11.3 forbids anything but the compact fence
    there. *plain* (None = auto-detect via :func:`plain_lane`) swaps the
    score-bar glyphs to ASCII; box drawing itself keeps riding the
    ``cli.to_ascii_box`` translation on the --plain/NO_COLOR lane.
    """
    plain = plain_lane(plain)
    score = envelope.get("score") or {}
    target = envelope.get("target") or {}
    width = 80
    title = " SKILL LENS "

    def row(text: str) -> str:
        return f"│ {text.ljust(width - 4)} │"

    def cell(text: str) -> str:
        """Clip one row's content to the panel interior (new rows only)."""
        return text if len(text) <= width - 4 else text[: width - 5] + "…"

    verdict_raw = str(score.get("verdict", "?"))
    gloss = VERDICT_GLOSS.get(verdict_raw.lower())
    bar_head = (
        f"score {score_bar(score.get('value'), plain=plain)} "
        f"{score.get('value', '?')}/100 · verdict {verdict_raw.upper()}"
    )
    bar_rows = [f"{bar_head} — {gloss}"] if gloss else [bar_head]
    if gloss and len(bar_rows[0]) > width - 4:
        # Long gloss (clean) wraps to an indented continuation row rather
        # than clipping the honesty tail or ragged-ing the box edge.
        bar_rows = [bar_head, f"        — {gloss}"]

    lines = [
        f"┌{title.center(width - 2, '─')}┐",
        row(_patient_line(envelope).replace("patient :", "patient  ")),
        row(_bundle_line(envelope).replace("bundle  :", "bundle   ")),
        f"├{'─' * (width - 2)}┤",
        *(row(cell(bar_row)) for bar_row in bar_rows),
    ]
    worst = _worst_headline(envelope)
    if worst is not None:
        lines.append(row(cell(worst)))
    lines += [
        row(f"capabilities {capability_line(envelope)}"),
        row(cell(overreach_line(envelope))),
        *(row(cell(line)) for line in diagnostics_lines(envelope)),
        f"├{'─' * (width - 2)}┤",
    ]
    for finding in worst_findings(envelope, 12):
        lines.extend(row(cell(line)) for line in _finding_block(finding))
    # Wave C overreach section: §9.3 explanations ride the envelope
    # pre-rendered (zero recomputation, bytes identical to --json).
    lines.extend(row(cell(line)) for line in _overreach_panel_lines(envelope))
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
    "VERDICT_GLOSS",
    "WORST_N_DEFAULT",
    "WORST_N_OVER_BUDGET",
    "capability_line",
    "counts_phrase",
    "diagnostics_lines",
    "fast_line_fail",
    "fast_line_coalesced",
    "fast_line_ok",
    "fast_line_scan_queued",
    "fast_line_skip",
    "overreach_line",
    "persist_full_text",
    "plain_lane",
    "render_chat_compact",
    "render_terminal_panel",
    "score_bar",
    "spoiler_wrap",
    "worst_findings",
]
