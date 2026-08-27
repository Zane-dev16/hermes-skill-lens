"""Opt-in personality layer — voices, autopsy narration, easter eggs.

Ground truth: SPEC §16 + FUN.md + docs/04_ux §6 translation matrix. The
laws encoded here are BINDING:

- **Default stays sober.** Every entry point below requires an explicit
  opt-in: a ``--voice`` flag, a plugin-settings key, or the user typing a
  hidden verb. Nothing here is reachable from default scans, hooks,
  one-liners, JSON, SARIF, or events.ndjson (those surfaces are
  PERMANENTLY exempt from fun — sober always).
- **Deterministic templates only.** No LLM, no randomness, no wall-clock:
  the same report renders byte-identical words every run. Connective
  phrases rotate by FINDING INDEX — a pure function of content order.
- **Data invariance.** Voices change prose, never findings, severities,
  grades, verdicts, exit codes, or machine formats. Severity words render
  verbatim in every voice; both voices narrate the SAME normalized fact
  rows (:func:`_autopsy_rows`).
- **Laugh at the codebase-as-patient, never the developer** (Law 4).
- Voice cap is THREE forever (FUN.md F-1); shipped today: ``clinical``
  (default = sober rendering, unchanged) and ``microscopy`` (dry lab
  dictation). ``noir`` stays DEFERRED usage-gated per HARD_QUESTIONS O4 —
  requesting it yields a notice naming the deferral, never camp prose.

Settings keys (plugin-relative; host prefixes plugins.entries.lens.settings.):

- ``voice`` — ``clinical`` | ``microscopy`` (default clinical = off).
- ``fun.allow_voices`` — master kill-switch (default true); when false the
  voice is pinned to clinical and non-default --voice flags are refused.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .render import (
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
    counts_phrase,
    persist_full_text,
    worst_findings,
)

#: Shipped voice register (FUN.md F-1 cap: three forever; O4 ships two).
VOICES: tuple[str, ...] = ("clinical", "microscopy")
DEFAULT_VOICE = "clinical"

#: Usage-gated registers that must NEVER render (O4 tone-bleed rationale).
DEFERRED_VOICES: tuple[str, ...] = ("noir",)

#: Plugin-relative settings keys (see module docstring).
VOICE_SETTING_KEY = "voice"
KILLSWITCH_KEY = "fun.allow_voices"

#: Bones chart hard ceiling (FUN.md F-6: one fenced block ≤1900 chars —
#: the one format every platform chunker preserves intact).
BONES_BUDGET = 1900

#: Fixed dry-dictation openers, rotated BY INDEX (deterministic rotation —
#: never random selection). Understatement IS the joke; keep them flat.
_MICROSCOPY_OPENERS: tuple[str, ...] = (
    "On examination,",
    "Further sectioning shows",
    "The field confirms",
    "Higher power reveals",
)

_SELF_SCAN_GAG_TAIL = "(Yes, we ran it on ourselves. That's the point.)"


# ---------------------------------------------------------------------------
# Settings seam (defensive reads; coercion reuses the policy layer's table)
# ---------------------------------------------------------------------------


def _setting(view: Any, key: str) -> Any:
    """Read + coerce one plugin setting; any failure degrades to unset."""
    if view is None:
        return None
    getter = getattr(view, "get_config", None)
    if not callable(getter):
        return None
    try:
        raw = getter(key, None)
    except Exception:  # noqa: BLE001 — host seams may raise anything
        return None
    if raw is None:
        return None
    from .policy import _coerce_setting

    return _coerce_setting(key, raw)


def validate_voice_choice(choice: str | None) -> str | None:
    """Usage error for an explicitly requested bad voice; None when fine."""
    if choice is None:
        return None
    if choice in VOICES:
        return None
    if choice in DEFERRED_VOICES:
        return (
            f"voice {choice!r} is deferred (usage-gated; HARD_QUESTIONS O4) — "
            f"shipped voices: {', '.join(VOICES)}"
        )
    return f"unknown voice {choice!r} — shipped voices: {', '.join(VOICES)}"


def resolve_voice(view: Any, flag_value: str | None = None) -> tuple[str, str | None]:
    """Resolve the effective voice; returns ``(voice, notice_or_None)``.

    Precedence: kill-switch > explicit ``--voice`` flag > ``voice`` setting
    > default. With ``fun.allow_voices=false`` the voice pins to clinical
    and a non-default flag is refused with a notice (the kill-switch must
    beat per-invocation flags — that is what makes it a kill-switch).
    *flag_value* must already pass :func:`validate_voice_choice`.
    """
    kill = _setting(view, KILLSWITCH_KEY)
    if kill is False:
        if flag_value is not None and flag_value != DEFAULT_VOICE:
            return (
                DEFAULT_VOICE,
                f"voice {flag_value!r} refused — {KILLSWITCH_KEY}=false "
                "(kill-switch); clinical rendered",
            )
        return DEFAULT_VOICE, None
    if flag_value is not None:
        return flag_value, None
    configured = _setting(view, VOICE_SETTING_KEY)
    if isinstance(configured, str) and configured in VOICES:
        return configured, None
    return DEFAULT_VOICE, None


# ---------------------------------------------------------------------------
# Autopsy narration (F-1) — shared fact rows, voice-specific templates
# ---------------------------------------------------------------------------


def _autopsy_rows(envelope: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalized fact rows for EVERY active finding, worst-first.

    BOTH voices narrate these exact rows — the data-invariance mechanism.
    Order is the DETERMINISM LAW key (severity desc, then rule/path/line).
    """
    rows: list[dict[str, Any]] = []
    for finding in worst_findings(envelope, 1 << 30):
        eff = str(finding.get("effective_severity") or finding.get("severity") or "")
        location = finding.get("location") or {}
        line = location.get("start_line")
        where = str(location.get("path", ""))
        if isinstance(line, int):
            where += f":{line}"
        snippet = " ".join(str(location.get("snippet", "")).split())
        declared_word = "declared" if finding.get("declared") else "UNDECLARED"
        rows.append(
            {
                "id": str(finding.get("id", "")),
                "severity": eff,
                "rule_id": str(finding.get("rule_id", "")),
                "title": str(finding.get("title", "")),
                "where": where,
                "capability": str(finding.get("capability", "")),
                "declared": declared_word,
                "confidence": float(finding.get("confidence", 0.0)),
                "snippet": snippet[:80],
            }
        )
    return rows


def _autopsy_head(envelope: Mapping[str, Any], voice: str) -> list[str]:
    """Sober head block — identical fields both voices (facts stay facts)."""
    from .render import _bundle_line, _patient_line

    score = envelope.get("score") or {}
    target = envelope.get("target") or {}
    head = [
        f"AUTOPSY {target.get('name', '?')} · voice {voice}",
        _patient_line(envelope),
        _bundle_line(envelope),
        f"grade   : {score.get('grade', '?')} {score.get('value', '?')}/100"
        f" · verdict {str(score.get('verdict', '?')).upper()}",
        f"findings: {counts_phrase(envelope)}",
    ]
    return head


def _clinical_block(row: Mapping[str, Any]) -> list[str]:
    block = [
        f"{row['id']} · {row['severity']} · {row['rule_id']} — {row['title']}",
        f"      where : {row['where']}",
        f"      what  : {row['capability']} · {row['declared']}"
        f" · confidence {row['confidence']:.2f}",
    ]
    if row["snippet"]:
        block.append(f"      reads : {row['snippet']}")
    return block


def _microscopy_block(index: int, row: Mapping[str, Any]) -> list[str]:
    opener = _MICROSCOPY_OPENERS[index % len(_MICROSCOPY_OPENERS)]
    sentence = (
        f"Slide {row['id']} — opacity noted at {row['where']}. {opener} rule "
        f"{row['rule_id']} reports: {row['title']}. Staining: "
        f"{row['capability']}, {row['declared']}, confidence "
        f"{row['confidence']:.2f}. Severity: {row['severity']}."
    )
    if row["snippet"]:
        sentence += f" The imprint reads: {row['snippet']}."
    return [sentence]


def render_autopsy(
    envelope: Mapping[str, Any],
    *,
    voice: str = DEFAULT_VOICE,
    plugin_data_dir: Path | str | None = None,
    soft_budget: int | None = None,
) -> str:
    """Autopsy narrative for one report envelope (never raises).

    Clinical voice = the sober walkthrough (default rendering, unchanged);
    microscopy re-narrates the SAME fact rows as dry lab dictation. Chat
    ladder (§11.3): full render targets the soft budget; overflow collapses
    to the top-3 slides plus a persisted-full pointer; extreme overflow
    keeps the head + pointer only. Automation surfaces never call this.
    """
    rows = _autopsy_rows(envelope)
    if soft_budget is None:
        soft = CHAT_SOFT_BUDGET
    else:
        soft = max(200, min(int(soft_budget), CHAT_HARD_BUDGET))

    def body_for(count: int, pointer: str | None) -> str:
        sections = ["\n".join(_autopsy_head(envelope, voice))]
        blocks: list[str] = []
        if voice == "microscopy":
            for index, row in enumerate(rows[:count]):
                blocks.extend(_microscopy_block(index, row))
            if count and count >= len(rows) and rows:
                blocks.append("Impression: findings as listed. Recommend higher magnification.")
        else:
            for row in rows[:count]:
                blocks.extend(_clinical_block(row))
        hidden = len(rows) - min(count, len(rows))
        if hidden > 0:
            blocks.append(f"… {hidden} more in the full report")
        if blocks:
            sections.append("\n".join(blocks))
        tail = ["next: /lens report · /lens explain-rules"]
        if pointer:
            tail.append(f"full narrative: {pointer}")
        sections.append("\n".join(tail))
        inner = "\n\n".join(section.strip("\n") for section in sections)
        inner += "\n" + COVERAGE_FOOTER
        return f"```\n{inner}\n```\n"

    body = body_for(len(rows) or 1, None)
    if len(body) <= soft:
        return body
    pointer = persist_full_text(
        plugin_data_dir, "autopsy", envelope, body_for(len(rows) or 1, None)
    )
    collapsed = body_for(3, pointer)
    if len(collapsed) <= CHAT_HARD_BUDGET:
        return collapsed
    return body_for(0, pointer)


# ---------------------------------------------------------------------------
# bones chart (F-6) — anatomical skeleton of a file tree
# ---------------------------------------------------------------------------

BONE_ORDER: tuple[str, ...] = ("cranium", "spine", "ribs", "femur", "appendix")

#: Static quips per bone position (template prose — data supplies sizes and
#: counts; the joke targets STRUCTURE, never authors).
BONE_NOTES: dict[str, str] = {
    "cranium": "cognition: decisions originate here",
    "spine": "load-bearing; do not amputate casually",
    "ribs": "cage around the vital organs",
    "femur": "carries the weight",
    "appendix": "vestigial; candidate for removal",
}


def top_level_groups(rel_paths: Mapping[str, int]) -> list[tuple[str, int, int]]:
    """Group relative paths by first path segment; rank by bytes desc.

    Returns ``(label, total_bytes, file_count)`` rows — labels carry a
    trailing "/" for directories. Ties break by label ascending (stable).
    """
    groups: dict[str, list[int]] = {}
    for rel, size in rel_paths.items():
        parts = rel.split("/")
        key = parts[0] + ("/" if len(parts) > 1 else "")
        bucket = groups.setdefault(key, [0, 0])
        bucket[0] += size
        bucket[1] += 1
    ranked = sorted(groups.items(), key=lambda item: (-item[1][0], item[0]))
    return [(label, total, count) for label, (total, count) in ranked]


def render_bones_chart(title: str, entries: list[tuple[str, int, int]]) -> str:
    """Anatomical chart over ranked groups (≤ BONES_BUDGET by construction).

    Bone names assign in fixed order to the biggest structures; the last
    ranked group lands on ``appendix``. Overflow rows collapse behind a
    count line. Pure function — same tree, same chart.
    """
    lines = [f"SKELETON · {title}"]
    shown = entries[: len(BONE_ORDER)]
    hidden = len(entries) - len(shown)
    for bone, (label, total, count) in zip(BONE_ORDER, shown, strict=False):
        note = BONE_NOTES[bone]
        kb = max(1, round(total / 1024))
        detail = f"{kb} KB" if count == 1 else f"{count} files · {kb} KB"
        clipped = label[:24]
        lines.append(f"   {bone:<8} ──── {clipped:<24} {note} ({detail})")
    if hidden > 0:
        lines.append(f"   … {hidden} more structures below the knee")
    chart = "\n".join(lines)
    while len(chart) > BONES_BUDGET and len(lines) > 1:
        lines.pop()
        chart = "\n".join(lines)
    return chart


def _tree_rel_sizes(root: Path, *, skip_pyc: bool = True) -> dict[str, int]:
    """Relative-path → size map under *root* (deterministic, bounded walk).

    ``__pycache__``/``*.pyc`` are skipped when *skip_pyc*: bytecode caches
    regenerate out-of-band and would make charts/hashes drift run-to-run
    (DETERMINISM LAW). Dot-entries follow the ingest walk policy (skipped).
    """
    sizes: dict[str, int] = {}
    if root.is_file():
        try:
            return {root.name: root.stat().st_size}
        except OSError:
            return sizes
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for child in children:
            name = child.name
            if name.startswith("."):
                continue
            if skip_pyc and (name == "__pycache__" or name.endswith((".pyc", ".pyo"))):
                continue
            try:
                if child.is_symlink():
                    continue
                if child.is_dir():
                    stack.append(child)
                elif child.is_file():
                    rel = child.relative_to(root).as_posix()
                    sizes[rel] = child.stat().st_size
            except OSError:
                continue
    return sizes


def bones_for_tree(title: str, root: Path) -> str:
    """Chart of one filesystem tree (bundle dir or the lens package itself)."""
    return render_bones_chart(title, top_level_groups(_tree_rel_sizes(root)))


# ---------------------------------------------------------------------------
# Self-scan gag (`lens lens` twin of F-6) — dogfooding pressure, exit 0
# ---------------------------------------------------------------------------


def self_scan_target() -> Path:
    """The instrument's own package directory (read-only scan target)."""
    return Path(__file__).resolve().parent


def self_scan_mirror() -> Path:
    """Pyc-free temporary mirror of the package (DETERMINISM LAW guard).

    ``__pycache__`` bytecode regenerates out-of-band; scanning the live dir
    would let cache churn move the bundle hash and the gag's words. The
    mirror copies exactly the files the tree walker sees. Caller removes it
    (``shutil.rmtree``) after the scan.
    """
    source = self_scan_target()
    mirror = Path(tempfile.mkdtemp(prefix="lens-selfscan-"))
    for rel in sorted(_tree_rel_sizes(source)):
        destination = mirror / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(source / rel, destination)
        except OSError:
            destination.write_bytes(b"")  # unreadable source degrades, never raises
    return mirror


def render_self_scan(envelope: Mapping[str, Any]) -> str:
    """Fenced self-scan block; grade line stays SOBER-formatted (F-6).

    A real active CRITICAL prints straight — no joke (F-6 guardrail). Exit
    codes are never joked with: callers keep the advisor stance (exit 0).
    """
    score = envelope.get("score") or {}
    value = score.get("value", "?")
    grade = score.get("grade", "?")
    verdict = str(score.get("verdict", "?")).upper()
    critical_active = any(
        str(f.get("effective_severity") or f.get("severity") or "").startswith("CRITICAL")
        for f in envelope.get("findings", ())
        if not f.get("suppressed", False)
    )
    if critical_active:
        # Straight print: the instrument found something real in itself.
        from .render import _finding_block

        lines = [
            "Self-examination complete — REAL findings printed straight:",
            *(line for row in worst_findings(envelope, 3) for line in _finding_block(row)),
            "No joke. Fix the instrument.",
            COVERAGE_FOOTER,
        ]
    else:
        lines = [
            f"lens self-scan · GRADE {grade} {value}/100 · verdict {verdict} · "
            f"{counts_phrase(envelope)}",
            "Self-examination complete. The instrument remains fit to inspect others.",
            _SELF_SCAN_GAG_TAIL,
        ]
    inner = "\n".join(lines)[: BONES_BUDGET - len("```\n\n```\n")]
    return f"```\n{inner}\n```\n"


__all__ = [
    "BONES_BUDGET",
    "BONE_NOTES",
    "BONE_ORDER",
    "DEFAULT_VOICE",
    "DEFERRED_VOICES",
    "KILLSWITCH_KEY",
    "self_scan_target",
    "VOICES",
    "VOICE_SETTING_KEY",
    "bones_for_tree",
    "render_autopsy",
    "render_bones_chart",
    "render_self_scan",
    "resolve_voice",
    "self_scan_mirror",
    "top_level_groups",
    "validate_voice_choice",
]
