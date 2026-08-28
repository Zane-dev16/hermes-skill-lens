"""``/lens explain-rules`` — effective rule set with provenance (D-EXPLAIN).

Rules are data; explanation is mechanical. This module renders the EFFECTIVE
rule view: rule metadata, the detection-spec summary, and the provenance
chain (pack version/checksum → profile → policy layers → any active
severity_override with its reason/expiry). No LLM prose anywhere — every
line is a deterministic template over :class:`skill_lens.policy.EffectivePolicy`
and :class:`skill_lens.rules.RulePack` data.

Weight math is rendered from the SCORING CONSTANTS (what the rubric actually
charges), never from policy-reachable values — policy can override SEVERITY
display but can never move weights/caps/ceilings (hard boundary; the card
says so in one line).

Surface contract: output is a fenced, ANSI-free, pipe-table-free string that
obeys the §11.3 chat budgets (soft 1200 / hard 1800) via a collapse ladder;
overflow persists the full index to ``<plugin-data>/reports/`` and appends a
pointer. The byte-frozen coverage footer rides on every render (§12.6).
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Any

from .render import (
    ADVISOR_LINE,
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
)
from .rules import RulePack

_FENCE = "```"

#: Display clips (§12.2 ~80-col discipline with headroom for row prefixes).
_TITLE_CLIP = 44
_DETECTION_CLIP = 160
_REMEDIATION_CLIP = 120

_SEV_SHORT = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}

#: Overflow artifact naming (mirrors render.py's D-032 discipline).
_STEM_MAX = 48


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def find_rule(pack: RulePack, rule_id: str) -> tuple[Any, ...]:
    """All rules whose id matches *rule_id* (usually 0 or 1)."""
    wanted = str(rule_id).strip()
    return tuple(rule for rule in pack.rules if rule.id == wanted)


def _weight_line(severity: str) -> str:
    """The pinned pricing math for a tier, from scoring constants (T3)."""
    from .scoring import TIER_CAPS, TIER_FIRST_WEIGHT, TIER_SUBSEQUENT_WEIGHT

    first = TIER_FIRST_WEIGHT.get(severity, 0)
    subsequent = TIER_SUBSEQUENT_WEIGHT.get(severity, 0)
    cap = TIER_CAPS.get(severity)
    cap_text = "none" if cap is None else f"−{cap}"
    return f"−{first} first / −{subsequent} subsequent · tier cap {cap_text}"


def _clip(text: str | None, width: int) -> str:
    value = " ".join(str(text or "").split())
    if len(value) <= width:
        return value
    return value[: width - 1] + "…"


def _override_label(policy: Any, rule_id: str, base_severity: str) -> str:
    """Active override for one rule with reason + expiry + writing layer.

    ``none`` when no override is active — a built-in default nobody set is
    not news (provenance noise law: only lines that TOUCH this rule render).
    """
    override = policy.severity_override_for(rule_id)
    if override is None:
        return "none"
    expiry = f" · expires {override.expires.isoformat()}" if override.expires else ""
    writer = (getattr(policy, "provenance", {}) or {}).get("rules.severity_override", "built-in")
    return f"{base_severity}→{override.severity}{expiry} · {_clip(override.reason, 80)} ← {writer}"


def _provenance_lines(policy: Any, rule_id: str, base_severity: str) -> list[str]:
    provenance = getattr(policy, "provenance", {}) or {}
    profile_writer = provenance.get("profile", "built-in")
    lines = [
        f"  profile : {policy.profile} ← {profile_writer}",
        f"  sources : {' · '.join(policy.sources)}",
    ]
    if policy.is_disabled(rule_id):
        writer = provenance.get("rules.disable", "policy")
        lines.append(f"  disable : DISABLED ← {writer}")
        lines.append("  override: none (disabled rules take no overrides)")
    else:
        lines.append(f"  override: {_override_label(policy, rule_id, base_severity)}")
    return lines


def _pack_header(pack: RulePack, policy: Any) -> list[str]:
    checksum = pack.content_checksum()
    short = checksum[len("sha256:") :][:8] if checksum.startswith("sha256:") else checksum[:8]
    return [
        f"RULE PACK {pack.name} {pack.version} · sha256:{short} · "
        f"profile {policy.profile} · {len(pack.rules)} rules",
        f"sources: {' · '.join(policy.sources)}",
    ]


def _persist_explain(text: str, plugin_data_dir: Path | str | None, stem: str) -> str | None:
    """Persist full text under reports/; returns path or None when impossible."""
    if plugin_data_dir is None:
        return None
    shard = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem)[:_STEM_MAX]
    path = Path(plugin_data_dir) / "reports" / f"{safe or 'explain'}-{shard}.txt"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8", newline="\n")
    except OSError:
        return None
    return str(path)


def _finish(body: str) -> str:
    inner = body.rstrip("\n") + "\n" + ADVISOR_LINE + "\n" + COVERAGE_FOOTER
    return f"{_FENCE}\n{inner}\n{_FENCE}\n"


# ---------------------------------------------------------------------------
# Single-rule detail card
# ---------------------------------------------------------------------------


def render_rule_card(
    rule: Any,
    policy: Any,
    *,
    report_date: date | None = None,
) -> str:
    """Detail card for one rule: metadata, weight math, provenance chain."""
    del report_date  # expiry filtering already applied by EffectivePolicy
    disabled = policy.is_disabled(rule.id)
    status = "DISABLED by policy" if disabled else "active"
    origin = f" · origin {rule.origin}" if rule.origin else ""
    lines = [
        f"RULE {rule.id} v{rule.rule_version} · engine {rule.engine}{origin}",
        f"title     : {rule.title}",
        f"capability: {rule.capability}",
        f"severity  : {rule.severity} · pricing tier {rule.severity}"
        " (weights are pinned constants — not user-reachable)",
        f"weight    : {_weight_line(rule.severity)}",
        f"evidence  : {rule.evidence_kind} · confidence {rule.confidence_default:.2f}"
        f" · static_only {str(bool(rule.static_only)).lower()}",
        f"status    : {status}",
        "provenance:",
        *_provenance_lines(policy, rule.id, rule.severity),
        f"detection : {_clip(rule.detection, _DETECTION_CLIP)}",
        f"remediation: {_clip(rule.remediation, _REMEDIATION_CLIP)}",
    ]
    if rule.tags:
        lines.append("tags      : " + ", ".join(rule.tags))
    return _finish("\n".join(lines))


# ---------------------------------------------------------------------------
# Full index
# ---------------------------------------------------------------------------


def _index_rows(pack: RulePack, policy: Any) -> list[str]:
    rows: list[str] = []
    for rule in sorted(pack.rules, key=lambda r: r.id):
        marker = ""
        if policy.is_disabled(rule.id):
            marker = " · DISABLED"
        else:
            override = policy.severity_override_for(rule.id)
            if override is not None:
                marker = f" · sev→{override.severity}"
        title = _clip(rule.title, _TITLE_CLIP)
        rows.append(
            f"{rule.id:<13} {_SEV_SHORT.get(rule.severity, rule.severity):<4} "
            f"{rule.engine:<11} {title}{marker}"
        )
    return rows


def _index_rows_compact(pack: RulePack, policy: Any) -> list[str]:
    rows: list[str] = []
    # Ids are fixed-width by grammar (LNS-XXX-NNN = 12 chars), so the compact
    # render skips the alignment pad — at 44 rules the collapsed ladder rung
    # must still fit the HARD chat budget (§11.3: collapsed render keeps the
    # full effective set).
    for rule in sorted(pack.rules, key=lambda r: r.id):
        suffix = ""
        if policy.is_disabled(rule.id):
            suffix = " DISABLED"
        elif policy.severity_override_for(rule.id) is not None:
            suffix = " overridden"
        rows.append(f"{rule.id} {rule.capability}{suffix}")
    return rows


def render_rule_index(
    pack: RulePack,
    policy: Any,
    *,
    plugin_data_dir: Path | str | None = None,
) -> str:
    """Effective-set index with provenance header and budget ladder."""
    overrides_active = sum(
        1 for rule in pack.rules if policy.severity_override_for(rule.id) is not None
    )
    disabled_count = sum(1 for rule in pack.rules if policy.is_disabled(rule.id))

    def body(rows: list[str]) -> str:
        head = _pack_header(pack, policy)
        summary = f"overrides: {overrides_active} active · disabled: {disabled_count}"
        return "\n".join([*head, summary, "", *rows])

    full_text = body(_index_rows(pack, policy))
    text = _finish(full_text)
    if len(text) <= CHAT_SOFT_BUDGET:
        return text

    compact_text = _finish(body(_index_rows_compact(pack, policy)))
    if len(compact_text) <= CHAT_HARD_BUDGET:
        # §11.3 ladder: over soft ⇒ collapsed render still carrying the full
        # effective set; only past the HARD ceiling do we degrade further.
        return compact_text

    pointer = _persist_explain(full_text, plugin_data_dir, f"explain-{pack.name}")
    counts_by_engine: dict[str, int] = {}
    for rule in pack.rules:
        counts_by_engine[rule.engine] = counts_by_engine.get(rule.engine, 0) + 1
    engine_bits = ", ".join(
        f"{engine} ×{counts_by_engine[engine]}" for engine in sorted(counts_by_engine)
    )
    lines = [
        *_pack_header(pack, policy),
        f"{len(pack.rules)} rules ({engine_bits})",
        f"overrides: {overrides_active} active · disabled: {disabled_count}",
        "index too wide for chat — use /lens explain-rules --rule <ID> per rule",
    ]
    if pointer:
        lines.append(f"full index: {pointer}")
    else:
        lines.append("(full index could not be persisted)")
    text = _finish("\n".join(lines))
    if len(text) > CHAT_HARD_BUDGET:  # unreachable in practice; guard anyway
        engine_line = next(line for line in lines if "rules (" in line)
        text = _finish("\n".join(lines[:1] + [engine_line]))
    return text


# ---------------------------------------------------------------------------
# Verb entry point
# ---------------------------------------------------------------------------


def explain_rules(
    pack: RulePack,
    policy: Any,
    *,
    rule_id: str | None = None,
    plugin_data_dir: Path | str | None = None,
) -> tuple[str, str | None]:
    """Render explain output. Returns ``(text, error_notice)``.

    Exactly one of the two is non-empty: an unknown ``--rule ID`` yields a
    sober one-line notice (user-initiated verbs never answer silence), a
    known one yields the card; ``rule_id=None`` yields the full index.
    Never raises.
    """
    try:
        if rule_id is None:
            return render_rule_index(pack, policy, plugin_data_dir=plugin_data_dir), ""
        matches = find_rule(pack, rule_id)
        if not matches:
            return "", (
                f"unknown rule id {rule_id!r} — /lens explain-rules lists the "
                f"{len(pack.rules)} rules of pack {pack.name} {pack.version}"
            )
        # Duplicate ids cannot survive the loader; take the deterministic first.
        return render_rule_card(matches[0], policy), ""
    except Exception as exc:  # noqa: BLE001 — renderer must never raise past here
        return "", _render_fault_notice(exc)


def _render_fault_notice(exc: BaseException) -> str:
    reason = " ".join(str(exc).split())[:120]
    if not reason:
        reason = exc.__class__.__name__
    return f"lens fail explain-rules · render fault: {reason} · /lens doctor"


__all__ = ["explain_rules", "find_rule", "render_rule_card", "render_rule_index"]
