"""Scoring rubric v2 (SPEC §8) — integer-point math, environment-blind.

The scorer consumes the pipeline's deduped ``§7`` finding dicts and produces
the ``report/1`` ``score`` block: ``{value, grade, verdict, needs_review,
score_math}``. Every number traces (T3): each finding's scheduled weight,
applied modifiers, tier truncation, and any ceiling appear in
:data:`ScoreResult.score_math`.

Rubric shape (SPEC §8.2 — weights/modifiers table quoted verbatim):

====  ========  ==========  =====================================
Sev   First     Subsequent  Tier cap (max deduction per tier)
====  ========  ==========  =====================================
CRIT  −40       −25         none (cap via score ceiling)
HIGH  −18       −12         −36
MED   −7        −4          −20
LOW   −2        −1          −6
====  ========  ==========  =====================================

Modifiers ×0.5 each, multiplicative, applied before rounding; every
contribution rounds half-up to whole points. Confidence below 0.6 marks a
finding *suspected*: a suspected CRITICAL cannot trigger the
confirmed-critical ceiling (it takes the 40-ceiling instead) and raises the
orthogonal ``needs_review`` flag.

Occurrence indexing (DECISIONS D-029): "first occurrence full, each
subsequent reduced" counts occurrences PER MODIFIER SIGNATURE within a
tier — the diminishing-returns clause exists so repetition of the SAME
evidence class saturates ("prevents 40 identical lows from nuking a noisy
formatter"), and per-signature counting keeps the schedule monotone:
inserting a finding can never lower a tier's total (a new member pays at
least the subsequent weight of its own class, and only its own class's
former first occurrence demotes). Every §8.3 worked example prices
identically under both readings — its tiers are modifier-homogeneous.

Score ceilings apply as ``score = min(score, cap)`` and stack by min;
each also CLAMPS THE GRADE (ceilings are verdicts, not discounts):

- any confirmed CRITICAL (conf ≥ 0.6)      → ≤ 25, grade F
- only *suspected* CRITICAL (conf < 0.6)   → ≤ 40, grade D (+ needs_review)
- undeclared money-touch                   → ≤ 70, grade at most C
- integrity/override attempt               → ≤ 80, grade at most C

Grades A ≥ 90 / B ≥ 75 / C ≥ 60 / D ≥ 40 / F < 40. Verdicts are derived
top-down from ``effective_severity`` after discounts exactly per the §8.2
ladder; ``needs_review`` is a boolean FLAG, never a fifth verdict.

DETERMINISM LAW: pure integer/float arithmetic over the finding dicts, no
wall-clock, no randomness, stable iteration everywhere. Pricing tiers key on
the rule-assigned severity (weights pinned per rule, §9.1) while ceiling,
flag, and verdict logic read ``effective_severity`` after engine-side
discounts (DECISIONS D-025).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

#: Severity tiers, highest first (shared vocabulary with the rules loader).
SEVERITY_TIERS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: §8.2 schedule — full price for the first occurrence in a tier…
TIER_FIRST_WEIGHT: dict[str, int] = {"CRITICAL": 40, "HIGH": 18, "MEDIUM": 7, "LOW": 2}

#: …and the reduced price for each subsequent occurrence.
TIER_SUBSEQUENT_WEIGHT: dict[str, int] = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 4, "LOW": 1}

#: Per-tier saturation caps (max TOTAL deduction per tier). ``None`` = uncapped.
TIER_CAPS: dict[str, int | None] = {"CRITICAL": None, "HIGH": 36, "MEDIUM": 20, "LOW": 6}

#: Multiplicative modifiers (§8.2), applied before rounding.
MODIFIER_FACTORS: dict[str, float] = {"static_only": 0.5, "declared": 0.5}

#: Confidence at/below this boundary the finding is *suspected* (§8.2).
CONFIRMED_CONFIDENCE = 0.6

#: Grade bands (§8.2). F < 40 ≤ D < 60 ≤ C < 75 ≤ B < 90 ≤ A.
GRADE_A_MIN = 90
GRADE_B_MIN = 75
GRADE_C_MIN = 60
GRADE_D_MIN = 40

GRADES: tuple[str, ...] = ("A", "B", "C", "D", "F")
_GRADE_RANK: dict[str, int] = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

VERDICT_ALERT = "alert"
VERDICT_WARN = "warn"
VERDICT_NOTICE = "notice"
VERDICT_CLEAN = "clean"
VERDICTS: tuple[str, ...] = (VERDICT_ALERT, VERDICT_WARN, VERDICT_NOTICE, VERDICT_CLEAN)

#: Ladder order used by ``--fail-on`` comparisons (weakest → strongest).
VERDICT_LADDER: tuple[str, ...] = (VERDICT_CLEAN, VERDICT_NOTICE, VERDICT_WARN, VERDICT_ALERT)

#: ``--fail-on`` levels (§8.4). Default none ⇒ plain scans never exit 1.
FAIL_ON_LEVELS: tuple[str, ...] = ("clean", "notice", "warn", "alert")


# ---------------------------------------------------------------------------
# Ceilings (SPEC §8.2 table, normative mapping condition → cap → grade floor)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Ceiling:
    """One score ceiling: trigger name, score cap, and grade floor."""

    name: str
    score_cap: int
    grade_floor: str  # grade may be no BETTER than this


#: Any confirmed CRITICAL (conf ≥ 0.6) → ≤ 25 → F.
CEILING_CONFIRMED_CRITICAL = Ceiling("confirmed-critical", 25, "F")
#: Only *suspected* CRITICAL (conf < 0.6) → ≤ 40 → D, plus needs_review.
CEILING_SUSPECTED_CRITICAL = Ceiling("suspected-critical", 40, "D")
#: Undeclared money-touch (wallet/payment/crypto movement) → ≤ 70 → at least C/warn.
CEILING_MONEY = Ceiling("undeclared-money", 70, "C")
#: Integrity/override attempt (permission bypass, hidden invocation,
#: agent-config/persona/skill-tree writes) → ≤ 80 → at least C/warn.
CEILING_INTEGRITY = Ceiling("integrity-attempt", 80, "C")

#: Capability families whose ACTIVE evidence arms :data:`CEILING_MONEY`.
MONEY_FAMILY = "money"

#: Capability families whose active DYNAMIC evidence arms
#: :data:`CEILING_INTEGRITY`. ``static_only`` findings are excluded so an
#: omission-shaped manifest note can never raise the ceiling alone
#: (DECISIONS D-020/D-025: LNS-MAN-004 must not arm it by itself).
INTEGRITY_FAMILIES: frozenset[str] = frozenset(
    {"integrity.override", "persona.write", "spawn.agent"}
)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def round_half_up(value: float) -> int:
    """Round *value* half-up to whole points (§8.2 rounding law).

    Python's built-in :func:`round` uses banker's rounding; the rubric
    pins half-up, so this helper is the ONLY rounding seam in the scorer.
    """
    return math.floor(value + 0.5)


def contribution_points(
    weight: int,
    *,
    static_only: bool = False,
    declared: bool = False,
) -> int:
    """Applied deduction magnitude: weight × modifier factors, half-up.

    Modifiers multiply before rounding exactly once (§8.2 "multiplicative,
    applied before rounding").
    """
    factor = 1.0
    if static_only:
        factor *= MODIFIER_FACTORS["static_only"]
    if declared:
        factor *= MODIFIER_FACTORS["declared"]
    return round_half_up(weight * factor)


def grade_for_score(value: int) -> str:
    """Band grade for *value* (§8.2 thresholds)."""
    if value >= GRADE_A_MIN:
        return "A"
    if value >= GRADE_B_MIN:
        return "B"
    if value >= GRADE_C_MIN:
        return "C"
    if value >= GRADE_D_MIN:
        return "D"
    return "F"


def apply_ceiling(value: int, ceiling: Ceiling) -> int:
    """``score = min(score, cap)`` (§8.2); idempotent by construction.

    Exposed as a named seam so property tests can pin cap-idempotence on
    the exact operation the scorer uses (never an ad-hoc ``min`` call).
    """
    return min(value, ceiling.score_cap)


# ---------------------------------------------------------------------------
# Score result + math trace (T3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoreMathRow:
    """Per-finding scoring trace (SPEC §12.3 ``score_math`` entry)."""

    finding: str  # report id "F-N"
    rule_id: str
    severity: str  # pricing tier (rule-assigned)
    weight: int  # scheduled base weight BEFORE modifiers
    modifiers: tuple[str, ...]
    points: int  # APPLIED deduction after modifiers + tier truncation
    tier_cap_applied: bool
    ceiling_applied: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "weight": self.weight,
            "modifiers": list(self.modifiers),
            "points": self.points,
            "tier_cap_applied": self.tier_cap_applied,
            "ceiling_applied": self.ceiling_applied,
        }


@dataclass(frozen=True)
class ScoreResult:
    """The ``report/1`` ``score`` block plus its derivation trace."""

    value: int
    grade: str
    verdict: str
    needs_review: bool
    ceilings_applied: tuple[str, ...]
    score_math: tuple[ScoreMathRow, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "grade": self.grade,
            "verdict": self.verdict,
            "needs_review": self.needs_review,
            "ceilings_applied": list(self.ceilings_applied),
            "score_math": [row.to_dict() for row in self.score_math],
        }


# ---------------------------------------------------------------------------
# Finding-field helpers (tolerant: junk degrades to the weakest bucket)
# ---------------------------------------------------------------------------

_FALLBACK_TIER = "LOW"


def _pricing_tier(finding: Mapping[str, Any]) -> str:
    severity = str(finding.get("severity", ""))
    return severity if severity in TIER_FIRST_WEIGHT else _FALLBACK_TIER


def _effective_severity(finding: Mapping[str, Any]) -> str:
    eff = str(finding.get("effective_severity", "")) or str(finding.get("severity", ""))
    return eff if eff in SEVERITY_TIERS else _FALLBACK_TIER


def _confidence(finding: Mapping[str, Any]) -> float:
    value = finding.get("confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 1.0
    return float(value)


def _capability_family(finding: Mapping[str, Any]) -> str:
    return str(finding.get("capability", "")).partition(":")[0]


def _sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    location = finding.get("location") or {}
    start = location.get("start_line")
    return (
        str(finding.get("rule_id", "")),
        str(location.get("path", "")),
        start if isinstance(start, int) else 0,
    )


def _is_active(finding: Mapping[str, Any]) -> bool:
    return not bool(finding.get("suppressed", False))


# ---------------------------------------------------------------------------
# The scorer
# ---------------------------------------------------------------------------


def score_findings(findings: Iterable[Mapping[str, Any]]) -> ScoreResult:
    """Score *findings* under rubric v2 (pure; SPEC §8).

    Accepts ``§7``-shaped dicts (the pipeline wire form). Suppressed
    findings are inactive and priced nothing. Deterministic: tiers price in
    ``(rule_id, path, start_line)`` order, so occurrence indices never
    depend on input order.
    """
    active = [f for f in findings if _is_active(f)]
    math_rows: list[ScoreMathRow] = []
    total_deduction = 0

    for tier in SEVERITY_TIERS:
        members = sorted((f for f in active if _pricing_tier(f) == tier), key=_sort_key)
        if not members:
            continue
        cap = TIER_CAPS[tier]
        tier_total = 0
        # Occurrence index counts per modifier signature (D-029): the
        # full/reduced schedule tracks repetition of the same evidence
        # class, and per-class counting keeps tier totals monotone under
        # insertion (suite property: adding findings never raises a score).
        class_rank: dict[tuple[bool, bool], int] = {}
        for finding in members:
            static_only = bool(finding.get("static_only", False))
            declared = bool(finding.get("declared", False))
            signature = (static_only, declared)
            index = class_rank.get(signature, 0)
            class_rank[signature] = index + 1
            base = TIER_FIRST_WEIGHT[tier] if index == 0 else TIER_SUBSEQUENT_WEIGHT[tier]
            modifiers: tuple[str, ...] = ()
            if static_only:
                modifiers += ("static_only",)
            if declared:
                modifiers += ("declared",)
            points = contribution_points(weight=base, static_only=static_only, declared=declared)

            remaining: int | None = None if cap is None else cap - tier_total
            truncated = remaining is not None and points > remaining
            applied = points if remaining is None else max(0, min(points, remaining))

            math_rows.append(
                ScoreMathRow(
                    finding=str(finding.get("id", "")),
                    rule_id=str(finding.get("rule_id", "")),
                    severity=tier,
                    weight=base,
                    modifiers=modifiers,
                    points=applied,
                    tier_cap_applied=truncated,
                    ceiling_applied=None,
                )
            )
            tier_total += applied
        total_deduction += tier_total

    value = max(0, 100 - total_deduction)
    grade_rank = _GRADE_RANK[grade_for_score(value)]

    # -- ceilings (stack by min; each clamps grade too) -----------------------
    def _arms(pred: Any) -> str | None:
        """Report id of the FIRST (deterministic order) finding satisfying pred."""
        for f in sorted(active, key=_sort_key):
            if pred(f):
                return str(f.get("id", ""))
        return None

    trigger_confirmed = _arms(
        lambda f: _effective_severity(f) == "CRITICAL" and _confidence(f) >= CONFIRMED_CONFIDENCE
    )
    trigger_suspected = _arms(
        lambda f: _effective_severity(f) == "CRITICAL" and _confidence(f) < CONFIRMED_CONFIDENCE
    )
    trigger_money = _arms(
        lambda f: _capability_family(f) == MONEY_FAMILY and not bool(f.get("declared", False))
    )
    trigger_integrity = _arms(
        lambda f: (
            _capability_family(f) in INTEGRITY_FAMILIES and not bool(f.get("static_only", False))
        )
    )

    armed: list[Ceiling] = []
    triggers_by_ceiling: dict[str, set[str]] = {}
    if trigger_confirmed is not None:
        armed.append(CEILING_CONFIRMED_CRITICAL)
        triggers_by_ceiling[CEILING_CONFIRMED_CRITICAL.name] = {trigger_confirmed}
    if trigger_suspected is not None:
        armed.append(CEILING_SUSPECTED_CRITICAL)
        triggers_by_ceiling[CEILING_SUSPECTED_CRITICAL.name] = {trigger_suspected}
    if trigger_money is not None:
        armed.append(CEILING_MONEY)
        triggers_by_ceiling[CEILING_MONEY.name] = {trigger_money}
    if trigger_integrity is not None:
        armed.append(CEILING_INTEGRITY)
        triggers_by_ceiling[CEILING_INTEGRITY.name] = {trigger_integrity}

    ceilings_applied: list[str] = []
    for ceiling in armed:
        value = min(value, ceiling.score_cap)
        grade_rank = max(grade_rank, _GRADE_RANK[ceiling.grade_floor])
        ceilings_applied.append(ceiling.name)

    # Attribute each ceiling to the finding(s) that ARMED it (lowest cap
    # wins when several ride the same finding). Annotation-only trace.
    attribution: dict[str, str] = {}
    for ceiling in sorted(armed, key=lambda c: c.score_cap):
        for finding_id in triggers_by_ceiling[ceiling.name]:
            attribution.setdefault(finding_id, ceiling.name)
    if attribution:
        math_rows = [
            (
                ScoreMathRow(
                    finding=row.finding,
                    rule_id=row.rule_id,
                    severity=row.severity,
                    weight=row.weight,
                    modifiers=row.modifiers,
                    points=row.points,
                    tier_cap_applied=row.tier_cap_applied,
                    ceiling_applied=attribution[row.finding],
                )
                if row.finding in attribution and row.ceiling_applied is None
                else row
            )
            for row in math_rows
        ]

    needs_review = trigger_suspected is not None or any(
        _effective_severity(f) in ("CRITICAL", "HIGH") and _confidence(f) < CONFIRMED_CONFIDENCE
        for f in active
    )

    grade = GRADES[grade_rank]
    verdict = _derive_verdict(
        value=value,
        grade=grade,
        active=active,
        ceilings={c.name for c in armed},
    )

    return ScoreResult(
        value=value,
        grade=grade,
        verdict=verdict,
        needs_review=needs_review,
        ceilings_applied=tuple(ceilings_applied),
        score_math=tuple(math_rows),
    )


def _derive_verdict(
    *,
    value: int,
    grade: str,
    active: list[Mapping[str, Any]],
    ceilings: set[str],
) -> str:
    """§8.2 verdict ladder, evaluated top-down over effective severities."""
    del value  # grade bands carry the thresholds; value kept for signature clarity
    confirmed_critical = any(
        _effective_severity(f) == "CRITICAL" and _confidence(f) >= CONFIRMED_CONFIDENCE
        for f in active
    )
    if grade == "F" or confirmed_critical:
        return VERDICT_ALERT
    undeclared_high = any(
        _effective_severity(f) == "HIGH" and not bool(f.get("declared", False)) for f in active
    )
    money_or_integrity_ceiling = bool(ceilings & {CEILING_MONEY.name, CEILING_INTEGRITY.name})
    if grade in ("C", "D") or undeclared_high or money_or_integrity_ceiling:
        return VERDICT_WARN
    medium_active = any(_effective_severity(f) == "MEDIUM" for f in active)
    declared_high = any(
        _effective_severity(f) == "HIGH" and bool(f.get("declared", False)) for f in active
    )
    if medium_active or declared_high or grade == "B":
        return VERDICT_NOTICE
    return VERDICT_CLEAN


# ---------------------------------------------------------------------------
# Exit-code projection (§8.4 / §18 — CLI verbs only)
# ---------------------------------------------------------------------------


def compute_exit_code(verdict: str, fail_on: str | None = None) -> int:
    """Project *verdict* onto CLI exit codes (§8.4 stub for later CLI verbs).

    Exit codes: 0 default; 1 ONLY under an explicit ``--fail-on`` breach
    (breach ⇔ verdict is at or beyond the requested level on the
    clean<notice<warn>alert ladder); 2 is reserved for TOTAL errors and is
    raised by callers, never synthesized here. Invalid inputs raise
    :class:`ValueError` so config seams can map them to exit 2 semantics.

    Slash/hook surfaces have no exit code to honor — verdict in text is the
    contract there (§8.4/D-SURF).
    """
    if verdict not in VERDICT_LADDER:
        raise ValueError(f"unknown verdict {verdict!r}")
    level = "none" if fail_on is None else str(fail_on).strip().lower()
    if level in ("", "none"):
        return 0
    if level not in FAIL_ON_LEVELS:
        raise ValueError(
            f"unknown --fail-on level {fail_on!r} (expected one of: {', '.join(FAIL_ON_LEVELS)})"
        )
    return 1 if VERDICT_LADDER.index(verdict) >= VERDICT_LADDER.index(level) else 0


__all__ = [
    "CEILING_CONFIRMED_CRITICAL",
    "CEILING_INTEGRITY",
    "CEILING_MONEY",
    "CEILING_SUSPECTED_CRITICAL",
    "CONFIRMED_CONFIDENCE",
    "FAIL_ON_LEVELS",
    "GRADES",
    "INTEGRITY_FAMILIES",
    "MONEY_FAMILY",
    "MODIFIER_FACTORS",
    "SEVERITY_TIERS",
    "TIER_CAPS",
    "TIER_FIRST_WEIGHT",
    "TIER_SUBSEQUENT_WEIGHT",
    "VERDICTS",
    "VERDICT_LADDER",
    "Ceiling",
    "ScoreMathRow",
    "ScoreResult",
    "apply_ceiling",
    "contribution_points",
    "compute_exit_code",
    "grade_for_score",
    "round_half_up",
    "score_findings",
]
