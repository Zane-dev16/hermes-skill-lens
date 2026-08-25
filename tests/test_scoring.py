"""Scoring rubric v2 (SPEC §8) — golden vectors A–G + property laws.

Golden half: SPEC §8.3 worked examples must reproduce EXACTLY (value,
grade, verdict; needs_review where the spec shows ⚑). The vectors are also
committed as a byte-stable JSON artifact under ``corpus/vectors/`` and
re-verified against it, per the PLAN Phase-1 exit criterion.

Property half (hypothesis, PLAN §3 item 5):
- monotonicity   — adding a finding never raises the score;
- cap-idempotence— applying a ceiling twice is identity;
- grade clamp    — an armed ceiling always floors the grade;
- verdict ladder — verdict thresholds stay consistent with grades per §8.2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from skill_lens.scoring import (
    CEILING_CONFIRMED_CRITICAL,
    CEILING_INTEGRITY,
    CEILING_MONEY,
    CEILING_SUSPECTED_CRITICAL,
    FAIL_ON_LEVELS,
    GRADES,
    VERDICTS,
    apply_ceiling,
    compute_exit_code,
    contribution_points,
    round_half_up,
    score_findings,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = REPO_ROOT / "corpus" / "vectors" / "scoring-v2.json"


# ---------------------------------------------------------------------------
# Finding factory (§7 wire shape, minimal keys the scorer reads)
# ---------------------------------------------------------------------------

_SEQ = iter(range(1, 10_000))


def make_finding(
    severity: str = "MEDIUM",
    *,
    confidence: float = 0.9,
    static_only: bool = False,
    declared: bool = False,
    capability: str = "execute.shell",
    rule_id: str | None = None,
    path: str = "scripts/a.sh",
    start_line: int = 1,
    suppressed: bool = False,
) -> dict[str, Any]:
    index = next(_SEQ)
    return {
        "id": f"F-{index}",
        "fingerprint": f"sha256:{index:064d}",
        "rule_id": rule_id or f"LNS-TST-{index % 1000:03d}",
        "severity": severity,
        "effective_severity": severity,
        "confidence": confidence,
        "evidence_kind": "regex",
        "static_only": static_only,
        "declared": declared,
        "capability": capability,
        "suppressed": suppressed,
        "location": {"path": path, "start_line": start_line},
    }


# ---------------------------------------------------------------------------
# Golden vectors (SPEC §8.3)
# ---------------------------------------------------------------------------


def _vector_a() -> list[dict[str, Any]]:
    return []


def _vector_b() -> list[dict[str, Any]]:
    """MED dyn undecl −7; LOW static −1; LOW static additional −1."""
    return [
        make_finding("MEDIUM", capability="credentials.read"),
        make_finding("LOW", static_only=True, capability="filesystem.read"),
        make_finding("LOW", static_only=True, capability="filesystem.read"),
    ]


def _vector_c(confidence: float = 0.93) -> list[dict[str, Any]]:
    """CRIT dyn undecl −40; HIGH static obfuscation −9 → ceiling."""
    return [
        make_finding("CRITICAL", confidence=confidence, capability="network.send"),
        make_finding("HIGH", static_only=True, capability="obfuscation"),
    ]


def _vector_d() -> list[dict[str, Any]]:
    """Declared lab: HIGH decl −9; MED decl −4; MED decl additional −2."""
    return [
        make_finding("HIGH", declared=True, capability="network.send"),
        make_finding("MEDIUM", declared=True, capability="execute.shell"),
        make_finding("MEDIUM", declared=True, capability="network.read"),
    ]


def _vector_e() -> list[dict[str, Any]]:
    """Rogue override: MED dyn undecl −7; LOW static ×2 −2 → integrity ceiling."""
    return [
        make_finding("MEDIUM", capability="integrity.override"),
        make_finding("LOW", static_only=True, capability="integrity.override"),
        make_finding("LOW", static_only=True, capability="persona.write"),
    ]


def _vector_f() -> list[dict[str, Any]]:
    """Noisy formatter: 6×LOW static → tier cap 6; 2×MED dyn undecl −11."""
    lows = [
        make_finding("LOW", static_only=True, capability=f"filesystem.read:{i}") for i in range(6)
    ]
    meds = [
        make_finding("MEDIUM", capability="execute.shell", start_line=2),
        make_finding("MEDIUM", capability="filesystem.write", start_line=3),
    ]
    return lows + meds


def _vector_g() -> list[dict[str, Any]]:
    """Undeclared wallet enumerator: HIGH dyn undecl −18 → money ceiling."""
    return [make_finding("HIGH", capability="money")]


#: (label, findings, expected score/grade/verdict/needs_review) per SPEC §8.3.
GOLDEN_VECTORS: tuple[tuple[str, list, dict[str, Any]], ...] = (
    ("A", _vector_a(), {"score": 100, "grade": "A", "verdict": "clean"}),
    ("B", _vector_b(), {"score": 91, "grade": "A", "verdict": "notice"}),
    ("C", _vector_c(), {"score": 25, "grade": "F", "verdict": "alert"}),
    (
        "C-prime",
        _vector_c(confidence=0.55),
        {"score": 40, "grade": "D", "verdict": "warn", "needs_review": True},
    ),
    ("D", _vector_d(), {"score": 85, "grade": "B", "verdict": "notice"}),
    ("E", _vector_e(), {"score": 80, "grade": "C", "verdict": "warn"}),
    ("F", _vector_f(), {"score": 83, "grade": "B", "verdict": "notice"}),
    ("G", _vector_g(), {"score": 70, "grade": "C", "verdict": "warn"}),
)


def test_round_half_up_is_not_bankers() -> None:
    assert round_half_up(0.5) == 1
    assert round_half_up(1.5) == 2
    assert round_half_up(2.5) == 3
    assert round_half_up(3.5) == 4
    assert round_half_up(18 * 0.5) == 9


def test_contribution_modifier_combinations() -> None:
    assert contribution_points(7) == 7
    assert contribution_points(7, declared=True) == 4  # 3.5 half-up
    assert contribution_points(2, static_only=True) == 1
    assert contribution_points(1, static_only=True) == 1  # 0.5 half-up
    assert contribution_points(18, static_only=True) == 9
    assert contribution_points(7, static_only=True, declared=True) == 2  # 1.75


@pytest.mark.parametrize(
    "label,findings,expected", GOLDEN_VECTORS, ids=[v[0] for v in GOLDEN_VECTORS]
)
def test_golden_vectors_reproduce_spec_83(
    label: str, findings: list, expected: dict[str, Any]
) -> None:
    del label
    result = score_findings(findings)
    assert result.value == expected["score"]
    assert result.grade == expected["grade"]
    assert result.verdict == expected["verdict"]
    if "needs_review" in expected:
        assert result.needs_review is expected["needs_review"]


def test_committed_vector_artifact_matches_scorer() -> None:
    """The corpus/vectors artifact stays byte-equal to live scorer output."""
    artifact = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert set(artifact) == {label for label, _, _ in GOLDEN_VECTORS}
    for label, findings, expected in GOLDEN_VECTORS:
        result = score_findings(findings)
        recorded = artifact[label]
        assert recorded["score"] == result.value == expected["score"], label
        assert recorded["grade"] == result.grade == expected["grade"], label
        assert recorded["verdict"] == result.verdict == expected["verdict"], label
        assert recorded["needs_review"] is result.needs_review, label


def test_suppressed_findings_are_inactive() -> None:
    findings = [
        make_finding("CRITICAL", suppressed=True, capability="network.send"),
        make_finding("HIGH", suppressed=True, capability="money"),
    ]
    result = score_findings(findings)
    assert result.value == 100
    assert result.grade == "A"
    assert result.verdict == "clean"
    assert result.ceilings_applied == ()


def test_tier_saturation_noisy_lows_cost_exactly_cap() -> None:
    """50 LOW findings still cost exactly 6 (§8.1 ordering check)."""
    findings = [make_finding("LOW", static_only=True, start_line=i) for i in range(50)]
    result = score_findings(findings)
    assert result.value == 94
    rows = result.score_math
    assert sum(row.points for row in rows) == 6
    assert any(row.tier_cap_applied for row in rows)


def test_static_only_integrity_note_never_arms_ceiling_alone() -> None:
    """LNS-MAN-004-shaped omission (static, integrity.override) ⇒ no ceiling."""
    findings = [
        make_finding("LOW", static_only=True, capability="integrity.override:deceptive_metadata")
    ]
    result = score_findings(findings)
    assert result.value == 99  # 100 - round(2*0.5)=1
    assert result.ceilings_applied == ()
    assert result.verdict == "clean"


def test_declared_money_still_scores_but_no_money_ceiling() -> None:
    findings = [make_finding("HIGH", declared=True, capability="money")]
    result = score_findings(findings)
    assert result.value == 91  # -(18*0.5)
    assert result.ceilings_applied == ()
    assert result.verdict == "notice"  # declared HIGH escalates one level weaker


def test_score_math_traces_weights_modifiers_and_caps() -> None:
    findings = _vector_f()
    result = score_findings(findings)
    low_rows = [row for row in result.score_math if row.severity == "LOW"]
    assert low_rows[0].weight == 2 and low_rows[0].modifiers == ("static_only",)
    assert all(row.points == 1 for row in low_rows)
    med_rows = [row for row in result.score_math if row.severity == "MEDIUM"]
    # First/subsequent §8.2 schedule, in deterministic tier order:
    assert [(row.weight, row.points) for row in med_rows] == [(7, 7), (4, 4)]
    assert all(row.modifiers == () for row in med_rows)


# ---------------------------------------------------------------------------
# --fail-on / exit codes (§8.4 stub contract)
# ---------------------------------------------------------------------------


def test_exit_code_default_and_errors() -> None:
    for verdict in VERDICTS:
        assert compute_exit_code(verdict) == 0
        assert compute_exit_code(verdict, None) == 0
        assert compute_exit_code(verdict, "none") == 0
    with pytest.raises(ValueError):
        compute_exit_code("banana")
    with pytest.raises(ValueError):
        compute_exit_code("clean", "catastrophic")


@pytest.mark.parametrize("fail_on", FAIL_ON_LEVELS)
def test_exit_code_fail_on_ladder(fail_on: str) -> None:
    order = ["clean", "notice", "warn", "alert"]
    threshold = order.index(fail_on)
    for verdict in order:
        expected = 1 if order.index(verdict) >= threshold else 0
        assert compute_exit_code(verdict, fail_on) == expected, (fail_on, verdict)


def test_exit_code_warn_example_from_spec() -> None:
    """§8.4: with --fail-on warn, exit 1 iff verdict ∈ {warn, alert}."""
    assert compute_exit_code("warn", "warn") == 1
    assert compute_exit_code("alert", "warn") == 1
    assert compute_exit_code("notice", "warn") == 0
    assert compute_exit_code("clean", "warn") == 0


# ---------------------------------------------------------------------------
# Property laws (hypothesis)
# ---------------------------------------------------------------------------

_severities = st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
_confidences = st.floats(min_value=0.05, max_value=1.0)
_capabilities = st.sampled_from(
    [
        "network.send",
        "network.send:messaging_human",
        "money",
        "integrity.override",
        "integrity.override:control_plane",
        "persona.write",
        "spawn.agent:skill_ref",
        "obfuscation",
        "filesystem.read",
        "persistence:cron_json",
    ]
)


@st.composite
def finding_lists(draw: st.DrawFn) -> list[dict[str, Any]]:
    count = draw(st.integers(min_value=0, max_value=14))
    findings: list[dict[str, Any]] = []
    for index in range(count):
        findings.append(
            make_finding(
                draw(_severities),
                confidence=draw(_confidences),
                static_only=draw(st.booleans()),
                declared=draw(st.booleans()),
                capability=draw(_capabilities),
                rule_id=f"LNS-PRP-{index:03d}",
                path=f"scripts/f{index}.sh",
                start_line=index + 1,
            )
        )
    return findings


@settings(max_examples=200, deadline=None)
@given(findings=finding_lists(), extra=finding_lists())
def test_property_monotonicity_adding_findings_never_raises_score(
    findings: list, extra: list
) -> None:
    base = score_findings(findings).value
    combined = score_findings([*findings, *extra]).value
    assert combined <= base


@settings(max_examples=200, deadline=None)
@given(
    value=st.integers(min_value=0, max_value=120),
    ceiling=st.sampled_from(
        [
            CEILING_CONFIRMED_CRITICAL,
            CEILING_SUSPECTED_CRITICAL,
            CEILING_MONEY,
            CEILING_INTEGRITY,
        ]
    ),
)
def test_property_cap_idempotence(value: int, ceiling: Any) -> None:
    once = apply_ceiling(value, ceiling)
    assert apply_ceiling(once, ceiling) == once


@settings(max_examples=250, deadline=None)
@given(findings=finding_lists())
def test_property_ceilings_clamp_grade_and_score(findings: list) -> None:
    result = score_findings(findings)
    rank_of = {g: i for i, g in enumerate(GRADES)}
    floor_rank = max(
        (
            rank_of[c.grade_floor]
            for c, armed in (
                (CEILING_CONFIRMED_CRITICAL, "confirmed-critical" in result.ceilings_applied),
                (CEILING_SUSPECTED_CRITICAL, "suspected-critical" in result.ceilings_applied),
                (CEILING_MONEY, "undeclared-money" in result.ceilings_applied),
                (CEILING_INTEGRITY, "integrity-attempt" in result.ceilings_applied),
            )
            if armed
        ),
        default=-1,
    )
    if result.ceilings_applied:
        assert rank_of[result.grade] >= floor_rank
        if "confirmed-critical" in result.ceilings_applied:
            assert result.value <= CEILING_CONFIRMED_CRITICAL.score_cap
            assert result.grade == "F"
        if "suspected-critical" in result.ceilings_applied:
            assert result.value <= CEILING_SUSPECTED_CRITICAL.score_cap
            assert result.needs_review is True
        if "undeclared-money" in result.ceilings_applied:
            assert result.value <= CEILING_MONEY.score_cap
            assert result.verdict in ("warn", "alert")
        if "integrity-attempt" in result.ceilings_applied:
            assert result.value <= CEILING_INTEGRITY.score_cap
            assert result.verdict in ("warn", "alert")


@settings(max_examples=250, deadline=None)
@given(findings=finding_lists())
def test_property_verdict_consistent_with_grade_ladder(findings: list) -> None:
    result = score_findings(findings)
    active = [f for f in findings if not f.get("suppressed", False)]
    confirmed_critical = any(
        str(f.get("effective_severity") or f.get("severity")) == "CRITICAL"
        and float(f.get("confidence", 1.0)) >= 0.6
        for f in active
    )
    medium_plus_active = any(
        str(f.get("effective_severity") or f.get("severity")) in ("CRITICAL", "HIGH", "MEDIUM")
        for f in active
    )

    assert result.verdict in VERDICTS
    if result.verdict == "clean":
        assert not medium_plus_active
        assert result.grade == "A"
        assert not result.needs_review
    if result.grade == "F" or confirmed_critical:
        assert result.verdict == "alert"
    if result.grade in ("C", "D"):
        assert result.verdict in ("warn", "alert")
    if result.grade == "B":
        assert result.verdict in ("notice", "warn", "alert")
    # needs_review ⇔ suspected critical ceiling or any active HIGH+ conf < 0.6
    flagged_present = any(
        str(f.get("effective_severity") or f.get("severity")) in ("CRITICAL", "HIGH")
        and float(f.get("confidence", 1.0)) < 0.6
        for f in active
    )
    assert result.needs_review == flagged_present or (
        result.needs_review and "suspected-critical" in result.ceilings_applied
    )


@settings(max_examples=100, deadline=None)
@given(findings=finding_lists())
def test_property_determinism_same_input_same_result(findings: list) -> None:
    """Input ORDER must never matter: tiers re-sort by the law key internally."""
    first = score_findings(findings)
    second = score_findings(list(reversed(list(findings))))
    assert first.to_dict() == second.to_dict()
