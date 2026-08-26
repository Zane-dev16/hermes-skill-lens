"""Benign floor gate (PLAN §1 Phase 3 exit criterion).

Exit math: **100% of benign fixtures grade >= B on the street profile.**
The corpus silence gate (tests/test_corpus.py) demands zero fired core-pack
rules; this module restates the requirement independently THROUGH the
scorer, so a future engine overfire cannot degrade a benign bundle through
the grade channel unnoticed (FP-as-fixture law: the failing case here is
either an accidentally-malicious-looking fixture or a rule that must be
tightened — see docs/fp-regression.md).

Also pins the SPEC §10 / D-STREETLAB semantics the mandated pentest-lab hard
case exercises: street IGNORES the ``[lab:declared-offensive]`` marker for
offensive-tooling rules — the lab fixture must stay >=B on street by being
genuinely inert, never by earning a declaration discount.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_lens.corpus import discover_fixtures, run_case
from skill_lens.policy import (
    MARKER_LAB_DECLARED_OFFENSIVE,
    declares_offensive_scope,
    lab_declared_offensive,
)
from skill_lens.rules import load_core_pack
from skill_lens.scoring import GRADE_B_MIN, score_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = REPO_ROOT / "corpus" / "fixtures"

#: Grade rank, lower = better (mirrors scoring._GRADE_RANK; kept local so the
#: floor gate cannot drift with scorer internals).
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

BENIGN_SPECS = tuple(s for s in discover_fixtures(CORPUS_ROOT) if not s.is_malicious)


def test_benign_corpus_meets_phase3_floor_size() -> None:
    assert len(BENIGN_SPECS) >= 30, "PLAN Phase 3 requires >=30 benign fixtures"


@pytest.mark.parametrize("spec", BENIGN_SPECS, ids=lambda s: s.name)
def test_benign_fixture_grades_at_least_b_on_street(spec, tmp_path) -> None:
    """The exit criterion: computed grade >= B (and verdict clean/notice)."""
    result = run_case(spec, tmp_root=tmp_path, pack=load_core_pack())
    scored = score_findings(result.findings)
    assert _GRADE_RANK[scored.grade] <= _GRADE_RANK["B"], (
        f"{spec.name}: grade {scored.grade} (score {scored.value}) below the "
        f"benign floor B (>={GRADE_B_MIN}); ceilings={scored.ceilings_applied}"
    )
    assert scored.verdict in ("clean", "notice"), (
        f"{spec.name}: verdict {scored.verdict!r} is not an advisory-clean stance"
    )


# ---------------------------------------------------------------------------
# SPEC §10 profile semantics exercised by the mandated lab hard case
# ---------------------------------------------------------------------------


def test_street_ignores_declared_marker() -> None:
    """D-STREETLAB: the marker discounts NOTHING under street."""
    assert MARKER_LAB_DECLARED_OFFENSIVE == "[lab:declared-offensive]"
    assert not lab_declared_offensive("street", "execute.shell", True)
    assert not lab_declared_offensive("street", "network.scan", True)
    assert lab_declared_offensive("lab", "execute.shell", True)


def test_lab_fixture_carries_marker_and_declares_scope() -> None:
    spec = next(s for s in BENIGN_SPECS if s.name == "lab-recon-playbook")
    text = (spec.path / "SKILL.md").read_text(encoding="utf-8")
    assert MARKER_LAB_DECLARED_OFFENSIVE in text
    assert declares_offensive_scope(text)
