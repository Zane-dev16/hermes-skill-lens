"""Phase 5 — pack semver governor (skill_lens.packver, SPEC §15).

Builds tiny in-memory packs via tmp YAML trees and pins every transition
class: legal patch (new rule), REQUIRED minor + rationale for weight/severity
movement, illegal-jump rejection WITH reasons, deprecation horizon math,
removal gating, changelog-discipline checks, and no-op legality.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_lens.packver import (
    REMOVAL_HORIZON_MINORS,
    PackVerError,
    enforce,
    minor_index,
    version_tuple,
)
from skill_lens.rules import RulePack, load_pack

# ---------------------------------------------------------------------------
# Pack-tree factory
# ---------------------------------------------------------------------------

PACK_YAML = """\
name: testpack
version: "{version}"
spec_version: rule-pack/1
description: governor fixture pack
rules_dir: rules
changelog:
  - version: "{version}"
    date: "2026-08-26"
    notes:
      - "{note}"
{rationale_line}
"""

RULE_TMPL = """\
id: {rid}
title: "{title}"
rule_version: "1"
status: {status}
engine: manifest
capability: integrity.override:{subpath}
severity: {severity}
weight: {weight}
evidence_kind: manifest
confidence_default: {confidence}
static_only: true
tags:
  - governor-fixture
remediation: >-
  Fixture remediation text.
rationale: >-
  Fixture rationale text.
detection: >-
  Fixture detection spec ({marker}).
{deprecated_line}
fixtures:
  positive:
    - corpus/fixtures/malicious/metadata-abuse
  negative:
    - corpus/fixtures/benign/rich-legit-metadata
"""


def _write_pack(
    root: Path,
    *,
    version: str,
    rules: list[dict[str, object]],
    note: str = "governor fixture entry",
    rationale: str | None = None,
) -> RulePack:
    pack_dir = root / "pack"
    rules_dir = pack_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rationale_line = f"    rationale: \"{rationale}\"" if rationale else ""
    (pack_dir / "pack.yaml").write_text(
        PACK_YAML.format(version=version, note=note, rationale_line=rationale_line),
        encoding="utf-8",
    )
    for spec in rules:
        rid = str(spec["id"])
        (rules_dir / f"{rid}.yaml").write_text(
            RULE_TMPL.format(
                rid=rid,
                title=str(spec.get("title", f"Rule {rid}")),
                status=str(spec.get("status", "active")),
                subpath=str(spec.get("subpath", "control_plane")),
                severity=str(spec.get("severity", "LOW")),
                weight=int(spec.get("weight", 2)),  # type: ignore[arg-type]
                confidence=float(spec.get("confidence", 0.9)),  # type: ignore[call-overload]
                marker=rid,
                deprecated_line=(
                    f"deprecated_since: \"{spec['deprecated_since']}\""
                    if spec.get("deprecated_since")
                    else ""
                ),
            ),
            encoding="utf-8",
        )
    return load_pack(pack_dir)


BASE_RULES = [
    {"id": "LNS-MAN-101"},
    {"id": "LNS-MAN-102", "severity": "MEDIUM", "weight": 7},
]


@pytest.fixture
def base(tmp_path: Path) -> RulePack:
    return _write_pack(tmp_path / "base", version="2026.08.6", rules=list(BASE_RULES))


def _next_tree(tmp_path: Path, name: str, **kwargs: object) -> RulePack:
    return _write_pack(tmp_path / name, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Version arithmetic
# ---------------------------------------------------------------------------


def test_version_ordering_and_minor_index() -> None:
    assert version_tuple("2026.08.6") == (2026, 8, 6)
    assert version_tuple("2026.12.0") > version_tuple("2026.09.99")
    assert minor_index("2025.07.3") + 13 == minor_index("2026.08.0")


# ---------------------------------------------------------------------------
# Legal transitions
# ---------------------------------------------------------------------------


def test_new_rule_only_is_legal_patch(base: RulePack, tmp_path: Path) -> None:
    new_rules = list(BASE_RULES) + [{"id": "LNS-MAN-103"}]
    new = _next_tree(
        tmp_path, "new", version="2026.08.7", rules=new_rules, note="Add LNS-MAN-103"
    )
    report = enforce(base, new)
    assert report.ok and report.added == ("LNS-MAN-103",)
    assert report.summary_line().startswith("2026.08.6 → 2026.08.7")


def test_identical_pack_is_a_legal_noop(base: RulePack, tmp_path: Path) -> None:
    same = _next_tree(tmp_path, "same", version="2026.08.6", rules=list(BASE_RULES))
    report = enforce(base, same)
    assert report.ok


# ---------------------------------------------------------------------------
# Illegal transitions — the §15 teeth
# ---------------------------------------------------------------------------


def test_weight_change_with_patch_only_bump_rejected(base: RulePack, tmp_path: Path) -> None:
    rules = [dict(BASE_RULES[0]), dict(BASE_RULES[1], severity="HIGH", weight=18)]
    # HIGH tier first weight is 18 — a real score-visible movement.
    new = _next_tree(
        tmp_path, "new", version="2026.08.7", rules=rules, note="tweak LNS-MAN-102"
    )
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    reasons = "\n".join(excinfo.value.violations)
    assert "MINOR bump" in reasons
    assert "LNS-MAN-102" in reasons
    assert "rationale" in reasons


def test_weight_change_minor_with_rationale_passes(base: RulePack, tmp_path: Path) -> None:
    rules = [dict(BASE_RULES[0]), dict(BASE_RULES[1], severity="HIGH", weight=18)]
    new = _next_tree(
        tmp_path,
        "new",
        version="2026.09.0",
        rules=rules,
        note="recalibrate",
        rationale="LNS-MAN-102 escalated after field FPs: severity HIGH reflects "
        "control-plane write impact (§17 H5)",
    )
    report = enforce(base, new)
    assert report.ok
    assert report.material_changed == ("LNS-MAN-102",)


def test_minor_without_rationale_field_rejected(base: RulePack, tmp_path: Path) -> None:
    rules = [dict(BASE_RULES[0]), dict(BASE_RULES[1], severity="HIGH", weight=18)]
    new = _next_tree(
        tmp_path, "new", version="2026.09.0", rules=rules, note="silent recalibration"
    )
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    assert any("rationale" in v for v in excinfo.value.violations)


def test_version_not_advancing_rejected(base: RulePack, tmp_path: Path) -> None:
    new = _next_tree(
        tmp_path,
        "new",
        version="2026.08.6",
        rules=[*list(BASE_RULES), {"id": "LNS-MAN-103"}],
    )
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    assert any("did not advance" in v for v in excinfo.value.violations)


# ---------------------------------------------------------------------------
# Deprecation lifecycle
# ---------------------------------------------------------------------------


def test_deprecation_requires_deprecated_since_stamp(base: RulePack, tmp_path: Path) -> None:
    rules = [
        dict(BASE_RULES[0], status="deprecated"),
        dict(BASE_RULES[1]),
    ]
    new = _next_tree(tmp_path, "new", version="2026.08.7", rules=rules)
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    assert any("'deprecated_since'" in v for v in excinfo.value.violations)

    stamped = [
        dict(BASE_RULES[0], status="deprecated", deprecated_since="2026.08.7"),
        dict(BASE_RULES[1]),
    ]
    ok = _next_tree(tmp_path, "ok", version="2026.08.7", rules=stamped)
    assert enforce(base, ok).newly_deprecated == ("LNS-MAN-101",)


def test_removal_before_horizon_rejected(base: RulePack, tmp_path: Path) -> None:
    # Deprecated at .6; removal attempted 1 minor later (< horizon).
    dep = [
        dict(BASE_RULES[0], status="deprecated", deprecated_since="2026.08.6"),
        dict(BASE_RULES[1]),
    ]
    mid = _next_tree(tmp_path, "mid", version="2026.08.7", rules=dep)
    assert enforce(base, mid).ok  # deprecation itself is fine

    removed = [dict(BASE_RULES[1])]
    too_soon = _next_tree(tmp_path, "soon", version="2026.09.0", rules=removed)
    with pytest.raises(PackVerError) as excinfo:
        enforce(mid, too_soon)
    joined = "\n".join(excinfo.value.violations)
    assert f">={REMOVAL_HORIZON_MINORS}" in joined


def test_removal_after_two_minors_with_rationale_passes(base: RulePack, tmp_path: Path) -> None:
    dep = [
        dict(BASE_RULES[0], status="deprecated", deprecated_since="2026.08.6"),
        dict(BASE_RULES[1]),
    ]
    mid = _next_tree(tmp_path, "mid", version="2026.08.7", rules=dep)
    later = _write_pack(
        tmp_path / "later",
        version="2026.10.0",
        rules=[dict(BASE_RULES[1])],
        note="Remove LNS-MAN-101",
        rationale="LNS-MAN-101 removal after full horizon: superseded by sink-side "
        "correlation, zero field hits across two cycles",
    )
    report = enforce(mid, later)
    assert report.ok and report.removed == ("LNS-MAN-101",)


def test_active_rule_cannot_be_removed_directly(base: RulePack, tmp_path: Path) -> None:
    orphaned = [dict(BASE_RULES[1])]
    rogue = _next_tree(tmp_path, "rogue", version="2026.09.0", rules=orphaned)
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, rogue)
    joined = "\n".join(excinfo.value.violations)
    assert "deprecated first" in joined


# ---------------------------------------------------------------------------
# Changelog discipline + schema gate
# ---------------------------------------------------------------------------


def test_stale_changelog_head_rejected_on_minor(base: RulePack, tmp_path: Path) -> None:
    rules = [dict(BASE_RULES[0]), dict(BASE_RULES[1], severity="HIGH", weight=18)]
    new = _write_pack(
        tmp_path / "stale",
        version="2026.09.0",
        rules=rules,
        note="recalibrate",
        rationale="LNS-MAN-102 escalation rationale text",
    )
    # Force the head entry to carry the OLD version (changelog not updated).
    object.__setattr__(
        new,
        "changelog",
        tuple([{"version": "2026.08.6", "date": "x", "notes": ["old"], "rationale": "LNS-MAN-102"}])
        + new.changelog[1:],
    )
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    assert any("changelog head" in v for v in excinfo.value.violations)


def test_spec_version_change_flagged_as_major_territory(
    base: RulePack, tmp_path: Path
) -> None:
    new = _next_tree(tmp_path, "new", version="2026.09.0", rules=list(BASE_RULES))
    object.__setattr__(new, "spec_version", "rule-pack/2")
    with pytest.raises(PackVerError) as excinfo:
        enforce(base, new)
    assert any("MAJOR bump" in v for v in excinfo.value.violations)


# ---------------------------------------------------------------------------
# Real embedded pack sanity
# ---------------------------------------------------------------------------


def test_embedded_pack_self_transition_is_noop() -> None:
    from skill_lens.rules import load_core_pack

    pack = load_core_pack()
    assert enforce(pack, pack).ok
