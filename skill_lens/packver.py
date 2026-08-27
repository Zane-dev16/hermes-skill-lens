"""Pack semver governor — §15 transition enforcement between two pack states.

SPEC §15 change classes are NORMATIVE:

* ``new rule = patch bump`` — additions never move scores of existing rules;
* ``weight/severity change = minor bump + changelog rationale`` — scores
  shift visibly, so the report-embedded pack version changes meaning and
  every affected rule id needs a written rationale in the new pack's head
  changelog entry;
* ``IR/schema break = major bump`` — the loader pins ``spec_version``, so a
  schema break cannot even LOAD under this plugin; the governor reports it
  as refuse-to-load (the major-bump territory marker);
* ``deprecation ≥2 minor releases before removal`` — deprecated rules keep
  SHIPPING until their removal horizon opens.

The governor diffs two loaded :class:`RulePack` objects (CI: base ref vs
head; release tooling: last tag vs working tree) and either blesses the
transition or returns/raises with EVERY violation listed — an illegal jump
is rejected loudly with reasons, never silently waved through.

Version arithmetic: ``YYYY.MM.N`` orders lexicographically as
(year, month, patch); "minor distance" between versions is the month index
``year*12 + (month-1)`` difference — that's what counts deprecation
horizons. Patch numbers never extend a horizon (a patch cannot smuggle a
score-visible change past review).

Rationale location: the NEW pack's changelog HEAD entry must carry a
``rationale`` key (string or list of strings) naming every materially
changed rule id, and its ``version`` must equal the new pack version
(changelog discipline). This field is additive metadata on the existing
changelog-entry mapping — the loader already tolerates extra keys there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from .rules import Rule, RulePack

#: Version token shape (mirrors rules.PACK_VERSION_RE semantics).
_VERSION_RE = re.compile(r"^(\d{4})\.(\d{1,2})\.(\d+)$")

#: Per-rule fields whose movement is score-visible → minor bump + rationale.
#: weight/severity are the §15-named pair; capability/engine/evidence_kind
#: change WHAT fires (same visibility class); confidence_default moves the
#: scorer prior (§8 consumes it directly) — all read as "weight/severity
#: class" per the D-055 reading that §15's clause covers score-visible
#: detection changes generally.
MATERIAL_FIELDS: tuple[str, ...] = (
    "severity",
    "weight",
    "capability",
    "engine",
    "evidence_kind",
    "confidence_default",
)

#: How many MINOR releases a deprecated rule must ship through before its
#: removal horizon opens (§15: "deprecated (≥2 minor releases)").
REMOVAL_HORIZON_MINORS = 2


class PackVerError(Exception):
    """Illegal pack-version transition — carries every reason at once."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = list(violations)
        joined = "\n  - ".join(self.violations)
        super().__init__(f"pack version transition rejected:\n  - {joined}")


def version_tuple(version: str) -> tuple[int, int, int]:
    """Parse ``YYYY.MM.N`` into an ordering triple (raises ValueError)."""
    match = _VERSION_RE.match(version)
    if match is None:
        raise ValueError(f"version {version!r} is not YYYY.MM.N semver")
    year, month, patch = (int(part) for part in match.groups())
    if not 1 <= month <= 12:
        raise ValueError(f"version {version!r}: month out of range")
    return year, month, patch


def minor_index(version: str) -> int:
    """Month-index of a version: ``year*12 + (month-1)`` — horizon math."""
    year, month, _patch = version_tuple(version)
    return year * 12 + (month - 1)


@dataclass(frozen=True)
class TransitionReport:
    """Full classification of one old→new pack transition."""

    old_version: str
    new_version: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    #: ids with score-visible field movement (severity/weight/capability/…).
    material_changed: tuple[str, ...]
    #: ids whose non-material prose moved (title/remediation/detection text,
    #: tags, fixtures, origin) — recorded, NOT gated (§15 names only the
    #: material classes; silent drift stays visible here for reviewers).
    prose_changed: tuple[str, ...]
    #: ids newly marked deprecated in this transition.
    newly_deprecated: tuple[str, ...]
    violations: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary_line(self) -> str:
        """One-line human verdict used by CI logs and the verify verb."""
        bits = [f"{self.old_version} → {self.new_version}"]
        if self.added:
            bits.append(f"+{len(self.added)} rules")
        if self.removed:
            bits.append(f"-{len(self.removed)} removed")
        if self.material_changed:
            bits.append(f"~{len(self.material_changed)} material")
        if self.newly_deprecated:
            bits.append(f"dep:{','.join(self.newly_deprecated)}")
        return " · ".join(bits)


def _rule_signature(rule: Rule) -> dict[str, Any]:
    """Material + prose fields relevant to diffing (pure data view)."""
    return {
        "status": rule.status,
        "severity": rule.severity,
        "weight": rule.weight,
        "capability": rule.capability,
        "engine": rule.engine,
        "evidence_kind": rule.evidence_kind,
        "confidence_default": rule.confidence_default,
        "title": rule.title,
        "remediation": rule.remediation,
        "detection": rule.detection,
        "static_only": rule.static_only,
    }


def _head_entry(pack: RulePack) -> dict[str, Any] | None:
    return pack.changelog[0] if pack.changelog else None


def _rationale_text(entry: dict[str, Any]) -> str:
    """Joined rationale strings from a changelog entry ('' when absent)."""
    raw = entry.get("rationale")
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return "\n".join(str(item) for item in raw)
    return str(raw)


def classify(old: RulePack, new: RulePack) -> TransitionReport:
    """Diff two packs into a :class:`TransitionReport` WITHOUT enforcing.

    Enforcement lives in :func:`enforce` so tools can display the full
    classification even when they intend to fail.
    """
    old_by_id = {rule.id: rule for rule in old.rules}
    new_by_id = {rule.id: rule for rule in new.rules}
    added = tuple(sorted(set(new_by_id) - set(old_by_id)))
    removed = tuple(sorted(set(old_by_id) - set(new_by_id)))
    material: list[str] = []
    prose: list[str] = []
    newly_deprecated: list[str] = []
    for rule_id in sorted(set(old_by_id) & set(new_by_id)):
        was, now = old_by_id[rule_id], new_by_id[rule_id]
        old_sig, new_sig = _rule_signature(was), _rule_signature(now)
        moved_material = any(old_sig[f] != new_sig[f] for f in MATERIAL_FIELDS)
        if moved_material:
            material.append(rule_id)
        elif old_sig != new_sig:
            prose.append(rule_id)
        if was.status != "deprecated" and now.status == "deprecated":
            newly_deprecated.append(rule_id)
    return TransitionReport(
        old_version=old.version,
        new_version=new.version,
        added=added,
        removed=removed,
        material_changed=tuple(material),
        prose_changed=tuple(prose),
        newly_deprecated=tuple(sorted(newly_deprecated)),
    )


def enforce(old: RulePack, new: RulePack) -> TransitionReport:
    """Classify AND gate the transition; raises :class:`PackVerError`.

    Violations accumulate (every reason reported in one pass — CI shows the
    full repair list, not whack-a-mole).
    """
    report = classify(old, new)
    v: list[str] = []

    # R0 — versions parse (loader validates format too; double-check here so
    # hand-built packs in tests cannot dodge the arithmetic below).
    try:
        old_t = version_tuple(old.version)
        new_t = version_tuple(new.version)
    except ValueError as exc:
        v.append(f"unparsable pack version: {exc}")
        raise PackVerError(v) from exc

    # R1 — any actual content change requires a strictly advancing version
    # (a byte-identical no-op is legal; CI never even invokes the governor
    # for it). Everything below keys off the classified deltas.
    content_unchanged = (
        old.content_checksum() == new.content_checksum()
        and old.spec_version == new.spec_version
    )
    anything_changed = bool(
        report.added
        or report.removed
        or report.material_changed
        or report.prose_changed
        or report.newly_deprecated
    )
    if not content_unchanged and not anything_changed:
        # Byte drift outside rule semantics (e.g. description/pack.yaml meta)
        # still counts as a change worth naming.
        anything_changed = True
    if anything_changed and new_t <= old_t:
        v.append(
            f"pack version did not advance: {old.version} → {new.version} "
            "(§15 requires a strictly greater YYYY.MM.N whenever pack content "
            "changes)"
        )

    bumped_minor_or_more = minor_index(new.version) > minor_index(old.version)
    head = _head_entry(new)
    affected = sorted(set(report.material_changed) | set(report.removed))

    # R2 — material changes require a minor-or-greater bump …
    if affected and not bumped_minor_or_more:
        v.append(
            f"score-visible change(s) {', '.join(affected)} require a MINOR bump "
            "(YYYY.MM patch may not change detection outcomes; §15)"
        )

    # R3 — … plus a head changelog entry AT the new version carrying a
    # rationale naming every affected id.
    if affected:
        if head is None:
            v.append("new pack declares no changelog entries (§15 requires one)")
        else:
            head_version = str(head.get("version", ""))
            if head_version != new.version:
                v.append(
                    f"changelog head entry is {head_version!r}, expected the new "
                    f"pack version {new.version!r} (changelog discipline)"
                )
            rationale = _rationale_text(head)
            notes_text = "\n".join(str(note) for note in head.get("notes") or [])
            missing = [
                rid for rid in affected if rid not in rationale and rid not in notes_text
            ]
            if not rationale:
                v.append(
                    "minor bump without changelog rationale: head entry needs a "
                    "'rationale' field explaining the score-visible change(s) "
                    f"({', '.join(affected)}; §15)"
                )
            elif missing:
                v.append(
                    "changelog rationale does not name affected rule(s): "
                    + ", ".join(missing)
                )

    # R4 — removals: deprecated ≥2 minors ago AND shipped deprecated since.
    for rule_id in report.removed:
        was = next(r for r in old.rules if r.id == rule_id)
        if was.status != "deprecated":
            v.append(
                f"rule {rule_id} REMOVED while still {was.status!r} — retire via "
                "deprecated first (§15 lifecycle active→deprecated→removed)"
            )
        elif not was.deprecated_since:
            v.append(
                f"rule {rule_id} removed but its deprecation never recorded a "
                "'deprecated_since' version — removal horizon unverifiable"
            )
        else:
            try:
                gap = minor_index(new.version) - minor_index(was.deprecated_since)
            except ValueError:
                v.append(f"rule {rule_id} has unparsable deprecated_since {was.deprecated_since!r}")
                continue
            if gap < REMOVAL_HORIZON_MINORS:
                v.append(
                    f"rule {rule_id} removed after {gap} minor release(s) since "
                    f"deprecation ({was.deprecated_since}) — horizon is "
                    f">={REMOVAL_HORIZON_MINORS} minors (§15)"
                )

    # R5 — new deprecations must stamp their horizon start.
    for rule_id in report.newly_deprecated:
        now = next(r for r in new.rules if r.id == rule_id)
        if not now.deprecated_since:
            v.append(
                f"rule {rule_id} marked deprecated without 'deprecated_since' — "
                "stamp the retiring version so the removal horizon is computable"
            )
        elif minor_index(now.deprecated_since) > minor_index(new.version):
            v.append(
                f"rule {rule_id} 'deprecated_since' {now.deprecated_since!r} lies in "
                f"the future relative to pack {new.version}"
            )

    # R6 — schema breaks are refuse-to-load territory (loader pins
    # spec_version; a mismatched pack never reaches scoring). Reported as a
    # violation so CI flags it at DIFF time rather than load time.
    if old.spec_version != new.spec_version:
        v.append(
            f"spec_version changed {old.spec_version!r} → {new.spec_version!r}: "
            "IR/schema break = MAJOR bump territory; current loaders refuse "
            "non-current packs outright (D-RULEOWN)"
        )

    final = replace(report, violations=tuple(v))
    if v:
        raise PackVerError(v)
    return final


__all__ = [
    "MATERIAL_FIELDS",
    "REMOVAL_HORIZON_MINORS",
    "PackVerError",
    "TransitionReport",
    "classify",
    "enforce",
    "minor_index",
    "version_tuple",
]
