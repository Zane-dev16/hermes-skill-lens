"""Rule-pack model, loader, and validation (SPEC §15 governance).

A rule pack is a directory holding ``pack.yaml`` (manifest) plus YAML rule
files (default subdirectory ``rules/``). Rules are pure DATA — detection
logic lives in engines; a rule declares *what* fires (id, capability,
severity, weight, evidence kind, confidence prior) so scores stay
recomputable (T3) and ``explain-rules`` can quote the math back.

Schema (minimal set satisfying SPEC §15 + §7 + scoring §8 inputs; pinned by
DECISIONS D-012):

    id: LNS-NET-011          # ^LNS-[A-Z]{2,4}-\\d{3}$, unique pack-wide
    title: str               # human line, rendered verbatim
    rule_version: "1"        # per-rule revision (§7 finding.rule_version)
    status: active           # draft|rc|active|deprecated|removed (§15)
    engine: netgraph         # must be in ENGINE_CATALOG (§4)
    capability: network.send # §9.1 family, optional ":" subpath
    severity: CRITICAL       # CRITICAL|HIGH|MEDIUM|LOW
    weight: 40               # int points, MUST equal tier first-occurrence
    evidence_kind: crossref  # ast|crossref|regex|manifest|unicode (§7)
    confidence_default: 0.88 # 0 < c <= 1 prior for the scorer
    static_only: false       # §7 modifier default for emitted findings
    tags: [...]              # free-form evidence tags
    remediation: str         # REQUIRED (§15)
    rationale: str           # REQUIRED (§15)
    detection: str           # REQUIRED detection spec for engine implementers
    origin: adapted-from ... # optional attribution (§15 O1)
    fixtures:                # REQUIRED >=1 positive + >=1 negative (§15);
      positive: [...]        # paths are repo-relative; existence is checked
      negative: [...]        # by verify_rule_fixtures(), never at load time

Validation law: structural faults (bad YAML, duplicate ids, unknown engine,
missing required fields, weight/tier drift) raise :class:`RulePackError` —
the loader sits on the exit-2 path (unreadable config), unlike scan-time
code which degrades to diagnostics. Unknown FIELDS warn-and-record and load
continues (host precedent, advisor-safest).

DETERMINISM LAW: rule files are parsed in sorted filename order; the pack's
rule tuple is sorted by id; no wall-clock values anywhere (changelog dates
are authored static text, not computed timestamps).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skill_lens.diagnostics import (
    Diagnostic,
    DiagnosticsCollector,
)

#: Stable diagnostic codes for the rule subsystem.
CODE_RULE_UNKNOWN_FIELD = "LNS-RULE-UNKNOWN-FIELD"
CODE_RULE_UNKNOWN_SUBPATH = "LNS-RULE-UNKNOWN-SUBPATH"
CODE_RULE_FIXTURE_MISSING = "LNS-RULE-FIXTURE-MISSING"
CODE_PACK_CHANGELOG_MISSING = "LNS-PACK-CHANGELOG-MISSING"

#: Version token carried by rule files themselves (schema evolution seam).
RULE_PACK_SPEC_VERSION = "rule-pack/1"

# -- closed vocabularies ------------------------------------------------------

#: The eight v0.9 engines (SPEC §4). Bindings referencing anything else are
#: structural errors — an engine typo must never silently silence a rule.
ENGINE_CATALOG: frozenset[str] = frozenset(
    {
        "manifest",
        "textinject",
        "shellscan",
        "pyscan",
        "jsscan",
        "netgraph",
        "secretscan",
        "depintel",
    }
)

#: Severity tiers, highest first (§8.2).
SEVERITY_TIERS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: First-occurrence weights per tier (§8.2 schedule). A rule's pinned weight
#: MUST equal its tier's entry here — drift breaks hand-recomputability.
TIER_FIRST_WEIGHT: dict[str, int] = {"CRITICAL": 40, "HIGH": 18, "MEDIUM": 7, "LOW": 2}

#: Evidence kinds (§7 table, normative).
EVIDENCE_KINDS: tuple[str, ...] = ("ast", "crossref", "regex", "manifest", "unicode")

#: Rule lifecycle states (§15). ``removed`` rules are deleted from packs,
#: never shipped with the flag set.
RULE_STATUSES: tuple[str, ...] = ("draft", "rc", "active", "deprecated")

#: Capability families (§9.1). Subpaths after ":" are tolerated freely
#: (unknown ones warn) so ontology growth never blocks older packs.
CAPABILITY_FAMILIES: frozenset[str] = frozenset(
    {
        "network.read",
        "network.send",
        "execute.shell",
        "execute.code",
        "filesystem.read",
        "filesystem.write",
        "filesystem.outside",
        "credentials.read",
        "secrets.exfil",
        "persistence",
        "surveillance",
        "money",
        "obfuscation",
        "integrity.override",
        "persona.write",
        "spawn.agent",
    }
)

RULE_ID_RE = re.compile(r"^LNS-[A-Z]{2,4}-[0-9]{3}$")
PACK_VERSION_RE = re.compile(r"^(\d{4})\.(\d{1,2})\.(\d+)$")


class RulePackError(Exception):
    """Structural rule-pack fault (exit-2 semantics, SPEC §18).

    Raised for unreadable/unparsable pack data, duplicate rule ids, unknown
    engine bindings, missing required fields, enum violations, and
    weight/severity drift. Never raised past a scan callback — loaders are
    configuration seams, not observer hooks.
    """


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One detection rule (pure data; engines consume, scorer prices)."""

    id: str
    title: str
    rule_version: str
    status: str
    engine: str
    capability_family: str
    capability_subpath: str | None
    severity: str
    weight: int
    evidence_kind: str
    confidence_default: float
    static_only: bool
    tags: tuple[str, ...]
    remediation: str
    rationale: str
    detection: str
    origin: str | None
    fixtures_positive: tuple[str, ...]
    fixtures_negative: tuple[str, ...]
    source_path: str  # display label of the YAML file it came from

    @property
    def capability(self) -> str:
        """Full capability string incl. subpath (e.g. ``spawn.agent:skill_ref``)."""
        if self.capability_subpath:
            return f"{self.capability_family}:{self.capability_subpath}"
        return self.capability_family

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe mapping (canonical dumps apply sort_keys upstream)."""
        return {
            "id": self.id,
            "title": self.title,
            "rule_version": self.rule_version,
            "status": self.status,
            "engine": self.engine,
            "capability": self.capability,
            "severity": self.severity,
            "weight": self.weight,
            "evidence_kind": self.evidence_kind,
            "confidence_default": self.confidence_default,
            "static_only": self.static_only,
            "tags": list(self.tags),
            "remediation": self.remediation,
            "rationale": self.rationale,
            "detection": self.detection,
            "origin": self.origin,
            "fixtures_positive": list(self.fixtures_positive),
            "fixtures_negative": list(self.fixtures_negative),
            "source_path": self.source_path,
        }


@dataclass(frozen=True)
class RulePack:
    """A loaded rule pack: manifest metadata plus sorted immutable rules."""

    name: str
    version: str
    spec_version: str
    description: str
    changelog: tuple[dict[str, Any], ...]
    rules: tuple[Rule, ...]  # sorted by id
    source_label: str
    _file_inputs: tuple[tuple[str, bytes], ...] = field(repr=False)

    def rule_by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def rules_by_engine(self) -> dict[str, tuple[Rule, ...]]:
        """Rules grouped by engine binding, groups and members sorted."""
        grouped: dict[str, list[Rule]] = {}
        for rule in self.rules:
            grouped.setdefault(rule.engine, []).append(rule)
        return {
            engine: tuple(sorted(rules, key=lambda r: r.id))
            for engine, rules in sorted(grouped.items())
        }

    def content_checksum(self) -> str:
        """Deterministic ``sha256:<hex>`` over sorted ``(name, file_bytes)``.

        Mirrors the bundle-hash recipe (D-HASH) so doctor/verify (Phase 5)
        and release artifacts can pin pack bytes without re-parsing YAML.
        """
        digest = hashlib.sha256()
        for name, data in sorted(self._file_inputs, key=lambda item: item[0]):
            digest.update(name.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
        return "sha256:" + digest.hexdigest()

    def active_rules(self) -> tuple[Rule, ...]:
        return tuple(rule for rule in self.rules if rule.status == "active")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _yaml_safe_load(text: str, *, where: str) -> Any:
    """Parse YAML or raise :class:`RulePackError` (config-path semantics)."""
    try:
        import yaml  # lazy: keeps the default import closure stdlib-only
    except ImportError as exc:  # pragma: no cover — PyYAML is declared dep
        raise RulePackError(f"PyYAML unavailable; cannot load rule pack: {exc}") from exc
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 — any parser fault is structural
        first_line = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        raise RulePackError(f"{where}: YAML parse failed: {first_line[:200]}") from exc


def _require_str(mapping: dict[str, Any], key: str, *, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RulePackError(f"{where}: field {key!r} is required and must be a non-empty string")
    return value


_CORE_PACK_DIR = "core"


def core_pack_path() -> Path:
    """Filesystem path of the embedded core pack (package data, offline)."""
    from importlib.resources import files

    return Path(str(files("skill_lens") / "rules" / _CORE_PACK_DIR))


def load_core_pack(
    *,
    diagnostics: DiagnosticsCollector | None = None,
) -> RulePack:
    """Load the embedded ``core`` pack from package data — zero network."""
    return load_pack(core_pack_path(), diagnostics=diagnostics)


def load_pack(
    path: Path | str,
    *,
    diagnostics: DiagnosticsCollector | None = None,
) -> RulePack:
    """Load and validate a rule pack directory.

    Structural faults raise :class:`RulePackError`; unknown fields produce
    warning diagnostics on the supplied (or fresh) collector and loading
    continues. Output is fully deterministic: sorted traversal, id-sorted
    rules, insertion-ordered diagnostics.
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    root = Path(path)
    if not root.is_dir():
        raise RulePackError(f"rule pack directory not found: {root}")

    pack_yaml_path = root / "pack.yaml"
    try:
        pack_text = pack_yaml_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RulePackError(f"pack.yaml unreadable: {exc.strerror}") from exc
    file_inputs: list[tuple[str, bytes]] = [("pack.yaml", pack_text.encode("utf-8"))]

    pack_meta = _yaml_safe_load(pack_text, where=str(pack_yaml_path))
    if not isinstance(pack_meta, dict):
        raise RulePackError("pack.yaml must be a mapping")
    _report_unknown_fields(
        pack_meta,
        known=_PACK_KNOWN_FIELDS,
        diags=diags,
        where="pack.yaml",
    )

    name = _require_str(pack_meta, "name", where="pack.yaml")
    version_raw = _require_str(pack_meta, "version", where="pack.yaml")
    _validate_pack_version(version_raw)
    spec_version = _require_str(pack_meta, "spec_version", where="pack.yaml")
    if spec_version != RULE_PACK_SPEC_VERSION:
        raise RulePackError(
            f"pack.yaml: unsupported spec_version {spec_version!r} "
            f"(expected {RULE_PACK_SPEC_VERSION!r})"
        )
    description = pack_meta.get("description", "")
    if not isinstance(description, str):
        raise RulePackError("pack.yaml: 'description' must be a string")

    changelog_raw = pack_meta.get("changelog")
    if not isinstance(changelog_raw, list) or not changelog_raw:
        # §15: "changelog required" — structural, but tolerate-with-warning
        # for third-party packs mid-authoring; our own packs always carry it.
        diags.warning(
            CODE_PACK_CHANGELOG_MISSING,
            "pack.yaml declares no changelog entries (SPEC §15 requires one)",
            path="pack.yaml",
        )
        changelog: tuple[dict[str, Any], ...] = ()
    else:
        changelog = tuple(
            dict(entry) if isinstance(entry, dict) else {"note": str(entry)}
            for entry in changelog_raw
        )

    rules_dir = pack_meta.get("rules_dir", "rules")
    if not isinstance(rules_dir, str) or not rules_dir:
        raise RulePackError("pack.yaml: 'rules_dir' must be a non-empty string")
    rules_root = root / rules_dir
    if not rules_root.is_dir():
        raise RulePackError(f"rule pack rules directory not found: {rules_root}")

    rule_files = sorted(p for p in rules_root.glob("*.yaml") if p.is_file())
    if not rule_files:
        raise RulePackError(f"rule pack contains no rule files: {rules_root}")

    rules: list[Rule] = []
    seen_ids: dict[str, str] = {}
    for rule_path in rule_files:
        rel_name = f"{rules_dir}/{rule_path.name}"
        try:
            text = rule_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RulePackError(f"rule file unreadable ({exc.strerror}): {rule_path}") from exc
        file_inputs.append((rel_name, text.encode("utf-8")))
        raw = _yaml_safe_load(text, where=str(rule_path))
        if not isinstance(raw, dict):
            raise RulePackError(f"{rule_path.name}: rule file must be a mapping")
        rule = _build_rule(raw, where=rel_name, diags=diags)
        if rule.id in seen_ids:
            raise RulePackError(
                f"duplicate rule id {rule.id!r} in {rel_name} "
                f"(first defined in {seen_ids[rule.id]})"
            )
        seen_ids[rule.id] = rel_name
        rules.append(rule)

    return RulePack(
        name=name,
        version=version_raw,
        spec_version=spec_version,
        description=description,
        changelog=changelog,
        rules=tuple(sorted(rules, key=lambda rule: rule.id)),
        source_label=str(root),
        _file_inputs=tuple(file_inputs),
    )


_PACK_KNOWN_FIELDS = frozenset(
    {"name", "version", "spec_version", "description", "changelog", "rules_dir"}
)


def _validate_pack_version(version: str) -> None:
    match = PACK_VERSION_RE.match(version)
    if match is None:
        raise RulePackError(f"pack.yaml: version {version!r} is not YYYY.MM.N semver (SPEC §15)")
    try:
        year, month, patch = (int(part) for part in match.groups())
    except ValueError:  # pragma: no cover — regex groups are digit-only
        raise RulePackError(f"pack.yaml: unparsable version components in {version!r}") from None
    if not 1 <= month <= 12:
        raise RulePackError(f"pack.yaml: version month out of range in {version!r}")
    if year < 2000 or patch < 0:
        raise RulePackError(f"pack.yaml: implausible version {version!r}")


def _report_unknown_fields(
    mapping: dict[str, Any],
    *,
    known: frozenset[str],
    diags: DiagnosticsCollector,
    where: str,
) -> None:
    """Warn-diagnostic per unknown field (tolerate-and-record, host style)."""
    for key in sorted(set(mapping) - known):
        diags.warning(
            CODE_RULE_UNKNOWN_FIELD,
            f"unknown field tolerated and recorded: {key}",
            path=where,
            detail={"key": str(key), "value_kind": type(mapping[key]).__name__},
        )


def _build_rule(
    raw: dict[str, Any],
    *,
    where: str,
    diags: DiagnosticsCollector,
) -> Rule:
    """Validate one rule mapping into a :class:`Rule`; faults are fatal."""
    _report_unknown_fields(raw, known=_RULE_KNOWN_FIELDS, diags=diags, where=where)

    rule_id = _require_str(raw, "id", where=where)
    if RULE_ID_RE.match(rule_id) is None:
        raise RulePackError(f"{where}: rule id {rule_id!r} does not match LNS-XXX-nnn scheme")
    title = _require_str(raw, "title", where=where)
    remediation = _require_str(raw, "remediation", where=where)
    rationale = _require_str(raw, "rationale", where=where)
    detection = _require_str(raw, "detection", where=where)

    rule_version = raw.get("rule_version", "1")
    if not isinstance(rule_version, str) or not rule_version.strip():
        raise RulePackError(f"{where}: 'rule_version' must be a non-empty string")

    status = raw.get("status", "draft")
    if status not in RULE_STATUSES:
        raise RulePackError(
            f"{where}: unknown status {status!r} (expected one of {', '.join(RULE_STATUSES)})"
        )

    engine = _require_str(raw, "engine", where=where)
    if engine not in ENGINE_CATALOG:
        raise RulePackError(
            f"{where}: rule {rule_id} references unknown engine {engine!r} "
            f"(catalog: {', '.join(sorted(ENGINE_CATALOG))})"
        )

    capability_raw = _require_str(raw, "capability", where=where)
    family, subpath = _split_capability(capability_raw)
    if family not in CAPABILITY_FAMILIES:
        raise RulePackError(
            f"{where}: rule {rule_id} declares unknown capability family {family!r} (§9.1)"
        )
    if subpath is not None and subpath not in KNOWN_CAPABILITY_SUBPATHS.get(family, ()):
        diags.warning(
            CODE_RULE_UNKNOWN_SUBPATH,
            f"unknown capability subpath tolerated: {capability_raw}",
            path=where,
            detail={"rule_id": rule_id},
        )

    severity = _require_str(raw, "severity", where=where)
    if severity not in SEVERITY_TIERS:
        raise RulePackError(
            f"{where}: rule {rule_id} has unknown severity {severity!r} "
            f"(tiers: {', '.join(SEVERITY_TIERS)})"
        )

    weight_raw = raw.get("weight")
    expected_weight = TIER_FIRST_WEIGHT[severity]
    if not isinstance(weight_raw, int) or isinstance(weight_raw, bool):
        raise RulePackError(f"{where}: rule {rule_id} must declare integer 'weight'")
    if weight_raw != expected_weight:
        raise RulePackError(
            f"{where}: rule {rule_id} weight {weight_raw} does not equal the "
            f"{severity} tier first-occurrence weight {expected_weight} (§8.2); "
            "scores must stay recomputable"
        )

    evidence_kind = _require_str(raw, "evidence_kind", where=where)
    if evidence_kind not in EVIDENCE_KINDS:
        raise RulePackError(
            f"{where}: rule {rule_id} has unknown evidence_kind {evidence_kind!r} "
            f"(kinds: {', '.join(EVIDENCE_KINDS)})"
        )

    confidence_raw = raw.get("confidence_default")
    if not isinstance(confidence_raw, (int, float)) or isinstance(confidence_raw, bool):
        raise RulePackError(f"{where}: rule {rule_id} must declare numeric confidence_default")
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):  # pragma: no cover — guarded above
        raise RulePackError(
            f"{where}: rule {rule_id} must declare numeric confidence_default"
        ) from None
    if not 0.0 < confidence <= 1.0:
        raise RulePackError(
            f"{where}: rule {rule_id} confidence_default {confidence} outside (0, 1]"
        )

    static_only = raw.get("static_only", False)
    if not isinstance(static_only, bool):
        raise RulePackError(f"{where}: rule {rule_id} 'static_only' must be a boolean")

    tags_raw = raw.get("tags", [])
    if not isinstance(tags_raw, list) or not all(isinstance(t, str) for t in tags_raw):
        raise RulePackError(f"{where}: rule {rule_id} 'tags' must be a list of strings")

    origin_raw = raw.get("origin")
    if origin_raw is not None and not isinstance(origin_raw, str):
        raise RulePackError(f"{where}: rule {rule_id} 'origin' must be a string when present")

    fixtures_raw = raw.get("fixtures", {})
    positive, negative = _validate_fixtures(
        fixtures_raw, rule_id=rule_id, where=where, status=status
    )

    return Rule(
        id=rule_id,
        title=title,
        rule_version=rule_version,
        status=status,
        engine=engine,
        capability_family=family,
        capability_subpath=subpath,
        severity=severity,
        weight=weight_raw,
        evidence_kind=evidence_kind,
        confidence_default=confidence,
        static_only=static_only,
        tags=tuple(sorted(dict.fromkeys(tags_raw))),
        remediation=remediation,
        rationale=rationale,
        detection=detection,
        origin=origin_raw,
        fixtures_positive=positive,
        fixtures_negative=negative,
        source_path=where,
    )


_RULE_KNOWN_FIELDS = frozenset(
    {
        "id",
        "title",
        "rule_version",
        "status",
        "engine",
        "capability",
        "severity",
        "weight",
        "evidence_kind",
        "confidence_default",
        "static_only",
        "tags",
        "remediation",
        "rationale",
        "detection",
        "origin",
        "fixtures",
    }
)

#: Known sub-tags from §9.1 — unknown ones only warn (ontology growth).
KNOWN_CAPABILITY_SUBPATHS: dict[str, frozenset[str]] = {
    "network.send": frozenset({"messaging_human"}),
    "filesystem.read": frozenset({"cross_profile"}),
    "persistence": frozenset({"cron_json", "chronos"}),
    "integrity.override": frozenset({"control_plane"}),
    "persona.write": frozenset({"memory"}),
    "spawn.agent": frozenset({"skill_ref", "kanban", "cron_job", "subprocess_agent"}),
}


def _split_capability(capability: str) -> tuple[str, str | None]:
    family, sep, subpath = capability.partition(":")
    family = family.strip()
    if not sep:
        return family, None
    subpath = subpath.strip()
    if not family or not subpath:
        raise ValueError(f"malformed capability {capability!r}")
    return family, subpath


def _validate_fixtures(
    fixtures_raw: Any,
    *,
    rule_id: str,
    where: str,
    status: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Check the mandatory TP/FP fixture declarations (§15 merge blocker)."""
    if fixtures_raw is None:
        fixtures_raw = {}
    if not isinstance(fixtures_raw, dict):
        raise RulePackError(f"{where}: rule {rule_id} 'fixtures' must be a mapping")
    positive = fixtures_raw.get("positive", [])
    negative = fixtures_raw.get("negative", [])
    for label, entries in (("positive", positive), ("negative", negative)):
        if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
            raise RulePackError(
                f"{where}: rule {rule_id} fixtures.{label} must be a list of strings"
            )
    if status in ("rc", "active"):
        if not positive:
            raise RulePackError(
                f"{where}: {status} rule {rule_id} lacks a positive golden fixture (§15)"
            )
        if not negative:
            raise RulePackError(
                f"{where}: {status} rule {rule_id} lacks a benign negative fixture (§15); "
                "missing negatives block merge"
            )
    return tuple(positive), tuple(negative)


# ---------------------------------------------------------------------------
# Fixture existence verification (CI-side; never part of offline loading)
# ---------------------------------------------------------------------------


def verify_rule_fixtures(
    pack: RulePack,
    repo_root: Path | str,
    *,
    diagnostics: DiagnosticsCollector | None = None,
) -> tuple[Diagnostic, ...]:
    """Check every declared fixture path exists under *repo_root*.

    Separated from :func:`load_pack` deliberately: installed/embedded packs
    load offline without a corpus alongside them (D-RULEOWN), while CI runs
    this before merge — missing negatives block merge (§15).
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    root = Path(repo_root)
    for rule in pack.rules:
        for kind, refs in (
            ("positive", rule.fixtures_positive),
            ("negative", rule.fixtures_negative),
        ):
            for ref in refs:
                if not (root / ref).is_dir():
                    diags.warning(
                        CODE_RULE_FIXTURE_MISSING,
                        f"rule {rule.id} declares missing {kind} fixture: {ref}",
                        path=rule.source_path,
                        detail={"rule_id": rule.id, "fixture": ref, "kind": kind},
                    )
    return diags.snapshot()


# ---------------------------------------------------------------------------
# Convenience accessor used by surfaces that only need lookup callables
# ---------------------------------------------------------------------------


def rule_lookup(pack: RulePack) -> Callable[[str], Rule | None]:
    """Stable id→Rule resolver closure (renderers, explain-rules)."""
    index = {rule.id: rule for rule in pack.rules}
    return index.get
