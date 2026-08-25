"""E1 manifest engine — frontmatter/metadata integrity (SPEC §4 row E1).

Structural facts only: agentskills.io-style permission/visibility fields,
Hermes ``metadata.hermes`` dialect abuse (unknown keys, category mismatch,
sensitive install-time config), skill-chaining declarations, and the
claims-stage vague-description rule whose ownership transfers here
unchanged (DECISIONS D-020 — implemented by delegating to the exact claims
detector, so behavior is byte-identical across the transfer).

All rules bind evidence_kind ``manifest`` (structural band, confidence
0.90-1.00 per SPEC §7) and cap at LOW-MEDIUM severity; heuristics never
inflate (D-FP). Required-field presence and name/dirname consistency ship
as pure hooks (:func:`required_field_gaps`, :func:`name_dirname_consistent`)
for future rule ids — no core-pack rule carries them yet, so the engine
emits NO findings for them (advisor-safest: never invent detections).

Evidence lines resolve from the real SKILL.md text via :class:`ScanContext`
when available; without context, spans degrade to path-only (line
``None``) honestly. Fingerprints normalize field/key names and value
SHAPES only — never line numbers, never absolute paths (SPEC §7/D-HASH).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from glob import escape as _glob_escape
from typing import TYPE_CHECKING, Any

from skill_lens.claims import vague_description_finding
from skill_lens.engines.base import (
    Finding,
    Location,
    ScanContext,
    finding_sort_key,
    manifest_rel_path,
    read_skill_md_text,
)
from skill_lens.ir import LAYOUT_CATEGORIZED, SkillIR

if TYPE_CHECKING:  # data-only module; runtime code never needs Rule objects
    from collections.abc import Iterable

    from skill_lens.rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "manifest"

#: Rules implemented here — pack rules bound to ``manifest`` but missing
#: from this tuple surface as LNS-ENG-001 diagnostics (never silence).
RULE_IDS: tuple[str, ...] = (
    "LNS-MAN-001",
    "LNS-MAN-002",
    "LNS-MAN-003",
    "LNS-MAN-004",
    "LNS-MAN-005",
    "LNS-MAN-007",
)

# -- detection vocabulary -----------------------------------------------------

#: MAN-001 generic permission-bypass field names (rule detection verbatim).
_BYPASS_KEY_RE = re.compile(r"(?i)(bypass|skip|disable)[-_]?(permission|approval|confirm)")

#: MAN-001 extension per Phase-1 task scope: persona/SOUL override markers
#: declared in frontmatter fields (DECISIONS D-023). Same truthy-value gate.
_PERSONA_OVERRIDE_KEY_RE = re.compile(
    r"^(?:persona|soul)[-_]?(?:override|overwrite|hijack|replace|write)$",
    re.IGNORECASE,
)

_SECRETISH_KEY_RE = re.compile(r"(?i)(api[_-]?key|token|secret|credential|password)")

_TRUTHY_STRINGS = frozenset({"true", "yes", "on", "1"})
_FALSY_STRING_VALUES = frozenset({"false", "no", "off", "0", "none", "null"})

#: MAN-007 sensitive config namespaces/segments (rule detection verbatim).
_SENSITIVE_SEGMENT_RE = re.compile(
    r"(?i)(approve|permission|allow|deny|platform|disabled|api[_-]?key|token|secret|credential)"
)
_RESERVED_CONFIG_PREFIXES: tuple[str, ...] = ("plugins.entries.", "security.", "hooks.")
_RESERVED_CONFIG_EXACT = frozenset({"plugins.entries", "security", "hooks"})

_SNIPPET_MAX = 160


def required_field_gaps(frontmatter: Any) -> tuple[str, ...]:
    """Hook: required frontmatter fields absent from *frontmatter*.

    Sorted, stable. The agentskills-style minimum is ``name`` +
    ``description``; ingest already tolerates their absence with validation
    errors, and no core-pack rule consumes this yet (future-rule hook only,
    DECISIONS D-023) — the engine emits nothing from it today.
    """
    gaps: list[str] = []
    if not getattr(frontmatter, "name", "").strip():
        gaps.append("name")
    if not getattr(frontmatter, "description_raw", "").strip():
        gaps.append("description")
    return tuple(sorted(gaps))


def name_dirname_consistent(frontmatter_name: str, dirname: str) -> bool:
    """Hook: does the declared ``name`` match the bundle directory name?

    Exact-case comparison (host behavior is case-sensitive); ingest already
    records mismatches as diagnostics. No core-pack rule consumes this yet
    (future-rule hook only, DECISIONS D-023).
    """
    return frontmatter_name.strip() == dirname.strip()


class ManifestEngine:
    """E1 implementation — pure structural checks over the typed IR."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}

    # -- entry point ----------------------------------------------------------

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        frontmatter = bundle_ir.frontmatter
        if frontmatter is None:
            return []

        text = read_skill_md_text(bundle_ir, ctx)
        locator = _FrontmatterLocator(text)
        manifest_path = manifest_rel_path(bundle_ir)

        findings: list[Finding] = []
        rule = self._rules.get("LNS-MAN-001")
        if rule is not None:
            findings.extend(self._man001(frontmatter, rule, locator, manifest_path))
        rule = self._rules.get("LNS-MAN-002")
        if rule is not None and frontmatter.hermes is not None:
            findings.extend(
                self._man002(frontmatter.hermes.unknown_fields, rule, locator, manifest_path)
            )
        rule = self._rules.get("LNS-MAN-003")
        if rule is not None:
            finding = self._man003(bundle_ir, frontmatter, rule, locator, manifest_path)
            if finding is not None:
                findings.append(finding)
        rule = self._rules.get("LNS-MAN-004")
        if rule is not None:
            finding = self._man004(frontmatter, rule, manifest_path)
            if finding is not None:
                findings.append(finding)
        rule = self._rules.get("LNS-MAN-005")
        if rule is not None and frontmatter.hermes is not None:
            findings.extend(
                self._man005(
                    bundle_ir,
                    frontmatter.hermes.related_skills,
                    rule,
                    locator,
                    manifest_path,
                    ctx,
                )
            )
        rule = self._rules.get("LNS-MAN-007")
        if rule is not None and frontmatter.hermes is not None:
            findings.extend(self._man007(frontmatter.hermes.config, rule, locator, manifest_path))

        findings.sort(key=finding_sort_key)
        return findings

    # -- LNS-MAN-001 ----------------------------------------------------------

    def _man001(
        self,
        frontmatter: Any,
        rule: Rule,
        locator: _FrontmatterLocator,
        manifest_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        candidates: list[tuple[str, Any]] = [
            *sorted(frontmatter.unknown_fields.items()),
            *sorted(frontmatter.vendor_fields.items()),
        ]
        seen_keys: set[str] = set()
        for key, value in candidates:
            normalized_key = key.strip().lower()
            if normalized_key in seen_keys or not _man001_matches(normalized_key, value):
                continue
            seen_keys.add(normalized_key)
            line = locator.find_field_line(key)
            raw_snippet = locator.line_text(line)
            secretish = bool(_SECRETISH_KEY_RE.search(normalized_key))
            snippet, redacted = _evidence_line(raw_snippet, secretish=secretish)
            findings.append(
                Finding(
                    fingerprint=_fp(rule, f"{normalized_key}={_norm_scalar(value)}"),
                    rule_id=rule.id,
                    rule_version=rule.rule_version,
                    engine=rule.engine,
                    title=rule.title,
                    capability=rule.capability,
                    severity=rule.severity,
                    effective_severity=rule.severity,
                    confidence=rule.confidence_default,
                    evidence_kind=rule.evidence_kind,
                    static_only=rule.static_only,
                    location=Location(
                        path=manifest_path,
                        start_line=line,
                        end_line=line,
                        snippet=snippet,
                        redacted=redacted,
                    ),
                    message=(
                        f"frontmatter field '{key}' overrides invocation "
                        "permissions or hides the skill"
                    ),
                    remediation=rule.remediation,
                    tags=tuple(rule.tags),
                )
            )
        return findings

    # -- LNS-MAN-002 ----------------------------------------------------------

    def _man002(
        self,
        unknown_fields: Mapping[str, Any],
        rule: Rule,
        locator: _FrontmatterLocator,
        manifest_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key in sorted(unknown_fields):
            normalized_key = key.strip().lower()
            # Fingerprint binds ONLY the key name (rule detection: values may
            # be secret-bearing and must never widen the redaction surface).
            line = locator.find_field_line(key, hermes_nested=True)
            raw_snippet = locator.line_text(line)
            snippet, redacted = _evidence_line(raw_snippet, secretish=True)
            findings.append(
                Finding(
                    fingerprint=_fp(rule, normalized_key),
                    rule_id=rule.id,
                    rule_version=rule.rule_version,
                    engine=rule.engine,
                    title=rule.title,
                    capability=rule.capability,
                    severity=rule.severity,
                    effective_severity=rule.severity,
                    confidence=rule.confidence_default,
                    evidence_kind=rule.evidence_kind,
                    static_only=rule.static_only,
                    location=Location(
                        path=manifest_path,
                        start_line=line,
                        end_line=line,
                        snippet=snippet,
                        redacted=redacted,
                    ),
                    message=f"unknown key '{key}' inside metadata.hermes",
                    remediation=rule.remediation,
                    tags=tuple(rule.tags),
                )
            )
        return findings

    # -- LNS-MAN-003 ----------------------------------------------------------

    def _man003(
        self,
        bundle_ir: SkillIR,
        frontmatter: Any,
        rule: Rule,
        locator: _FrontmatterLocator,
        manifest_path: str,
    ) -> Finding | None:
        hermes = frontmatter.hermes
        if hermes is None or hermes.category is None:
            return None
        if bundle_ir.identity.layout != LAYOUT_CATEGORIZED or not bundle_ir.identity.category:
            return None  # flat/single-file layouts have no authoritative dir category
        declared = hermes.category.strip().lower()
        installed = bundle_ir.identity.category.strip().lower()
        if declared == installed:
            return None
        return Finding(
            fingerprint=_fp(rule, f"{declared}!={installed}"),
            rule_id=rule.id,
            rule_version=rule.rule_version,
            engine=rule.engine,
            title=rule.title,
            capability=rule.capability,
            severity=rule.severity,
            effective_severity=rule.severity,
            confidence=rule.confidence_default,
            evidence_kind=rule.evidence_kind,
            static_only=rule.static_only,
            location=Location(
                path=manifest_path,
                start_line=locator.find_category_line(),
                end_line=None,
                snippet=(f"category: {hermes.category}")[:_SNIPPET_MAX],
                redacted=False,
            ),
            message=(
                f"declared category '{hermes.category}' does not match install "
                f"directory category '{bundle_ir.identity.category}'"
            ),
            remediation=rule.remediation,
            tags=tuple(rule.tags),
        )

    # -- LNS-MAN-004 (ownership transferred unchanged, D-020) -----------------

    def _man004(self, frontmatter: Any, rule: Rule, manifest_path: str) -> Finding | None:
        produced = vague_description_finding(
            frontmatter,
            rule,
            manifest_path=manifest_path,
            description_line=getattr(frontmatter, "description_line", None),
        )
        if produced is None:
            return None
        return Finding.from_dict(produced)

    # -- LNS-MAN-005 ----------------------------------------------------------

    def _man005(
        self,
        bundle_ir: SkillIR,
        related_skills: tuple[str, ...],
        rule: Rule,
        locator: _FrontmatterLocator,
        manifest_path: str,
        ctx: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for ref in related_skills:
            name = ref.strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            if _skill_reference_resolves(ctx.skills_root, name):
                continue
            line = locator.find_list_item_line("related_skills", name)
            findings.append(
                Finding(
                    # Fingerprint binds the referenced NAME so fixing one
                    # entry clears one finding without shifting others.
                    fingerprint=_fp(rule, name.lower()),
                    rule_id=rule.id,
                    rule_version=rule.rule_version,
                    engine=rule.engine,
                    title=rule.title,
                    capability=rule.capability,
                    severity=rule.severity,
                    effective_severity=rule.severity,
                    confidence=rule.confidence_default,
                    evidence_kind=rule.evidence_kind,
                    static_only=rule.static_only,
                    location=Location(
                        path=manifest_path,
                        start_line=line,
                        end_line=line,
                        snippet=(f"- {name}")[:_SNIPPET_MAX],
                        redacted=False,
                    ),
                    message=(
                        f"related_skills reference '{name}' resolves to no "
                        "installed skill in the scanned tree"
                    ),
                    remediation=rule.remediation,
                    tags=tuple(rule.tags),
                )
            )
        del bundle_ir
        return findings

    # -- LNS-MAN-007 ----------------------------------------------------------

    def _man007(
        self,
        config: Mapping[str, Any],
        rule: Rule,
        locator: _FrontmatterLocator,
        manifest_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key in sorted(config):
            lowered = key.strip().lower()
            segments = [segment.strip() for segment in lowered.split(".")]
            offending_segment = next(
                (segment for segment in segments if _SENSITIVE_SEGMENT_RE.search(segment)), None
            )
            reserved = lowered.startswith(_RESERVED_CONFIG_PREFIXES) or lowered in (
                _RESERVED_CONFIG_EXACT
            )
            if offending_segment is None and not reserved:
                continue
            detail = (
                f"sensitive segment '{offending_segment}'"
                if offending_segment is not None
                else "reserved Hermes namespace"
            )
            line = locator.find_config_key_line(key)
            findings.append(
                Finding(
                    fingerprint=_fp(rule, lowered),
                    rule_id=rule.id,
                    rule_version=rule.rule_version,
                    engine=rule.engine,
                    title=rule.title,
                    capability=rule.capability,
                    severity=rule.severity,
                    effective_severity=rule.severity,
                    confidence=rule.confidence_default,
                    evidence_kind=rule.evidence_kind,
                    static_only=rule.static_only,
                    location=Location(
                        path=manifest_path,
                        start_line=line,
                        end_line=line,
                        snippet=(f"{key}: <install-time config>")[:_SNIPPET_MAX],
                        redacted=True,
                    ),
                    message=(
                        f"config key '{key}' targets a sensitive settings namespace ({detail})"
                    ),
                    remediation=rule.remediation,
                    tags=tuple(rule.tags),
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Detection predicates + shared helpers (module-level = unit-testable)
# ---------------------------------------------------------------------------


def _man001_matches(normalized_key: str, value: Any) -> bool:
    """Rule detection table for LNS-MAN-001 (verbatim + D-023 extension)."""
    if normalized_key == "disable-model-invocation":
        return _truthy(value)
    if normalized_key == "user-invocable":
        return _explicit_false(value)
    if normalized_key == "context":
        return isinstance(value, str) and value.strip().lower() == "fork"
    if _BYPASS_KEY_RE.search(normalized_key):
        return _truthy(value)
    if _PERSONA_OVERRIDE_KEY_RE.match(normalized_key):
        return _truthy(value)
    return False


def _truthy(value: Any) -> bool:
    """Truthy per YAML-ish intuition: booleans, true-ish strings, 1."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUTHY_STRINGS
    if isinstance(value, int):
        return value == 1
    return False


def _explicit_false(value: Any) -> bool:
    """MAN-001's ``user-invocable: false`` fires on an explicit FALSE."""
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "no", "off"}
    return False


def _norm_scalar(value: Any) -> str:
    """Value SHAPE for fingerprints — collapsed, lowercased, bounded."""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = " ".join(str(value).split()).lower()
    return text[:64]


def _skill_reference_resolves(skills_root: Any, name: str) -> bool:
    """Does ``<skills>/**/<name>/SKILL.md`` exist (any category)?

    Flat placement checked first, then any category level; deterministic
    candidate order and glob-metacharacter-safe via :func:`glob.escape`.
    Path-traversal shapes (``..``, separators, dot-names) never resolve.
    Without a skills tree every reference counts as unresolved — exactly
    the single-bundle fallback the rule detection specifies.
    """
    if skills_root is None:
        return False
    if "/" in name or "\\" in name or name in (".", "..") or name.startswith("."):
        return False
    escaped = _glob_escape(name)
    try:
        direct = (skills_root / name / "SKILL.md").is_file()
        nested = any(match.is_file() for match in sorted(skills_root.glob(f"*/{escaped}/SKILL.md")))
    except OSError:  # pragma: no cover — unreadable tree degrades to unresolved
        return False
    return direct or nested


def _fp(rule: Rule, normalized_evidence: str) -> str:
    from skill_lens.claims import finding_fingerprint

    return finding_fingerprint(rule.id, rule.capability, normalized_evidence)


def _evidence_line(raw_line: str | None, *, secretish: bool) -> tuple[str, bool]:
    """Surface-safe snippet from a raw frontmatter line.

    Secret-bearing keys get their value masked (privacy law: secrets are
    never rendered unredacted); ordinary structural lines pass through
    bounded. Returns ``(snippet, redacted)``.
    """
    if raw_line is None:
        return "", False
    line = raw_line.strip()
    if secretish and ":" in line:
        head, _, _value = line.partition(":")
        return f"{head}: <redacted>"[:_SNIPPET_MAX], True
    return line[:_SNIPPET_MAX], False


class _FrontmatterLocator:
    """Line resolver over the delimited frontmatter block (pure, tolerant).

    All searches bound to the ``---`` block so body prose can never
    mislocate evidence. Without text every lookup yields ``None``.
    """

    def __init__(self, text: str | None) -> None:
        lines = text.splitlines() if text is not None else []
        end = len(lines)
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                end = idx
                break
        has_block = bool(lines) and lines[0].strip() == "---" and end > 0
        self._lines: tuple[str, ...] = tuple(lines[:end]) if has_block else ()
        self._hermes_anchor: int | None = self._find_prefix("hermes:")

    def _find_prefix(self, prefix: str) -> int | None:
        for idx, line in enumerate(self._lines, start=1):
            if line.strip().startswith(prefix):
                return idx
        return None

    def find_field_line(self, key: str, *, hermes_nested: bool = False) -> int | None:
        """Line whose stripped form starts with ``key:`` inside the block.

        ``hermes_nested`` restricts the search to the window after the
        ``hermes:`` anchor so a same-named top-level field cannot shadow it.
        """
        if not self._lines:
            return None
        start = 1
        if hermes_nested:
            if self._hermes_anchor is None:
                return None
            start = self._hermes_anchor
        target = f"{key}:"
        for idx in range(start, len(self._lines) + 1):
            stripped = self._lines[idx - 1].strip()
            if stripped.startswith(target):
                return idx
        return None

    def find_category_line(self) -> int | None:
        """First ``category:`` line at hermes nesting depth."""
        if self._hermes_anchor is not None:
            nested = self.find_field_line("category", hermes_nested=True)
            if nested is not None:
                return nested
        return self.find_field_line("category")

    def find_config_key_line(self, key: str) -> int | None:
        """Line of a ``config:`` child key (dot-path aware display form)."""
        config_anchor = self.find_field_line("config", hermes_nested=True)
        if config_anchor is None:
            return self.find_field_line(key)
        leaf = key.rsplit(".", 1)[-1]
        for idx in range(config_anchor + 1, len(self._lines) + 1):
            line = self._lines[idx - 1]
            stripped = line.strip()
            if idx > config_anchor + 1 and stripped and not line[:1].isspace():
                break  # left the config block
            if stripped.startswith(f"{leaf}:"):
                return idx
        return self.find_field_line(leaf, hermes_nested=True)

    def find_list_item_line(self, anchor_key: str, item: str) -> int | None:
        """Line of ``- item`` inside *anchor_key*'s indented block."""
        anchor = self.find_field_line(anchor_key, hermes_nested=True)
        if anchor is None:
            anchor = self.find_field_line(anchor_key)
        if anchor is None:
            return None
        for idx in range(anchor + 1, len(self._lines) + 1):
            line = self._lines[idx - 1]
            stripped = line.strip()
            if idx > anchor + 1 and stripped and not line[:1].isspace():
                break  # left the list block
            if stripped in (f"- {item}", f"-{item}") or stripped == item:
                return idx
        return None

    def line_text(self, line_number: int | None) -> str | None:
        if line_number is None or not self._lines:
            return None
        if 1 <= line_number <= len(self._lines):
            return self._lines[line_number - 1]
        return None


__all__ = [
    "ENGINE_NAME",
    "ManifestEngine",
    "RULE_IDS",
    "name_dirname_consistent",
    "required_field_gaps",
]
