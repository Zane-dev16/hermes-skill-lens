"""SkillIR — the typed, versioned intermediate representation (SPEC §5.2).

The IR is the single artifact every later stage reads: engines annotate it,
the scorer consumes findings derived from it, and ``lens map`` renders from
it. It is *serializable* (see :meth:`SkillIR.canonical_dict`) and versioned
under ``ir/1``; additive key growth stays inside ``ir/1``, renames/removals
bump the tool major version.

Laws honored here:

- **DETERMINISM**: no wall-clock values, no absolute host paths. Paths are
  stored exactly as given by the caller, which for Hermes-native targets
  means ``$HERMES_HOME``-normalized labels (e.g. ``~/.hermes/skills/...``);
  file paths are relative to the bundle root.
- **PRIVACY / advisor stance**: plain data only; nothing here executes,
  phones home, or blocks.
- **D-PROV (S7/R8)**: hub provenance is *annotation*. It is stored and
  rendered, and no scoring arithmetic may read it.

Unknown frontmatter fields are tolerated-and-recorded: they land verbatim in
the ``unknown_fields`` mapping of the owning section and a warning
:class:`~skill_lens.diagnostics.Diagnostic` is emitted via
:func:`report_unknown_fields`. Nothing crashes on junk input.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .diagnostics import (
    SEVERITY_WARNING,
    Diagnostic,
    DiagnosticsCollector,
)


def _render_overreach_section(claimed_paths: Iterable[str], actual_paths: Iterable[str]) -> str:
    """Lazy claims-module bridge (module-cycle safety: claims imports ir)."""
    from .claims import render_overreach_section

    return render_overreach_section(claimed_paths, actual_paths)


#: Version pinned to SPEC §5.2. Breaking changes bump the tool major version.
IR_SPEC_VERSION = "ir/1"

#: Tool name embedded in the IR ``tool`` block (NAMING LAW: CLI verb root).
TOOL_NAME = "lens"

# -- vocabulary constants (closed sets rendered as plain strings) ------------

SOURCE_DIR = "dir"
SOURCE_ZIP = "zip"
SOURCE_GIT = "git"
SOURCE_QUARANTINE = "quarantine"
SOURCE_KINDS: tuple[str, ...] = (SOURCE_DIR, SOURCE_ZIP, SOURCE_GIT, SOURCE_QUARANTINE)

#: Directory-layout kind of the bundle as observed at ingestion.
#: Not named by SPEC §5.2 — chosen advisor-safest (DECISIONS D-008).
LAYOUT_CATEGORIZED = "categorized"  # <category>/<name>/ under a skills root
LAYOUT_FLAT = "flat"  # <name>/ without a category level
LAYOUT_SINGLE_FILE = "single_file"  # one SKILL.md, no directory bundle
LAYOUTS: tuple[str, ...] = (LAYOUT_CATEGORIZED, LAYOUT_FLAT, LAYOUT_SINGLE_FILE)

ROLE_SCRIPT = "script"
ROLE_DOC = "doc"
ROLE_ASSET = "asset"
ROLE_REFERENCE = "reference"
ROLE_UNKNOWN = "unknown"
ROLES: tuple[str, ...] = (ROLE_SCRIPT, ROLE_DOC, ROLE_ASSET, ROLE_REFERENCE, ROLE_UNKNOWN)

PATH_LABEL_INSIDE_SKILL_ROOT = "inside_skill_root"
PATH_LABEL_AGENT_HOME_PREFIX = "agent_home:"
PATH_LABEL_OUTSIDE = "outside"

#: Lifecycle source classes (SPEC §5.1) — bounded, no URLs, no trust levels.
PROV_SOURCE_INSTALLED = "installed"
PROV_SOURCE_AGENT_CREATED = "agent_created"
PROV_SOURCE_EXTERNAL = "external"
PROV_SOURCE_LOCAL = "local"
PROV_SOURCE_UNKNOWN = "unknown"

PROV_RESOLVED_HUB_LOCK = "hub_lock"
PROV_RESOLVED_QUARANTINE_DIR = "quarantine_dir"
PROV_RESOLVED_LIFECYCLE_EVENT = "lifecycle_event"

#: Diagnostic code for tolerated-but-recorded unknown frontmatter fields.
CODE_FRONTMATTER_UNKNOWN = "LNS-FRONTMATTER-UNKNOWN"


def tool_version() -> str:
    """Package version for the IR ``tool`` block (lazy import avoids cycles)."""
    from . import __version__

    return __version__


# -- bundle identity ----------------------------------------------------------


@dataclass(frozen=True)
class BundleIdentity:
    """Who/where a scanned bundle is — display identity, not evidence.

    ``path`` is the path *as given* to the scanner. For Hermes-native
    targets callers must pass the ``$HERMES_HOME``-normalized label form
    (``~/.hermes/skills/<category>/<name>``); absolute host paths must never
    reach this field (DETERMINISM LAW).
    """

    name: str
    category: str | None = None
    path: str = ""
    layout: str = LAYOUT_FLAT


# -- provenance (annotation ONLY — never feeds arithmetic, D-PROV S7/R8) ------


@dataclass(frozen=True)
class Provenance:
    """Hub/lifecycle provenance annotations (SPEC §5.2 ``bundle.provenance``).

    Every field is optional; consumers must treat the whole object as
    descriptive metadata. No scoring, discounting, or ceiling logic may
    branch on any field here.
    """

    #: Lifecycle event class (§5.1): installed|agent_created|external|local|unknown.
    source_class: str | None = None
    identifier: str | None = None  # e.g. "@vercel-labs/agent-skills"
    trust_level: str | None = None  # trusted|null|community|builtin|agent-created
    resolved_from: str | None = None  # hub_lock|quarantine_dir|lifecycle_event|null
    install_path: str | None = None  # $HERMES_HOME-normalized label
    # Additive annotation-only enrichment fields straight from .hub/lock.json
    # (SPEC §5.1 names source/identifier/trust_level/content_hash/
    # scan_provenance as the enrichment set). ir/1-additive per DECISIONS
    # D-008/D-010; like every field here, NEVER read by scoring arithmetic.
    hub_source: str | None = None  # e.g. "official"|"github"|"clawhub"
    content_hash: str | None = None  # hub-recorded install-time hash
    scan_provenance: Mapping[str, Any] | None = None  # gate scan record, verbatim

    def __post_init__(self) -> None:
        if self.scan_provenance is not None:
            object.__setattr__(self, "scan_provenance", dict(self.scan_provenance))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_class": self.source_class,
            "identifier": self.identifier,
            "trust_level": self.trust_level,
            "resolved_from": self.resolved_from,
            "install_path": self.install_path,
            "hub_source": self.hub_source,
            "content_hash": self.content_hash,
            "scan_provenance": (
                dict(self.scan_provenance) if self.scan_provenance is not None else None
            ),
        }


# -- per-file records ---------------------------------------------------------


@dataclass(frozen=True)
class FileRecord:
    """One file in the bundle, with its hashing and decode outcomes.

    ``path`` is relative to the bundle root. ``encoding`` records the
    decode-as-data ladder outcome (e.g. ``utf-8``, ``utf-8-sig``,
    ``utf-16``, ``binary``); ``None`` means not yet determined (Phase 0
    shells carry it empty until the ingest walk lands).
    """

    path: str
    size: int = 0
    sha256: str | None = None  # "sha256:<hex>"
    encoding: str | None = None
    role: str = ROLE_UNKNOWN
    language: str | None = None
    decode_layers: tuple[str, ...] = ("raw",)
    path_labels: tuple[str, ...] = (PATH_LABEL_INSIDE_SKILL_ROOT,)
    partial: bool = False  # true when bounded projection was applied (>16 MiB)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
            "language": self.language,
            "encoding": self.encoding,
            "decode_layers": list(self.decode_layers),
            "path_labels": list(self.path_labels),
            "partial": self.partial,
        }


@dataclass(frozen=True)
class DecodedView:
    """A parallel decoded stream over one file (ghost text, NFC view, ...)."""

    file: str  # FileRecord.path this view belongs to
    view: str  # e.g. "ghost_text", "nfc", "base64@1"
    hidden_codepoint_count: int = 0
    blocks: tuple[str, ...] = ()  # e.g. ["U+E0000-U+E007F"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "view": self.view,
            "hidden_codepoint_count": self.hidden_codepoint_count,
            "blocks": list(self.blocks),
        }


# -- frontmatter (manifest section of the IR) ----------------------------------


@dataclass(frozen=True)
class HermesMetadata:
    """``metadata.hermes`` — kept verbatim-but-typed per SPEC §5.2."""

    tags: tuple[str, ...] = ()
    related_skills: tuple[str, ...] = ()  # unresolved refs flagged by E1 later
    category: str | None = None  # vs install dir — mismatch fires (E1)
    requires_toolsets: tuple[str, ...] = ()
    fallback_for_toolsets: tuple[str, ...] = ()
    requires_tools: tuple[str, ...] = ()
    fallback_for_tools: tuple[str, ...] = ()
    config: Mapping[str, Any] = field(default_factory=dict)  # install-time keys
    validation_errors: tuple[str, ...] = ()
    unknown_fields: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Defensive copies keep these frozen dataclasses honest about their
        # immutable contract even when callers pass mutable dicts.
        object.__setattr__(self, "config", dict(self.config))
        object.__setattr__(self, "unknown_fields", dict(self.unknown_fields))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tags": list(self.tags),
            "related_skills": list(self.related_skills),
            "category": self.category,
            "requires_toolsets": list(self.requires_toolsets),
            "fallback_for_toolsets": list(self.fallback_for_toolsets),
            "requires_tools": list(self.requires_tools),
            "fallback_for_tools": list(self.fallback_for_tools),
            "config": dict(self.config),
            "validation_errors": list(self.validation_errors),
            "unknown_fields": dict(self.unknown_fields),
        }


@dataclass(frozen=True)
class ResolvedFrontmatter:
    """Resolved SKILL.md frontmatter (SPEC §5.2 ``manifest`` section).

    ``description_raw`` is verbatim, bounded to 1024 chars *by the parser*
    (Phase 1); this type stores what it is given. Unknown top-level
    frontmatter fields are tolerated-and-recorded in ``unknown_fields``
    (warn via :func:`report_unknown_fields`), never dropped, never fatal.
    """

    name: str
    description_raw: str = ""
    #: 1-based line of the ``description`` key in SKILL.md when the raw text
    #: was available at parse time (additive ir/1 per DECISIONS D-008/D-016;
    #: consumed by LNS-MAN-004 evidence locations). ``None`` = unresolved.
    description_line: int | None = None
    allowed_tools: tuple[str, ...] = ()
    compatibility: str | None = None
    vendor_fields: Mapping[str, Any] = field(default_factory=dict)
    hermes: HermesMetadata | None = None
    validation_errors: tuple[str, ...] = ()
    unknown_fields: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "vendor_fields", dict(self.vendor_fields))
        object.__setattr__(self, "unknown_fields", dict(self.unknown_fields))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description_raw": self.description_raw,
            "description_line": self.description_line,
            "allowed_tools": list(self.allowed_tools),
            "compatibility": self.compatibility,
            "vendor_fields": dict(self.vendor_fields),
            "hermes": self.hermes.to_dict() if self.hermes is not None else None,
            "validation_errors": list(self.validation_errors),
            "unknown_fields": dict(self.unknown_fields),
        }


def report_unknown_fields(
    unknown: Mapping[str, Any],
    collector: DiagnosticsCollector,
    *,
    path: str | None = None,
) -> list[Diagnostic]:
    """Emit one stable-ordered warning per unknown frontmatter field.

    Tolerate-and-record law: the value itself is NOT copied into the
    diagnostic detail (it may be huge or non-JSON-safe); we record its JSON
    type name so the finding stays evidence-shaped without leaking bulk.
    Returns the records created (sorted by key for byte-stable output).
    """
    created: list[Diagnostic] = []
    for key in sorted(unknown):
        created.append(
            collector.warning(
                CODE_FRONTMATTER_UNKNOWN,
                f"unknown frontmatter field tolerated and recorded: {key}",
                path=path,
                detail={"key": key, "value_kind": type(unknown[key]).__name__},
            )
        )
    return created


# -- claims (SPEC §7 claim-record schema; extraction lives in claims.py) -------

#: Claim ``kind`` vocabulary (SPEC §7). ``description_phrase`` claims arrive
#: with lexicon v1 (Phase 1.5); field-direct extraction emits the other three.
CLAIM_KIND_FRONTMATTER_FIELD = "frontmatter_field"
CLAIM_KIND_DESCRIPTION_PHRASE = "description_phrase"
CLAIM_KIND_COMPATIBILITY = "compatibility"
CLAIM_KIND_ALLOWED_TOOLS = "allowed_tools"
CLAIM_KINDS: tuple[str, ...] = (
    CLAIM_KIND_FRONTMATTER_FIELD,
    CLAIM_KIND_DESCRIPTION_PHRASE,
    CLAIM_KIND_COMPATIBILITY,
    CLAIM_KIND_ALLOWED_TOOLS,
)

#: Extraction methods (SPEC §7 ``extractor``). Lexicon v1 lands Phase 1.5.
EXTRACTOR_FIELD_DIRECT = "field-direct"
EXTRACTOR_LEXICON_V1 = "lexicon:v1"


@dataclass(frozen=True)
class ClaimSpan:
    """Verbatim quote location of a claim (SPEC §7 ``span``).

    ``line`` is 1-based into the manifest document when the raw SKILL.md
    text was available at extraction time; ``None`` means the span was
    resolved from typed frontmatter alone (quote stays verbatim either way).

    ``start_offset``/``end_offset`` are additive ir/1 fields (D-038) carried
    ONLY by lexicon spans: character offsets into the exact string the span
    was mined from (the description text or the body region), satisfying
    "quote spans verbatim with offsets". They serialize only when set so
    every field-direct span keeps its historical §7 wire shape byte-exact.
    """

    path: str
    line: int | None
    quote: str
    start_offset: int | None = None
    end_offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        span = {"path": self.path, "line": self.line, "quote": self.quote}
        if self.start_offset is not None:
            span["start_offset"] = self.start_offset
        if self.end_offset is not None:
            span["end_offset"] = self.end_offset
        return span


@dataclass(frozen=True)
class ClaimRecord:
    """One declared capability, quoted verbatim from its source (SPEC §7).

    Field-direct construction happens exclusively in
    :mod:`skill_lens.claims`; everything downstream (overreach diff,
    declared-discount math, ``lens map``) consumes these records.
    """

    id: str  # "C-N", assigned post-sort so ids are input-deterministic
    kind: str  # CLAIM_KINDS member
    capability: str  # §9.1 path, optional ":" subpath
    span: ClaimSpan
    extractor: str  # EXTRACTOR_* member

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "capability": self.capability,
            "span": self.span.to_dict(),
            "extractor": self.extractor,
        }


def extract_claims(ir: SkillIR) -> tuple[ClaimRecord, ...]:
    """Field-direct extraction over *ir*'s manifest (SPEC §9.2 group 1).

    Delegates to :func:`skill_lens.claims.extract_field_direct_claims` via a
    lazy import (module-cycle safety: ``claims`` imports these types). Spans
    resolved here carry ``line=None`` because the raw SKILL.md text is not
    retained on the IR; the ingest path extracts with text and precise lines.
    """
    if ir.frontmatter is None:
        return ()
    from .claims import extract_field_direct_claims

    return extract_field_direct_claims(ir.frontmatter)


# -- root record ----------------------------------------------------------------


@dataclass(frozen=True)
class SkillIR:
    """Root SkillIR record (SPEC §5.2).

    ``diagnostics`` is the structured diagnostics list shared across the
    pipeline. The dataclass is frozen, but the collector itself is an
    intentionally mutable sink (thread-safe, append-only); freeze semantics
    cover rebinding, not the collector's interior.
    """

    identity: BundleIdentity
    source_kind: str = SOURCE_DIR
    bundle_hash: str | None = None  # "sha256:…" over sorted (rel_path, bytes)
    files: tuple[FileRecord, ...] = ()
    provenance: Provenance | None = None
    frontmatter: ResolvedFrontmatter | None = None
    claims: tuple[ClaimRecord, ...] = ()
    decoded_views: tuple[DecodedView, ...] = ()
    notes: tuple[str, ...] = ()  # e.g. "partial_analysis: assets/big.bin ..."
    diagnostics: DiagnosticsCollector = field(default_factory=DiagnosticsCollector)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(record.size for record in self.files)

    def canonical_dict(self) -> dict[str, Any]:
        """Full SPEC §5.2 mapping — the deterministic payload.

        Contains no wall-clock values and no absolute host paths; the
        canonical writer (:mod:`skill_lens.canonical`) serializes this with
        sorted keys. Diagnostics are snapshotted in insertion order, which
        is deterministic for a given input and execution path.
        """
        return {
            "spec_version": IR_SPEC_VERSION,
            "tool": {"name": TOOL_NAME, "version": tool_version()},
            "bundle": {
                "root_label": self.identity.name,
                "category": self.identity.category,
                "path_as_given": self.identity.path,
                "layout": self.identity.layout,
                "source_kind": self.source_kind,
                "bundle_hash": self.bundle_hash,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
                "provenance": self.provenance.to_dict() if self.provenance else None,
                "files": [record.to_dict() for record in self.files],
            },
            "manifest": self.frontmatter.to_dict() if self.frontmatter else None,
            "claims": [claim.to_dict() for claim in self.claims],
            "decoded_views": [view.to_dict() for view in self.decoded_views],
            "notes": list(self.notes),
            "diagnostics": [diag.to_dict() for diag in self.diagnostics.snapshot()],
        }


# -- Phase 0 human surface ------------------------------------------------------


def render_inventory(
    ir: SkillIR,
    *,
    actual_capabilities: Iterable[str] | None = None,
) -> str:
    """Minimal stable-text inventory dump (PLAN day-2 "inventory dump works").

    Plain text, no color, stable ordering: files are emitted in ascending
    ``path`` order (stable sort), sections in fixed order. Reads only
    deterministic fields, so two renders of equal IRs are byte-identical.

    ``actual_capabilities`` — engine evidence of what the bundle actually
    does — is OPTIONAL: when supplied, a deterministic overreach section
    (SPEC §9.2/§9.3) renders right after the claims line; the default
    ``None`` keeps byte-compatibility with Phase 0 output.
    """
    lines: list[str] = [
        f"bundle: {ir.identity.name}",
        f"layout: {ir.identity.layout}"
        + (f" (category={ir.identity.category})" if ir.identity.category else ""),
        f"path: {ir.identity.path}",
        f"source: {ir.source_kind}",
        f"hash: {ir.bundle_hash or 'unhashed'}",
        f"files: {ir.file_count} ({ir.total_bytes} bytes)",
    ]
    for record in sorted(ir.files, key=lambda rec: rec.path):
        encoding = record.encoding or "undetermined"
        partial_note = " partial" if record.partial else ""
        lines.append(
            f"  - {record.path} [{record.role}, {record.size} bytes, {encoding}{partial_note}]"
        )
    fm = ir.frontmatter
    if fm is not None:
        tools = ",".join(fm.allowed_tools) if fm.allowed_tools else "-"
        lines.append(f"manifest: name={fm.name} allowed-tools={tools}")
        if fm.hermes is not None and fm.hermes.category is not None:
            lines.append(f"hermes: category={fm.hermes.category}")
    prov = ir.provenance
    if prov is not None:
        lines.append(
            "provenance: "
            f"source_class={prov.source_class or PROV_SOURCE_UNKNOWN}"
            f" resolved_from={prov.resolved_from or 'null'}"
            f" trust_level={prov.trust_level or 'null'}"
        )
    lines.append(f"claims: {len(ir.claims)}")
    if actual_capabilities is not None:
        claimed = [claim.capability for claim in ir.claims]
        lines.extend(_render_overreach_section(claimed, actual_capabilities).splitlines())
    lines.append(f"decoded_views: {len(ir.decoded_views)}")
    lines.append(f"notes: {len(ir.notes)}")
    snapshots = ir.diagnostics.snapshot()
    loud = sum(1 for diag in snapshots if diag.severity in (SEVERITY_WARNING, "error"))
    lines.append(f"diagnostics: {len(snapshots)} ({loud} warning/error)")
    return "\n".join(lines) + "\n"
