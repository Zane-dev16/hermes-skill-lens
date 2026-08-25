"""Ingestion — discover, read, and decode Hermes skill bundles into SkillIR.

Phase 0 walkers per SPEC §5.1 / PLAN §1 Phase 0:

- :func:`discover_bundles` walks the categorized layout
  ``<home>/skills/<category>/<name>/`` plus the hub quarantine dir
  ``<home>/skills/.hub/quarantine/**`` (bundles at variable depth; staged
  ``*.zip`` archives are first-class targets there). Tolerates the rmtree
  race: a directory vanishing mid-walk degrades to a logged skip diagnostic.
- :func:`load_bundle` ingests one target: a directory, a ``.zip`` (in-memory,
  size-capped), or a lone ``SKILL.md``. Git/remote URLs are NOT fetched —
  they produce structured diagnostic ``LNS-ING-NET`` and an empty partial IR
  (privacy G1: zero network in the default path).
- Frontmatter parsing maps SKILL.md YAML (incl. ``metadata.hermes``) into the
  IR; unknown fields are tolerated-and-recorded; name/dirname mismatch is a
  diagnostic. Malformed frontmatter yields partial IR, never an exception.
- Provenance enrichment reads ``<home>/skills/.hub/lock.json`` when present;
  fields attach as ANNOTATION ONLY (D-PROV) and never affect any score.

Resource ceilings (SPEC §5.1): ≤10,000 files/bundle, traversal depth ≤32,
canonical bytes ≤64 MiB, single file ≤16 MiB (bounded projection +
``partial_analysis`` note). The 60 s end-to-end soft deadline is an
orchestration-layer concern (DECISIONS D-011): wall-clock checks inside this
walk would make deterministic payloads timing-dependent.

DETERMINISM LAW honored throughout: sorted iteration everywhere, no
wall-clock values, paths stored as ``$HERMES_HOME``-normalized labels
(``~`` = the active home) or exactly as given by the caller.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skill_lens.claims import extract_all_claims
from skill_lens.diagnostics import (
    DiagnosticsCollector,
)
from skill_lens.ir import (
    LAYOUT_CATEGORIZED,
    LAYOUT_FLAT,
    LAYOUT_SINGLE_FILE,
    PATH_LABEL_INSIDE_SKILL_ROOT,
    ROLE_ASSET,
    ROLE_DOC,
    ROLE_REFERENCE,
    ROLE_SCRIPT,
    ROLE_UNKNOWN,
    SOURCE_DIR,
    SOURCE_QUARANTINE,
    SOURCE_ZIP,
    BundleIdentity,
    FileRecord,
    Provenance,
    ResolvedFrontmatter,
    SkillIR,
    report_unknown_fields,
)

# ---------------------------------------------------------------------------
# Resource ceilings (exact numbers from SPEC §5.1)
# ---------------------------------------------------------------------------

MAX_FILES_PER_BUNDLE = 10_000
MAX_TRAVERSAL_DEPTH = 32
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # canonical bytes ≤ 64 MiB
MAX_SINGLE_FILE_BYTES = 16 * 1024 * 1024  # larger ⇒ bounded projection


@dataclass(frozen=True)
class Ceilings:
    """Per-bundle resource ceilings (SPEC §5.1 defaults; tests may shrink)."""

    max_files: int = MAX_FILES_PER_BUNDLE
    max_depth: int = MAX_TRAVERSAL_DEPTH
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_file_bytes: int = MAX_SINGLE_FILE_BYTES


DEFAULT_CEILINGS = Ceilings()

# Bounded length of verbatim description text carried in the IR (§5.2).
DESCRIPTION_MAX_CHARS = 1024

# Stable diagnostic codes for the ingest subsystem.
CODE_INGEST_NET = "LNS-ING-NET"  # remote target refused (privacy G1)
CODE_INGEST_RACE = "LNS-ING-RACE"  # dir vanished mid-walk (rmtree race)
CODE_INGEST_SYMLINK = "LNS-ING-SYMLINK"  # symlink entry not followed
CODE_INGEST_DEPTH = "LNS-ING-DEPTH"  # traversal depth ceiling hit
CODE_INGEST_FILE_CAP = "LNS-ING-FILE-CAP"  # >max_files files in bundle
CODE_INGEST_SIZE_CAP = "LNS-ING-SIZE-CAP"  # >max_total_bytes canonical bytes
CODE_INGEST_FILE_SIZE = "LNS-ING-FILE-SIZE"  # single file projected (>16 MiB)
CODE_INGEST_READ = "LNS-ING-READ"  # unreadable file/dir entry skipped
CODE_INGEST_TARGET = "LNS-ING-TARGET"  # missing/unsupported scan target
CODE_INGEST_ZIP = "LNS-ING-ZIP"  # malformed zip container
CODE_INGEST_ENCODING = "LNS-ING-ENCODING"  # non-UTF-8 file content
CODE_PROV_LOCK = "LNS-PROV-LOCK"  # hub lock.json problems
CODE_FRONT_PARSE = "LNS-FRONT-PARSE"  # YAML/frontmatter parse failure
CODE_FRONT_SHAPE = "LNS-FRONT-SHAPE"  # frontmatter not a mapping
CODE_FRONT_NAME_MISMATCH = "LNS-FRONT-NAME-MISMATCH"  # fm.name ≠ dirname

_SKILL_DOC = "SKILL.md"

# Walk policy: dot-entries are packaging metadata (.git, .hub internals),
# not skill surface — skipped everywhere except the explicit corridor
# <skills>/.hub/quarantine (DECISIONS D-011).
_HUB_DIRNAME = ".hub"
_QUARANTINE_DIRNAME = "quarantine"


def _abs_norm(path: Path) -> Path:
    """Absolute normalized path WITHOUT symlink resolution (stable labels)."""
    return Path(os.path.normpath(os.path.abspath(str(path))))


def home_label(path: Path | str, home: Path | str) -> str:
    """``$HERMES_HOME``-normalized display label for a path.

    Paths under *home* become ``~/.hermes/<relative.posix>`` when *home* is
    the user's real ``<home>/.hermes`` (matching the SPEC §5.2 display form,
    e.g. ``~/.hermes/skills/tools/web-design-guidelines``); for any other
    Hermes home (scratch profiles, quarantine sandboxes) labels take the
    ``~/<relative.posix>`` form where ``~`` denotes the active home.
    Anything NOT under *home* is returned exactly as given (callers own that
    choice — the inventory scanner only passes label forms, keeping absolute
    host paths out of deterministic payloads).
    """
    p = _abs_norm(Path(path))
    h = _abs_norm(Path(home))
    try:
        rel = p.relative_to(h)
    except ValueError:
        return str(path)
    prefix = "~/.hermes" if h == _abs_norm(Path.home() / ".hermes") else "~"
    if rel == Path("."):
        return prefix
    return prefix + "/" + rel.as_posix()


# ---------------------------------------------------------------------------
# Sorted scandir — the single filesystem-entry seam (monkeypatch hook for
# race tests); every walker sorts by entry name for byte-stable traversal.
# ---------------------------------------------------------------------------


def _scandir_sorted(path: Path) -> list[os.DirEntry[str]]:
    """List directory entries sorted by name. OSError propagates to caller."""
    with os.scandir(path) as it:
        return sorted(it, key=lambda e: e.name)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleRef:
    """One discovered bundle target, ready for :func:`load_bundle`."""

    name: str
    category: str | None
    path: Path  # real filesystem path (never enters the IR payload)
    label: str  # $HERMES_HOME-normalized identity.path form
    layout: str  # ir.LAYOUT_* constant
    source_kind: str  # ir.SOURCE_DIR | SOURCE_QUARANTINE | SOURCE_ZIP


@dataclass
class _DiscoveryState:
    parts_to_ref: dict[tuple[str, ...], tuple[str, str | None, Path]] = field(default_factory=dict)
    zips: list[tuple[tuple[str, ...], Path]] = field(default_factory=list)


def _entry_safe_is_dir(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _discover_walk(
    root: Path,
    *,
    rel: tuple[str, ...],
    mode: str,  # "tree" | "hub" | "quarantine"
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    state: _DiscoveryState,
    depth: int,
    skills_root_label: str,
) -> None:
    """Depth-first discovery of bundle candidate dirs and quarantined zips."""
    if depth > ceilings.max_depth:
        diags.warning(
            CODE_INGEST_DEPTH,
            f"traversal depth ceiling ({ceilings.max_depth}) reached; deeper levels not scanned",
            path=_walk_label(skills_root_label, rel),
        )
        return
    try:
        entries = _scandir_sorted(root)
    except OSError as exc:
        # The rmtree race (or any transient IO failure): degrade to a logged
        # skip — never a crash (SPEC §5.1 quarantine tolerance).
        diags.warning(
            CODE_INGEST_RACE,
            f"directory vanished mid-walk ({exc.strerror}); skipped",
            path=_walk_label(skills_root_label, rel),
        )
        return

    # Candidate registration: any walked dir carrying SKILL.md is a bundle.
    if rel and _dir_has_skill_doc(root):
        state.parts_to_ref[rel] = (_bundle_name_from_parts(rel), None, root)

    for entry in entries:
        name = entry.name
        child_rel = rel + (name,)
        try:
            is_symlink = entry.is_symlink()
        except OSError:
            is_symlink = False
        if is_symlink:
            diags.warning(
                CODE_INGEST_SYMLINK,
                "symlinked entry not followed during discovery",
                path=_walk_label(skills_root_label, child_rel),
            )
            continue
        if _entry_safe_is_dir(entry):
            hidden = name.startswith(".")
            if mode == "tree" and rel == () and name == _HUB_DIRNAME:
                # The single sanctioned hidden corridor:
                # <skills>/.hub/quarantine/** (DECISIONS D-011).
                _discover_walk(
                    root / name,
                    rel=child_rel,
                    mode="hub",
                    ceilings=ceilings,
                    diags=diags,
                    state=state,
                    depth=depth + 1,
                    skills_root_label=skills_root_label,
                )
                continue
            if mode == "hub":
                # Inside .hub only the quarantine corridor is traversed.
                if name == _QUARANTINE_DIRNAME:
                    _discover_walk(
                        root / name,
                        rel=child_rel,
                        mode="quarantine",
                        ceilings=ceilings,
                        diags=diags,
                        state=state,
                        depth=depth + 1,
                        skills_root_label=skills_root_label,
                    )
                continue
            if hidden:
                continue
            next_mode = "tree"
            if mode == "quarantine":
                next_mode = "quarantine"
            _discover_walk(
                root / name,
                rel=child_rel,
                mode=next_mode,
                ceilings=ceilings,
                diags=diags,
                state=state,
                depth=depth + 1,
                skills_root_label=skills_root_label,
            )
        else:
            if mode == "quarantine" and name.lower().endswith(".zip"):
                state.zips.append((child_rel, root / name))


def _walk_label(root_label: str, rel: tuple[str, ...]) -> str:
    if not rel:
        return root_label
    return root_label.rstrip("/") + "/" + "/".join(rel)


def _dir_has_skill_doc(path: Path) -> bool:
    try:
        return (path / _SKILL_DOC).is_file()
    except OSError:
        return False


def discover_bundles(
    home: Path | str,
    *,
    ceilings: Ceilings = DEFAULT_CEILINGS,
    diagnostics: DiagnosticsCollector | None = None,
) -> list[BundleRef]:
    """Discover scannable bundles under ``<home>/skills``.

    Covers the categorized layout ``skills/<category>/<name>/``, flat
    ``skills/<name>/`` (category optional per grammars), nested bundles at
    greater depth (nearest ancestor bundle wins), and the hub quarantine
    corridor ``skills/.hub/quarantine/**`` where bundles sit at variable
    depth and staged ``*.zip`` archives count as targets. Output is sorted
    by relative path parts (byte-stable). A vanishing directory degrades to
    a logged :data:`CODE_INGEST_RACE` skip diagnostic, never an exception.
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    home_p = _abs_norm(Path(home))
    skills_root = home_p / "skills"
    refs: list[BundleRef] = []
    if not skills_root.is_dir():
        return refs

    root_label = home_label(skills_root, home_p)
    state = _DiscoveryState()

    def visit(path: Path, rel: tuple[str, ...], mode: str, depth: int) -> None:
        _discover_walk(
            path,
            rel=rel,
            mode=mode,
            ceilings=ceilings,
            diags=diags,
            state=state,
            depth=depth,
            skills_root_label=root_label,
        )

    visit(skills_root, (), "tree", 0)

    # Nearest ancestor wins: a bundle dir containing another SKILL.md deeper
    # down owns those files; drop candidates nested inside kept candidates.
    kept_parts: set[tuple[str, ...]] = set()
    for parts in sorted(state.parts_to_ref):
        if any(parts[:k] in kept_parts for k in range(1, len(parts))):
            continue  # content of an enclosing bundle
        kept_parts.add(parts)

    for parts in sorted(kept_parts):
        name, _unused, path = state.parts_to_ref[parts]
        inside_quarantine = _QUARANTINE_DIRNAME in parts and _HUB_DIRNAME in parts
        if len(parts) >= 2 and not inside_quarantine:
            category: str | None = parts[0]
            layout = LAYOUT_CATEGORIZED
        else:
            category = None
            layout = LAYOUT_FLAT
        refs.append(
            BundleRef(
                name=name,
                category=category,
                path=path,
                label=home_label(path, home_p),
                layout=layout,
                source_kind=SOURCE_QUARANTINE if inside_quarantine else SOURCE_DIR,
            )
        )
    for parts, zip_path in sorted(state.zips, key=lambda item: item[0]):
        if any(parts[:k] in kept_parts for k in range(1, len(parts))):
            continue  # a zip inside a discovered bundle dir belongs to it
        refs.append(
            BundleRef(
                name=Path(zip_path.name).stem,
                category=None,
                path=zip_path,
                label=home_label(zip_path, home_p),
                layout=LAYOUT_FLAT,
                source_kind=SOURCE_ZIP,
            )
        )
    return refs


def _bundle_name_from_parts(rel: tuple[str, ...]) -> str:
    return rel[-1] if rel else "skills"


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------

_KNOWN_TOP_FIELDS = frozenset(
    {"name", "description", "allowed-tools", "allowed_tools", "compatibility", "metadata"}
)

_KNOWN_HERMES_KEYS = frozenset(
    {
        "tags",
        "related_skills",
        "related-skills",
        "category",
        "requires_toolsets",
        "requires-toolsets",
        "fallback_for_toolsets",
        "fallback-for-toolsets",
        "requires_tools",
        "requires-tools",
        "fallback_for_tools",
        "fallback-for-tools",
        "config",
    }
)


def _yaml_safe_load(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse YAML safely; returns (mapping|None, error_message|None)."""
    try:
        import yaml  # lazy: keeps the default closure stdlib-only on import
    except ImportError:  # pragma: no cover — PyYAML is an install dep
        return None, "PyYAML unavailable; frontmatter not parsed"
    try:
        loaded = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 — any parser failure is a diag
        first_line = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return None, first_line[:200]
    if loaded is None:
        return {}, None
    if not isinstance(loaded, dict):
        return None, f"frontmatter is {type(loaded).__name__}, expected mapping"
    return loaded, None


def split_frontmatter(
    text: str,
    *,
    diagnostics: DiagnosticsCollector,
    path: str = _SKILL_DOC,
) -> dict[str, Any] | None:
    """Extract the delimited ``---`` frontmatter block as a mapping.

    Returns ``None`` (with a structured diagnostic) when the document has no
    delimited block, an unterminated one, unparsable YAML, or a non-mapping
    payload. Never raises.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    end_idx = -1
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx < 0:
        diagnostics.warning(CODE_FRONT_PARSE, "frontmatter block is unterminated", path=path)
        return None
    mapping, err = _yaml_safe_load("\n".join(lines[1:end_idx]))
    if err is not None:
        diagnostics.warning(CODE_FRONT_PARSE, f"frontmatter parse failed: {err}", path=path)
        return None
    if mapping is None:
        diagnostics.warning(CODE_FRONT_SHAPE, "frontmatter is not a mapping", path=path)
        return None
    return mapping


def _coerce_str_list(value: Any) -> tuple[str, ...] | None:
    """Hermes-tolerant string-list coercion (list items, or comma string).

    Mirrors the host's ``_parse_tags`` tolerance. ``None`` means wrong shape.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    items.append(stripped)
            elif item is not None:
                items.append(str(item))
        return tuple(items)
    return None


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return None


def _hermes_validation(fm_errors: list[str], message: str) -> str:
    fm_errors.append(message)
    return message


def build_frontmatter(
    mapping: dict[str, Any],
    *,
    fallback_name: str,
    diagnostics: DiagnosticsCollector,
    path: str = _SKILL_DOC,
) -> ResolvedFrontmatter:
    """Map raw frontmatter into :class:`ResolvedFrontmatter`.

    Known fields map to typed slots (including ``metadata.hermes``);
    unknown top-level fields land in ``unknown_fields`` with one stable
    warning each (:func:`skill_lens.ir.report_unknown_fields`). Wrong-shaped
    values degrade to validation errors, never exceptions.
    """
    errors: list[str] = []

    name = _coerce_str(mapping.get("name"))
    if name is None:
        name = fallback_name
        _hermes_validation(errors, "field 'name' must be a string")
    description = _coerce_str(mapping.get("description"))
    if description is None:
        description = str(mapping.get("description"))
        _hermes_validation(errors, "field 'description' must be a string")
    description = description[:DESCRIPTION_MAX_CHARS]

    allowed_raw = mapping.get("allowed-tools", mapping.get("allowed_tools"))
    allowed: tuple[str, ...] = ()
    if allowed_raw is not None:
        coerced = _coerce_str_list(allowed_raw)
        if coerced is None:
            _hermes_validation(errors, "field 'allowed-tools' must be a list or string")
        else:
            allowed = coerced

    compatibility = _coerce_str(mapping.get("compatibility"))
    if compatibility is None:
        compatibility = str(mapping.get("compatibility"))
        _hermes_validation(errors, "field 'compatibility' must be a string")

    vendor_fields: dict[str, Any] = {}
    hermes: dict[str, Any] | None = None
    metadata_raw = mapping.get("metadata")
    if metadata_raw is not None and not isinstance(metadata_raw, dict):
        _hermes_validation(errors, "field 'metadata' must be a mapping")
    elif isinstance(metadata_raw, dict):
        hermes_raw = metadata_raw.get("hermes")
        if hermes_raw is not None and not isinstance(hermes_raw, dict):
            _hermes_validation(errors, "field 'metadata.hermes' must be a mapping")
        elif isinstance(hermes_raw, dict):
            hermes = dict(hermes_raw)
        vendor_fields = {key: value for key, value in metadata_raw.items() if key != "hermes"}

    resolved_hermes = None
    if hermes is not None:
        resolved_hermes = _build_hermes_metadata(hermes, errors, diagnostics, path)

    known_keys = set(_KNOWN_TOP_FIELDS)
    if metadata_raw is not None:
        known_keys.add("metadata")
    unknown_top = {key: mapping[key] for key in sorted(set(mapping) - known_keys)}
    if unknown_top:
        report_unknown_fields(unknown_top, diagnostics, path=path)

    return ResolvedFrontmatter(
        name=name,
        description_raw=description,
        allowed_tools=allowed,
        compatibility=compatibility,
        vendor_fields=vendor_fields,
        hermes=resolved_hermes,
        validation_errors=tuple(errors),
        unknown_fields=unknown_top,
    )


def _build_hermes_metadata(
    hermes: dict[str, Any],
    errors: list[str],
    diagnostics: DiagnosticsCollector,
    path: str,
) -> Any:
    """Type ``metadata.hermes`` against the observed grammar (tolerantly)."""
    from skill_lens.ir import HermesMetadata  # local: avoids import cycles in tests

    hm_errors: list[str] = []

    def take_list(*keys: str) -> tuple[str, ...]:
        for key in keys:
            if key in hermes:
                coerced = _coerce_str_list(hermes[key])
                if coerced is None:
                    _hermes_validation(hm_errors, f"metadata.hermes.{key} must be a list")
                    return ()
                return coerced
        return ()

    tags = take_list("tags")
    related = take_list("related_skills", "related-skills")
    requires_toolsets = take_list("requires_toolsets", "requires-toolsets")
    fallback_toolsets = take_list("fallback_for_toolsets", "fallback-for-toolsets")
    requires_tools = take_list("requires_tools", "requires-tools")
    fallback_tools = take_list("fallback_for_tools", "fallback-for-tools")

    category = None
    if "category" in hermes:
        coerced_cat = _coerce_str(hermes["category"])
        if coerced_cat is None:
            _hermes_validation(hm_errors, "metadata.hermes.category must be a string")
            coerced_cat = str(hermes["category"])
        category = coerced_cat or None

    config: dict[str, Any] = {}
    if "config" in hermes:
        raw_config = hermes["config"]
        if isinstance(raw_config, dict):
            config = dict(raw_config)
        elif raw_config is not None:
            _hermes_validation(hm_errors, "metadata.hermes.config must be a mapping")

    unknown_hermes = {key: hermes[key] for key in sorted(set(hermes) - _KNOWN_HERMES_KEYS)}
    if unknown_hermes:
        prefixed = {f"metadata.hermes.{key}": unknown_hermes[key] for key in unknown_hermes}
        report_unknown_fields(prefixed, diagnostics, path=path)

    return HermesMetadata(
        tags=tags,
        related_skills=related,
        category=category,
        requires_toolsets=requires_toolsets,
        fallback_for_toolsets=fallback_toolsets,
        requires_tools=requires_tools,
        fallback_for_tools=fallback_tools,
        config=config,
        validation_errors=tuple(hm_errors),
        unknown_fields=unknown_hermes,
    )


# ---------------------------------------------------------------------------
# Encoding detection (decode-as-data ladder, Phase 0 subset)
# ---------------------------------------------------------------------------

ENCODING_UTF8 = "utf-8"
ENCODING_UTF8_SIG = "utf-8-sig"
ENCODING_UTF16 = "utf-16"
ENCODING_BINARY = "binary"
ENCODING_LOSSY = "lossy-replacement"


def detect_encoding(data: bytes) -> tuple[str, str | None]:
    """Sniff BOMs then UTF-8; returns ``(encoding_token, text_or_None)``.

    ``text`` is ``None`` for binary payloads; lossy decoding replaces
    undecodable bytes (U+FFFD) so structure parsing can still proceed — the
    caller records the diagnostic. Pure function of the bytes.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return ENCODING_UTF8_SIG, data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return ENCODING_LOSSY, data.decode("utf-8-sig", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return ENCODING_UTF16, data.decode("utf-16")
        except UnicodeDecodeError:
            return ENCODING_LOSSY, data.decode("utf-16", errors="replace")
    try:
        return ENCODING_UTF8, data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if b"\x00" in data[:8192]:
        return ENCODING_BINARY, None
    return ENCODING_LOSSY, data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Role / language classification
# ---------------------------------------------------------------------------

_LANGUAGE_BY_SUFFIX = {
    ".sh": "bash",
    ".bash": "bash",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".md": "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
}

_ROLE_BY_TOP_DIR = {
    "scripts": ROLE_SCRIPT,
    "assets": ROLE_ASSET,
    "templates": ROLE_ASSET,
    "references": ROLE_REFERENCE,
    "examples": ROLE_REFERENCE,
}

_SCRIPT_SUFFIXES = frozenset({".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts"})


def classify_file(rel_path: str) -> tuple[str, str | None]:
    """Return ``(role, language)`` for a bundle-relative path (pure).

    The shallowest recognized directory component wins (``scripts/``,
    ``assets/``, ``references/``, ``templates/``, ``examples/``), so zip
    wrapper roots (``root/scripts/x.sh``) still classify correctly; without
    one, script suffixes imply ``script`` and markdown implies ``doc``.
    """
    parts = rel_path.split("/")
    suffix = Path(parts[-1]).suffix.lower()
    language = _LANGUAGE_BY_SUFFIX.get(suffix)
    for part in parts[:-1]:
        role = _ROLE_BY_TOP_DIR.get(part)
        if role is not None:
            return role, language
    if parts[-1] == _SKILL_DOC or suffix == ".md":
        return ROLE_DOC, language
    if suffix in _SCRIPT_SUFFIXES:
        return ROLE_SCRIPT, language
    return ROLE_UNKNOWN, language


# ---------------------------------------------------------------------------
# Hub lockfile provenance (ANNOTATION ONLY — D-PROV)
# ---------------------------------------------------------------------------


def read_hub_lock(
    home: Path | str,
    *,
    diagnostics: DiagnosticsCollector | None = None,
) -> dict[str, dict[str, Any]]:
    """Read ``<home>/skills/.hub/lock.json`` → ``{name: entry}`` mapping.

    Missing file ⇒ empty mapping plus an info diagnostic ("skip silently-
    with-diagnostic"). Corrupt/unshaped file ⇒ warning diagnostic. Never
    raises; never used for arithmetic (D-PROV).
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()
    lock_path = _abs_norm(Path(home)) / "skills" / _HUB_DIRNAME / "lock.json"
    try:
        raw = lock_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        diags.info(
            CODE_PROV_LOCK,
            "hub lockfile absent; provenance not enriched",
            path=home_label(lock_path, home),
        )
        return {}
    except OSError as exc:
        diags.warning(
            CODE_PROV_LOCK,
            f"hub lockfile unreadable: {exc.strerror}",
            path=home_label(lock_path, home),
        )
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        diags.warning(
            CODE_PROV_LOCK,
            f"hub lockfile corrupt JSON: {exc.msg}",
            path=home_label(lock_path, home),
        )
        return {}
    installed = data.get("installed") if isinstance(data, dict) else None
    if not isinstance(installed, dict):
        diags.warning(
            CODE_PROV_LOCK,
            "hub lockfile lacks an 'installed' mapping",
            path=home_label(lock_path, home),
        )
        return {}
    return {name: entry for name, entry in installed.items() if isinstance(entry, dict)}


def _lock_entry_for(
    ref_name: str,
    ref_label: str,
    lock: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Match a lock entry by skills-relative install path, falling back to name."""
    for name, entry in sorted(lock.items()):
        install_path = entry.get("install_path")
        if isinstance(install_path, str):
            tail = install_path.strip("/").rsplit("/", 1)[-1]
            label_tail = ref_label.rstrip("/").rsplit("/", 1)[-1]
            if label_tail and label_tail == tail and name == ref_name:
                return entry
    entry = lock.get(ref_name)
    if isinstance(entry, dict):
        return entry
    return None


def enrich_provenance(
    ref: BundleRef,
    lock: dict[str, dict[str, Any]],
) -> Provenance | None:
    """Attach hub provenance annotation for *ref* (never scored, D-PROV).

    Quarantine bundles always carry ``resolved_from="quarantine_dir"``;
    lock-matched bundles carry ``resolved_from="hub_lock"`` with the SPEC
    §5.1 enrichment set (source/identifier/trust_level/content_hash/
    scan_provenance). Unmatched plain bundles get ``None``.
    """
    entry = _lock_entry_for(ref.name, ref.label, lock)
    if ref.source_kind == SOURCE_QUARANTINE and entry is None:
        return Provenance(resolved_from="quarantine_dir", install_path=ref.label)
    if entry is None:
        return None

    def opt_str(key: str) -> str | None:
        value = entry.get(key)
        return value if isinstance(value, str) else None

    source_class = None
    trust = opt_str("trust_level")
    if trust == "agent-created":
        source_class = "agent_created"
    return Provenance(
        source_class=source_class,
        identifier=opt_str("identifier"),
        trust_level=trust,
        resolved_from="hub_lock",
        install_path=ref.label,
        hub_source=opt_str("source"),
        content_hash=opt_str("content_hash"),
        scan_provenance=(
            dict(entry["scan_provenance"])
            if isinstance(entry.get("scan_provenance"), dict)
            else None
        ),
    )


# ---------------------------------------------------------------------------
# Target classification + loading
# ---------------------------------------------------------------------------

_GIT_URL_PREFIXES = ("git@", "ssh://", "git://", "http://", "https://")


def looks_like_git_url(target: str) -> bool:
    """True for remote git targets (refused offline per privacy G1).

    Scheme forms and scp-like ``git@host:path`` are remote; a bare
    ``name.git`` string stays ambiguous and is treated as a local path —
    advisor-safest: never refuse to scan something that might exist on
    disk.
    """
    return target.startswith(_GIT_URL_PREFIXES)


def load_bundle(
    target: str | Path,
    *,
    home: Path | str | None = None,
    ceilings: Ceilings = DEFAULT_CEILINGS,
    diagnostics: DiagnosticsCollector | None = None,
    provenance_lock: dict[str, dict[str, Any]] | None = None,
) -> SkillIR:
    """Ingest ONE bundle target into a :class:`SkillIR`.

    Accepts a bundle directory, a ``.zip`` archive (read fully in memory,
    capped per SPEC §5.1 ceilings), or a lone ``SKILL.md`` file. Remote/git
    URLs are never fetched: they yield a partial IR carrying diagnostic
    ``LNS-ING-NET`` ("remote targets unsupported in v0.9 default path").
    Every failure mode degrades to diagnostics plus partial IR; nothing
    raises out to callers.
    """
    diags = diagnostics if diagnostics is not None else DiagnosticsCollector()

    if isinstance(target, str):
        as_given = target
    else:
        as_given = str(target)

    if isinstance(target, str) and looks_like_git_url(target):
        identity = BundleIdentity(name=_target_display_name(target), path=as_given)
        diags.warning(
            CODE_INGEST_NET,
            "remote targets unsupported in v0.9 default path (zero-network privacy guarantee G1)",
            path=as_given,
        )
        return SkillIR(
            identity=identity,
            source_kind="git",
            notes=("ingest_skipped: remote target refused (G1)",),
            diagnostics=diags,
        )

    path = Path(as_given).expanduser()
    exists = path.exists()
    if not exists:
        identity = BundleIdentity(name=path.name or as_given, path=as_given)
        diags.error(CODE_INGEST_TARGET, f"scan target does not exist: {as_given}", path=as_given)
        return SkillIR(identity=identity, diagnostics=diags)

    if path.is_dir():
        return _load_dir_bundle(
            path,
            home=home,
            ceilings=ceilings,
            diags=diags,
            provenance_lock=provenance_lock,
            as_given=as_given,
        )
    if path.is_file() and path.name == _SKILL_DOC:
        return _load_single_skill_doc(path, ceilings=ceilings, diags=diags, as_given=as_given)
    if path.is_file() and path.suffix.lower() == ".zip":
        return _load_zip_bundle(path, ceilings=ceilings, diags=diags, as_given=as_given)

    identity = BundleIdentity(name=path.name or as_given, path=as_given)
    diags.error(
        CODE_INGEST_TARGET,
        f"unsupported scan target type: {as_given} (expected directory, .zip, or SKILL.md)",
        path=as_given,
    )
    return SkillIR(identity=identity, diagnostics=diags)


def _target_display_name(target: str) -> str:
    tail = target.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[: -len(".git")]
    return tail or target


# ---------------------------------------------------------------------------
# Directory bundle walking
# ---------------------------------------------------------------------------


@dataclass
class _Collected:
    files: list[tuple[str, Path]] = field(default_factory=list)
    total_projected_bytes: int = 0
    stopped_reason: str | None = None
    depth_skips: int = 0


def _collect_bundle_files(
    root: Path,
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    root_label: str,
) -> _Collected:
    """Sorted DFS over a bundle dir collecting regular-file candidates.

    Enforces depth/file/size ceilings; skips dot-entries, symlinks, and
    unreadable entries with structured diagnostics (races included).
    """
    out = _Collected()
    visited_dirs: set[tuple[int, int]] = set()

    def walk(directory: Path, rel: tuple[str, ...], depth: int) -> None:
        if out.stopped_reason is not None:
            return
        if depth > ceilings.max_depth:
            out.depth_skips += 1
            return
        try:
            st = directory.stat()
            marker = (st.st_dev, st.st_ino)
            if marker in visited_dirs:
                diags.warning(
                    CODE_INGEST_SYMLINK,
                    "directory loop detected (already visited); branch skipped",
                    path=_walk_label(root_label, rel),
                )
                return
            visited_dirs.add(marker)
            entries = _scandir_sorted(directory)
        except OSError as exc:
            diags.warning(
                CODE_INGEST_RACE,
                f"directory vanished mid-walk ({exc.strerror}); skipped",
                path=_walk_label(root_label, rel),
            )
            return

        for entry in entries:
            if out.stopped_reason is not None:
                return
            name = entry.name
            child_rel = rel + (name,)
            label = _walk_label(root_label, child_rel)
            try:
                if entry.is_symlink():
                    diags.warning(
                        CODE_INGEST_SYMLINK,
                        "symlinked entry not followed inside bundle",
                        path=label,
                    )
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if name.startswith("."):
                        continue
                    walk(directory / name, child_rel, depth + 1)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    diags.info(
                        CODE_INGEST_READ,
                        "non-regular file entry skipped",
                        path=label,
                    )
                    continue
                if name.startswith("."):
                    continue
                st_size = entry.stat(follow_symlinks=False).st_size
                projected = min(st_size, ceilings.max_file_bytes)
                if out.total_projected_bytes + projected > ceilings.max_total_bytes:
                    diags.warning(
                        CODE_INGEST_SIZE_CAP,
                        f"canonical bytes ceiling ({ceilings.max_total_bytes}) "
                        "reached; remaining files not ingested",
                        path=label,
                    )
                    out.stopped_reason = "size_cap"
                    return
                if len(out.files) >= ceilings.max_files:
                    diags.warning(
                        CODE_INGEST_FILE_CAP,
                        f"file-count ceiling ({ceilings.max_files}) reached; "
                        "remaining files not ingested",
                        path=label,
                    )
                    out.stopped_reason = "file_cap"
                    return
                out.files.append(("/".join(child_rel), directory / name))
                out.total_projected_bytes += projected
            except OSError as exc:
                diags.warning(
                    CODE_INGEST_RACE,
                    f"entry vanished mid-walk ({exc.strerror}); skipped",
                    path=label,
                )
                continue

    walk(root, (), 0)
    if out.depth_skips:
        diags.warning(
            CODE_INGEST_DEPTH,
            f"traversal depth ceiling ({ceilings.max_depth}) reached; "
            f"{out.depth_skips} branch(es) not scanned",
            path=root_label,
        )
    return out


def _load_dir_bundle(
    path: Path,
    *,
    home: Path | str | None,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    provenance_lock: dict[str, dict[str, Any]] | None,
    as_given: str,
) -> SkillIR:
    home_p = _abs_norm(Path(home)) if home is not None else None
    label = home_label(path, home_p) if home_p is not None else as_given
    collected = _collect_bundle_files(path, ceilings=ceilings, diags=diags, root_label=label)

    files_payload = _read_collected_files(collected, ceilings=ceilings, diags=diags)
    fm_text = files_payload.resolve_skill_doc_text()

    identity = BundleIdentity(name=path.name, path=label, layout=LAYOUT_FLAT)
    source_kind = SOURCE_DIR
    if home_p is not None:
        # Categorized vs flat decided against the real tree position.
        skills_root = home_p / "skills"
        try:
            rel_to_skills = path.resolve().relative_to(skills_root.resolve())
        except ValueError:
            rel_to_skills = None
        if rel_to_skills is not None and len(rel_to_skills.parts) >= 2:
            identity = BundleIdentity(
                name=path.name,
                category=rel_to_skills.parts[0],
                path=label,
                layout=LAYOUT_CATEGORIZED,
            )
            quarantine_root = (skills_root / _HUB_DIRNAME / _QUARANTINE_DIRNAME).resolve()
            try:
                path.resolve().relative_to(quarantine_root)
                source_kind = SOURCE_QUARANTINE
            except ValueError:
                pass

    ref = BundleRef(
        name=identity.name,
        category=identity.category,
        path=path,
        label=label,
        layout=identity.layout,
        source_kind=source_kind,
    )
    provenance = None
    if home_p is not None:
        lock = (
            provenance_lock
            if provenance_lock is not None
            else read_hub_lock(home_p, diagnostics=diags)
        )
        provenance = enrich_provenance(ref, lock)

    frontmatter = _resolve_frontmatter_or_fallback(
        fm_text, fallback_name=identity.name, diags=diags
    )
    claims = (
        extract_all_claims(
            frontmatter,
            manifest_path=files_payload.resolve_skill_doc_rel(),
            skill_md_text=fm_text,
        )
        if frontmatter is not None
        else ()
    )
    if frontmatter is not None and frontmatter.name != identity.name:
        diags.warning(
            CODE_FRONT_NAME_MISMATCH,
            f"frontmatter name {frontmatter.name!r} does not match "
            f"directory name {identity.name!r}",
            path=f"{label}/{_SKILL_DOC}",
        )

    return SkillIR(
        identity=identity,
        source_kind=source_kind,
        bundle_hash=compute_bundle_hash(files_payload.hash_inputs),
        files=tuple(files_payload.records),
        provenance=provenance,
        frontmatter=frontmatter,
        claims=claims,
        decoded_views=(),
        notes=tuple(files_payload.notes),
        diagnostics=diags,
    )


# ---------------------------------------------------------------------------
# File reading, hashing, record building
# ---------------------------------------------------------------------------


@dataclass
class _FilesPayload:
    records: list[FileRecord] = field(default_factory=list)
    hash_inputs: list[tuple[str, bytes]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skill_doc_candidates: list[tuple[str, str]] = field(default_factory=list)

    def total_member_bytes(self) -> int:
        """Bytes already absorbed (zip-path cumulative cap accounting)."""
        return sum(len(data) for _rel, data in self.hash_inputs)

    def note_skill_doc(self, rel_path: str, text: str) -> None:
        """Register a SKILL.md text candidate under the manifest-doc rule.

        Bundles may nest SKILL.md files (zips especially); the manifest is
        the SHALLOWEST candidate, ties broken by smallest rel path — a
        deterministic total order.
        """
        depth = rel_path.count("/")
        for existing_rel, _existing_text in self.skill_doc_candidates:
            existing_depth = existing_rel.count("/")
            if (existing_depth, existing_rel) <= (depth, rel_path):
                return
        self.skill_doc_candidates.append((rel_path, text))

    def resolve_skill_doc_text(self) -> str | None:
        if not self.skill_doc_candidates:
            return None
        return min(self.skill_doc_candidates, key=lambda item: (item[0].count("/"), item[0]))[1]

    def resolve_skill_doc_rel(self) -> str:
        """Rel-path of the shallowest SKILL.md candidate (display label)."""
        if not self.skill_doc_candidates:
            return _SKILL_DOC
        return min(self.skill_doc_candidates, key=lambda item: (item[0].count("/"), item[0]))[0]


def _read_collected_files(
    collected: _Collected,
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
) -> _FilesPayload:
    """Read/hash/classify collected files into FileRecords (sorted, capped)."""
    payload = _FilesPayload()
    for rel_path, abs_path in sorted(collected.files, key=lambda item: item[0]):
        cap = ceilings.max_file_bytes
        try:
            with open(abs_path, "rb") as fh:
                data = fh.read(cap + 1)
        except OSError as exc:
            diags.warning(
                CODE_INGEST_READ,
                f"file unreadable ({exc.strerror}); recorded without content",
                path=rel_path,
            )
            continue
        partial = False
        if len(data) > cap:
            data = data[:cap]
            partial = True
            note = f"partial_analysis: {rel_path} projected to first {cap} bytes"
            payload.notes.append(note)
            diags.warning(
                CODE_INGEST_FILE_SIZE,
                f"single-file ceiling ({cap} bytes) exceeded; bounded projection applied",
                path=rel_path,
            )
        encoding, text = detect_encoding(data)
        if encoding == ENCODING_LOSSY:
            diags.warning(
                CODE_INGEST_ENCODING,
                "file is not valid UTF-8; decoded lossily (replacement characters)",
                path=rel_path,
            )
        elif encoding == ENCODING_BINARY:
            diags.info(
                CODE_INGEST_ENCODING,
                "binary file recorded by hash only (no text view)",
                path=rel_path,
            )
        role, language = classify_file(rel_path)
        payload.records.append(
            FileRecord(
                path=rel_path,
                size=len(data),
                sha256="sha256:" + hashlib.sha256(data).hexdigest(),
                encoding=encoding,
                role=role,
                language=language,
                partial=partial,
                path_labels=(PATH_LABEL_INSIDE_SKILL_ROOT,),
            )
        )
        payload.hash_inputs.append((rel_path, data))
        if Path(rel_path).name == _SKILL_DOC:
            if text is not None:
                payload.note_skill_doc(rel_path, text)
            else:
                diags.warning(
                    CODE_INGEST_ENCODING,
                    "SKILL.md is binary; frontmatter not parsed",
                    path=rel_path,
                )
    return payload


def compute_bundle_hash(hash_inputs: list[tuple[str, bytes]]) -> str | None:
    """Canonical ``sha256:<hex>`` over sorted ``(rel_path, file_bytes)`` (D-HASH).

    Empty bundles hash the empty input deterministically rather than returning
    ``None`` so degraded scans stay comparable run-to-run.
    """
    digest = hashlib.sha256()
    for rel_path, data in sorted(hash_inputs, key=lambda item: item[0]):
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return "sha256:" + digest.hexdigest()


def _resolve_frontmatter_or_fallback(
    text: str | None,
    *,
    fallback_name: str,
    diags: DiagnosticsCollector,
) -> ResolvedFrontmatter:
    """Frontmatter resolution that always yields a usable manifest section."""
    if text is None:
        return ResolvedFrontmatter(
            name=fallback_name,
            validation_errors=("SKILL.md missing, unreadable, or not valid text",),
        )
    mapping = split_frontmatter(text, diagnostics=diags)
    if mapping is None:
        return ResolvedFrontmatter(
            name=fallback_name,
            validation_errors=("frontmatter missing or unparsable",),
        )
    resolved = build_frontmatter(mapping, fallback_name=fallback_name, diagnostics=diags)
    description_line = _locate_description_line(text)
    if description_line is not None:
        resolved = ResolvedFrontmatter(
            name=resolved.name,
            description_raw=resolved.description_raw,
            description_line=description_line,
            allowed_tools=resolved.allowed_tools,
            compatibility=resolved.compatibility,
            vendor_fields=resolved.vendor_fields,
            hermes=resolved.hermes,
            validation_errors=resolved.validation_errors,
            unknown_fields=resolved.unknown_fields,
        )
    return resolved


def _locate_description_line(text: str) -> int | None:
    """1-based line of the ``description`` key inside the frontmatter block.

    Pure text scan (no YAML round-trip): first block line whose stripped form
    starts with ``description:``. ``None`` when absent — LNS-MAN-004 evidence
    locations degrade to path-only spans honestly.
    """
    lines = text.splitlines()
    end = len(lines)
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end = idx
            break
    for idx in range(0, min(end, len(lines))):
        stripped = lines[idx].strip()
        if stripped.startswith("description") and ":" in stripped:
            return idx + 1
    return None


# ---------------------------------------------------------------------------
# Single SKILL.md target
# ---------------------------------------------------------------------------


def _load_single_skill_doc(
    path: Path,
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    as_given: str,
) -> SkillIR:
    try:
        data = path.read_bytes()[: ceilings.max_file_bytes]
    except OSError as exc:
        diags.error(CODE_INGEST_READ, f"SKILL.md unreadable: {exc.strerror}", path=as_given)
        data = b""
    payload = _FilesPayload()
    if data:
        _absorb_inline(payload, [(_SKILL_DOC, data)], ceilings=ceilings, diags=diags)
    fm_text = payload.resolve_skill_doc_text()
    frontmatter = _resolve_frontmatter_or_fallback(
        fm_text,
        fallback_name=path.parent.name or _SKILL_DOC,
        diags=diags,
    )
    claims = (
        extract_all_claims(
            frontmatter,
            manifest_path=payload.resolve_skill_doc_rel(),
            skill_md_text=fm_text,
        )
        if frontmatter is not None
        else ()
    )
    if frontmatter is not None and frontmatter.name != (path.parent.name or _SKILL_DOC):
        diags.warning(
            CODE_FRONT_NAME_MISMATCH,
            f"frontmatter name {frontmatter.name!r} does not match "
            f"parent directory {(path.parent.name or '/')!r}",
            path=as_given,
        )
    return SkillIR(
        identity=BundleIdentity(
            name=path.parent.name or _SKILL_DOC,
            path=as_given,
            layout=LAYOUT_SINGLE_FILE,
        ),
        source_kind=SOURCE_DIR,
        bundle_hash=compute_bundle_hash(payload.hash_inputs),
        files=tuple(payload.records),
        frontmatter=frontmatter,
        claims=claims,
        notes=tuple(payload.notes),
        diagnostics=diags,
    )


def _absorb_inline(
    payload: _FilesPayload,
    members: list[tuple[str, bytes]],
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
) -> None:
    """Hash/classify already-in-memory members (shared by single-file path).

    Zip members go through :func:`_record_member`, which performs the same
    duties with projection support; this helper covers the simple case where
    content fits (single SKILL.md is pre-capped by the caller).
    """
    for rel_path, data in sorted(members, key=lambda item: item[0]):
        _record_member(payload, rel_path, data, ceilings=ceilings, diags=diags, partial=False)


def _record_member(
    payload: _FilesPayload,
    rel_path: str,
    data: bytes,
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    partial: bool,
) -> None:
    encoding, text = detect_encoding(data)
    if encoding == ENCODING_LOSSY:
        diags.warning(
            CODE_INGEST_ENCODING,
            "file is not valid UTF-8; decoded lossily (replacement characters)",
            path=rel_path,
        )
    elif encoding == ENCODING_BINARY:
        diags.info(
            CODE_INGEST_ENCODING,
            "binary file recorded by hash only (no text view)",
            path=rel_path,
        )
    role, language = classify_file(rel_path)
    payload.records.append(
        FileRecord(
            path=rel_path,
            size=len(data),
            sha256="sha256:" + hashlib.sha256(data).hexdigest(),
            encoding=encoding,
            role=role,
            language=language,
            partial=partial,
            path_labels=(PATH_LABEL_INSIDE_SKILL_ROOT,),
        )
    )
    payload.hash_inputs.append((rel_path, data))
    if Path(rel_path).name == _SKILL_DOC:
        if text is not None:
            payload.note_skill_doc(rel_path, text)
        else:
            diags.warning(
                CODE_INGEST_ENCODING,
                "SKILL.md is binary; frontmatter not parsed",
                path=rel_path,
            )


# ---------------------------------------------------------------------------
# Zip targets (in-memory, size-capped per SPEC §5.1)
# ---------------------------------------------------------------------------


def _load_zip_bundle(
    path: Path,
    *,
    ceilings: Ceilings,
    diags: DiagnosticsCollector,
    as_given: str,
) -> SkillIR:
    payload = _FilesPayload()
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            infos.sort(key=lambda info: info.filename)
            seen_members = 0
            for info in infos:
                name = info.filename
                parts = name.split("/")
                if any(part.startswith(".") for part in parts[:-1]):
                    continue  # dot-path packaging metadata (D-011 rule)
                base = parts[-1]
                if not base or base.startswith("."):
                    continue
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    diags.warning(
                        CODE_INGEST_SYMLINK,
                        "symlinked zip member not ingested",
                        path=name,
                    )
                    continue
                if seen_members >= ceilings.max_files:
                    diags.warning(
                        CODE_INGEST_FILE_CAP,
                        f"file-count ceiling ({ceilings.max_files}) reached; "
                        "remaining members not ingested",
                        path=name,
                    )
                    break
                declared = max(info.file_size, 0)
                read_n = min(declared, ceilings.max_file_bytes)
                try:
                    with zf.open(info) as member_fh:
                        data = member_fh.read(read_n)
                except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
                    diags.warning(
                        CODE_INGEST_ZIP,
                        f"zip member unreadable ({exc.__class__.__name__}); skipped",
                        path=name,
                    )
                    continue
                actual_partial = len(data) < declared or declared > ceilings.max_file_bytes
                if len(data) > ceilings.max_file_bytes:
                    data = data[: ceilings.max_file_bytes]
                    actual_partial = True
                if payload.total_member_bytes() + len(data) > ceilings.max_total_bytes:
                    diags.warning(
                        CODE_INGEST_SIZE_CAP,
                        f"canonical bytes ceiling ({ceilings.max_total_bytes}) reached; "
                        "remaining members not ingested",
                        path=name,
                    )
                    break
                partial = actual_partial
                if partial:
                    note = f"partial_analysis: {name} projected to first {len(data)} bytes"
                    payload.notes.append(note)
                    diags.warning(
                        CODE_INGEST_FILE_SIZE,
                        "member exceeds single-file ceiling; bounded projection applied",
                        path=name,
                    )
                _record_member(payload, name, data, ceilings=ceilings, diags=diags, partial=partial)
                seen_members += 1
    except zipfile.BadZipFile:
        diags.error(CODE_INGEST_ZIP, "not a readable zip archive", path=as_given)
    except OSError as exc:
        diags.error(CODE_INGEST_ZIP, f"zip unreadable: {exc.strerror}", path=as_given)

    fm_text = payload.resolve_skill_doc_text()
    frontmatter = _resolve_frontmatter_or_fallback(
        fm_text,
        fallback_name=Path(as_given).stem or path.stem,
        diags=diags,
    )
    return SkillIR(
        identity=BundleIdentity(
            name=Path(as_given).stem or path.stem,
            path=as_given,
            layout=LAYOUT_FLAT,
        ),
        source_kind=SOURCE_ZIP,
        bundle_hash=compute_bundle_hash(payload.hash_inputs),
        files=tuple(payload.records),
        frontmatter=frontmatter,
        claims=extract_all_claims(
            frontmatter,
            manifest_path=payload.resolve_skill_doc_rel(),
            skill_md_text=fm_text,
        )
        if frontmatter is not None
        else (),
        notes=tuple(payload.notes),
        diagnostics=diags,
    )
