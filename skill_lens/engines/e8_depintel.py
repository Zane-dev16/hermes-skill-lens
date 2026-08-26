"""E8 depintel engine — dependency-manifest supply-chain intel (SPEC §4 row E8).

Scope per the §4 catalog row and §17 R8 ("malicious dependency · offline
heuristic; --osv closes opt-in"):

- **LNS-DEP-001** unpinned-dependency notes over ``requirements*.txt``,
  ``pyproject.toml`` ([project] dependencies + optional-dependencies +
  [tool.poetry.dependencies]) and ``package.json`` (dependencies,
  devDependencies, optionalDependencies): a dependency whose spec carries NO
  version information resolves to whatever publishes next — the classic
  supply-chain hijack surface. LOW severity hygiene note, ``static_only``
  (pure structural fact).
- **LNS-DEP-002** typosquat heuristics OFFLINE: every declared name is
  compared against a bundled allowlist of top-known packages per ecosystem.
  Fires when a name is (a) a homoglyph/confusable form of a known package
  (reuses the E2 TR39-style :func:`skeleton` table, D-037), (b) a leet
  spelling (``requ3sts``), or (c) within edit distance ≤ 2 of exactly the
  kind of near-miss typosquats register to harvest mistyped installs.
  MEDIUM heuristic cap per D-FP (uncorroborated heuristics never exceed
  MED); evidence_kind ``heuristic`` at the weak-evidence confidence band.
- **LNS-DEP-003** npm install lifecycle hooks (``preinstall``/``install``/
  ``postinstall``) declared in package.json scripts: these execute at
  INSTALL time on any consumer that runs npm against the bundle —
  demonstrated execution surface, hence ``static_only=false``. The engine
  raises confidence when the script body matches download-and-execute
  shapes (D-036 explicitly deferred package.json hooks here).

NETWORK LAW: this engine is pure static analysis and NEVER touches the
network. OSV.dev enrichment lives in :mod:`skill_lens.enrich.osv`, which is
LAZY-imported only inside the explicit ``--osv`` flagged codepath (SPEC §14
G1/G2/G3) — the default closure never imports it.

Determinism: findings sort by ``(rule_id, path, start_line)``; fingerprints
bind normalized package identities and command SHAPES — never line numbers
or absolute paths. Allowlists are bundled sorted tuples; no wall clock, no
randomness, no environment reads.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import TYPE_CHECKING

from ..claims import finding_fingerprint
from ..ir import SkillIR
from .base import (
    Finding,
    Location,
    ScanContext,
    finding_sort_key,
    iter_text_files,
)
from .e2_textinject import safe_text, skeleton

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "depintel"

#: Rules implemented here — pack rules bound to ``depintel`` but missing
#: from this tuple surface as LNS-ENG-001 diagnostics (never silence).
RULE_IDS: tuple[str, ...] = ("LNS-DEP-001", "LNS-DEP-002", "LNS-DEP-003")

#: Snippet/message sanitization clip (mirrors sibling engines' evidence caps).
_SNIPPET_MAX = 160

# ---------------------------------------------------------------------------
# Bundled allowlists — top-known packages per ecosystem (sorted tuples).
# Deliberately CONSERVATIVE breadth: a name absent from these lists simply
# gets no squat verdict (advisor-safest); the lists exist to catch lookalikes
# of packages every skill author actually uses. Sorted for determinism.
# D-048 precision closure: the dev-toolchain/runtime staples below were
# absent while their own near-neighbors WERE listed, so e.g. `black` scored
# as a distance-2 near-miss of `click`/`flask`. Allowlist membership strictly
# reduces FPs and can only EXTEND squat coverage to lookalikes of the added
# names — no TP regression is possible by construction.
# ---------------------------------------------------------------------------

PYPI_TOP_PACKAGES: tuple[str, ...] = (
    "aiohttp",
    "anyio",
    "attrs",
    "beautifulsoup4",
    "black",
    "boto3",
    "certifi",
    "charset-normalizer",
    "click",
    "cryptography",
    "django",
    "fastapi",
    "flake8",
    "flask",
    "gunicorn",
    "h11",
    "httpcore",
    "httpx",
    "hypothesis",
    "idna",
    "isort",
    "jinja2",
    "markupsafe",
    "matplotlib",
    "mypy",
    "numpy",
    "openai",
    "packaging",
    "pandas",
    "pillow",
    "psutil",
    "psycopg2-binary",
    "pydantic",
    "pylint",
    "pytest",
    "python-dateutil",
    "python-dotenv",
    "pyyaml",
    "redis",
    "requests",
    "rich",
    "ruff",
    "scikit-learn",
    "scipy",
    "setuptools",
    "six",
    "sniffio",
    "sqlalchemy",
    "tomli",
    "tqdm",
    "typing-extensions",
    "urllib3",
    "uvicorn",
    "virtualenv",
    "wheel",
)

NPM_TOP_PACKAGES: tuple[str, ...] = (
    "@types/node",
    "axios",
    "chalk",
    "commander",
    "cross-env",
    "dotenv",
    "eslint",
    "express",
    "fs-extra",
    "glob",
    "jest",
    "lodash",
    "moment",
    "next",
    "node-fetch",
    "npm-run-all",
    "prettier",
    "react",
    "react-dom",
    "rimraf",
    "semver",
    "serialport",
    "socket.io",
    "ts-node",
    "typescript",
    "vue",
    "webpack",
    "yargs",
    "zod",
)

_ALLOWLISTS: dict[str, frozenset[str]] = {
    "pypi": frozenset(PYPI_TOP_PACKAGES),
    "npm": frozenset(NPM_TOP_PACKAGES),
}

#: Names shorter than this are never squat-evaluated: edit distance ≤ 2 from
#: a 1–3 char name spans most of the alphabet (FP magnet, zero signal).
_MIN_SQUAT_NAME_LEN = 4

#: Maximum edit distance that still counts as a typosquat lookalike.
_MAX_EDIT_DISTANCE = 2

#: Nearest neighbors cited per finding (deterministic top-k).
_CITE_NEAREST = 3

# ---------------------------------------------------------------------------
# Manifest parsers (pure text -> structured deps; stdlib only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DepRef:
    """One declared dependency, normalized for detection/fingerprinting."""

    name: str  # as written in the manifest
    ecosystem: str  # "pypi" | "npm"
    pinned: bool  # spec carries version info / direct reference
    spec: str  # raw version/spec text ("" when bare)
    source_path: str  # IR rel-path of the declaring manifest
    line: int | None  # resolved line (None degrades honestly)


@dataclass(frozen=True)
class ScriptHook:
    """One npm lifecycle script declaration (install-time execution)."""

    key: str  # preinstall | install | postinstall
    command: str
    source_path: str
    line: int | None


_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQ_LINE_SKIP_RE = re.compile(r"^\s*(?:-r|--requirement|-c|--constraint|#|$)")
_VCS_PREFIXES = ("git+", "http://", "https://", "svn+", "bzr+")

_LIFECYCLE_KEYS: tuple[str, ...] = ("preinstall", "install", "postinstall")


def _pip_unpinned(spec_text: str) -> bool:
    """PEP 508 spec unpinned iff the post-name remainder names NO version.

    A remainder with no digit and no direct reference (``@ url``) floats:
    bare names, extras-only specs, marker-only specs. Comparators (``==``,
    ``>=``, ``~=``, …) all carry digits by grammar. VCS/direct URLs pin by
    reference (advisor-conservative: local wheels and locked checkouts are
    exact artifacts; flagging them would drown the signal).
    """
    body = spec_text.split(";", 1)[0].strip()  # markers never pin anything
    if "@" in body:
        return False
    return not any(ch.isdigit() for ch in body)


def parse_requirements_text(text: str, source_path: str) -> list[DepRef]:
    """requirements*.txt lines -> DepRefs (line numbers natural)."""
    refs: list[DepRef] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or _REQ_LINE_SKIP_RE.match(line):
            continue
        stripped = line[2:].strip() if line.startswith("-e ") else line
        if stripped.startswith(_VCS_PREFIXES):
            continue  # VCS URL lines: name extraction unreliable — stay silent
        match = _PEP508_NAME_RE.match(stripped)
        if match is None:
            continue
        name = match.group(1)
        spec = stripped[match.end() :].strip()
        refs.append(
            DepRef(
                name=name,
                ecosystem="pypi",
                pinned=not _pip_unpinned(spec),
                spec=spec,
                source_path=source_path,
                line=lineno,
            )
        )
    return refs


def parse_pyproject_text(text: str, source_path: str) -> list[DepRef]:
    """pyproject.toml dependencies (PEP 621 + Poetry table) -> DepRefs.

    tomllib loses positions, so lines re-resolve by searching for the verbatim
    spec/key text (first occurrence wins — deterministic). Unparsable TOML
    yields nothing here; ingest already owns the parse diagnostic.
    """
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError):
        return []
    entries: list[tuple[str, str, str]] = []  # (name, spec, search_needle)
    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for spec in deps:
                if isinstance(spec, str) and (match := _PEP508_NAME_RE.match(spec.strip())):
                    entries.append((match.group(1), spec.strip(), f'"{spec.strip()}"'))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in sorted(optional):
                group_deps = optional[group]
                if isinstance(group_deps, list):
                    for spec in group_deps:
                        if isinstance(spec, str) and (m := _PEP508_NAME_RE.match(spec.strip())):
                            entries.append((m.group(1), spec.strip(), f'"{spec.strip()}"'))
    poetry = data.get("tool")
    if isinstance(poetry, dict):
        poetry = poetry.get("poetry")
    if isinstance(poetry, dict):
        poetry_deps = poetry.get("dependencies")
        if isinstance(poetry_deps, dict):
            for name in sorted(poetry_deps):
                if name == "python":
                    continue
                constraint = poetry_deps[name]
                spec = constraint if isinstance(constraint, str) else ""
                entries.append((name, spec, f"{name} ="))

    lines = text.splitlines()
    refs: list[DepRef] = []
    for name, spec, needle in entries:
        refs.append(
            DepRef(
                name=name,
                ecosystem="pypi",
                pinned=not _poetry_or_pip_unpinned(name, spec),
                spec=spec,
                source_path=source_path,
                line=_find_line(lines, needle),
            )
        )
    return refs


def _poetry_or_pip_unpinned(name: str, spec: str) -> bool:
    """Unpinned verdict shared by PEP 508 strings and Poetry constraints."""
    if not spec:
        return True
    if "@" in spec:
        return False
    body = spec.split(";", 1)[0].strip()
    remainder = body[len(name) :] if body.startswith(name) else body
    if remainder.startswith(("^", "~=", "~")):
        return False  # caret/tilde ranges anchor a concrete base version
    return not any(ch.isdigit() for ch in remainder)


def parse_package_json_text(text: str, source_path: str) -> tuple[list[DepRef], list[ScriptHook]]:
    """package.json -> (dependency DepRefs, lifecycle ScriptHooks).

    Scope per §4 row E8: the dep fields the bundle DECLARES for itself
    (dependencies/devDependencies/optionalDependencies — peerDependencies
    constrain consumers, not this install) plus the three install-time
    lifecycle script keys (D-036 deferred exactly this here). Malformed JSON
    parses to nothing (ingest owns the diagnostic; advisor stays silent).
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeError, ValueError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    lines = text.splitlines()
    refs: list[DepRef] = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name in sorted(block):
            spec = block[name]
            spec_text = spec if isinstance(spec, str) else ""
            refs.append(
                DepRef(
                    name=str(name),
                    ecosystem="npm",
                    pinned=not _npm_unpinned(spec_text),
                    spec=spec_text,
                    source_path=source_path,
                    line=_find_line(lines, f'"{name}"'),
                )
            )
    hooks: list[ScriptHook] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in _LIFECYCLE_KEYS:
            command = scripts.get(key)
            if isinstance(command, str) and command.strip():
                hooks.append(
                    ScriptHook(
                        key=key,
                        command=command,
                        source_path=source_path,
                        line=_find_line(lines, f'"{key}"'),
                    )
                )
    return refs, hooks


def _npm_unpinned(spec_text: str) -> bool:
    """npm range unpinned iff it carries NO concrete version digits.

    ``*``, ``latest``, ``x``, empty, dist-tags and unhashed git/hosted URLs
    all float; ``^1.2.3``/``~1.2.3``/``1.2.x`` anchor real versions and stay
    pinned enough for an advisory note (they cannot silently jump major
    ecosystems the way a tag-less float can).
    """
    stripped = spec_text.strip()
    if not stripped or stripped in ("*", "latest", "x", "X"):
        return True
    return not any(ch.isdigit() for ch in stripped)


def _find_line(lines: list[str], needle: str) -> int | None:
    """First 1-based line containing *needle*, or None (honest degrade)."""
    if not needle:
        return None
    for lineno, line in enumerate(lines, start=1):
        if needle in line:
            return lineno
    return None


# ---------------------------------------------------------------------------
# LNS-DEP-002 — offline typosquat heuristics
# ---------------------------------------------------------------------------

#: Leet spellings collapse before allowlist comparison (classic squat trick).
_DELEET_TABLE = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}
)


def _edit_distance_at_most(left: str, right: str, limit: int) -> int:
    """Damerau-Levenshtein (OSA) distance, early-exit above *limit*.

    Bounded DP over short identifier strings; returns ``limit + 1`` once the
    distance provably exceeds *limit* so allowlist sweeps stay cheap.
    """
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    prev_prev: list[int] | None = None
    prev = list(range(len(right) + 1))
    for i, lch in enumerate(left, start=1):
        cur = [i] + [0] * len(right)
        row_min = i
        for j, rch in enumerate(right, start=1):
            cost = 0 if lch == rch else 1
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (
                prev_prev is not None
                and i > 1
                and j > 1
                and lch == right[j - 2]
                and left[i - 2] == rch
            ):
                best = min(best, prev_prev[j - 2] + 1)
            cur[j] = best
            row_min = min(row_min, best)
        if row_min > limit:
            return limit + 1
        prev_prev, prev = prev, cur
    return prev[-1]


def nearest_known_names(name: str, ecosystem: str) -> list[tuple[int, str]]:
    """Allowlist entries within :data:`_MAX_EDIT_DISTANCE`, nearest-first.

    Deterministic order: ``(distance, name)`` ascending, capped at
    :data:`_CITE_NEAREST`. Empty when the name IS known or nothing is close.
    """
    lowered = name.casefold()
    known = _ALLOWLISTS.get(ecosystem)
    if known is None or lowered in known:
        return []
    hits: list[tuple[int, str]] = []
    for entry in sorted(known):
        distance = _edit_distance_at_most(lowered, entry, _MAX_EDIT_DISTANCE)
        if distance <= _MAX_EDIT_DISTANCE:
            hits.append((distance, entry))
    hits.sort()
    return hits[:_CITE_NEAREST]


def typosquat_verdict(name: str, ecosystem: str) -> tuple[str, str, list[str]] | None:
    """``(kind, canonical_target, cited_names)`` squat shape, or None.

    Precedence: confusable skeleton (homoglyph) > leet collapse > edit
    distance. All three are offline, deterministic name-shape facts.
    """
    lowered = name.casefold()
    known = _ALLOWLISTS.get(ecosystem)
    if known is None or len(lowered.strip()) < _MIN_SQUAT_NAME_LEN:
        return None
    skel = skeleton(name)
    if skel != lowered and skel in known:
        return ("confusable", skel, [skel])
    deleeted = lowered.translate(_DELEET_TABLE)
    if deleeted != lowered and deleeted in known:
        return ("leet", deleeted, [deleeted])
    near = nearest_known_names(lowered, ecosystem)
    if near:
        return ("near-miss", near[0][1], [entry for _, entry in near])
    return None


# ---------------------------------------------------------------------------
# LNS-DEP-003 — install-script danger shapes (confidence refinement only;
# severity stays the rule-assigned MED cap per D-FP).
# ---------------------------------------------------------------------------

_DOWNLOAD_EXEC_RE = re.compile(
    r"(?i)(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh|python3?)\b"
    r"|\bnode\s+(?:-e|--eval)\b"
    r"|\bpowershell\s+-enc\b"
    r"|\biwr\b.*\|\s*iex\b"
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DepIntelEngine:
    """E8 depintel — dependency manifests, offline squats, lifecycle hooks."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:  # noqa: ARG002
        dep001 = self._rules.get("LNS-DEP-001")
        dep002 = self._rules.get("LNS-DEP-002")
        dep003 = self._rules.get("LNS-DEP-003")
        findings: list[Finding] = []
        for record, text in iter_text_files(bundle_ir, ctx):
            basename = record.path.rsplit("/", 1)[-1]
            if fnmatch(basename, "requirements*.txt"):
                refs = parse_requirements_text(text, record.path)
                hooks: list[ScriptHook] = []
            elif basename == "pyproject.toml":
                refs = parse_pyproject_text(text, record.path)
                hooks = []
            elif basename == "package.json":
                refs, hooks = parse_package_json_text(text, record.path)
            else:
                continue
            if dep001 is not None:
                findings.extend(self._unpinned_findings(dep001, refs))
            if dep002 is not None:
                findings.extend(self._typosquat_findings(dep002, refs))
            if dep003 is not None:
                findings.extend(self._lifecycle_findings(dep003, hooks))
        findings.sort(key=finding_sort_key)
        return findings

    # -- LNS-DEP-001 ----------------------------------------------------------

    def _unpinned_findings(self, rule: Rule, refs: list[DepRef]) -> list[Finding]:
        seen: set[str] = set()
        findings: list[Finding] = []
        for ref in refs:
            if ref.pinned:
                continue
            key = f"{ref.ecosystem}:{ref.name.casefold()}"
            if key in seen:  # cross-file copies collapse via shared fingerprint
                continue
            seen.add(key)
            detail = {"ecosystem": ref.ecosystem, "package": ref.name.casefold()}
            findings.append(
                Finding(
                    fingerprint=finding_fingerprint(
                        rule.id, rule.capability, f"{ref.ecosystem}:unpinned:{ref.name.casefold()}"
                    ),
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
                    location=self._location(ref.source_path, ref.line, rule),
                    message=(
                        f"{ref.ecosystem} dependency '{ref.name}' declares no version pin "
                        "(floating install target)"
                    ),
                    remediation=rule.remediation,
                    tags=tuple(rule.tags) + (f"ecosystem:{ref.ecosystem}",),
                    detail=(detail,),
                )
            )
        return findings

    # -- LNS-DEP-002 ----------------------------------------------------------

    def _typosquat_findings(self, rule: Rule, refs: list[DepRef]) -> list[Finding]:
        seen: set[str] = set()
        findings: list[Finding] = []
        for ref in refs:
            verdict = typosquat_verdict(ref.name, ref.ecosystem)
            if verdict is None:
                continue
            kind, target, cited = verdict
            key = f"{ref.ecosystem}:{ref.name.casefold()}:{kind}:{target}"
            if key in seen:
                continue
            seen.add(key)
            if kind == "confusable":
                message = (
                    f"Dependency name '{ref.name}' is a homoglyph/confusable form of "
                    f"'{target}' ({ref.ecosystem})"
                )
            elif kind == "leet":
                message = (
                    f"Dependency name '{ref.name}' is a leet spelling of "
                    f"'{target}' ({ref.ecosystem})"
                )
            else:
                message = (
                    f"Dependency name '{ref.name}' is within edit distance "
                    f"{_MAX_EDIT_DISTANCE} of '{target}' ({ref.ecosystem}) — "
                    "possible typosquat"
                )
            detail = {
                "ecosystem": ref.ecosystem,
                "package": ref.name.casefold(),
                "squat_kind": kind,
                "nearest_known": sorted(cited),
            }
            findings.append(
                Finding(
                    fingerprint=finding_fingerprint(rule.id, rule.capability, key),
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
                    location=self._location(ref.source_path, ref.line, rule),
                    message=message,
                    remediation=rule.remediation,
                    tags=tuple(rule.tags) + (f"squat:{kind}", f"ecosystem:{ref.ecosystem}"),
                    detail=(detail,),
                )
            )
        return findings

    # -- LNS-DEP-003 ----------------------------------------------------------

    def _lifecycle_findings(self, rule: Rule, hooks: list[ScriptHook]) -> list[Finding]:
        findings: list[Finding] = []
        for hook in hooks:
            dangerous = bool(_DOWNLOAD_EXEC_RE.search(hook.command))
            confidence = 0.97 if dangerous else rule.confidence_default
            normalized = " ".join(hook.command.split()).casefold()[:96]
            message = (
                f"npm lifecycle hook '{hook.key}' declares commands that run at "
                "INSTALL time on consumers"
            )
            if dangerous:
                message += "; script body matches a download-and-execute pattern"
            detail = {
                "ecosystem": "npm",
                "package": "",
                "script_hook": hook.key,
                "dangerous_body": dangerous,
            }
            findings.append(
                Finding(
                    fingerprint=finding_fingerprint(
                        rule.id,
                        rule.capability,
                        f"npm:lifecycle-hook:{hook.key}:{normalized}",
                    ),
                    rule_id=rule.id,
                    rule_version=rule.rule_version,
                    engine=rule.engine,
                    title=rule.title,
                    capability=rule.capability,
                    severity=rule.severity,
                    effective_severity=rule.severity,
                    confidence=confidence,
                    evidence_kind=rule.evidence_kind,
                    static_only=rule.static_only,
                    location=Location(
                        path=hook.source_path,
                        start_line=hook.line,
                        end_line=hook.line,
                        snippet=safe_text(hook.command.strip())[:_SNIPPET_MAX],
                        redacted=False,
                    ),
                    message=message,
                    remediation=rule.remediation,
                    tags=tuple(rule.tags) + (f"hook:{hook.key}",),
                    detail=(detail,),
                )
            )
        return findings

    @staticmethod
    def _location(path: str, line: int | None, rule: Rule) -> Location:
        return Location(
            path=path,
            start_line=line,
            end_line=line,
            snippet="",
            redacted=False,
        )


__all__ = [
    "ENGINE_NAME",
    "NPM_TOP_PACKAGES",
    "PYPI_TOP_PACKAGES",
    "RULE_IDS",
    "DepIntelEngine",
    "DepRef",
    "ScriptHook",
    "nearest_known_names",
    "parse_package_json_text",
    "parse_pyproject_text",
    "parse_requirements_text",
    "typosquat_verdict",
]
