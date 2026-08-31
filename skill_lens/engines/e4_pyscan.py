"""E4 pyscan engine — Python AST behavior scan with first-class degradation.

Detection per core-pack rule specs (rule YAMLs are normative; SPEC §4 row E4;
§17 rows R3/R4/R6/R7/R11/H1/H2/H5/H6/H9). Two modes over every recorded
``*.py`` file, selected ONLY by ``ParserGateway.parse`` outcome mode
(D-PARSE: engines branch on mode/tree, never on reason codes):

- **AST mode** (grammar active): tree-sitter walks collect import aliases,
  string assignments, and call sites; sink predicates evaluate against
  resolved callees with same-file source→sink dataflow (the §7 v0.9
  reachability bar). Evidence ``ast``, rule-default confidence band.
- **Degraded mode** (any degradation cause): the golden-tested line-scanner
  fallback consumes :func:`skill_lens.parsing.line_tokens` ONLY — regex
  heuristics matching the SAME rule ids with evidence_kind ``regex`` and a
  visibly weaker confidence cap (D-PARSE: never silently equal).

Rule map (ids owned here):

- **LNS-PYS-001** ``exec``/``eval`` over a non-literal argument (dynamic
  code execution sink). Literal-string arguments stay silent — the code is
  reviewable as-is.
- **LNS-PYS-002** encoded-payload chains: ``base64.b64decode`` /
  ``zlib.decompress`` / ``codecs.decode`` results flowing (directly or via
  same-file assignments) into ``exec``/``eval``/``os.system``/
  ``subprocess``/``__import__``.
- **LNS-PYS-003** interpreter-mediated shell sinks: ``os.system``/``popen``,
  ``subprocess.*(..., shell=True)``, ``sh -c``-style argv lists, and the
  ``getoutput`` family. Fixed argv lists without ``shell=True`` never fire
  (the declared-capability safe pattern).
- **LNS-PYS-004** sensitive-source→network-send flow: environment reads,
  file reads, or their same-file assignees reaching ``requests.post`` /
  ``urlopen(data=…)`` / socket sends (R3 exfil shape).
- **LNS-PYS-005** Hermes-state persona/memory writes at AST fidelity
  (``agent_home:<sub>`` labels through the §5.1 normalization primitive).
- **LNS-PYS-006** agent-cron state writes (``cron/jobs.json``).
- **LNS-PYS-007** control-plane/gateway/skill-tree writes (config.yaml,
  channel_directory.json, pairing/**, skills/**). Engine-side escalation: a
  ``platform_disabled`` token anywhere in the file escalates effective
  severity toward CRITICAL (mirrors SHL-006; no benign authoring story).
- **LNS-PYS-008** recursive/delete sinks aimed outside the skill root
  (``shutil.rmtree``/``os.remove`` family; R11), unknown-variable targets at
  the §4 reduced confidence.

DETERMINISM LAW: evidence tokens carry shapes and basenames only — no line
numbers, no absolute paths, no wall-clock. Both modes emit the SAME
fingerprint vocabulary for the same detection content, so active-vs-degraded
parity is provable down to fingerprint equality (tests pin this).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..claims import finding_fingerprint, is_declared
from ..ir import SkillIR
from ..parsing import GATEWAY, ParserGateway, line_tokens
from .base import (
    Finding,
    Location,
    ScanContext,
    claimed_capability_paths,
    iter_text_files,
)
from .e3_shellscan import (
    _PLATFORM_DISABLED_RE,
    PERSONA_BASENAMES,
    _persona_kind,
    classify_path_literal,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "pyscan"

RULE_IDS: tuple[str, ...] = (
    "LNS-PYS-001",
    "LNS-PYS-002",
    "LNS-PYS-003",
    "LNS-PYS-004",
    "LNS-PYS-005",
    "LNS-PYS-006",
    "LNS-PYS-007",
    "LNS-PYS-008",
)

#: Degraded-mode confidence ceiling: top of the §7 regex band so fallback
#: findings are VISIBLY weaker than ast-grade evidence, never silently equal.
DEGRADED_CONFIDENCE_CAP = 0.72

#: Reduced-confidence bands (§4 conservative treatment, mirroring E3 values).
REDUCED_CONFIDENCE_STATE = 0.70
REDUCED_CONFIDENCE_DELETE = 0.65

#: Same-file line window for the degraded source→sink pairing heuristic.
DEGRADED_FLOW_WINDOW = 15

_SNIPPET_MAX = 160


# ---------------------------------------------------------------------------
# Callee vocabularies (resolved dotted names, compared lowercased)
# ---------------------------------------------------------------------------

EXEC_SINKS = frozenset({"exec", "eval", "__import__"})
SHELL_DIRECT_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "commands.getoutput",
        "commands.getstatusoutput",
    }
)
_SUBPROCESS_TAILS = frozenset({"run", "call", "check_call", "check_output", "popen"})
_DECODE_SUFFIXES = ("b64decode", "decodebytes", "decodestring", "a2b_base64")
_DECODE_EXACT = frozenset({"zlib.decompress", "codecs.decode", "lzma.decompress"})
_ENV_READ_CALLS = frozenset({"os.environ.get", "os.getenv"})
_FILE_READ_TAILS = frozenset({"read", "readline", "readlines", "read_text", "read_bytes"})
_DELETE_SINKS = frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"})
_COPY_DEST_TAILS = frozenset({"replace", "rename", "copy", "copytree", "move"})
_WRITE_METHOD_TAILS = frozenset({"write_text", "write_bytes"})

_CRON_SUFFIX = "cron/jobs.json"
_CONFIG_BASENAMES = ("config.yaml", "channel_directory.json")
_SKILL_TREE_PREFIX = "skills/"

_INTERPRETER_BASE_RE = re.compile(r"^(?:ba|z|da|k|fi)?sh$", re.IGNORECASE)
_INTERPRETER_FLAG_C_RE = re.compile(r"^-[a-zA-Z]*c$", re.IGNORECASE)


def _is_interpreter_token(token: str) -> bool:
    """True for sh/bash/zsh/dash/ksh/fish, path-insensitive (``/bin/sh`` ok)."""
    base = token.strip().strip("\"'").rsplit("/", 1)[-1].lower()
    return bool(_INTERPRETER_BASE_RE.match(base))


def _tail(resolved: str | None) -> str:
    return (resolved or "").rsplit(".", 1)[-1]


def _is_decode_callee(resolved: str | None) -> bool:
    name = (resolved or "").lower()
    return name in _DECODE_EXACT or name.endswith(_DECODE_SUFFIXES)


# ---------------------------------------------------------------------------
# Shared routing (both modes converge here so fingerprints agree)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _StateHit:
    """One routed Hermes-state/delete sink occurrence."""

    rule_id: str
    evidence: str
    confidence: float | None  # None ⇒ rule default
    detail: str
    snippet_target: str


_STATE_BASENAME_ROUTES: tuple[tuple[str, str], ...] = (
    # (rule_id, evidence prefix) for reduced-confidence basename adjacency
    ("LNS-PYS-005", "hstate-write:unknown-path"),
    ("LNS-PYS-006", "cron-json-write"),
    ("LNS-PYS-007", "config-write"),
)


def _route_agent_home_sub(sub: str, basename: str) -> tuple[str | None, str]:
    """Map one ``agent_home:<sub>`` write to (rule_id, evidence token)."""
    if sub.endswith(_CRON_SUFFIX):
        return "LNS-PYS-006", "cron-json-write"
    if sub.startswith(_SKILL_TREE_PREFIX):
        return "LNS-PYS-007", f"skill-tree-write:{basename}".rstrip(":")
    if any(sub == b or sub.endswith(b) for b in _CONFIG_BASENAMES):
        return "LNS-PYS-007", f"config-write:{basename}"
    if sub.startswith("pairing/"):
        return "LNS-PYS-007", f"gateway-state-write:{basename}".rstrip(":")
    kind = _persona_kind(classify_path_literal(f"${{HERMES_HOME}}/{sub}"))
    if kind is not None:
        return "LNS-PYS-005", f"hstate-write:{kind}:{basename}".rstrip(":")
    return None, ""


def _reduced_basename_route(basename: str) -> _StateHit | None:
    """§4 conservative treatment: unknown-target writes near known state."""
    if basename in PERSONA_BASENAMES:
        return _StateHit(
            "LNS-PYS-005",
            f"hstate-write:unknown-path:{basename}",
            REDUCED_CONFIDENCE_STATE,
            f"unresolvable target adjacent to '{basename}'",
            basename,
        )
    if basename == "jobs.json":
        return _StateHit(
            "LNS-PYS-006",
            "cron-json-write",
            REDUCED_CONFIDENCE_STATE,
            "unresolvable cron-state target",
            basename,
        )
    if basename in _CONFIG_BASENAMES:
        return _StateHit(
            "LNS-PYS-007",
            f"config-write:{basename}",
            REDUCED_CONFIDENCE_STATE,
            f"unresolvable control-plane target '{basename}'",
            basename,
        )
    return None


def _route_candidates(candidates: list[str], *, env_marked: bool) -> list[_StateHit]:
    """Classify extracted write-target literals into state-write hits.

    Mirrors the §4 conservative treatment: resolvable ``agent_home:`` labels
    fire at full strength; unresolvable forms adjacent to known persona/cron/
    config basenames fire at reduced confidence — and only when an env/
    expansion marker co-occurs, so ordinary relative paths stay silent.
    """
    hits: list[_StateHit] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        token = candidate.strip().strip("\"'").strip()
        if not token:
            continue
        label = classify_path_literal(token)
        hit: _StateHit | None = None
        if label.is_agent_home:
            rule_id, evidence = _route_agent_home_sub(label.agent_sub, label.basename)
            if rule_id is not None:
                hit = _StateHit(rule_id, evidence, None, label.agent_sub, token)
        elif env_marked:
            hit = _reduced_basename_route(label.basename)
        key = (hit.rule_id, hit.evidence) if hit else ("", "")
        if hit is not None and key not in seen:
            seen.add(key)
            hits.append(hit)
    return hits


def _route_delete_targets(candidates: list[str]) -> list[_StateHit]:
    """Delete-sink routing: outside fires; unknown-var fires reduced."""
    hits: list[_StateHit] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        token = candidate.strip().strip("\"'").strip()
        if not token:
            continue
        label = classify_path_literal(token)
        hit: _StateHit | None = None
        if label.label == "outside":
            hit = _StateHit(
                "LNS-PYS-008",
                f"delete-outside:{label.detail}",
                None,
                f"target resolves outside ({label.detail})",
                token,
            )
        elif label.label == "unknown-var" and label.basename:
            hit = _StateHit(
                "LNS-PYS-008",
                "delete-outside:unknown-var",
                REDUCED_CONFIDENCE_DELETE,
                f"unresolvable variable target '{label.basename}'",
                token,
            )
        key = (hit.rule_id, hit.evidence) if hit else ("", "")
        if hit is not None and key not in seen:
            seen.add(key)
            hits.append(hit)
    return hits


def _state_message(rule_id: str, detail: str) -> str:
    if rule_id == "LNS-PYS-005":
        return (
            "Script writes agent persona/memory state ("
            f"{detail}) — prompt-injected every boot and durable past skill removal."
        )
    if rule_id == "LNS-PYS-006":
        return (
            "Script writes agent-cron state (cron/jobs.json) — one JSON write "
            "is recurring full-agent execution."
        )
    return (
        "Script writes agent control-plane/skill-tree state ("
        f"{detail}) — the knobs and surfaces gating permissions, platforms, "
        "and future behavior."
    )


class _FindingBuilder:
    """Per-file finding factory carrying the declared-discount inputs."""

    def __init__(
        self,
        rules: dict[str, Rule],
        rel_path: str,
        claimed: list[str],
        escalated: bool,
    ) -> None:
        self._rules = rules
        self._rel_path = rel_path
        self._claimed = claimed
        self._escalated = escalated

    def build(
        self,
        rule_id: str,
        lineno: int | None,
        end_lineno: int | None,
        snippet: str,
        evidence: str,
        message: str,
        *,
        confidence: float | None = None,
        extra_tags: tuple[str, ...] = (),
    ) -> Finding | None:
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        declared = is_declared(rule.capability, self._claimed)
        tags = rule.tags + (("declared-capability",) if declared else ()) + extra_tags
        eff_severity = "CRITICAL" if self._escalated and rule_id == "LNS-PYS-007" else rule.severity
        return Finding(
            fingerprint=finding_fingerprint(rule.id, rule.capability, evidence),
            rule_id=rule.id,
            rule_version=rule.rule_version,
            engine=rule.engine,
            title=rule.title,
            capability=rule.capability,
            severity=rule.severity,
            effective_severity=eff_severity,
            confidence=rule.confidence_default if confidence is None else confidence,
            evidence_kind=rule.evidence_kind,
            static_only=rule.static_only,
            declared=declared,
            location=Location(
                path=self._rel_path,
                start_line=lineno,
                end_line=end_lineno,
                snippet=snippet[:_SNIPPET_MAX],
                redacted=False,
            ),
            message=message,
            remediation=rule.remediation,
            tags=tuple(dict.fromkeys(tags)),
        )

    def degraded(self, finding: Finding) -> Finding:
        """Project one finding onto the regex-grade degraded contract."""
        rule = self._rules.get(finding.rule_id)
        cap = min(rule.confidence_default if rule else 1.0, DEGRADED_CONFIDENCE_CAP)
        tags = finding.tags + ("degraded-scanner",)
        return Finding(
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            engine=finding.engine,
            title=finding.title,
            capability=finding.capability,
            severity=finding.severity,
            effective_severity=finding.effective_severity,
            confidence=min(finding.confidence, cap),
            evidence_kind="regex",
            static_only=finding.static_only,
            declared=finding.declared,
            location=finding.location,
            message=finding.message,
            remediation=finding.remediation,
            tags=tuple(dict.fromkeys(tags)),
        )


# ---------------------------------------------------------------------------
# AST mode
# ---------------------------------------------------------------------------


@dataclass
class _AstFile:
    """Everything one tree walk collects for sink evaluation."""

    aliases: dict[str, str] = field(default_factory=dict)
    assignments: dict[str, list[Any]] = field(default_factory=dict)  # name -> value nodes
    param_names: frozenset[str] = frozenset()
    calls: list[Any] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _dotted_name(node: Any, source: bytes) -> str | None:
    """``a.b.c`` for identifier/attribute chains; None otherwise."""
    if node.type == "identifier":
        return _node_text(node, source)
    if node.type == "attribute":
        base = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        if base is None or attr is None:
            return None
        prefix = _dotted_name(base, source)
        if prefix is None:
            return None
        return f"{prefix}.{_node_text(attr, source)}"
    return None


def _walk_calls(node: Any, out: list[Any], collected: _AstFile, source: bytes) -> None:
    """Single deterministic pre-order walk collecting the analysis inputs."""
    ntype = node.type
    if ntype == "call":
        out.append(node)
    elif ntype == "import_statement":
        for child in node.named_children:
            if child.type == "dotted_name":
                mod = _node_text(child, source)
                collected.imports.add(mod)
                root = mod.partition(".")[0]
                collected.aliases.setdefault(root, root)
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node is not None and alias_node is not None:
                    mod = _node_text(name_node, source)
                    collected.imports.add(mod)
                    collected.aliases[_node_text(alias_node, source)] = mod
    elif ntype == "import_from_statement":
        module_node = node.child_by_field_name("module_name")
        module = _node_text(module_node, source) if module_node is not None else ""
        if module:
            collected.imports.add(module)
        for child in node.named_children:
            # Identity comparison is WRONG here: tree-sitter hands out fresh
            # wrapper objects per access — compare underlying byte spans.
            if child.type in ("wildcard_import", "alias") or (
                module_node is not None and child.start_byte == module_node.start_byte
            ):
                continue
            if child.type in ("dotted_name", "identifier"):
                local = _node_text(child, source)
                if module and local != "*":
                    collected.aliases.setdefault(local, f"{module}.{local}")
                    collected.imports.add(f"{module}.{local}")
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node is not None and alias_node is not None:
                    local = _node_text(name_node, source)
                    collected.aliases[_node_text(alias_node, source)] = f"{module}.{local}"
                    if module and local != "*":
                        collected.imports.add(f"{module}.{local}")
    elif ntype == "assignment":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            targets = (
                [left]
                if left.type == "identifier"
                else [item for item in left.named_children if item.type == "identifier"]
            )
            for target in targets:
                collected.assignments.setdefault(_node_text(target, source), []).append(right)
    elif ntype == "function_definition":
        params = node.child_by_field_name("parameters")
        if params is not None:
            names = [
                _node_text(child, source)
                for child in params.named_children
                if child.type == "identifier"
            ]
            collected.param_names |= frozenset(names)
    for child in node.children:
        _walk_calls(child, out, collected, source)


_GETATTR_TAILS = frozenset({"getattr", "getattribute"})


def _static_string(node: Any, source: bytes) -> str | None:
    """Concatenated literal text of a pure string expression; None if dynamic.

    Covers plain strings, implicit concatenation (``concatenated_string``),
    and explicit ``+`` chains of literals (``binary_operator``). Anything
    with an interpolation, name, or call inside stays dynamic — guessing is
    never allowed to invent an attribute name.
    """
    ntype = node.type
    if ntype == "string":
        if _has_descendant(node, "interpolation"):
            return None
        parts = [
            _node_text(child, source)
            for child in node.named_children
            if child.type == "string_content"
        ]
        return "".join(parts) if parts else None
    if ntype == "concatenated_string":
        pieces = []
        for child in node.named_children:
            piece = _static_string(child, source)
            if piece is None:
                return None
            pieces.append(piece)
        return "".join(pieces)
    if ntype == "binary_operator":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return None
        if not any(child.type == "+" for child in node.children):
            return None
        lhs = _static_string(left, source)
        rhs = _static_string(right, source)
        if lhs is None or rhs is None:
            return None
        return lhs + rhs
    return None


class _Resolver:
    """Alias-aware callee resolution with obfuscation peeling.

    Beyond import aliases (existing contract), resolves two shapes regex
    fallbacks structurally cannot see:

    - ``getattr(base, <static literal>)`` — including ``"ev" + "al"``-style
      literal concatenation — resolves to ``base.attr``;
    - identifiers bound by simple same-file assignments resolve through
      their assigned expression (first assignment in byte order wins), so
      ``handler = getattr(builtins, "ex" + "ec")`` then ``handler(x)``
      still lands on ``builtins.exec``.

    Unresolvable shapes stay unresolved (None / bare name): ambiguity
    degrades to silence, never to invention.
    """

    def __init__(self, collected: _AstFile, source: bytes) -> None:
        self._aliases = collected.aliases
        self._assignments = collected.assignments
        self._source = source

    def callee(self, call_node: Any) -> str | None:
        func = call_node.child_by_field_name("function")
        if func is None:
            return None
        if func.type == "call":
            indirect = self._resolve_getattr_call(func, frozenset())
            if indirect is not None:
                return indirect
            return self.resolved(func)
        if func.type == "identifier":
            name = _node_text(func, self._source)
            if name in self._aliases:
                return self._aliases[name]
            followed = self._follow_name(name, frozenset())
            return followed if followed is not None else name
        return self.resolved(func)

    def resolved(self, node: Any) -> str | None:
        dotted = _dotted_name(node, self._source)
        if dotted is None:
            return None
        root, sep, rest = dotted.partition(".")
        head = self._aliases.get(root, root)
        return f"{head}{sep}{rest}" if sep else head

    # -- obfuscation peeling -----------------------------------------------

    def _resolve_getattr_call(self, call_node: Any, seen: frozenset[str]) -> str | None:
        """``getattr(base, <static>)`` resolves to ``base.<static>``."""
        func = call_node.child_by_field_name("function")
        target = self.resolved(func) if func is not None else None
        if target is None or _tail(target.lower()) not in _GETATTR_TAILS:
            return None
        positional = _positional_args(call_node, self._source)
        if len(positional) < 2:
            return None
        attr = _static_string(positional[1], self._source)
        if attr is None or not attr.isidentifier():
            return None
        base_node = positional[0]
        base: str | None
        if base_node.type == "identifier":
            base_name = _node_text(base_node, self._source)
            base = self._follow_name(base_name, seen) or self.resolved(base_node)
        else:
            base = self.resolved(base_node)
        if not base:
            return None
        return f"{base}.{attr}"

    def _follow_name(self, name: str, seen: frozenset[str]) -> str | None:
        """Resolve one identifier through its same-file simple assignments."""
        if name in seen:
            return None  # cycle guard: x = x-style loops stay unresolved
        values = self._assignments.get(name)
        if not values:
            return None
        seen = seen | {name}
        for value in values:  # walk order == byte order: deterministic
            candidate = self._resolve_value(value, seen)
            if candidate is not None:
                return candidate
        return None

    def _resolve_value(self, value: Any, seen: frozenset[str]) -> str | None:
        ntype = value.type
        if ntype == "call":
            return self._resolve_getattr_call(value, seen)
        if ntype == "identifier":
            inner = _node_text(value, self._source)
            if inner in self._aliases:
                return self._aliases[inner]
            return self._follow_name(inner, seen)
        if ntype == "attribute":
            return self.resolved(value)
        return None


def _has_descendant(node: Any, node_type: str) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current is not node and current.type == node_type:
            return True
        stack.extend(current.children)
    return False


def _is_pure_literal(node: Any) -> bool:
    """True for string/number/bool/None constants (f-strings are dynamic)."""
    if node.type in ("string", "integer", "float", "true", "false", "none"):
        return not _has_descendant(node, "interpolation")
    if node.type == "concatenated_string":
        return not _has_descendant(node, "interpolation")
    return False


def _literals_in(node: Any, source: bytes) -> list[str]:
    """Unquoted contents of pure string descendants, in byte order."""
    out: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "string" and not _has_descendant(current, "interpolation"):
            body = _node_text(current, source).strip()
            if len(body) >= 2 and body[0] in "\"'" and body[-1] == body[0]:
                body = body[1:-1]
            cleaned = body.strip().strip("\"'").strip()
            if cleaned:
                out.append(cleaned)
            continue
        # Reverse-order push keeps byte order at pop time (deterministic).
        stack.extend(reversed(current.children))
    deduped: list[str] = []
    for item in out:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _args(call_node: Any, source: bytes) -> list[tuple[str | None, Any]]:
    """(keyword-name-or-None, node) pairs in source order."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    out: list[tuple[str | None, Any]] = []
    for child in args_node.named_children:
        if child.type == "keyword_argument":
            name_node = child.child_by_field_name("name")
            value_node = child.child_by_field_name("value")
            if name_node is not None and value_node is not None:
                out.append((_node_text(name_node, source), value_node))
        else:
            out.append((None, child))
    return out


def _positional_args(call_node: Any, source: bytes) -> list[Any]:
    return [node for name, node in _args(call_node, source) if name is None]


def _kwarg(call_node: Any, name: str, source: bytes) -> Any | None:
    for key, node in _args(call_node, source):
        if key == name:
            return node
    return None


def _truthy_kwarg(call_node: Any, name: str, source: bytes) -> bool:
    node = _kwarg(call_node, name, source)
    if node is None:
        return False
    return _node_text(node, source).strip() == "True"


def _identifiers(node: Any, source: bytes) -> list[str]:
    return [
        _node_text(child, source) for child in node.named_children if child.type == "identifier"
    ]


class _Flow:
    """Same-file dataflow facts (fixpoint over assignments; file-global)."""

    def __init__(self, collected: _AstFile, resolver: _Resolver, source: bytes) -> None:
        self._collected = collected
        self._resolver = resolver
        self._source = source
        self.sensitive_names: set[str] = set()
        self.decode_names: set[str] = set()

    def _expr_source_kind(self, node: Any) -> str | None:
        """Sensitive-source marker INSIDE this expression: env | file-read."""
        stack = [node]
        found: str | None = None
        while stack:
            current = stack.pop()
            if current.type == "call":
                resolved = (self._resolver.callee(current) or "").lower()
                if resolved in _ENV_READ_CALLS:
                    found = found or "env"
                tail = _tail(resolved)
                if (resolved == "open" or tail in _FILE_READ_TAILS) and not _open_mode_writes(
                    current, self._source
                ):
                    found = found or "file-read"
            elif current.type == "subscript":
                # tree-sitter-python names the base field "value".
                obj = current.child_by_field_name("object") or current.child_by_field_name("value")
                if obj is not None:
                    resolved = (self._resolver.resolved(obj) or "").lower()
                    if resolved == "os.environ":
                        found = found or "env"
            elif current.type == "attribute":
                attr = current.child_by_field_name("attribute")
                if attr is not None and _node_text(attr, self._source) == "expanduser":
                    found = found or "env"
            elif current.type == "identifier":
                if _node_text(current, self._source) in self.sensitive_names:
                    found = found or "env"
            stack.extend(current.children)
        return found

    def _expr_has_decode(self, node: Any) -> bool:
        """Decode-call marker inside this expression (calls or tainted ids)."""
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == "call" and _is_decode_callee(self._resolver.callee(current)):
                return True
            if current.type == "identifier" and (
                _node_text(current, self._source) in self.decode_names
            ):
                return True
            stack.extend(current.children)
        return False

    def compute(self) -> None:
        """Fixpoint the two name-taint sets over simple assignments."""
        rounds = 0
        changed = True
        bound = len(self._collected.assignments) + 1
        while changed and rounds <= bound:
            changed = False
            rounds += 1
            for name, values in sorted(self._collected.assignments.items()):
                if name not in self.sensitive_names and any(
                    self._expr_source_kind(value) is not None for value in values
                ):
                    self.sensitive_names.add(name)
                    changed = True
                if name not in self.decode_names and any(
                    self._expr_has_decode(value) for value in values
                ):
                    self.decode_names.add(name)
                    changed = True


def _open_mode_writes(call_node: Any, source: bytes) -> bool:
    """Does this open()/Path.open() call carry a write/append/truncate mode?"""
    mode_node = _kwarg(call_node, "mode", source)
    if mode_node is None:
        positional = _positional_args(call_node, source)
        mode_node = positional[1] if len(positional) > 1 else None
    if mode_node is None:
        return False
    for literal in _literals_in(mode_node, source):
        flags = literal.replace("b", "").replace("t", "")
        if any(ch in flags for ch in ("w", "a", "x", "+")):
            return True
    return False


def _receiver_of(call_node: Any) -> Any | None:
    func = call_node.child_by_field_name("function")
    if func is None or func.type != "attribute":
        return None
    return func.child_by_field_name("object")


def _write_target_exprs(call_node: Any, source: bytes, resolver: _Resolver) -> list[Any]:
    """Destination expressions for write/copy sinks, in evaluation order."""
    lowered = (resolver.callee(call_node) or "").lower()
    tail = _tail(lowered)
    positional = _positional_args(call_node, source)
    if lowered == "open" or tail == "open":
        return positional[:1]
    if tail in _WRITE_METHOD_TAILS:
        receiver = _receiver_of(call_node)
        if receiver is None:
            return []
        if receiver.type == "call":  # Path("x") / Path("a") / "b" chains
            return _positional_args(receiver, source)[:1]
        return [receiver]
    if tail in _COPY_DEST_TAILS:
        return positional[1:2]
    if lowered in _DELETE_SINKS:
        return positional[:1]
    return []


def _target_candidates(target_exprs: list[Any], resolver: _Resolver, flow: _Flow) -> list[str]:
    """Literal candidates for target expressions incl. variable resolution."""
    candidates: list[str] = []
    for expr in target_exprs:
        if expr is None:
            continue
        literals = _literals_in(expr, resolver._source)
        if not literals and expr.type == "identifier":
            name = _node_text(expr, resolver._source)
            for value in flow._collected.assignments.get(name, []):
                literals.extend(_literals_in(value, resolver._source))
        candidates.extend(literals)
    deduped: list[str] = []
    for item in candidates:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _sink_short(resolved: str | None) -> str:
    name = (resolved or "").lower()
    if name.startswith("requests."):
        return f"requests.{_tail(name)}"
    if "urlopen" in name:
        return "urlopen"
    if name == "socket.create_connection":
        return "socket.connect"
    if _tail(name) in {"send", "sendall", "sendto", "connect"}:
        return "socket.send" if "send" in _tail(name) else "socket.connect"
    return name or "unknown"


def _net_send_match(resolver: _Resolver, call_node: Any, source: bytes) -> str | None:
    """Send-sink classifier; returns the sink-short token or None."""
    lowered = (resolver.callee(call_node) or "").lower()
    tail = _tail(lowered)
    if lowered.startswith("requests.") and tail in {"post", "put", "patch", "delete", "request"}:
        return _sink_short(lowered)
    if "urlopen" in lowered:
        positional = _positional_args(call_node, source)
        if len(positional) > 1 or _kwarg(call_node, "data", source) is not None:
            return "urlopen"
        return None
    if lowered == "socket.create_connection":
        return "socket.connect"
    receiver = _receiver_of(call_node)
    if receiver is not None:
        root = (_dotted_name(receiver, source) or "").lower().partition(".")[0]
        if "sock" in root:
            if tail in {"send", "sendall", "sendto"}:
                return "socket.send"
            if tail == "connect":
                return "socket.connect"
    return None


def _interpreter_argv(call_node: Any, resolver: _Resolver, source: bytes) -> bool:
    """True when argv[0] is an interpreter and argv[1] is its ``-c`` flag."""
    positional = _positional_args(call_node, source)
    if not positional:
        return False
    elements = [
        child
        for child in positional[0].named_children
        if child.type not in (",", "list_splat", "dictionary_splat")
    ]
    if len(elements) < 2:
        return False
    first = " ".join(_literals_in(elements[0], source)).strip()
    second = " ".join(_literals_in(elements[1], source)).strip()
    return bool(_is_interpreter_token(first) and _INTERPRETER_FLAG_C_RE.match(second.strip()))


def _scan_file_ast(
    builder: _FindingBuilder,
    text: str,
    tree: Any,
    rules: dict[str, Rule],
    collected: _AstFile | None = None,
    calls: list[Any] | None = None,
    resolver: _Resolver | None = None,
    flow: _Flow | None = None,
) -> list[Finding]:
    """AST-mode collectors for one parsed file (caller guards exceptions)."""
    source = text.encode("utf-8")
    lines = text.splitlines()
    if collected is None or calls is None or resolver is None or flow is None:
        collected = _AstFile() if collected is None else collected
        calls = [] if calls is None else calls
        if not calls:
            _walk_calls(tree.root_node, calls, collected, source)
        resolver = _Resolver(collected, source) if resolver is None else resolver
        flow = _Flow(collected, resolver, source) if flow is None else flow
        flow.compute()
    else:
        pass

    findings: list[Finding] = []

    def span_for(node: Any) -> tuple[int, int | None, str]:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        raw = lines[start_line - 1] if start_line - 1 < len(lines) else ""
        end = end_line if end_line >= start_line else None
        return start_line, end, raw.strip()

    for call_node in calls:
        lowered = (resolver.callee(call_node) or "").lower()
        tail = _tail(lowered)
        lineno, end_lineno, snippet = span_for(call_node)

        # --- LNS-PYS-002 decode chains (evaluated before PYS-001) ---
        chain_sink: str | None = None
        if lowered in EXEC_SINKS or lowered in SHELL_DIRECT_SINKS:
            chain_sink = tail
        elif lowered.startswith("subprocess.") and tail in _SUBPROCESS_TAILS:
            chain_sink = tail
        if chain_sink is not None:
            args_node = call_node.child_by_field_name("arguments")
            probe = args_node if args_node is not None else call_node
            direct = any(
                _is_decode_callee(resolver.callee(child))
                for child in probe.named_children
                if child.type == "call"
            )
            flowed = any(name in flow.decode_names for name in _identifiers(probe, source))
            if direct or flowed:
                finding = builder.build(
                    "LNS-PYS-002",
                    lineno,
                    end_lineno,
                    snippet,
                    f"decode-chain:{chain_sink}",
                    "Encoded payload decoded straight into an execution sink "
                    f"({chain_sink}) — the executed bytes are hidden from review.",
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-PYS-001 dynamic exec/eval ---
        # Tail match: alias-resolved and getattr-peeled callees land here as
        # dotted names (``builtins.eval``, ``getattr-built os.system``), so
        # exact-name equality would miss every obfuscated shape.
        if tail in ("exec", "eval"):
            positional = _positional_args(call_node, source)
            arg0 = positional[0] if positional else None
            if arg0 is not None and not _is_pure_literal(arg0):
                noun = "execution" if tail == "exec" else "evaluation"
                finding = builder.build(
                    "LNS-PYS-001",
                    lineno,
                    end_lineno,
                    snippet,
                    f"{tail}-dynamic",
                    f"Dynamic {noun} sink ({tail}) over runtime-derived input "
                    "executes unreviewable code.",
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-PYS-003 interpreter-mediated shell sinks ---
        shell_token: str | None = None
        if lowered in SHELL_DIRECT_SINKS:
            if lowered.endswith("system"):
                shell_token = "os-system"
            elif "popen" in lowered:
                shell_token = "os-popen"
            else:
                shell_token = "shell-getoutput"
        elif lowered.startswith("subprocess.") and tail in ("getoutput", "getstatusoutput"):
            shell_token = "shell-getoutput"
        elif lowered.startswith("subprocess.") and tail in _SUBPROCESS_TAILS:
            if _truthy_kwarg(call_node, "shell", source):
                shell_token = "subprocess-shell-true"
            elif _interpreter_argv(call_node, resolver, source):
                shell_token = "interpreter-argv"
        if shell_token is not None:
            finding = builder.build(
                "LNS-PYS-003",
                lineno,
                end_lineno,
                snippet,
                shell_token,
                "Interpreter-mediated shell execution sink "
                f"({shell_token}) runs a command string through a shell — "
                "injection-shaped control, not a fixed argv.",
            )
            if finding is not None:
                findings.append(finding)

        # --- LNS-PYS-004 sensitive source → network-send flow ---
        send_short = _net_send_match(resolver, call_node, source)
        if send_short is not None:
            args_node = call_node.child_by_field_name("arguments")
            probe = args_node if args_node is not None else call_node
            source_kind = flow._expr_source_kind(probe)
            if source_kind is not None:
                human = "environment variables" if source_kind == "env" else "file contents"
                finding = builder.build(
                    "LNS-PYS-004",
                    lineno,
                    end_lineno,
                    snippet,
                    f"sensitive-flow:{source_kind}:{send_short}",
                    f"Locally collected sensitive input ({human}) flows into a "
                    f"network-send sink ({send_short}) in this file — the "
                    "credential-harvest exfil shape.",
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-PYS-005/006/007 Hermes-state writes ---
        target_exprs = _write_target_exprs(call_node, source, resolver)
        write_like = bool(target_exprs) and lowered not in _DELETE_SINKS
        if write_like:
            candidates = _target_candidates(target_exprs, resolver, flow)
            marked = any(flow._expr_source_kind(expr) == "env" for expr in target_exprs)
            for hit in _route_candidates(candidates, env_marked=marked):
                finding = builder.build(
                    hit.rule_id,
                    lineno,
                    end_lineno,
                    f">> {hit.snippet_target}",
                    hit.evidence,
                    _state_message(hit.rule_id, hit.detail),
                    confidence=hit.confidence,
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-PYS-008 deletes outside the root ---
        if lowered in _DELETE_SINKS:
            positional = _positional_args(call_node, source)
            candidates = _target_candidates(positional[:1], resolver, flow)
            for hit in _route_delete_targets(candidates):
                finding = builder.build(
                    hit.rule_id,
                    lineno,
                    end_lineno,
                    snippet,
                    hit.evidence,
                    "Recursive/delete sink aims outside the skill root "
                    f"({hit.detail}) — data-destruction reach beyond the bundle.",
                    confidence=hit.confidence,
                )
                if finding is not None:
                    findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Degraded mode (line scanner over parsing.line_tokens ONLY)
# ---------------------------------------------------------------------------

_DEG_EXEC_RE = re.compile(r"(?<![\w.])(exec|eval)\s*\(\s*(?![fF]?['\"])[^)#]")
_DEG_DECODE_RE = re.compile(
    r"\b(?:base64\s*\.\s*)?(?:b64decode|decodebytes|decodestring)\b"
    r"|\bbinascii\s*\.\s*a2b_base64\b|\bzlib\s*\.\s*decompress\b|\bcodecs\s*\.\s*decode\b"
)
_DEG_EXECISH_RE = re.compile(
    r"(?<![\w.])(?:exec|eval)\s*\(|\bos\s*\.\s*(?:system|popen)\s*\(|\bsubprocess\b"
    r"|\bpopen\b|\b__import__\b"
)
_DEG_OS_SYSTEM_RE = re.compile(r"\bos\s*\.\s*system\s*\(|(?<![\w.])system\s*\(")
_DEG_OS_POPEN_RE = re.compile(r"\bos\s*\.\s*popen\s*\(|(?<![\w.])popen\s*\(")
_DEG_GETOUTPUT_RE = re.compile(r"\b(?:commands|subprocess)\s*\.\s*getstatus?output\s*\(")
_DEG_SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
_DEG_INTERP_ARGV_RE = re.compile(
    r"[\"\']/?(?:[\w.-]+/)*(?:ba|z|da|k|fi)?sh[\"\']\s*,\s*[\"\']-[a-zA-Z]*c\b",
    re.IGNORECASE,
)
_DEG_ENV_SOURCE_RE = re.compile(
    r"\bos\s*\.\s*environ\b|\bos\s*\.\s*getenv\s*\(|(?<![\w.])getenv\s*\(|expanduser"
)
_DEG_FILEREAD_SOURCE_RE = re.compile(r"\bopen\s*\(|\.read(?:line|lines|_text|_bytes)?\s*\(")
_DEG_SEND_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "requests.post",
        re.compile(r"\brequests?\s*\.\s*(?:post|put|patch|delete|request)\s*\("),
    ),
    ("urlopen", re.compile(r"\burlopen\s*\(")),
    ("socket.send", re.compile(r"\.send(?:all|to)?\s*\(")),
    ("socket.connect", re.compile(r"\.(?:connect|create_connection)\s*\(")),
)
_DEG_QUOTED_RE = re.compile(r"[\"']([^\"'\n]+)[\"']")
_DEG_ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(.+)$")

#: Deterministic degraded chain-sink vocabulary — mirrors the AST-mode
#: ``decode-chain:<tail>`` tokens so fingerprints agree across modes.
_DEG_CHAIN_SINK_RES: tuple[tuple[str, str], ...] = (
    ("exec", r"(?<![\w.])exec\s*\("),
    ("eval", r"(?<![\w.])eval\s*\("),
    ("import", r"\b__import__\s*\("),
    ("system", r"(?:\bos\s*\.\s*)?system\s*\("),
    ("popen", r"(?:\bos\s*\.\s*|\bsubprocess\s*\.\s*)?popen\s*\("),
    (
        "run",
        r"(?:\bsubprocess\s*\.\s*)?(?:run|call|check_call|check_output)\s*\("
        r"|\bsubprocess\b",
    ),
    (
        "getoutput",
        r"(?:\b(?:commands|subprocess)\s*\.\s*)?(?:getoutput|getstatusoutput)\s*\(",
    ),
)
_DEG_OPEN_CALL_RE = re.compile(r"(?<![\w.])open\s*\(([^)]*)")
_DEG_MODE_KW_RE = re.compile(r"mode\s*=\s*[\"']([^\"']+)[\"']")
_DEG_WRITE_METHOD_RE = re.compile(r"([A-Za-z_]\w*)\s*\.\s*(?:write_text|write_bytes)\s*\(")
_DEG_COPY_DEST_RE = re.compile(
    r"\b(?:shutil\s*\.\s*)?(?:copytree|copy|move|replace|rename)\s*\(([^)]*)"
)
_DEG_DELETE_CALL_RE = re.compile(
    r"\b(?:(?:shutil\s*\.\s*)?rmtree|os\s*\.\s*(?:remove|unlink|rmdir|removedirs))"
    r"\s*\(([^)]*)"
)


def _strip_comment(line: str) -> str:
    """Naive comment strip (regex-grade substrate; quotes win over ``#``)."""
    quote: str | None = None
    for index, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _deg_assignment_map(tokens: list[dict[str, Any]]) -> dict[str, str]:
    """name -> last quoted literal on simple ``NAME = ...`` lines."""
    mapping: dict[str, str] = {}
    for token in tokens:
        stripped = _strip_comment(token["text"]).strip()
        match = _DEG_ASSIGN_RE.match(stripped)
        if match is None:
            continue
        quoted = _DEG_QUOTED_RE.findall(match.group(2))
        if quoted:
            mapping[match.group(1)] = quoted[-1].strip().strip("\"'").strip()
    return mapping


def _deg_resolve(blob_fragment: str, assignments: dict[str, str]) -> str:
    """Resolve one argument fragment through the assignment map (or itself)."""
    token = blob_fragment.strip().rstrip(",").strip().strip("\"'").strip()
    if token in assignments:
        return assignments[token]
    return ""


def _deg_blob_candidates(blob: str, assignments: dict[str, str]) -> list[str]:
    """Quoted literals in an argument blob, assignment-resolved; else bare var."""
    fragments = _DEG_QUOTED_RE.findall(blob)
    if fragments:
        resolved = [
            _deg_resolve(fragment, assignments) or fragment.strip().strip("\"'").strip()
            for fragment in fragments
        ]
        deduped: list[str] = []
        for item in resolved:
            if item and item not in deduped:
                deduped.append(item)
        return deduped
    bare = _deg_resolve(blob.split(",")[0], assignments)
    return [bare] if bare else []


def _deg_open_writes(blob: str) -> bool:
    """Does this degraded open()-call blob carry a write-shaped mode?"""
    match = _DEG_MODE_KW_RE.search(blob)
    if match is not None:
        flags = match.group(1).replace("b", "").replace("t", "")
        return any(ch in flags for ch in "wax+")
    parts = blob.split(",")
    if len(parts) < 2:
        return False  # single-argument open defaults to read
    quoted = _DEG_QUOTED_RE.search(parts[1])
    if quoted is None:
        return False  # non-literal mode cannot confirm a write; stay silent
    flags = quoted.group(1).replace("b", "").replace("t", "")
    return any(ch in flags for ch in "wax+")


def _deg_source_kind(line: str) -> str | None:
    if _DEG_ENV_SOURCE_RE.search(line):
        return "env"
    if _DEG_FILEREAD_SOURCE_RE.search(line):
        return "file-read"
    return None


def _deg_decode_names(tokens: list[dict[str, Any]]) -> set[str]:
    """Names transitively assigned from decode calls (same-file flow)."""
    names: set[str] = set()
    rounds = 0
    changed = True
    bound = len(tokens) + 1
    while changed and rounds <= bound:
        changed = False
        rounds += 1
        for token in tokens:
            match = _DEG_ASSIGN_RE.match(_strip_comment(token["text"]).strip())
            if match is None:
                continue
            name, rhs = match.group(1), match.group(2)
            if name in names:
                continue
            flows = bool(_DEG_DECODE_RE.search(rhs)) or any(
                re.search(rf"\b{re.escape(other)}\b", rhs) for other in sorted(names)
            )
            if flows:
                names.add(name)
                changed = True
    return names


def _deg_chain_sink(line: str) -> str | None:
    """Chain-sink short token for one line (AST-vocabulary aligned)."""
    for token, pattern in _DEG_CHAIN_SINK_RES:
        if re.search(pattern, line):
            return token
    return None


def _scan_file_lines(
    builder: _FindingBuilder,
    text: str,
    rules: dict[str, Rule],
) -> list[Finding]:
    """Degraded collectors: same rule ids, regex-grade evidence contract."""
    del rules  # builder carries the rule table
    tokens = line_tokens(text)
    assignments = _deg_assignment_map(tokens)
    decode_names = _deg_decode_names(tokens)
    findings: list[Finding] = []

    def emit(
        rule_id: str,
        token: dict[str, Any],
        snippet: str,
        evidence: str,
        message: str,
        *,
        confidence: float | None = None,
    ) -> None:
        finding = builder.build(
            rule_id,
            token["line"],
            token["line"],
            snippet,
            evidence,
            message,
            confidence=confidence,
        )
        if finding is not None:
            findings.append(builder.degraded(finding))

    source_lines = [_strip_comment(token["text"]) for token in tokens]

    # LNS-PYS-004 window pass (needs the whole stream before per-line work).
    last_source: tuple[int, str] | None = None
    for token, line in zip(tokens, source_lines, strict=True):
        kind = _deg_source_kind(line)
        if kind is not None:
            last_source = (token["line"], kind)
        send_short = next((name for name, regex in _DEG_SEND_RES if regex.search(line)), None)
        if send_short is None or last_source is None:
            continue
        distance = token["line"] - last_source[0]
        if 0 <= distance <= DEGRADED_FLOW_WINDOW:
            emit(
                "LNS-PYS-004",
                token,
                token["text"].strip(),
                f"sensitive-flow:{last_source[1]}:{send_short}",
                "Locally collected sensitive input flows into a network-send "
                f"sink ({send_short}) within this file — the credential-harvest "
                "exfil shape (line-window heuristic).",
            )

    for token, line in zip(tokens, source_lines, strict=True):
        stripped = line.strip()
        if not stripped:
            continue

        # LNS-PYS-001 dynamic exec/eval
        match = _DEG_EXEC_RE.search(stripped)
        if match is not None:
            emit(
                "LNS-PYS-001",
                token,
                stripped,
                f"{match.group(1)}-dynamic",
                f"Dynamic execution sink ({match.group(1)}) over runtime-derived "
                "input executes unreviewable code (line-heuristic).",
            )

        # LNS-PYS-002 decode chains (same-line marker or flowed name)
        chain_line = _DEG_DECODE_RE.search(stripped) is not None or any(
            re.search(rf"\b{re.escape(name)}\b", stripped) for name in sorted(decode_names)
        )
        chain_sink = _deg_chain_sink(stripped) if chain_line else None
        if chain_line and _DEG_EXECISH_RE.search(stripped) and chain_sink is not None:
            emit(
                "LNS-PYS-002",
                token,
                stripped,
                f"decode-chain:{chain_sink}",
                "Encoded payload decoded straight into an execution sink — the "
                "executed bytes are hidden from review (line-heuristic).",
            )

        # LNS-PYS-003 interpreter-mediated shell sinks
        shell_token = (
            "os-system"
            if _DEG_OS_SYSTEM_RE.search(stripped)
            else "os-popen"
            if _DEG_OS_POPEN_RE.search(stripped)
            else "shell-getoutput"
            if _DEG_GETOUTPUT_RE.search(stripped)
            else "subprocess-shell-true"
            if _DEG_SHELL_TRUE_RE.search(stripped)
            else "interpreter-argv"
            if _DEG_INTERP_ARGV_RE.search(stripped)
            else None
        )
        if shell_token is not None:
            emit(
                "LNS-PYS-003",
                token,
                stripped,
                shell_token,
                "Interpreter-mediated shell execution sink "
                f"({shell_token}) runs a command string through a shell "
                "(line-heuristic).",
            )

        # LNS-PYS-005/006/007 state writes (shared routing)
        deg_targets: list[str] = []
        for open_match in _DEG_OPEN_CALL_RE.finditer(stripped):
            blob = open_match.group(1)
            if _deg_open_writes(blob):
                # Target = the HEAD argument only; later comma parts are the
                # mode/encoding — never path candidates.
                deg_targets.extend(_deg_blob_candidates(blob.split(",")[0], assignments))
        for method_match in _DEG_WRITE_METHOD_RE.finditer(stripped):
            literal = assignments.get(method_match.group(1), "")
            if literal:
                deg_targets.append(literal)
        for copy_match in _DEG_COPY_DEST_RE.finditer(stripped):
            parts = copy_match.group(1).split(",")
            if len(parts) >= 2:
                resolved = _deg_resolve(parts[1], assignments)
                deg_targets.append(resolved or parts[1].strip().strip("\"'").strip())
        marked = _DEG_ENV_SOURCE_RE.search(stripped) is not None
        for hit in _route_candidates(deg_targets, env_marked=marked):
            emit(
                hit.rule_id,
                token,
                stripped,
                hit.evidence,
                _state_message(hit.rule_id, hit.detail),
                confidence=hit.confidence,
            )

        # LNS-PYS-008 deletes outside the root
        del_targets: list[str] = []
        for delete_match in _DEG_DELETE_CALL_RE.finditer(stripped):
            del_targets.extend(_deg_blob_candidates(delete_match.group(1), assignments))
        for hit in _route_delete_targets(del_targets):
            emit(
                hit.rule_id,
                token,
                stripped,
                hit.evidence,
                "Recursive/delete sink aims outside the skill root "
                f"({hit.detail}) — data-destruction reach beyond the bundle "
                "(line-heuristic).",
                confidence=hit.confidence,
            )

    return findings


# ---------------------------------------------------------------------------
# Cross-file taint (v1.0) — same-bundle, same-language, import-edge only
# ---------------------------------------------------------------------------

def _py_module_name(rel_path: str) -> str | None:
    """Bundle-relative module name for a ``.py`` file (``/``→``.``, strip ``.py``)."""
    if not rel_path.endswith(".py"):
        return None
    without = rel_path[:-3]
    if without.endswith("/__init__"):
        without = without[:-9]
        if not without:
            return ""
    elif without == "__init__":
        return ""
    return without.replace("/", ".")

def _py_package_for_path(rel_path: str) -> str:
    """Package (dotted) containing *rel_path*; ``scripts/a.py`` => ``scripts``."""
    dir_part = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
    return dir_part.replace("/", ".")

def _py_resolve_import(
    sink_path: str, import_mod: str, module_to_path: dict[str, str]
) -> str | None:
    """Resolve one raw import string from *sink_path* to a bundle path, or None."""
    if not import_mod:
        return None
    if import_mod.startswith("."):
        level = len(import_mod) - len(import_mod.lstrip("."))
        remainder = import_mod.lstrip(".")
        sink_pkg = _py_package_for_path(sink_path)
        pkg_parts = sink_pkg.split(".") if sink_pkg else []
        if level == 1:
            base = sink_pkg
            if base and remainder:
                absolute = f"{base}.{remainder}"
            else:
                absolute = remainder or base
        else:
            up = level - 1
            if up > len(pkg_parts):
                return None
            if up == len(pkg_parts):
                base = ""
            else:
                base = ".".join(pkg_parts[: len(pkg_parts) - up]) if pkg_parts else ""
            if base and remainder:
                absolute = f"{base}.{remainder}"
            else:
                absolute = remainder or base
        return module_to_path.get(absolute)
    return module_to_path.get(import_mod)

@dataclass
class _PyCrossInfo:
    path: str
    imports: set[str]
    source_kinds: set[str]
    source_sites: dict[str, tuple[int, int, str]]
    sink_shorts: set[str]
    sink_sites: dict[str, tuple[int, int, str]]
    escalated: bool

def _py_collect_source_info(
    collected: _AstFile,
    resolver: _Resolver,
    source_bytes: bytes,
    text: str,
    lines: list[str],
    calls: list[Any],
) -> tuple[set[str], dict[str, tuple[int, int, str]]]:
    kinds: set[str] = set()
    sites: dict[str, tuple[int, int, str]] = {}
    for call in calls:
        resolved = (resolver.callee(call) or "").lower()
        tail = _tail(resolved)
        if resolved in _ENV_READ_CALLS:
            if "env" not in sites:
                start_line = call.start_point[0] + 1
                end_line = call.end_point[0] + 1
                snippet = lines[start_line - 1].strip() if 0 <= start_line - 1 < len(lines) else ""
                sites["env"] = (start_line, end_line, snippet)
            kinds.add("env")
        if (resolved == "open" or tail in _FILE_READ_TAILS) and not _open_mode_writes(
            call, source_bytes
        ):
            if "file-read" not in sites:
                start_line = call.start_point[0] + 1
                end_line = call.end_point[0] + 1
                snippet = lines[start_line - 1].strip() if 0 <= start_line - 1 < len(lines) else ""
                sites["file-read"] = (start_line, end_line, snippet)
            kinds.add("file-read")
    if "os.environ" in text:
        if "env" not in sites:
            for idx, line in enumerate(lines, start=1):
                if "os.environ" in line:
                    sites["env"] = (idx, idx, line.strip())
                    break
        kinds.add("env")
    if "expanduser" in text:
        if "env" not in sites:
            for idx, line in enumerate(lines, start=1):
                if "expanduser" in line:
                    sites["env"] = (idx, idx, line.strip())
                    break
        kinds.add("env")
    if "getenv" in text and "env" not in kinds:
        kinds.add("env")
        if "env" not in sites:
            for idx, line in enumerate(lines, start=1):
                if "getenv" in line:
                    sites["env"] = (idx, idx, line.strip())
                    break
    return kinds, sites

def _py_collect_sink_info(
    calls: list[Any],
    resolver: _Resolver,
    source_bytes: bytes,
    lines: list[str],
) -> tuple[set[str], dict[str, tuple[int, int, str]]]:
    shorts: set[str] = set()
    sites: dict[str, tuple[int, int, str]] = {}
    for call in calls:
        short = _net_send_match(resolver, call, source_bytes)
        if short is not None:
            if short not in sites:
                start_line = call.start_point[0] + 1
                end_line = call.end_point[0] + 1
                snippet = lines[start_line - 1].strip() if 0 <= start_line - 1 < len(lines) else ""
                sites[short] = (start_line, end_line, snippet)
            shorts.add(short)
    return shorts, sites

def _py_cross_findings(
    cross_infos: dict[str, _PyCrossInfo],
    claimed: list[str],
    rules: dict[str, Rule],
) -> list[Finding]:
    if not cross_infos:
        return []
    module_to_path: dict[str, str] = {}
    for p in sorted(cross_infos.keys()):
        mod = _py_module_name(p)
        if mod is not None:
            if mod not in module_to_path:
                module_to_path[mod] = p
    findings: list[Finding] = []
    for sink_path in sorted(cross_infos.keys()):
        sink_info = cross_infos[sink_path]
        if not sink_info.sink_shorts:
            continue
        resolved_sources: set[str] = set()
        for imp in sorted(sink_info.imports):
            src = _py_resolve_import(sink_path, imp, module_to_path)
            if src is not None and src != sink_path and src in cross_infos:
                resolved_sources.add(src)
        if not resolved_sources:
            continue
        for src_path in sorted(resolved_sources):
            src_info = cross_infos[src_path]
            if not src_info.source_kinds:
                continue
            for src_kind in sorted(src_info.source_kinds):
                for sink_short in sorted(sink_info.sink_shorts):
                    evidence = f"xf-flow:{src_kind}:{sink_short}:{src_path}>{sink_path}"
                    sink_site = sink_info.sink_sites[sink_short]
                    src_site = src_info.source_sites[src_kind]
                    builder = _FindingBuilder(
                        rules, sink_path, claimed, escalated=sink_info.escalated
                    )
                    human = "environment variables" if src_kind == "env" else "file contents"
                    msg = (
                        f"Locally collected sensitive input ({human}) flows through "
                        f"an imported module ({src_path}) into a network-send sink "
                        f"({sink_short}) — the credential-harvest exfil shape "
                        f"(cross-file import edge)."
                    )
                    finding = builder.build(
                        "LNS-PYS-004",
                        sink_site[0],
                        sink_site[1],
                        sink_site[2],
                        evidence,
                        msg,
                        confidence=0.80,
                        extra_tags=("cross-file-flow",),
                    )
                    if finding is not None:
                        src_loc = Location(
                            path=src_path,
                            start_line=src_site[0],
                            end_line=src_site[1],
                            snippet=src_site[2][:160],
                            redacted=False,
                        )
                        sink_loc = finding.location
                        finding = Finding(
                            fingerprint=finding.fingerprint,
                            rule_id=finding.rule_id,
                            rule_version=finding.rule_version,
                            engine=finding.engine,
                            title=finding.title,
                            capability=finding.capability,
                            severity=finding.severity,
                            effective_severity=finding.effective_severity,
                            confidence=finding.confidence,
                            evidence_kind=finding.evidence_kind,
                            static_only=False,
                            declared=finding.declared,
                            overreach=finding.overreach,
                            location=sink_loc,
                            claim_ref=finding.claim_ref,
                            message=finding.message,
                            remediation=finding.remediation,
                            tags=finding.tags,
                            suppressed=finding.suppressed,
                            suppressed_by=finding.suppressed_by,
                            llm_touched=finding.llm_touched,
                            id=finding.id,
                            locations=(sink_loc, src_loc),
                            additional_location_count=0,
                            detail=finding.detail,
                        )
                        findings.append(finding)
    findings.sort(key=_finding_sort_key)
    return findings

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PyScanEngine:
    """E4 implementation — AST sinks with golden-tested line-scanner fallback."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule], gateway: ParserGateway | None = None) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}
        self._gateway = gateway if gateway is not None else GATEWAY

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        del ctx  # content arrives through the ambient seam via iter_text_files
        claimed = claimed_capability_paths(bundle_ir)
        findings: list[Finding] = []
        cross_infos: dict[str, _PyCrossInfo] = {}
        if type(self) is PyScanEngine:
            for record, text in iter_text_files(bundle_ir, _current_ctx()):
                if not record.path.endswith(".py"):
                    continue
                try:
                    outcome = self._gateway.parse("python", text)
                except Exception:  # noqa: BLE001
                    outcome = None
                if outcome is not None and outcome.mode == "ast" and outcome.tree is not None:
                    try:
                        source_bytes = text.encode("utf-8")
                        lines = text.splitlines()
                        collected = _AstFile()
                        calls: list[Any] = []
                        _walk_calls(outcome.tree.root_node, calls, collected, source_bytes)
                        resolver = _Resolver(collected, source_bytes)
                        flow = _Flow(collected, resolver, source_bytes)
                        flow.compute()
                        builder = _FindingBuilder(
                            self._rules,
                            record.path,
                            claimed,
                            escalated=bool(_PLATFORM_DISABLED_RE.search(text)),
                        )
                        findings.extend(
                            _scan_file_ast(
                                builder,
                                text,
                                outcome.tree,
                                self._rules,
                                collected=collected,
                                calls=calls,
                                resolver=resolver,
                                flow=flow,
                            )
                        )
                        src_kinds, src_sites = _py_collect_source_info(
                            collected, resolver, source_bytes, text, lines, calls
                        )
                        sink_shorts, sink_sites = _py_collect_sink_info(
                            calls, resolver, source_bytes, lines
                        )
                        cross_infos[record.path] = _PyCrossInfo(
                            path=record.path,
                            imports=set(collected.imports),
                            source_kinds=src_kinds,
                            source_sites=src_sites,
                            sink_shorts=sink_shorts,
                            sink_sites=sink_sites,
                            escalated=bool(_PLATFORM_DISABLED_RE.search(text)),
                        )
                        continue
                    except Exception:
                        pass
                builder = _FindingBuilder(
                    self._rules,
                    record.path,
                    claimed,
                    escalated=bool(_PLATFORM_DISABLED_RE.search(text)),
                )
                findings.extend(_scan_file_lines(builder, text, self._rules))
        else:
            for record, text in iter_text_files(bundle_ir, _current_ctx()):
                if not record.path.endswith(".py"):
                    continue
                try:
                    same = self._scan_file(record.path, text, claimed)
                except Exception:
                    raise
                findings.extend(same)
                try:
                    outcome = self._gateway.parse("python", text)
                except Exception:
                    outcome = None
                if outcome is not None and outcome.mode == "ast" and outcome.tree is not None:
                    try:
                        source_bytes = text.encode("utf-8")
                        lines = text.splitlines()
                        collected = _AstFile()
                        calls: list[Any] = []
                        _walk_calls(outcome.tree.root_node, calls, collected, source_bytes)
                        resolver = _Resolver(collected, source_bytes)
                        flow = _Flow(collected, resolver, source_bytes)
                        flow.compute()
                        src_kinds, src_sites = _py_collect_source_info(
                            collected, resolver, source_bytes, text, lines, calls
                        )
                        sink_shorts, sink_sites = _py_collect_sink_info(
                            calls, resolver, source_bytes, lines
                        )
                        cross_infos[record.path] = _PyCrossInfo(
                            path=record.path,
                            imports=set(collected.imports),
                            source_kinds=src_kinds,
                            source_sites=src_sites,
                            sink_shorts=sink_shorts,
                            sink_sites=sink_sites,
                            escalated=bool(_PLATFORM_DISABLED_RE.search(text)),
                        )
                    except Exception:
                        pass
        try:
            findings.extend(_py_cross_findings(cross_infos, claimed, self._rules))
        except Exception:
            pass
        findings.sort(key=_finding_sort_key)
        return findings

    def _scan_file(self, rel_path: str, text: str, claimed: list[str]) -> list[Finding]:
        """One file in whichever mode the gateway affords (never raises)."""
        builder = _FindingBuilder(
            self._rules,
            rel_path,
            claimed,
            escalated=bool(_PLATFORM_DISABLED_RE.search(text)),
        )
        try:
            outcome = self._gateway.parse("python", text)
        except Exception:  # noqa: BLE001 — contract says it cannot; belt+suspenders
            outcome = None
        if outcome is not None and outcome.mode == "ast" and outcome.tree is not None:
            try:
                return _scan_file_ast(builder, text, outcome.tree, self._rules)
            except Exception:  # noqa: BLE001 — per-file AST fault degrades that file
                pass
        return _scan_file_lines(builder, text, self._rules)


def _current_ctx() -> ScanContext:
    """Ambient scan context (engines/__init__ installs it around dispatch)."""
    from .base import current_context

    return current_context()


def _finding_sort_key(finding: Finding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


__all__ = [
    "DEGRADED_CONFIDENCE_CAP",
    "ENGINE_NAME",
    "RULE_IDS",
    "PyScanEngine",
]
