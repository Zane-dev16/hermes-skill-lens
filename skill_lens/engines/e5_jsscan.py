"""E5 jsscan engine — JS/TS AST behavior scan with first-class degradation.

Detection per core-pack rule specs (rule YAMLs are normative; SPEC §4 row
E5 scope ``scripts/**/*.{js,mjs,cjs,ts}``; §17 rows R3/R4/R6/R7/R11/H1/H2/
H5/H6/H9). Two modes over every recorded JS-family file, selected ONLY by
``ParserGateway.parse`` outcome mode (D-PARSE: engines branch on mode/tree,
never on reason codes):

- **AST mode** (javascript grammar active): tree-sitter walks collect
  require/import aliases, variable assignments, and call/new sites; sink
  predicates evaluate against resolved callees with same-file source→sink
  dataflow (the §7 v0.9 reachability bar). Evidence ``ast``, rule-default
  confidence band.
- **Degraded mode** (any degradation cause): the golden-tested line-scanner
  fallback consumes :func:`skill_lens.parsing.line_tokens` ONLY — regex
  heuristics matching the SAME rule ids with evidence_kind ``regex`` and a
  visibly weaker confidence cap (D-PARSE: never silently equal).

TypeScript note (honest scope): v0.9 parses ``*.ts`` sources through the
same tree-sitter-javascript grammar (JS is the TS execution substrate and
tree-sitter error recovery keeps ordinary call shapes intact); a dedicated
typescript grammar lane is deferred — the degraded line scanner remains the
contract floor for any construct it cannot see. ``package.json`` script
hooks are E8 depintel territory (SPEC §4 row E8), never scanned here.

Rule map (ids owned here):

- **LNS-JSS-001** dynamic code execution: ``eval`` / ``new Function`` /
  ``vm.runIn*Context`` over a non-literal argument. Literal-string bodies
  stay silent — the code is reviewable as-is.
- **LNS-JSS-002** encoded-payload chains: ``atob()`` / ``Buffer.from(x,
  "base64")`` results flowing (directly or via same-file assignments) into
  ``exec``/``execSync``/``spawn``/``eval``/``Function``/``vm.runIn*``.
- **LNS-JSS-003** ``child_process`` shell sinks: ``exec``/``execSync``
  (always shell-mediated), ``spawn`` with ``shell: true``, and
  ``["sh", "-c", …]`` interpreter argv. Fixed argv without ``shell: true``
  never fires (the declared-capability safe pattern).
- **LNS-JSS-004** sensitive-source→network-send flow: ``process.env`` reads,
  ``fs`` file reads, or their same-file assignees reaching ``fetch`` with a
  body, XHR ``send``, ``axios.post`` family, or ``sendBeacon`` (R3 exfil
  shape).
- **LNS-JSS-005** Hermes-state persona/memory writes at AST fidelity
  (``agent_home:<sub>`` labels through the §5.1 normalization primitive).
- **LNS-JSS-006** agent-cron state writes (``cron/jobs.json``).
- **LNS-JSS-007** control-plane/gateway/skill-tree writes (config.yaml,
  channel_directory.json, pairing/**, skills/**). Engine-side escalation: a
  ``platform_disabled`` token anywhere in the file escalates effective
  severity toward CRITICAL (mirrors PYS-007/SHL-006; no benign authoring
  story).
- **LNS-JSS-008** recursive/delete sinks aimed outside the skill root
  (``fs.rmSync``/``unlink`` family; R11), unknown-variable targets at the
  §4 reduced confidence.

DETERMINISM LAW: evidence tokens carry shapes and basenames only — no line
numbers, no absolute paths, no wall-clock. Both modes emit the SAME
fingerprint vocabulary for the same detection content, so active-vs-degraded
parity is provable down to fingerprint equality (tests pin this). The
Hermes-state/delete routing layer (rules 005–008) is shared verbatim with
E4 so the same path literal fingerprints identically whichever language
wrote it.
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
from .e3_shellscan import _PLATFORM_DISABLED_RE
from .e4_pyscan import (
    DEGRADED_CONFIDENCE_CAP,
    DEGRADED_FLOW_WINDOW,
    _is_interpreter_token,
    _route_candidates,
    _route_delete_targets,
    _state_message,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "jsscan"

RULE_IDS: tuple[str, ...] = (
    "LNS-JSS-001",
    "LNS-JSS-002",
    "LNS-JSS-003",
    "LNS-JSS-004",
    "LNS-JSS-005",
    "LNS-JSS-006",
    "LNS-JSS-007",
    "LNS-JSS-008",
)

#: Recorded-file suffixes in scope (SPEC §4 row E5). ``.tsx`` is NOT in the
#: normative scope list and stays out.
FILE_SUFFIXES: tuple[str, ...] = (".js", ".mjs", ".cjs", ".ts")

#: Gateway language fronting every suffix above (D-034 pinned lane set;
#: TS rides the javascript grammar — see module docstring).
GATEWAY_LANGUAGE = "javascript"

#: Reduced-confidence bands (§4 conservative treatment; E4 values reused so
#: the shared Hermes-state family behaves identically in either language).
REDUCED_CONFIDENCE_STATE = 0.70
REDUCED_CONFIDENCE_DELETE = 0.65

_SNIPPET_MAX = 160


# ---------------------------------------------------------------------------
# Callee vocabularies (resolved dotted names, compared lowercased)
# ---------------------------------------------------------------------------

_FS_MODULE_HEADS = frozenset({"fs", "fs-extra", "graceful-fs"})
_READ_TAILS = frozenset({"readfile", "readfilesync", "read", "createreadstream"})
_WRITE_TAILS = frozenset(
    {"writefile", "writefilesync", "appendfile", "appendfilesync", "createwritestream"}
)
_DELETE_TAILS = frozenset({"rm", "rmsync", "unlink", "unlinksync", "rmdir", "rmdirsync"})
_JOIN_TAILS = frozenset({"join", "resolve"})
_INTERPRETER_FLAG_C_RE = re.compile(r"^-[a-zA-Z]*c$", re.IGNORECASE)

#: resolved-callee -> JSS-002 chain-sink short token.
_CHILD_PROCESS_CHAIN_SINKS = {
    "child_process.exec": "exec",
    "child_process.execsync": "execsync",
    "child_process.spawn": "spawn",
    "child_process.spawnsync": "spawnsync",
}


def _tail(resolved: str | None) -> str:
    return (resolved or "").rsplit(".", 1)[-1]


def _is_fsish(resolved: str | None) -> bool:
    """True for callees resolved under an fs-like module root."""
    head = (resolved or "").lower().partition(".")[0]
    return head in _FS_MODULE_HEADS or head.startswith("fs/")


# ---------------------------------------------------------------------------
# Shared routing (both modes converge here so fingerprints agree)
# ---------------------------------------------------------------------------

#: E4's shared Hermes-state/delete router emits its own rule ids; translate
#: them to the jsscan slots here so the SAME evidence tokens route to the
#: SAME rule-family semantics in either language (fingerprints then agree
#: across engines by construction).
_ROUTED_RULE_IDS = {
    "LNS-PYS-005": "LNS-JSS-005",
    "LNS-PYS-006": "LNS-JSS-006",
    "LNS-PYS-007": "LNS-JSS-007",
    "LNS-PYS-008": "LNS-JSS-008",
}


def _routed_rule_id(rule_id: str) -> str:
    return _ROUTED_RULE_IDS.get(rule_id, rule_id)


@dataclass(frozen=True)
class _FindingBuilder:
    """Per-file finding factory carrying the declared-discount inputs."""

    rules: dict[str, Rule]
    rel_path: str
    claimed: list[str]
    escalated: bool

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
        rule = self.rules.get(rule_id)
        if rule is None:
            return None
        declared = is_declared(rule.capability, self.claimed)
        tags = rule.tags + (("declared-capability",) if declared else ()) + extra_tags
        eff_severity = "CRITICAL" if self.escalated and rule_id == "LNS-JSS-007" else rule.severity
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
                path=self.rel_path,
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
        rule = self.rules.get(finding.rule_id)
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


def _chain_message(sink: str) -> str:
    return (
        "Encoded payload decoded straight into an execution sink "
        f"({sink}) — the executed bytes are hidden from review."
    )


def _shell_message(token: str) -> str:
    return (
        "Interpreter-mediated shell execution sink "
        f"({token}) runs a command string through a shell — "
        "injection-shaped control, not a fixed argv."
    )


def _exfil_message(kind: str, sink: str) -> str:
    human = "environment variables" if kind == "env" else "file contents"
    return (
        f"Locally collected sensitive input ({human}) flows into a "
        f"network-send sink ({sink}) in this file — the credential-harvest "
        "exfil shape."
    )


# ---------------------------------------------------------------------------
# AST mode
# ---------------------------------------------------------------------------


@dataclass
class _AstFile:
    """Everything one tree walk collects for sink evaluation."""

    module_aliases: dict[str, str] = field(default_factory=dict)  # local -> module
    symbol_aliases: dict[str, str] = field(default_factory=dict)  # local -> dotted member
    assignments: dict[str, list[Any]] = field(default_factory=dict)  # name -> value nodes
    param_names: frozenset[str] = frozenset()
    calls: list[Any] = field(default_factory=list)
    constructions: list[Any] = field(default_factory=list)  # new_expression nodes
    xhr_receivers: set[str] = field(default_factory=set)  # receivers seen in <x>.open(


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _dotted_name(node: Any, source: bytes) -> str | None:
    """``a.b.c`` for identifier/member chains; None otherwise."""
    if node.type == "identifier":
        return _node_text(node, source)
    if node.type in ("member_expression", "member_chain"):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        prefix = _dotted_name(obj, source)
        if prefix is None:
            return None
        return f"{prefix}.{_node_text(prop, source)}"
    return None


def _string_literal(node: Any, source: bytes) -> str | None:
    """Joined ``string_fragment`` text of one string/template node."""
    fragments = [
        _node_text(child, source) for child in node.children if child.type == "string_fragment"
    ]
    if not fragments:
        return None
    return "".join(fragments)


def _require_module(call_node: Any, source: bytes) -> str | None:
    """Module name for ``require("<mod>")`` call nodes; None otherwise."""
    if call_node.type != "call_expression":
        return None
    func = call_node.child_by_field_name("function")
    if func is None or _node_text(func, source).strip() != "require":
        return None
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    for child in args_node.named_children:
        if child.type == "string":
            module = _string_literal(child, source)
            return module.strip() if module else None
    return None


def _collect_pattern_aliases(pattern: Any, module: str, collected: _AstFile, source: bytes) -> None:
    """Destructured require: ``const { exec } = require("child_process")``."""
    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            local = _node_text(child, source)
            collected.symbol_aliases.setdefault(local, f"{module}.{local}")
        elif child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is None or value is None or value.type != "identifier":
                continue
            local = _node_text(value, source)
            exported = _node_text(key, source)
            collected.symbol_aliases.setdefault(local, f"{module}.{exported}")


def _collect_import(node: Any, collected: _AstFile, source: bytes) -> None:
    """ES-import alias collection (default/named/namespace forms)."""
    module = None
    clause = None
    for child in node.children:
        if child.type == "string" and module is None:
            module = _string_literal(child, source)
        elif child.type == "import_clause":
            clause = child
    if not module:
        return
    if clause is None:  # side-effect import: never aliases a binding
        return
    for child in clause.named_children:
        if child.type == "identifier":
            collected.module_aliases.setdefault(_node_text(child, source), module)
        elif child.type == "namespace_import":
            for sub in child.children:
                if sub.type == "identifier":
                    collected.module_aliases.setdefault(_node_text(sub, source), module)
        elif child.type == "named_imports":
            for spec in child.named_children:
                if spec.type != "import_specifier":
                    continue
                name = spec.child_by_field_name("name")
                alias = spec.child_by_field_name("alias")
                if name is None:
                    continue
                local = _node_text(alias, source) if alias is not None else _node_text(name, source)
                collected.symbol_aliases.setdefault(local, f"{module}.{_node_text(name, source)}")


def _walk_calls(node: Any, out: list[Any], collected: _AstFile, source: bytes) -> None:
    """Single deterministic pre-order walk collecting the analysis inputs."""
    ntype = node.type
    if ntype == "call_expression":
        out.append(node)
        # XHR pairing: remember receivers of <x>.open(...) so <x>.send(...)
        # can be recognized later without guessing every `.send(` site.
        func = node.child_by_field_name("function")
        if func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            obj = func.child_by_field_name("object")
            if prop is not None and obj is not None:
                if _node_text(prop, source) == "open":
                    receiver = _dotted_name(obj, source)
                    if receiver:
                        collected.xhr_receivers.add(receiver)
    elif ntype == "new_expression":
        collected.constructions.append(node)
    elif ntype == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is not None and value_node is not None:
            if name_node.type == "identifier":
                collected.assignments.setdefault(_node_text(name_node, source), []).append(
                    value_node
                )
                module = _require_module(value_node, source)
                if module is not None:
                    collected.module_aliases.setdefault(_node_text(name_node, source), module)
            elif name_node.type == "object_pattern":
                module = _require_module(value_node, source)
                if module is not None:
                    _collect_pattern_aliases(name_node, module, collected, source)
    elif ntype == "import_statement":
        _collect_import(node, collected, source)
    elif ntype == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None and left.type == "identifier":
            collected.assignments.setdefault(_node_text(left, source), []).append(right)
    elif ntype == "formal_parameters":
        collected.param_names |= frozenset(
            _node_text(child, source) for child in node.named_children if child.type == "identifier"
        )
    for child in node.children:
        _walk_calls(child, out, collected, source)


class _Resolver:
    """Alias-aware callee resolution for one walked file."""

    def __init__(self, collected: _AstFile, source: bytes) -> None:
        self._symbol = collected.symbol_aliases
        self._modules = collected.module_aliases
        self._source = source

    def callee(self, call_node: Any) -> str | None:
        func = call_node.child_by_field_name("function")
        if func is None:
            return None
        return self.resolved(func)

    def ctor_name(self, new_node: Any) -> str | None:
        """Resolved constructor name of a ``new`` expression."""
        ctor = new_node.child_by_field_name("constructor")
        if ctor is None:
            return None
        return self.resolved(ctor)

    def resolved(self, node: Any) -> str | None:
        dotted = _dotted_name(node, self._source)
        if dotted is None:
            return None
        if dotted in self._symbol:
            return self._symbol[dotted]
        head, sep, rest = dotted.partition(".")
        module = self._modules.get(head)
        if module is not None:
            return f"{module}{sep}{rest}" if sep else module
        return dotted


def _has_descendant(node: Any, node_type: str) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current is not node and current.type == node_type:
            return True
        stack.extend(current.children)
    return False


def _is_pure_literal(node: Any) -> bool:
    """True for string/number/bool/null constants (template holes are dynamic)."""
    if node.type in ("string", "number", "true", "false", "null"):
        return True
    if node.type == "template_string":
        return not _has_descendant(node, "template_substitution")
    return False


def _literals_in(node: Any, source: bytes) -> list[str]:
    """Contents of pure string descendants (quoted + hole-free templates)."""
    out: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "string":
            body = _string_literal(current, source)
            if body and body.strip():
                out.append(body.strip())
            continue
        if current.type == "template_string" and not _has_descendant(
            current, "template_substitution"
        ):
            body = _string_literal(current, source)
            if body and body.strip():
                out.append(body.strip())
            continue
        # Reverse-order push keeps byte order at pop time (deterministic).
        stack.extend(reversed(current.children))
    deduped: list[str] = []
    for item in out:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _args(call_node: Any, source: bytes) -> list[Any]:
    """Positional argument nodes in source order (keyword pairs skipped)."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [child for child in args_node.named_children if child.type != "pair"]


def _pair_value(call_node: Any, key_name: str, source: bytes) -> Any | None:
    """Value of a ``{ key: value }`` pair among the arguments, or None."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    for child in args_node.named_children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        if key is not None and _node_text(key, source).lower() == key_name:
            return child.child_by_field_name("value")
    return None


def _truthy_pair(new_or_call: Any, key_name: str, source: bytes) -> bool:
    value = _pair_value(new_or_call, key_name, source)
    return value is not None and _node_text(value, source).strip().lower() in {
        "true",
        "'true'",
        '"true"',
    }


def _receiver_of(call_node: Any) -> Any | None:
    func = call_node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return None
    return func.child_by_field_name("object")


class _Flow:
    """Same-file dataflow facts (fixpoint over assignments; file-global)."""

    def __init__(self, collected: _AstFile, resolver: _Resolver, source: bytes) -> None:
        self._collected = collected
        self._resolver = resolver
        self._source = source
        self.sensitive_names: set[str] = set()
        self.decode_names: set[str] = set()

    # -- sensitive-source markers -----------------------------------------

    def _expr_source_kind(self, node: Any) -> str | None:
        """Sensitive-source marker INSIDE this expression: env | file-read."""
        stack = [node]
        found: str | None = None
        while stack:
            current = stack.pop()
            ntype = current.type
            if ntype in ("member_expression", "subscript_expression"):
                base = current.child_by_field_name("object")
                if base is not None:
                    dotted = (_dotted_name(base, self._source) or "").lower()
                    if dotted.startswith("process.env"):
                        found = found or "env"
            elif ntype == "call_expression":
                resolved = (self._resolver.callee(current) or "").lower()
                if _is_fsish(resolved) and _tail(resolved) in _READ_TAILS:
                    found = found or "file-read"
            elif ntype == "identifier":
                if _node_text(current, self._source) in self.sensitive_names:
                    found = found or "env"
            stack.extend(current.children)
        return found

    def _expr_has_decode(self, node: Any) -> bool:
        """Decode-call marker inside this expression (calls or tainted ids)."""
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == "call_expression":
                resolved = (self._resolver.callee(current) or "").lower()
                if (
                    _tail(resolved) == "atob"
                    or _buffer_from_base64(current, self._resolver)
                    or _legacy_buffer_base64(current, self._source)
                ):
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


def _buffer_from_base64(call_node: Any, resolver: _Resolver) -> bool:
    """``Buffer.from(x, "base64")`` shape (alias-aware on the receiver)."""
    func = call_node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return False
    prop = func.child_by_field_name("property")
    obj = func.child_by_field_name("object")
    if prop is None or obj is None:
        return False
    if _node_text(prop, resolver._source).lower() != "from":
        return False
    receiver = (resolver.resolved(obj) or "").rsplit(".", 1)[-1].lower()
    if receiver != "buffer":
        return False
    return _has_base64_flag_arg(call_node, resolver._source)


def _has_base64_flag_arg(call_node: Any, source: bytes) -> bool:
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return False
    for child in args_node.named_children:
        if child.type == "pair":
            continue
        for literal in _literals_in(child, source):
            if literal.strip().strip("\"'").lower() == "base64":
                return True
    return False


def _legacy_buffer_base64(new_or_call: Any, source: bytes) -> bool:
    """Legacy two-arg Buffer construction with a base64 encoding flag."""
    args_node = new_or_call.child_by_field_name("arguments")
    if args_node is None:
        return False
    positional = [c for c in args_node.named_children if c.type != "pair"]
    if len(positional) < 2:
        return False
    last = _node_text(positional[-1], source).strip().strip("\"'").lower()
    return last == "base64"


# --- sink predicates -------------------------------------------------------


def _interpreter_argv_js(call_node: Any, source: bytes) -> bool:
    """True when argv starts with an interpreter whose next element is -c."""
    positional = _args(call_node, source)
    if len(positional) < 2:
        return False
    first = " ".join(_literals_in(positional[0], source)).strip()
    if not _is_interpreter_token(first):
        return False
    for arg in positional[1:]:
        for literal in _literals_in(arg, source):
            if _INTERPRETER_FLAG_C_RE.match(literal.strip().strip("\"'")):
                return True
    return False


def _chain_sink_short(resolved: str | None) -> str | None:
    lowered = (resolved or "").lower()
    if lowered in _CHILD_PROCESS_CHAIN_SINKS:
        return _CHILD_PROCESS_CHAIN_SINKS[lowered]
    if lowered == "eval":
        return "eval"
    if lowered.startswith("vm.runin"):
        return "vm"
    return None


def _net_send_match(
    resolver: _Resolver, call_node: Any, collected: _AstFile, source: bytes
) -> str | None:
    """Send-sink classifier; returns the sink-short token or None."""
    lowered = (resolver.callee(call_node) or "").lower()
    tail = _tail(lowered)
    if tail == "fetch" and _args(call_node, source):
        return "fetch"
    if lowered.startswith("axios.") and tail in {"post", "put", "patch", "request"}:
        return "axios-send"
    if tail == "sendbeacon":
        return "beacon-send"
    if tail == "send":
        receiver = _receiver_of(call_node)
        dotted = _dotted_name(receiver, source) if receiver is not None else None
        if dotted is not None and dotted in collected.xhr_receivers:
            return "xhr-send"
    return None


def _open_mode_writes(call_node: Any, source: bytes) -> bool:
    """Does this fs.open()/fs.openSync() call carry a write/append flag?"""
    positional = _args(call_node, source)
    if len(positional) < 2:
        return False
    flags = positional[1]
    for literal in _literals_in(flags, source):
        cleaned = literal.strip().strip("\"'").replace("b", "").replace("t", "")
        if any(ch in cleaned for ch in ("w", "a", "x", "+")):
            return True
    return False


def _write_target_exprs(call_node: Any, source: bytes, resolver: _Resolver) -> list[Any]:
    """Destination expressions for write sinks, in evaluation order."""
    lowered = (resolver.callee(call_node) or "").lower()
    tail = _tail(lowered)
    positional = _args(call_node, source)
    if _is_fsish(lowered) and tail in _WRITE_TAILS:
        return positional[:1]
    if _is_fsish(lowered) and tail in ("open", "opensync") and _open_mode_writes(call_node, source):
        return positional[:1]
    return []


def _delete_target_exprs(call_node: Any, source: bytes, resolver: _Resolver) -> list[Any]:
    lowered = (resolver.callee(call_node) or "").lower()
    tail = _tail(lowered)
    positional = _args(call_node, source)
    if _is_fsish(lowered) and tail in _DELETE_TAILS:
        return positional[:1]
    return []


def _join_parts(
    call_node: Any, resolver: _Resolver, flow: _Flow, source: bytes
) -> list[str] | None:
    """Combined literal parts of a ``join(...)`` call, or None if dynamic."""
    parts: list[str] = []
    for arg in _args(call_node, source):
        literals = _literals_in(arg, source)
        if not literals and arg.type == "identifier":
            name = _node_text(arg, source)
            for value in flow._collected.assignments.get(name, []):
                literals.extend(_literals_in(value, source))
        if not literals:
            # A dynamic segment makes any combined path a guess.
            return None
        parts.append(literals[0])
    return parts if len(parts) >= 2 else None


def _target_candidates(target_exprs: list[Any], resolver: _Resolver, flow: _Flow) -> list[str]:
    """Literal candidates for target expressions incl. variable resolution.

    ``path.join(a, "b")`` shapes are COMBINED into a single candidate (each
    argument resolved through same-file assignments first) so Hermes-home
    prefixes survive segmentation — both at the sink site and through a
    ``const target = path.join(...);`` indirection. Plain expressions yield
    their literals, falling back to assignment-resolved literals for bare
    identifiers.
    """
    source = resolver._source
    candidates: list[str] = []

    def literals_resolved(expr: Any) -> list[str]:
        if expr.type == "identifier":
            name = _node_text(expr, source)
            for value in flow._collected.assignments.get(name, []):
                if value.type == "call_expression":
                    func = value.child_by_field_name("function")
                    tail = _tail(resolver.resolved(func) if func is not None else None)
                    if tail in _JOIN_TAILS:
                        parts = _join_parts(value, resolver, flow, source)
                        if parts is not None:
                            return ["/".join(parts)]
        literals = _literals_in(expr, source)
        if not literals and expr.type == "identifier":
            name = _node_text(expr, source)
            for value in flow._collected.assignments.get(name, []):
                literals.extend(_literals_in(value, source))
        return literals

    for expr in target_exprs:
        if expr is None:
            continue
        if expr.type == "call_expression":
            func = expr.child_by_field_name("function")
            resolved_tail = _tail(resolver.resolved(func) if func is not None else None)
            if resolved_tail in _JOIN_TAILS:
                parts = _join_parts(expr, resolver, flow, source)
                if parts is not None:
                    combined = "/".join(parts)
                    if combined not in candidates:
                        candidates.append(combined)
                    continue
        literals = literals_resolved(expr)
        for literal in literals:
            if literal not in candidates:
                candidates.append(literal)
    return candidates


def _scan_file_ast(builder: _FindingBuilder, text: str, tree: Any) -> list[Finding]:
    """AST-mode collectors for one parsed file (caller guards exceptions)."""
    source = text.encode("utf-8")
    lines = text.splitlines()
    collected = _AstFile()
    calls: list[Any] = []
    _walk_calls(tree.root_node, calls, collected, source)
    resolver = _Resolver(collected, source)
    flow = _Flow(collected, resolver, source)
    flow.compute()

    findings: list[Finding] = []

    def span_for(node: Any) -> tuple[int, int | None, str]:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        raw = lines[start_line - 1] if start_line - 1 < len(lines) else ""
        end = end_line if end_line >= start_line else None
        return start_line, end, raw.strip()

    # --- LNS-JSS-001 over `new Function(...)` / legacy ctors ---
    for new_node in collected.constructions:
        ctor = (resolver.ctor_name(new_node) or "").rsplit(".", 1)[-1].lower()
        lineno, end_lineno, snippet = span_for(new_node)
        if ctor == "function":
            arguments = [
                child
                for child in (new_node.child_by_field_name("arguments") or new_node).named_children
                if child.type != "pair"
            ]
            if any(not _is_pure_literal(arg) for arg in arguments):
                finding = builder.build(
                    "LNS-JSS-001",
                    lineno,
                    end_lineno,
                    snippet,
                    "function-constructor",
                    "Dynamic execution sink (Function constructor) compiles "
                    "runtime-derived input into unreviewable code.",
                )
                if finding is not None:
                    findings.append(finding)

    for call_node in calls:
        lowered = (resolver.callee(call_node) or "").lower()
        lineno, end_lineno, snippet = span_for(call_node)

        # --- LNS-JSS-002 decode chains (evaluated before 001/003) ---
        chain_sink = _chain_sink_short(lowered)
        if chain_sink is not None:
            args_node = call_node.child_by_field_name("arguments")
            probe = args_node if args_node is not None else call_node
            direct = any(
                _tail((resolver.callee(child) or "").lower()) == "atob"
                or _buffer_from_base64(child, resolver)
                or _legacy_buffer_base64(child, source)
                for child in probe.named_children
                if child.type == "call_expression"
            )
            flowed = any(
                _node_text(child, source) in flow.decode_names
                for child in probe.named_children
                if child.type == "identifier"
            )
            if direct or flowed:
                finding = builder.build(
                    "LNS-JSS-002",
                    lineno,
                    end_lineno,
                    snippet,
                    f"decode-chain:{chain_sink}",
                    _chain_message(chain_sink),
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-JSS-001 dynamic eval / vm.runIn* ---
        dyn_token: str | None = None
        if lowered == "eval":
            positional = _args(call_node, source)
            if positional and not _is_pure_literal(positional[0]):
                dyn_token = "eval-dynamic"
        elif lowered.startswith("vm.runin"):
            positional = _args(call_node, source)
            if positional and not _is_pure_literal(positional[0]):
                dyn_token = "vm-runin"
        if dyn_token is not None:
            noun = "evaluation" if dyn_token == "eval-dynamic" else "execution"
            finding = builder.build(
                "LNS-JSS-001",
                lineno,
                end_lineno,
                snippet,
                dyn_token,
                f"Dynamic {noun} sink ({dyn_token.split('-')[0]}) over "
                "runtime-derived input executes unreviewable code.",
            )
            if finding is not None:
                findings.append(finding)

        # --- LNS-JSS-003 child_process shell sinks ---
        shell_token: str | None = None
        if lowered == "child_process.exec":
            shell_token = "cp-exec"
        elif lowered == "child_process.execsync":
            shell_token = "cp-execsync"
        elif lowered in ("child_process.spawn", "child_process.spawnsync"):
            if _truthy_pair(call_node, "shell", source):
                shell_token = "spawn-shell-true"
            elif _interpreter_argv_js(call_node, source):
                shell_token = "interpreter-argv"
        if shell_token is not None:
            finding = builder.build(
                "LNS-JSS-003",
                lineno,
                end_lineno,
                snippet,
                shell_token,
                _shell_message(shell_token),
            )
            if finding is not None:
                findings.append(finding)

        # --- LNS-JSS-004 sensitive source → network-send flow ---
        send_short = _net_send_match(resolver, call_node, collected, source)
        if send_short is not None:
            args_node = call_node.child_by_field_name("arguments")
            probe = args_node if args_node is not None else call_node
            source_kind = flow._expr_source_kind(probe)
            if source_kind is not None:
                finding = builder.build(
                    "LNS-JSS-004",
                    lineno,
                    end_lineno,
                    snippet,
                    f"sensitive-flow:{source_kind}:{send_short}",
                    _exfil_message(source_kind, send_short),
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-JSS-005/006/007 Hermes-state writes ---
        target_exprs = _write_target_exprs(call_node, source, resolver)
        if target_exprs:
            candidates = _target_candidates(target_exprs, resolver, flow)
            marked = any(flow._expr_source_kind(expr) == "env" for expr in target_exprs)
            for hit in _route_candidates(candidates, env_marked=marked):
                finding = builder.build(
                    _routed_rule_id(hit.rule_id),
                    lineno,
                    end_lineno,
                    f">> {hit.snippet_target}",
                    hit.evidence,
                    _state_message(_routed_rule_id(hit.rule_id), hit.detail),
                    confidence=hit.confidence,
                )
                if finding is not None:
                    findings.append(finding)

        # --- LNS-JSS-008 deletes outside the root ---
        delete_exprs = _delete_target_exprs(call_node, source, resolver)
        if delete_exprs:
            candidates = _target_candidates(delete_exprs, resolver, flow)
            for hit in _route_delete_targets(candidates):
                finding = builder.build(
                    _routed_rule_id(hit.rule_id),
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

_DEG_EVAL_RE = re.compile(r"(?<![\w.$])eval\s*\(")
_DEG_FUNCTION_CTOR_RE = re.compile(r"\bnew\s+Function\s*\(")
_DEG_VM_RE = re.compile(r"\brunIn(?:This|New|Async)?Context\s*\(")
_DEG_DECODE_RE = re.compile(
    r"(?<![\w.$])atob\s*\("
    r"|(?:new\s+)?Buffer\s*\.\s*from\s*\([^)\n]*[\"']base64[\"']"
    r"|(?:new\s+)?Buffer\s*\(\s*[^,()\n]+,\s*[\"']base64[\"']"
)
_DEG_EXEC_SYNC_RE = re.compile(r"(?<![\w.$])(?:[\w$.]+\s*\.\s*)?execSync\s*\(")
_DEG_SPAWN_SYNC_RE = re.compile(r"(?<![\w.$])spawnSync\s*\(")
_DEG_EXEC_RE = re.compile(r"(?<![\w.$])(?:[\w$.]+\s*\.\s*)?exec\s*\(")
_DEG_SPAWN_RE = re.compile(r"(?<![\w.$])spawn\s*\(")
_DEG_SPAWN_SHELL_TRUE_RE = re.compile(r"\bspawn(?:Sync)?\s*\([^)\n]*\bshell\s*:")
_DEG_INTERP_ARGV_RE = re.compile(
    r"[\"']/?(?:[\w.-]+/)*(?:ba|z|da|k|fi)?sh[\"']\s*,\s*(?:\[\s*)?[\"']-[a-zA-Z]*c\b",
    re.IGNORECASE,
)
_DEG_ENV_SOURCE_RE = re.compile(r"process\s*\.\s*env\b")
_DEG_FILEREAD_SOURCE_RE = re.compile(
    r"\breadFile(?:Sync)?\s*\(|\.\s*read\s*\(|\bcreateReadStream\s*\("
)
_DEG_SEND_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fetch", re.compile(r"(?<![\w.$])fetch\s*\(")),
    ("axios-send", re.compile(r"\baxios\s*\.\s*(?:post|put|patch|request)\s*\(")),
    ("beacon-send", re.compile(r"\.\s*sendBeacon\s*\(")),
    ("xhr-send", re.compile(r"\.\s*send\s*\(")),
)
_DEG_QUOTED_RE = re.compile(r"[\"']([^\"'\n]+)[\"']")
_DEG_ASSIGN_RE = re.compile(r"^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$")
_DEG_JOIN_RE = re.compile(r"\bjoin\s*\(([^()]*)\)")
_DEG_WRITE_CALL_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("writeFileSync", re.compile(r"\bwriteFileSync\s*\(")),
    ("writeFile", re.compile(r"\bwriteFile\s*\(")),
    ("appendFileSync", re.compile(r"\bappendFileSync\s*\(")),
    ("appendFile", re.compile(r"\bappendFile\s*\(")),
    ("createWriteStream", re.compile(r"\bcreateWriteStream\s*\(")),
)
_DEG_DELETE_CALL_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brmSync\s*\(([^)\n]*)"),
    re.compile(r"(?<![\w.$])rm\s*\(([^)\n]*)"),
    re.compile(r"\bunlinkSync\s*\(([^)\n]*)"),
    re.compile(r"\bunlink\s*\(([^)\n]*)"),
    re.compile(r"\brmdirSync\s*\(([^)\n]*)"),
    re.compile(r"\brmdir\s*\(([^)\n]*)"),
)

#: Deterministic degraded chain-sink vocabulary — mirrors the AST-mode
#: ``decode-chain:<short>`` tokens so fingerprints agree across modes.
_DEG_CHAIN_SINK_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("execsync", _DEG_EXEC_SYNC_RE),
    ("spawnsync", _DEG_SPAWN_SYNC_RE),
    ("vm", _DEG_VM_RE),
    ("function", _DEG_FUNCTION_CTOR_RE),
    ("eval", _DEG_EVAL_RE),
    ("spawn", _DEG_SPAWN_RE),
    ("exec", _DEG_EXEC_RE),
)


def _strip_js_comment(line: str, in_block: bool) -> tuple[str, bool]:
    """Naive comment strip (regex-grade substrate; quotes win over marks).

    Returns ``(clean_line, in_block_after_this_line)``. Handles ``//`` line
    comments, ``/* */`` blocks spanning lines, and quote characters so URLs
    like ``https://api.example.com`` inside strings survive stripping.
    """
    out: list[str] = []
    quote: str | None = None
    index = 0
    length = len(line)
    while index < length:
        ch = line[index]
        if in_block:
            if ch == "*" and index + 1 < length and line[index + 1] == "/":
                in_block = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if ch == "\\":
                index += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
            index += 1
            continue
        if ch in "\"'`":
            quote = ch
            out.append(ch)
            index += 1
            continue
        if ch == "/" and index + 1 < length and line[index + 1] == "/":
            break
        if ch == "/" and index + 1 < length and line[index + 1] == "*":
            in_block = True
            index += 2
            continue
        out.append(ch)
        index += 1
    return "".join(out), in_block


def _deg_assignment_map(tokens: list[dict[str, Any]]) -> dict[str, str]:
    """name -> last quoted literal on simple ``const NAME = ...`` lines."""
    mapping: dict[str, str] = {}
    state = False
    for token in tokens:
        stripped, state = _strip_js_comment(token["text"], state)
        match = _DEG_ASSIGN_RE.match(stripped.strip())
        if match is None:
            continue
        quoted = _DEG_QUOTED_RE.findall(match.group(2))
        if quoted:
            mapping[match.group(1)] = quoted[-1].strip().strip("\"'").strip()
    return mapping


def _deg_decode_names(tokens: list[dict[str, Any]]) -> set[str]:
    """Names transitively assigned from decode calls (same-file flow)."""
    names: set[str] = set()
    rounds = 0
    changed = True
    bound = len(tokens) + 1
    while changed and rounds <= bound:
        changed = False
        rounds += 1
        state = False
        for token in tokens:
            clean, state = _strip_js_comment(token["text"], state)
            match = _DEG_ASSIGN_RE.match(clean.strip())
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


def _deg_chain_sink(stripped: str) -> str | None:
    """Chain-sink short token for one line (AST-vocabulary aligned)."""
    for token, pattern in _DEG_CHAIN_SINK_RES:
        if pattern.search(stripped):
            return token
    return None


def _deg_function_ctor_dynamic(stripped: str) -> bool:
    """``new Function(...)`` with at least one non-literal-looking argument."""
    match = _DEG_FUNCTION_CTOR_RE.search(stripped)
    if match is None:
        return False
    blob = stripped[match.end() :].split(")")[0]
    parts = [part.strip() for part in blob.split(",")]
    for part in parts:
        if not part:
            continue
        if "${" in part:
            return True
        if part[0] in "\"'`" and part[-1:] == part[0]:
            continue
        return True
    return False


def _deg_eval_dynamic(stripped: str) -> bool:
    """``eval(...)`` heuristic: quoted-first-argument lines stay silent."""
    match = _DEG_EVAL_RE.search(stripped)
    if match is None:
        return False
    rest = stripped[match.end() :].lstrip()
    if not rest:
        return True
    if rest[0] in "\"'":
        return False
    if rest[0] == "`":
        return "${" in rest.split("`")[1] if rest.count("`") >= 2 else True
    return True


def _deg_join_candidates(stripped: str) -> list[str]:
    """Innermost ``join(<literals>)`` fragments combined with ``/``."""
    out: list[str] = []
    for match in _DEG_JOIN_RE.finditer(stripped):
        parts = [
            fragment.strip().strip("\"'").strip()
            for fragment in _DEG_QUOTED_RE.findall(match.group(1))
        ]
        parts = [part for part in parts if part]
        if len(parts) >= 2:
            combined = "/".join(parts)
            if combined not in out:
                out.append(combined)
    return out


def _deg_resolve(blob_fragment: str, assignments: dict[str, str]) -> str:
    """Resolve one argument fragment through the assignment map (or itself)."""
    token = blob_fragment.strip().rstrip(",").strip().strip("\"'").strip()
    if token in assignments:
        return assignments[token]
    return ""


def _deg_head_candidates(blob: str, assignments: dict[str, str]) -> list[str]:
    """HEAD-argument candidates for one call blob (data args never count)."""
    head = blob.split(",")[0]
    resolved = _deg_resolve(head, assignments)
    if resolved:
        return [resolved]
    quoted = _DEG_QUOTED_RE.findall(head)
    if quoted:
        literal = quoted[0].strip().strip("\"'").strip()
        return [literal] if literal else []
    return []


def _deg_shell_token(stripped: str) -> str | None:
    if _DEG_INTERP_ARGV_RE.search(stripped):
        return "interpreter-argv"
    if _DEG_SPAWN_SHELL_TRUE_RE.search(stripped):
        return "spawn-shell-true"
    if _DEG_EXEC_SYNC_RE.search(stripped):
        return "cp-execsync"
    if _DEG_EXEC_RE.search(stripped):
        return "cp-exec"
    return None


def _deg_source_kind(line: str) -> str | None:
    if _DEG_ENV_SOURCE_RE.search(line):
        return "env"
    if _DEG_FILEREAD_SOURCE_RE.search(line):
        return "file-read"
    return None


def _scan_file_lines(builder: _FindingBuilder, text: str) -> list[Finding]:
    """Degraded collectors: same rule ids, regex-grade evidence contract."""
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

    clean_lines: list[str] = []
    state = False
    for token in tokens:
        clean, state = _strip_js_comment(token["text"], state)
        clean_lines.append(clean)

    # LNS-JSS-004 window pass (needs the whole stream before per-line work).
    last_source: tuple[int, str] | None = None
    for token, line in zip(tokens, clean_lines, strict=True):
        stripped = line.strip()
        kind = _deg_source_kind(line)
        if kind is not None:
            last_source = (token["line"], kind)
        send_short = next((name for name, regex in _DEG_SEND_RES if regex.search(stripped)), None)
        if send_short is None or last_source is None:
            continue
        distance = token["line"] - last_source[0]
        if 0 <= distance <= DEGRADED_FLOW_WINDOW:
            emit(
                "LNS-JSS-004",
                token,
                token["text"].strip(),
                f"sensitive-flow:{last_source[1]}:{send_short}",
                "Locally collected sensitive input flows into a network-send "
                f"sink ({send_short}) within this file — the credential-harvest "
                "exfil shape (line-window heuristic).",
            )

    for token, line in zip(tokens, clean_lines, strict=True):
        stripped = line.strip()
        if not stripped:
            continue

        # LNS-JSS-001 dynamic eval / Function constructor / vm contexts
        if _deg_eval_dynamic(stripped):
            emit(
                "LNS-JSS-001",
                token,
                stripped,
                "eval-dynamic",
                "Dynamic evaluation sink (eval) over runtime-derived input "
                "executes unreviewable code (line-heuristic).",
            )
        if _deg_function_ctor_dynamic(stripped):
            emit(
                "LNS-JSS-001",
                token,
                stripped,
                "function-constructor",
                "Dynamic execution sink (Function constructor) compiles "
                "runtime-derived input into unreviewable code (line-heuristic).",
            )
        if _DEG_VM_RE.search(stripped):
            emit(
                "LNS-JSS-001",
                token,
                stripped,
                "vm-runin",
                "Dynamic execution sink (vm.runIn*Context) over runtime-derived "
                "input executes unreviewable code (line-heuristic).",
            )

        # LNS-JSS-002 decode chains (same-line marker or flowed name)
        chain_line = _DEG_DECODE_RE.search(stripped) is not None or any(
            re.search(rf"\b{re.escape(name)}\b", stripped) for name in sorted(decode_names)
        )
        chain_sink = _deg_chain_sink(stripped) if chain_line else None
        if chain_sink is not None:
            emit(
                "LNS-JSS-002",
                token,
                stripped,
                f"decode-chain:{chain_sink}",
                "Encoded payload decoded straight into an execution sink — the "
                "executed bytes are hidden from review (line-heuristic).",
            )

        # LNS-JSS-003 child_process shell sinks
        shell_token = _deg_shell_token(stripped)
        if shell_token is not None:
            emit(
                "LNS-JSS-003",
                token,
                stripped,
                shell_token,
                _shell_message(shell_token)[:-1] + " (line-heuristic).",
            )

        # LNS-JSS-005/006/007 state writes (shared routing)
        deg_targets = _deg_join_candidates(stripped)
        for _, pattern in _DEG_WRITE_CALL_RES:
            match = pattern.search(stripped)
            if match is not None:
                blob = stripped[match.end() :]
                deg_targets.extend(_deg_head_candidates(blob, assignments))
        marked = _DEG_ENV_SOURCE_RE.search(stripped) is not None
        for hit in _route_candidates(deg_targets, env_marked=marked):
            emit(
                _routed_rule_id(hit.rule_id),
                token,
                stripped,
                hit.evidence,
                _state_message(_routed_rule_id(hit.rule_id), hit.detail),
                confidence=hit.confidence,
            )

        # LNS-JSS-008 deletes outside the root
        del_targets: list[str] = list(_deg_join_candidates(stripped))
        for pattern in _DEG_DELETE_CALL_RES:
            match = pattern.search(stripped)
            if match is not None:
                del_targets.extend(_deg_head_candidates(match.group(1), assignments))
        for hit in _route_delete_targets(del_targets):
            emit(
                _routed_rule_id(hit.rule_id),
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
# Engine
# ---------------------------------------------------------------------------


class JsScanEngine:
    """E5 implementation — AST sinks with golden-tested line-scanner fallback."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule], gateway: ParserGateway | None = None) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}
        self._gateway = gateway if gateway is not None else GATEWAY

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        claimed = claimed_capability_paths(bundle_ir)
        findings: list[Finding] = []
        wanted = tuple(FILE_SUFFIXES)
        for record, text in iter_text_files(bundle_ir, _current_ctx()):
            if not record.path.endswith(wanted):
                continue
            findings.extend(self._scan_file(record.path, text, claimed))
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
            outcome = self._gateway.parse(GATEWAY_LANGUAGE, text)
        except Exception:  # noqa: BLE001 — contract says it cannot; belt+suspenders
            outcome = None
        if outcome is not None and outcome.mode == "ast" and outcome.tree is not None:
            try:
                return _scan_file_ast(builder, text, outcome.tree)
            except Exception:  # noqa: BLE001 — per-file AST fault degrades that file
                pass
        return _scan_file_lines(builder, text)


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
    "FILE_SUFFIXES",
    "RULE_IDS",
    "JsScanEngine",
]
