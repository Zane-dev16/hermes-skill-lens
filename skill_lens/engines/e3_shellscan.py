"""E3 shellscan engine — token-level shell behavior scan (SPEC §4 row E3).

Detection per core-pack rule specs (rule YAMLs are normative; §17 rows R4,
R6, R11, H1, H2, H5, H6, H9):

- **LNS-SHL-001** remote fetch piped straight into a shell interpreter
  (``curl -fsSL URL | bash``); whitespace-obfuscated pipes still fire, a
  download WITHOUT an inline interpreter does not.
- **LNS-SHL-002** obfuscated execution chains: ``eval`` over encoded command
  substitution, ``base64 -d | sh``, hex-printf-to-shell, python/perl
  decode-and-exec one-liners.
- **LNS-SHL-003** ``rm`` recursive+force whose targets classify OUTSIDE the
  skill root (ingest path-label semantics, §5.1/H9); self-relative forms
  never fire; unknown-variable forms fire at reduced confidence 0.65 (§4
  conservative treatment).
- **LNS-SHL-004** writes into agent persona/memory state — normalized
  ``agent_home:<sub>`` sink labels (SOUL.md, AGENTS.md, CLAUDE.md,
  .cursorrules, .hermes.md, USER.md, MEMORY.md, memories/**, any *.md on the
  Hermes home root). Unknown-path writes adjacent to those basenames fire at
  reduced confidence 0.70.
- **LNS-SHL-005** recurring execution: ``cron/jobs.json`` writes under the
  Hermes home, crontab mutations, systemd user timers, ``hermes cron add``.
  Payload-marker escalation (credential/network tokens inside a written
  heredoc body) raises confidence toward 0.95 without changing the tier.
- **LNS-SHL-006** agent configuration / gateway-state writes (config.yaml,
  channel_directory.json, pairing/**). Engine-side escalation: a
  ``platform_disabled`` token or security-tool disable in the written payload
  escalates effective_severity toward CRITICAL (no benign authoring story).
  Reads of config.yaml NEVER fire — only sink sites trigger.

DECLARED-DISCOUNT interaction (task deliverable / §8.2 ×0.5 ``declared``
modifier): every finding carries ``declared =
is_declared(rule.capability, ir.claims)`` plus a ``declared-capability`` tag
when true; scoring applies the factor.

Scope: fenced bash/sh blocks live inside scanned markdown/SKILL.md text and
``scripts/*.sh`` files are plain text — token patterns run over every line of
every decodable IR file, which covers both inputs without re-parsing fences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from skill_lens.claims import finding_fingerprint, is_declared
from skill_lens.engines.base import (
    Finding,
    Location,
    ScanContext,
    claimed_capability_paths,
    iter_text_files,
)
from skill_lens.ir import PATH_LABEL_AGENT_HOME_PREFIX, PATH_LABEL_INSIDE_SKILL_ROOT, SkillIR

if TYPE_CHECKING:
    from collections.abc import Iterable

    from skill_lens.rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "shellscan"

RULE_IDS: tuple[str, ...] = (
    "LNS-SHL-001",
    "LNS-SHL-002",
    "LNS-SHL-003",
    "LNS-SHL-004",
    "LNS-SHL-005",
    "LNS-SHL-006",
)

# ---------------------------------------------------------------------------
# Path-label classification (consumes the §5.1 ingest normalization semantics)
# ---------------------------------------------------------------------------

PERSONA_BASENAMES: frozenset[str] = frozenset(
    {"soul.md", "agents.md", "claude.md", ".cursorrules", ".hermes.md", "user.md", "memory.md"}
)
_GATEWAY_BASENAMES: tuple[str, ...] = ("channel_directory.json",)

_HERMES_HOME_PREFIX_RE = re.compile(r"^\$\{HERMES_HOME(?::-[^}]*)?\}|^\$HERMES_HOME\b")
_HOME_PREFIXES = ("~/", "~", "$HOME/", "$HOME", "${HOME}/", "${HOME}")

#: Reduced-confidence band for conservative treatment (§4 note).
REDUCED_CONFIDENCE_RM = 0.65
REDUCED_CONFIDENCE_PERSONA = 0.70

_SNIPPET_MAX = 160


@dataclass(frozen=True)
class PathLabel:
    """Normalized label for one path literal (H9 primitive consumer)."""

    label: str  # inside_skill_root | outside | agent_home:<sub> | unknown-var
    detail: str  # classifying tail: absolute|home, agent sub, or basename
    basename: str  # final path segment, lowercased, quotes stripped

    @property
    def is_agent_home(self) -> bool:
        return self.label.startswith(PATH_LABEL_AGENT_HOME_PREFIX)

    @property
    def agent_sub(self) -> str:
        return self.label[len(PATH_LABEL_AGENT_HOME_PREFIX) :]


def _clean_token(token: str) -> str:
    return token.strip().strip("\"'").strip()


def classify_path_literal(raw_token: str) -> PathLabel:
    """Resolve one shell path literal to its canonical label (pure).

    Order matters: Hermes-home indirection wins first (H9), then user-home /
    absolute (outside), then self-relative shapes (inside), then anything
    carrying an unresolved variable degrades to ``unknown-var`` so callers
    apply the §4 conservative treatment instead of guessing.
    """
    token = _clean_token(raw_token)
    segment = re.split(r"[\\/]", token)[-1] if token else ""
    base = segment.lower()
    if not token:
        return PathLabel("unknown-var", "empty", "")
    if _HERMES_HOME_PREFIX_RE.match(token):
        sub = _HERMES_HOME_PREFIX_RE.sub("", token, count=1).lstrip("/")
        # Stop at any further variable: only the literal prefix is knowable.
        sub = re.split(r"\$\{?", sub, maxsplit=1)[0].rstrip("/")
        return PathLabel(f"{PATH_LABEL_AGENT_HOME_PREFIX}{sub.lower()}", sub.lower(), base)
    if token.startswith(_HOME_PREFIXES):
        return PathLabel("outside", "home", base)
    if token.startswith("/"):
        return PathLabel("outside", "absolute", base)
    if token.startswith(("./", "../")) or "$(dirname" in token:
        return PathLabel(PATH_LABEL_INSIDE_SKILL_ROOT, "", base)
    if "$" in token:
        return PathLabel("unknown-var", base, base)
    return PathLabel(PATH_LABEL_INSIDE_SKILL_ROOT, "", base)


# ---------------------------------------------------------------------------
# Line vocabulary (compiled once; deterministic order everywhere)
# ---------------------------------------------------------------------------

_FETCH_PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|#\n]*\|\s*(?:sudo\s+)?(?:env\s+\S+=\S+\s+)?"
    r"(?:sh|bash|zsh|dash|ksh|mksh)\b"
)
_B64_PIPE_SHELL_RE = re.compile(
    r"\bbase64\s+(?:-{1,2}[dD]\b|--decode\b)[^|#\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash)\b"
)
_EVAL_ENCODED_SUBST_RE = re.compile(
    r"\beval\b[^#\n]*\$\([^)#\n]*"
    r"(?:base64|xxd|\\\\x[0-9a-fA-F]{2}|printf\s+['\"]?[0-9a-zA-Z+/=]{8,})"
    r"[^)#\n]*\)"
)
_HEX_PRINTF_SHELL_RE = re.compile(
    r"\bprintf\s+['\"]?[0-9a-fA-F]{4,}[^|#\n]*\|\s*(?:sh|bash|zsh|dash)\b"
)
_PY_DECODE_EXEC_RES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:python3?|perl)\s+-c\b[^#\n]*(?:base64|zlib|codecs)[^#\n]*\b(?:exec|eval)\s*\("
    ),
    re.compile(r"\b(?:python3?|perl)\s+-c\b[^#\n]*\b(?:exec|eval)\s*\([^#\n]*(?:base64|codecs)"),
)

_RM_COMMAND_RE = re.compile(r"\brm\s+([^#;\n]+)")
_CRONTAB_SWAP_RE = re.compile(r"\bcrontab\s+-l\b[^#\n]*\|\s*crontab\s+-")
_CRON_DIR_REDIRECT_RE = re.compile(r">{1,2}\s*/etc/(?:crontab\b|cron\.d/)")
_SYSTEMD_USER_TIMER_RE = re.compile(r"\bsystemctl\s+--user\s+enable\b")
_HERMES_CRON_ADD_RE = re.compile(r"\bhermes\s+cron\s+add\b")
_HEREDOC_START_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")

#: Credential/network payload markers inside written content (SHL-005).
_PAYLOAD_MARKER_RE = re.compile(
    r"(?i)\b(curl|wget|https?://|token|secret|password|credential|key|send|upload|post)\b"
)
#: Control-plane escalation shapes (SHL-006): platform_disabled lists or a
#: security tool disabled by name — no benign authoring story (§17 H5).
_PLATFORM_DISABLED_RE = re.compile(r"(?i)platform_disabled|(?:skills_guard|lens)\s*:\s*false")

_REDIRECT_TARGET_RE = re.compile(r">{1,2}\s*(\"[^\"]*\"|'[^']*'|[^\s;&|<>]+)")
_TEE_TARGET_RE = re.compile(r"\btee\b(?:\s+-{1,2}[\w-]+)*\s+(\"[^\"]*\"|'[^']*'|[^\s;&|<>]+)")
_SED_INPLACE_RE = re.compile(r"\bsed\b[^;\n|]*\s-i(?:n-place)?\b([^;\n]*)")
_COPY_DEST_RE = re.compile(r"\b(?:cp|mv)\b[^;&\n]*?(\"[^\"]*\"|'[^']*'|[^\s;&|]+)\s*$")

_SINK_RES: tuple[re.Pattern[str], ...] = (
    _REDIRECT_TARGET_RE,
    _TEE_TARGET_RE,
    _SED_INPLACE_RE,
    _COPY_DEST_RE,
)


@dataclass(frozen=True)
class HeredocBlock:
    """One ``<<EOF`` block: sink target token plus verbatim body lines."""

    target_token: str
    body: tuple[str, ...]


@dataclass(frozen=True)
class SinkSite:
    """One write-sink occurrence: 1-based line number plus raw target."""

    lineno: int
    raw_target: str


def extract_heredoc_blocks(lines: list[str]) -> list[tuple[int, HeredocBlock]]:
    """Pair heredoc starts carrying a write redirect with their bodies.

    Unterminated blocks tolerate EOF silently; input redirections and process
    substitution never become sinks (the start must carry ``> target <<EOF``).
    """
    blocks: list[tuple[int, HeredocBlock]] = []
    index = 0
    while index < len(lines):
        match = _HEREDOC_START_RE.search(lines[index])
        if match is None:
            index += 1
            continue
        terminator = match.group(2)
        redirect = _REDIRECT_TARGET_RE.search(lines[index])
        body: list[str] = []
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].strip() != terminator:
            body.append(lines[cursor])
            cursor += 1
        if redirect is not None:
            blocks.append((index + 1, HeredocBlock(_clean_token(redirect.group(1)), tuple(body))))
        index = cursor + 1
    return blocks


def extract_sink_sites(lines: list[str]) -> list[SinkSite]:
    """Write-sink sites from redirects/tee/sed -i/cp-mv dest, in line order."""
    sites: list[SinkSite] = []
    seen: set[tuple[int, str]] = set()
    for lineno, line in enumerate(lines, start=1):
        candidates: list[str] = []
        for match in _REDIRECT_TARGET_RE.finditer(line):
            candidates.append(match.group(1))
        for match in _TEE_TARGET_RE.finditer(line):
            candidates.append(match.group(1))
        for match in _SED_INPLACE_RE.finditer(line):
            args = [t for t in match.group(1).split() if not t.startswith("-")]
            if args:
                candidates.append(args[-1])
        for match in _COPY_DEST_RE.finditer(line):
            candidates.append(match.group(1))
        for candidate in candidates:
            target = _clean_token(candidate)
            key = (lineno, target)
            if target and key not in seen:
                seen.add(key)
                sites.append(SinkSite(lineno, target))
    return sites


def _shell_split(text: str) -> list[str]:
    """Whitespace-split honoring quotes and ``$( )`` nesting (no eval)."""
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    depth = 0
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch.isspace() and depth <= 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def rm_outside_labels(line: str) -> list[PathLabel]:
    """Labels for ``rm`` recursive+force targets resolving outside the root.

    One entry per offending target in appearance order; ``[]`` when this is
    not an rm-with--r-and--f line or every target stays inside the skill
    root. Unknown-variable targets surface as ``unknown-var`` labels so the
    caller applies reduced confidence instead of silence.
    """
    labels: list[PathLabel] = []
    for match in _RM_COMMAND_RE.finditer(line):
        args = match.group(1)
        flag_chunks = re.findall(r"(?:^|\s)-{1,2}([\w-]+)", args)
        flag_chars = {ch for chunk in flag_chunks for ch in chunk}
        long_flags = {chunk.lower() for chunk in re.findall(r"--(\w+)", args)}
        has_r = "r" in flag_chars or "R" in flag_chars or "recursive" in long_flags
        has_f = "f" in flag_chars or "force" in long_flags
        if not (has_r and has_f):
            continue
        for token in (t for t in _shell_split(args) if not t.startswith("-")):
            label = classify_path_literal(token)
            outside = label.label == "outside" or label.is_agent_home
            unknown = label.label == "unknown-var" and bool(label.basename)
            if (outside or unknown) and label not in labels:
                labels.append(label)
    return labels


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ShellScanEngine:
    """E3 implementation — token-level scans with declared-discount flags."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        del ctx  # pure text analysis over IR-recorded files only
        claimed = claimed_capability_paths(bundle_ir)
        findings: list[Finding] = []
        for record, text in iter_text_files(bundle_ir, _current_ctx()):
            lines = text.splitlines()
            blocks = extract_heredoc_blocks(lines)
            sinks = extract_sink_sites(lines)
            sinks += [SinkSite(lineno, block.target_token) for lineno, block in blocks]
            findings.extend(_pipe_fetch_findings(self._rules, record.path, lines, claimed))
            findings.extend(_obfuscated_exec_findings(self._rules, record.path, lines, claimed))
            findings.extend(_rm_outside_findings(self._rules, record.path, lines, claimed))
            findings.extend(_persona_write_findings(self._rules, record.path, sinks, claimed))
            findings.extend(
                _cron_persistence_findings(self._rules, record.path, lines, sinks, blocks, claimed)
            )
            findings.extend(
                _control_plane_findings(self._rules, record.path, sinks, blocks, claimed)
            )
        findings.sort(key=_finding_sort_key)
        return findings


# ---------------------------------------------------------------------------
# Rule collectors (module-level functions = pure, unit-testable)
# ---------------------------------------------------------------------------


def _rule_of(rules: dict[str, Rule], rule_id: str) -> Rule | None:
    return rules.get(rule_id)


def _declared_flag(rule: Rule, claimed: list[str]) -> tuple[bool, tuple[str, ...]]:
    declared = is_declared(rule.capability, claimed)
    return declared, (("declared-capability",) if declared else ())


def _build(
    rule: Rule,
    rel_path: str,
    lineno: int,
    snippet: str,
    evidence: str,
    message: str,
    *,
    declared: bool,
    extra_tags: tuple[str, ...],
    confidence: float | None,
    effective_severity: str | None,
) -> Finding:
    return Finding(
        fingerprint=finding_fingerprint(rule.id, rule.capability, evidence),
        rule_id=rule.id,
        rule_version=rule.rule_version,
        engine=rule.engine,
        title=rule.title,
        capability=rule.capability,
        severity=rule.severity,
        effective_severity=effective_severity or rule.severity,
        confidence=rule.confidence_default if confidence is None else confidence,
        evidence_kind=rule.evidence_kind,
        static_only=rule.static_only,
        declared=declared,
        location=Location(
            path=rel_path,
            start_line=lineno,
            end_line=lineno,
            snippet=snippet[:_SNIPPET_MAX],
            redacted=False,
        ),
        message=message,
        remediation=rule.remediation,
        tags=rule.tags + extra_tags,
    )


def _pipe_fetch_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-001")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    out: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        match = _FETCH_PIPE_SHELL_RE.search(line)
        if match is None:
            continue
        fragment = match.group(0)
        interp = next(
            name
            for name in ("bash", "zsh", "dash", "mksh", "ksh", "sh")
            if re.search(rf"\b{name}\b", fragment)
        )
        out.append(
            _build(
                rule,
                rel_path,
                lineno,
                line.strip(),
                f"pipe-exec:{interp}",
                f"Remote script fetched and piped directly into '{interp}' — "
                "whatever the endpoint serves executes at run time.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=None,
                effective_severity=None,
            )
        )
    return out


def _obfuscated_exec_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-002")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    checks: tuple[tuple[re.Pattern[str], str], ...] = (
        (_B64_PIPE_SHELL_RE, "b64-pipe-shell"),
        (_EVAL_ENCODED_SUBST_RE, "eval-encoded-subst"),
        (_HEX_PRINTF_SHELL_RE, "hex-printf-shell"),
        (_PY_DECODE_EXEC_RES[0], "py-decode-exec"),
        (_PY_DECODE_EXEC_RES[1], "py-decode-exec"),
    )
    out: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        kind = next((name for regex, name in checks if regex.search(line)), None)
        if kind is None:
            continue
        out.append(
            _build(
                rule,
                rel_path,
                lineno,
                line.strip(),
                kind,
                f"Obfuscated execution chain ({kind}) hides the executed payload "
                "from review; decoded content still gets scanned as data.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=None,
                effective_severity=None,
            )
        )
    return out


def _rm_outside_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-003")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    out: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        for label in rm_outside_labels(line):
            if label.label == "unknown-var":
                evidence = "rm-outside:unknown-var"
                confidence: float | None = REDUCED_CONFIDENCE_RM
                detail = f"unresolvable variable target '{label.basename}'"
            else:
                evidence = f"rm-outside:{label.detail}"
                confidence = None
                detail = f"target resolves outside ({label.detail})"
            out.append(
                _build(
                    rule,
                    rel_path,
                    lineno,
                    line.strip(),
                    evidence,
                    f"Recursive forced delete aims outside the skill root ({detail}).",
                    declared=declared,
                    extra_tags=extra_tags,
                    confidence=confidence,
                    effective_severity=None,
                )
            )
    return out


def _persona_write_findings(
    rules: dict[str, Rule], rel_path: str, sinks: list[SinkSite], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-004")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    out: list[Finding] = []
    for site in sinks:
        label = classify_path_literal(site.raw_target)
        kind = _persona_kind(label)
        if kind is None:
            continue
        evidence = (
            f"persona-write:{kind}:{label.basename}" if label.basename else f"persona-write:{kind}"
        )
        out.append(
            _build(
                rule,
                rel_path,
                site.lineno,
                f">> {_clean_token(site.raw_target)}",
                evidence,
                "Script writes into agent persona/memory state ("
                + (label.agent_sub or label.basename)
                + ") — prompt-injected every boot and durable past skill removal.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=(REDUCED_CONFIDENCE_PERSONA if kind == "unknown-path" else None),
                effective_severity=None,
            )
        )
    return out


def _cron_persistence_findings(
    rules: dict[str, Rule],
    rel_path: str,
    lines: list[str],
    sinks: list[SinkSite],
    blocks: list[tuple[int, HeredocBlock]],
    claimed: list[str],
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-005")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    bodies = {block.target_token: block.body for _lineno, block in blocks}
    out: list[Finding] = []

    for site in sinks:
        label = classify_path_literal(site.raw_target)
        if not (label.is_agent_home and label.agent_sub.endswith("cron/jobs.json")):
            continue
        body_text = "\n".join(bodies.get(site.raw_target, ()))
        confidence = 0.92 if _PAYLOAD_MARKER_RE.search(body_text) else None
        out.append(
            _build(
                rule,
                rel_path,
                site.lineno,
                f">> {_clean_token(site.raw_target)}",
                "cron-json-write",
                "Writes agent-cron state (cron/jobs.json) — one JSON write is "
                "recurring full-agent execution.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=confidence,
                effective_severity=None,
            )
        )

    scheduler_lines: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("crontab-mutation", _CRONTAB_SWAP_RE),
        ("crontab-mutation", _CRON_DIR_REDIRECT_RE),
        ("os-user-timer", _SYSTEMD_USER_TIMER_RE),
        ("hermes-cron-add", _HERMES_CRON_ADD_RE),
    )
    reported: set[tuple[str, int]] = set()
    for lineno, line in enumerate(lines, start=1):
        for trigger, regex in scheduler_lines:
            if trigger in ("os-user-timer", "hermes-cron-add") and any(
                key[0] == trigger for key in reported
            ):
                continue  # invocations collapse onto one finding per file
            if regex.search(line) and (trigger, lineno) not in reported:
                reported.add((trigger, lineno))
                out.append(
                    _build(
                        rule,
                        rel_path,
                        lineno,
                        line.strip(),
                        trigger,
                        "Installs recurring execution via OS/agent scheduler "
                        f"mutation ({trigger}) — scheduled work re-arms after "
                        "restarts.",
                        declared=declared,
                        extra_tags=extra_tags,
                        confidence=None,
                        effective_severity=None,
                    )
                )
    return out


def _control_plane_findings(
    rules: dict[str, Rule],
    rel_path: str,
    sinks: list[SinkSite],
    blocks: list[tuple[int, HeredocBlock]],
    claimed: list[str],
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-006")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    bodies = {block.target_token: block.body for _lineno, block in blocks}
    out: list[Finding] = []
    for site in sinks:
        label = classify_path_literal(site.raw_target)
        trigger: str | None = None
        if label.is_agent_home and label.agent_sub.endswith("config.yaml"):
            trigger = "config-write"
        elif label.is_agent_home and (
            label.agent_sub.endswith(_GATEWAY_BASENAMES) or label.agent_sub.startswith("pairing/")
        ):
            trigger = "gateway-state-write"
        if trigger is None:
            continue
        body_text = "\n".join(bodies.get(site.raw_target, ()))
        escalated = bool(_PLATFORM_DISABLED_RE.search(body_text))
        out.append(
            _build(
                rule,
                rel_path,
                site.lineno,
                f">> {_clean_token(site.raw_target)}",
                trigger,
                "Script writes agent configuration/platform state ("
                f"{label.agent_sub}) — the knobs gating permissions, platforms, "
                "and plugin visibility.",
                declared=declared,
                extra_tags=extra_tags + (("escalated-critical",) if escalated else ()),
                confidence=None,
                effective_severity="CRITICAL" if escalated else None,
            )
        )
    return out


def _persona_kind(label: PathLabel) -> str | None:
    """Persona/memory classification for an agent_home or unknown-var sink."""
    if label.label == "unknown-var":
        return "unknown-path" if label.basename in PERSONA_BASENAMES else None
    sub = label.agent_sub
    if not sub:
        return None
    if sub.startswith("memories/"):
        return "memory"
    if "/" not in sub and sub in PERSONA_BASENAMES:
        return "self-state"
    if "/" not in sub and sub.endswith(".md"):
        return "home-md"
    return None


def _current_ctx() -> ScanContext:
    """Ambient scan context (engines/__init__ installs it around dispatch)."""
    from skill_lens.engines.base import current_context

    return current_context()


def _finding_sort_key(finding: Finding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


__all__ = [
    "ENGINE_NAME",
    "PERSONA_BASENAMES",
    "RULE_IDS",
    "PathLabel",
    "ShellScanEngine",
    "classify_path_literal",
]
