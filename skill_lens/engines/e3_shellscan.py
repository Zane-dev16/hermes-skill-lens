"""E3 shellscan engine — token-level shell behavior scan (SPEC §4 row E3).

Detection per core-pack rule specs (rule YAMLs are normative; §17 rows R4,
R6, R11, H1, H2, H5, H6, H9):

- **LNS-SHL-001** remote fetch piped straight into a shell interpreter
  (``curl -fsSL URL | bash``) or a script interpreter (``curl URL |
  python3``, ``| node``, ``| perl``, ``| ruby``); whitespace-obfuscated
  pipes still fire, a download WITHOUT an inline interpreter does not.
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
  Hermes home root) — plus durable SHELL/ACCESS persistence targets at any
  label: shell-startup rc files (~/.bashrc and kin) and ssh
  ``authorized_keys``. Unknown-path writes adjacent to those basenames fire
  at reduced confidence 0.70.
- **LNS-SHL-005** recurring execution: ``cron/jobs.json`` writes under the
  Hermes home, crontab mutations, systemd user timers, ``hermes cron add``.
  Payload-marker escalation (credential/network tokens inside a written
  heredoc body) raises confidence toward 0.95 without changing the tier.
- **LNS-SHL-006** agent configuration / gateway-state writes (config.yaml,
  channel_directory.json, pairing/**), git-hook planting (``.git/hooks/``
  writes execute on future git operations), and ``git config
  http.extraheader`` invocations (planted auth headers exfiltrate future git
  traffic). Engine-side escalation: a ``platform_disabled`` token or
  security-tool disable in the written payload escalates effective_severity
  toward CRITICAL (no benign authoring story). Reads of config.yaml NEVER
  fire — only sink sites trigger.
- **LNS-SHL-008** staged download-then-execute WITHOUT a pipe: a file
  fetched via curl/wget (``-o``/``-O``/redirect) that a LATER line executes
  (interpreter, ``./``/bare run, ``source``). The executed basename must
  match the downloaded one — verified-then-extracted installers (tarball
  in, different file out) stay silent.
- **LNS-SHL-009** cross-platform dropper vocabulary: Windows
  (``iwr | iex``, ``schtasks /create``, ``reg add`` Run keys) and macOS
  (``launchctl load/bootstrap/submit``, ``osascript -e``) execution and
  persistence primitives inside shell text.

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

from ..claims import finding_fingerprint, is_declared
from ..ir import PATH_LABEL_AGENT_HOME_PREFIX, PATH_LABEL_INSIDE_SKILL_ROOT, SkillIR
from .base import (
    Finding,
    Location,
    ScanContext,
    claimed_capability_paths,
    iter_text_files,
)
from .e6_netgraph import _CURL_SEND_RE, _WGET_SEND_RE

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "shellscan"

RULE_IDS: tuple[str, ...] = (
    "LNS-SHL-001",
    "LNS-SHL-002",
    "LNS-SHL-003",
    "LNS-SHL-004",
    "LNS-SHL-005",
    "LNS-SHL-006",
    "LNS-SHL-007",
    "LNS-SHL-008",
    "LNS-SHL-009",
)

# ---------------------------------------------------------------------------
# Path-label classification (consumes the §5.1 ingest normalization semantics)
# ---------------------------------------------------------------------------

PERSONA_BASENAMES: frozenset[str] = frozenset(
    {"soul.md", "agents.md", "claude.md", ".cursorrules", ".hermes.md", "user.md", "memory.md"}
)
#: Shell-startup rc files: sourced by every interactive shell, so a write
#: here is durable code execution one terminal open away — the POSIX half of
#: the SHL-004 persistence family (matched case-insensitively on basenames).
PERSISTENCE_RC_BASENAMES: frozenset[str] = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".shrc",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        ".login",
        ".logout",
    }
)
#: SSH access persistence: one appended key is permanent remote entry.
AUTHORIZED_KEYS_BASENAME = "authorized_keys"
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


def _is_git_hooks_path(token: str) -> bool:
    """True when *token* points inside a ``.git/hooks/`` directory (pure).

    Case-insensitive on the ``.git``/``hooks`` segments (filesystems vary);
    the match must be a real path SEGMENT (``agit/hooks/x`` never matches).
    Shared with E4/E5 routing so all three engines agree on the shape.
    """
    cleaned = _clean_token(token).casefold().replace("\\", "/")
    return "/.git/hooks/" in f"/{cleaned}/" or cleaned.endswith("/.git/hooks")


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
    r"(?:sh|bash|zsh|dash|ksh|mksh|python3?|node|perl|ruby)\b"
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

#: LNS-SHL-008 staged download-then-execute (no pipe): the download half.
#: ``curl -o FILE`` / ``curl -O`` (remote-name form) / ``wget -O FILE`` /
#: ``wget`` (remote-name form) / any curl|wget line redirecting to a file.
_STAGED_CURL_OUTPUT_RE = re.compile(r"\bcurl\b[^#\n]*?(?:-o\s*(\S+)|--output\s*(\S+)|\s-O\b)")
_STAGED_WGET_OUTPUT_RE = re.compile(r"\bwget\b[^#\n]*?(?:-O\s*(\S+)|--output-document=(\S+))")
_STAGED_REDIRECT_RE = re.compile(
    r"\b(?:curl|wget)\b[^#\n]*?>{1,2}\s*(\"[^\"]*\"|'[^']*'|[^\s;&|<>]+)"
)
#: The execute half: interpreter runs, ./-prefixed or bare runs, sourcing.
_STAGED_INTERP_RUN_RE = re.compile(
    r"(?:^|[;&|]\s*|\s)(?:sh|bash|zsh|dash|ksh|python3?|node|perl|ruby)\s+"
    r"(\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
)
_STAGED_DOT_RUN_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:\./|source\s+|\.\s+)(\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
)
#: LNS-SHL-009 cross-platform dropper vocabulary (single-line shapes).
_DROPPER_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("win-dropper:iwr-iex", re.compile(r"(?i)\biwr\b[^|#\n]*\|\s*iex\b")),
    (
        "win-dropper:invoke-webrequest-iex",
        re.compile(r"(?i)invoke-webrequest\b[^|#\n]*\|\s*invoke-expression\b"),
    ),
    ("win-persist:schtasks", re.compile(r"(?i)\bschtasks\b[^#\n]*/create\b")),
    ("win-persist:run-key", re.compile(r"(?i)\breg\s+add\b[^#\n]*\\run\b")),
    (
        "mac-persist:launchctl",
        re.compile(r"\blaunchctl\b\s+(?:load|bootstrap|submit)\b"),
    ),
    ("mac-exec:osascript", re.compile(r"\bosascript\b[^#\n]*\s-e\b")),
)

#: Credential/network payload markers inside written content (SHL-005).
_PAYLOAD_MARKER_RE = re.compile(
    r"(?i)\b(curl|wget|https?://|token|secret|password|credential|key|send|upload|post)\b"
)
#: ``git config`` planting an Authorization-bearing header: every future
#: fetch/clone through the configured URL carries the planted credential to
#: an attacker endpoint (SHL-006 invocation branch — no file sink involved).
#: Command-position anchored: ``git`` must open the command (line start,
#: separator, quote, or ``$(``) so pattern DEFINITIONS and prose mentions
#: never match — only real invocations (the self-scan law: the instrument's
#: own detector source must stay silent).
_GIT_EXTRAHEADER_RE = re.compile(
    r"(?:^|[;&|]\s*|[\"'`({$]\s*)(?:sudo\s+)?git\s+config\b[^#\n]*"
    r"\bhttp\.extraheader\b"
)
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

# -- LNS-SHL-007 — env-file source→send flow (D-014: correlation, not bare --
# presence). Send vocabulary is IMPORTED from e6_netgraph so SHL-007 and
# NET-011 never drift apart (established cross-engine import practice: e4/e5
# already consume e3 internals; fingerprints bind the rule id so no
# cross-engine collision is possible).

#: Dot-source idiom: ``source <file>`` / ``. <file>``, optionally behind
#: ``set -a`` (the ``&& `` satisfies the leading separator; ``set -a`` alone
#: is NOT a source — the pair is one source event).
_ENV_SOURCE_RE = re.compile(r"(?:^|[;&|]\s*)(?:source|\.)\s+([^\s;&|#]+)")
#: Export-by-substitution idiom: ``export $(cat <file>)`` (the bare ``eval
#: $(cat ...)`` form is SHL-002 territory and deliberately not matched here).
_EXPORT_SUBST_RE = re.compile(r"\bexport\s+\$?\(\s*cat\s+([^)#\s;&|]+)")
#: Shell variable interpolation / command substitution in send arguments.
_VAR_INTERP_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*|\$\(")
#: Fenced code blocks: opening fence with a shell language tag opens a shell
#: region; any fence line closes. Unclosed fences extend to EOF (tolerant,
#: matching heredoc handling).
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)\s*([A-Za-z0-9_+-]*)")
_FENCE_LANGS = frozenset({"bash", "sh", "shell", "zsh"})

#: Reduced-confidence band for unknown-variable env-adjacent source targets
#: (§4 conservative treatment, SHL-004's 0.70 sibling).
REDUCED_CONFIDENCE_ENV_SOURCE = 0.70


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
        if "<<" not in lines[index]:
            # Necessary-condition gate: _HEREDOC_START_RE requires "<<".
            index += 1
            continue
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
        if not (">" in line or "tee" in line or "sed" in line or "cp" in line or "mv" in line):
            continue  # necessary-condition gate: no sink regex can match (PERF)
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
    if "rm" not in line:
        return labels  # necessary-condition gate: _RM_COMMAND_RE requires "rm"
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
                _control_plane_findings(self._rules, record.path, lines, sinks, blocks, claimed)
            )
            findings.extend(_env_source_findings(self._rules, record.path, lines, claimed))
            findings.extend(_staged_exec_findings(self._rules, record.path, lines, claimed))
            findings.extend(_dropper_vocab_findings(self._rules, record.path, lines, claimed))
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
        if "curl" not in line and "wget" not in line:
            continue  # necessary-condition gate: _FETCH_PIPE_SHELL_RE requires curl|wget
        match = _FETCH_PIPE_SHELL_RE.search(line)
        if match is None:
            continue
        fragment = match.group(0)
        interp = next(
            canonical
            for canonical, aliases in (
                ("bash", ("bash",)),
                ("zsh", ("zsh",)),
                ("dash", ("dash",)),
                ("mksh", ("mksh",)),
                ("ksh", ("ksh",)),
                ("python3", ("python3", "python")),
                ("node", ("node",)),
                ("perl", ("perl",)),
                ("ruby", ("ruby",)),
                ("sh", ("sh",)),
            )
            if any(re.search(rf"\b{alias}\b", fragment) for alias in aliases)
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
        if not (
            "base64" in line
            or "eval" in line
            or "printf" in line
            or "python" in line
            or "perl" in line
        ):
            continue  # necessary-condition gate: every check regex requires one of these
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
                "from review; decode the matched bytes by hand — no decode "
                "ladder runs over them yet.",
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
        if kind in ("shell-rc", "authorized-keys"):
            evidence = f"persistence-write:{kind}:{label.basename}".rstrip(":")
            if kind == "shell-rc":
                message = (
                    "Script writes a shell-startup file ("
                    + (label.agent_sub or label.basename)
                    + ") — sourced by every interactive shell, so this is "
                    "durable code execution one terminal open away."
                )
            else:
                message = (
                    "Script writes ssh authorized_keys ("
                    + (label.agent_sub or label.basename)
                    + ") — an appended key is permanent remote entry."
                )
            confidence: float | None = (
                REDUCED_CONFIDENCE_PERSONA if label.label == "unknown-var" else None
            )
        else:
            evidence = (
                f"persona-write:{kind}:{label.basename}"
                if label.basename
                else f"persona-write:{kind}"
            )
            message = (
                "Script writes into agent persona/memory state ("
                + (label.agent_sub or label.basename)
                + ") — prompt-injected every boot and durable past skill removal."
            )
            confidence = REDUCED_CONFIDENCE_PERSONA if kind == "unknown-path" else None
        out.append(
            _build(
                rule,
                rel_path,
                site.lineno,
                f">> {_clean_token(site.raw_target)}",
                evidence,
                message,
                declared=declared,
                extra_tags=extra_tags,
                confidence=confidence,
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
        if not ("crontab" in line or "systemctl" in line or "hermes" in line or ">" in line):
            continue  # necessary-condition gate: every scheduler regex requires one of these
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
    lines: list[str],
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
        detail = label.agent_sub
        if label.is_agent_home and label.agent_sub.endswith("config.yaml"):
            trigger = "config-write"
        elif label.is_agent_home and (
            label.agent_sub.endswith(_GATEWAY_BASENAMES) or label.agent_sub.startswith("pairing/")
        ):
            trigger = "gateway-state-write"
        elif _is_git_hooks_path(site.raw_target):
            # Any label: a hook planted anywhere a git repo will execute it.
            trigger = "git-hooks-write"
            detail = _clean_token(site.raw_target)
        if trigger is None:
            continue
        body_text = "\n".join(bodies.get(site.raw_target, ()))
        escalated = bool(_PLATFORM_DISABLED_RE.search(body_text))
        if trigger == "git-hooks-write":
            message = (
                f"Script plants a git hook ({detail}) — hook scripts execute "
                "on future git operations with the operator's privileges."
            )
        else:
            message = (
                "Script writes agent configuration/platform state ("
                f"{label.agent_sub}) — the knobs gating permissions, platforms, "
                "and plugin visibility."
            )
        out.append(
            _build(
                rule,
                rel_path,
                site.lineno,
                f">> {_clean_token(site.raw_target)}",
                trigger,
                message,
                declared=declared,
                extra_tags=extra_tags + (("escalated-critical",) if escalated else ()),
                confidence=None,
                effective_severity="CRITICAL" if escalated else None,
            )
        )
    for lineno, line in enumerate(lines, start=1):
        if "git" not in line or "extraheader" not in line:
            continue  # necessary-condition gate: _GIT_EXTRAHEADER_RE needs both
        if _GIT_EXTRAHEADER_RE.search(line) is None:
            continue
        out.append(
            _build(
                rule,
                rel_path,
                lineno,
                line.strip(),
                "git-config-extraheader",
                "Script plants an Authorization-bearing git http.extraheader — "
                "every future fetch/clone through the configured URL carries "
                "the planted credential outward.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=None,
                effective_severity=None,
            )
        )
    return out


def _shell_regions(lines: list[str]) -> frozenset[int]:
    """Line numbers inside fenced bash/sh blocks (SHL-007 region refinement).

    Shell-suffixed files never call this (all lines count); non-shell text
    restricts BOTH flow sides to fenced ``bash``/``sh`` blocks so a README
    saying "run ``source .env`` first" plus a curl example cannot pair.
    """
    regions: set[int] = set()
    inside = False
    for lineno, line in enumerate(lines, start=1):
        match = _FENCE_RE.match(line)
        if match is not None:
            inside = (not inside) and match.group(1).casefold() in _FENCE_LANGS
            continue
        if inside:
            regions.add(lineno)
    return frozenset(regions)


def _env_source_kind(line: str) -> tuple[str | None, str]:
    """First source event on *line* (fixed kind order: dot-source, then
    export-substitution) as ``(kind, raw target)``; ``(None, "")`` when the
    line carries no sourcing grammar."""
    match = _ENV_SOURCE_RE.search(line)
    if match is not None:
        return "dot-source", match.group(1)
    match = _EXPORT_SUBST_RE.search(line)
    if match is not None:
        return "export-substitution", match.group(1)
    return None, ""


def _envfile_target_class(raw_target: str) -> str | None:
    """Classify a source target (basename/path level, case-insensitive).

    ``"env"`` — known env/credentials basename (``.env*`` prefix/suffix,
    ``credential*``, ``auth.json``; covers the ``${HERMES_HOME:-~/.hermes}/.env``
    idiom). ``"env-var"`` — variable-bearing target with no resolvable env
    basename whose stripped variable name still claims env/credential/auth
    semantics (``$ENV_FILE``) → reduced confidence 0.70. ``None`` — not an
    env/credentials target (plain ``$CONFIG`` sources never fire).
    """
    token = _clean_token(raw_target)
    lowered = token.casefold()
    if not lowered:
        return None
    segment = re.split(r"[\\/]", lowered)[-1]
    if (
        segment.startswith(".env")
        or segment.endswith(".env")
        or "credential" in segment
        or segment == "auth.json"
    ):
        return "env"
    if "$" in token:
        stripped = lowered.replace("$", "").replace("{", "").replace("}", "")
        bare = re.split(r"[\\/]", stripped)[-1]
        if (
            bare.startswith("env")
            or ".env" in stripped
            or "credential" in stripped
            or "auth" in stripped
        ):
            return "env-var"
    return None


def _env_source_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-007")
    if rule is None:
        return []
    # Necessary-condition gates (PERF, D-061 style): every send regex needs
    # curl/wget; every source regex needs source/. /cat vocabulary.
    if not any("curl" in line or "wget" in line for line in lines):
        return []
    if not any("source" in line or ". " in line or "cat" in line for line in lines):
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    shell_file = rel_path.endswith(".sh")
    region: frozenset[int] | None = None if shell_file else _shell_regions(lines)

    def _in_region(lineno: int) -> bool:
        return region is None or lineno in region

    # Pass 1: source events (line-ordered). Redirect reads (``base64 < file``)
    # and @file attaches never land here — that pairing is NET-011's turf, and
    # the exclusion is load-bearing for vector byte-exactness (C/C′ shapes).
    sources: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(lines, start=1):
        if "source" not in line and ". " not in line and "cat" not in line:
            continue
        if not _in_region(lineno):
            continue
        kind, target = _env_source_kind(line)
        if kind is not None and _envfile_target_class(target) is not None:
            sources.append((lineno, kind, target))
    if not sources:
        return []

    # Pass 2: one finding per qualifying send line, paired with the NEAREST
    # strictly-earlier source event (no window cap — ordered same-file bar,
    # matching E6's same-file correlation semantics).
    out: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        if "curl" not in line and "wget" not in line:
            continue
        if not _in_region(lineno):
            continue
        if _CURL_SEND_RE.search(line):
            send_short = "curl-data"
        elif _WGET_SEND_RE.search(line):
            send_short = "wget-data"
        else:
            continue
        if _VAR_INTERP_RE.search(line) is None:
            continue  # static-payload sends never fire; @file attaches are NET-011's
        prior = [source for source in sources if source[0] < lineno]
        if not prior:
            continue
        _src_lineno, kind, target = prior[-1]
        target_class = _envfile_target_class(target)
        if target_class is None:
            continue
        unknown_var = target_class == "env-var"
        out.append(
            _build(
                rule,
                rel_path,
                lineno,
                line.strip(),
                f"env-source-flow:{kind}:{send_short}",
                "Script sources an env/credentials file and later sends "
                "variable-bearing data out — after sourcing, every $VAR "
                "expansion is potentially credential-bearing.",
                declared=declared,
                extra_tags=extra_tags,
                confidence=(REDUCED_CONFIDENCE_ENV_SOURCE if unknown_var else None),
                effective_severity=None,
            )
        )
    return out


#: Device/null-ish redirect targets: never download events (SHL-008).
_STAGED_NULL_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})

_URL_BASENAME_RE = re.compile(r"https?://[^\s\"'<>|`]+?")


def _staged_download_basename(line: str) -> str | None:
    """Outfile basename when *line* downloads via curl/wget, else None.

    Covers ``-o``/``--output``/``-O`` (curl), ``-O``/``--output-document=``
    (wget), and ``curl|wget ... > FILE`` redirects. ``-O``/bare-``wget``
    forms resolve the remote name from the URL basename; ``/dev/*`` targets
    and unresolvable names yield None (never download events).
    """
    match = _STAGED_CURL_OUTPUT_RE.search(line)
    if match is not None:
        outfile = match.group(1) or match.group(2)
        if outfile is not None:
            return _download_key(outfile)
        return _remote_name_basename(line)  # bare -O: remote-name form
    match = _STAGED_WGET_OUTPUT_RE.search(line)
    if match is not None:
        outfile = match.group(1) or match.group(2)
        if outfile is not None:
            return _download_key(outfile)
    elif re.search(r"\bwget\b", line) is not None:
        remote = _remote_name_basename(line)
        if remote is not None:
            return remote
    match = _STAGED_REDIRECT_RE.search(line)
    if match is not None:
        return _download_key(match.group(1))
    return None


def _download_key(raw_target: str) -> str | None:
    """Normalized download basename, or None for null-device targets."""
    token = _clean_token(raw_target)
    if not token or token in _STAGED_NULL_TARGETS or token.startswith("/dev/"):
        return None
    base = re.split(r"[\\/]", token)[-1]
    return base or None


def _remote_name_basename(line: str) -> str | None:
    """URL-path basename for ``-O``/bare-wget remote-name downloads."""
    match = _URL_BASENAME_RE.search(line)
    if match is None:
        return None
    path = match.group(0).split("://", 1)[1]
    tail = path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    return tail or None


def _staged_exec_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-008")
    if rule is None:
        return []
    if not any("curl" in line or "wget" in line for line in lines):
        return []  # necessary-condition gate: downloads need curl|wget
    declared, extra_tags = _declared_flag(rule, claimed)
    shell_file = rel_path.endswith(".sh")
    region: frozenset[int] | None = None if shell_file else _shell_regions(lines)

    def _in_region(lineno: int) -> bool:
        return region is None or lineno in region

    downloads: list[tuple[int, str]] = []  # (lineno, basename), line-ordered
    for lineno, line in enumerate(lines, start=1):
        if "curl" not in line and "wget" not in line:
            continue
        if not _in_region(lineno):
            continue
        base = _staged_download_basename(line)
        if base is not None and all(known != base for _, known in downloads):
            downloads.append((lineno, base))
    if not downloads:
        return []
    out: list[Finding] = []
    for down_lineno, base in downloads:
        # The executed basename must EQUAL the downloaded one: tarball-in /
        # different-file-out installers (pinned-tarball-installer) stay silent.
        run_re = re.compile(rf"(?:^|[;&|]\s*)(?:\./)?{re.escape(base)}(?:\s|[;&|$])")
        for lineno, line in enumerate(lines, start=1):
            if lineno <= down_lineno or not _in_region(lineno):
                continue
            paired = False
            for match in _STAGED_INTERP_RUN_RE.finditer(line):
                candidate = re.split(r"[\\/]", _clean_token(match.group(1)))[-1]
                if candidate == base:
                    paired = True
                    break
            if not paired:
                for match in _STAGED_DOT_RUN_RE.finditer(line):
                    candidate = re.split(r"[\\/]", _clean_token(match.group(1)))[-1]
                    if candidate == base:
                        paired = True
                        break
            if not paired and run_re.search(line) is not None:
                paired = True
            if paired:
                out.append(
                    _build(
                        rule,
                        rel_path,
                        lineno,
                        line.strip(),
                        f"staged-exec:{base}",
                        f"File '{base}' fetched from the network is executed "
                        "later in this file — staged download-then-execute "
                        "without a pipe; whatever the endpoint served runs "
                        "at run time.",
                        declared=declared,
                        extra_tags=extra_tags,
                        confidence=None,
                        effective_severity=None,
                    )
                )
                break  # first execution wins per downloaded basename
    return out


_DROPPER_MESSAGES: dict[str, str] = {
    "win-dropper:iwr-iex": (
        "PowerShell download-crandle (iwr piped to iex) fetches and executes "
        "remote code in one line."
    ),
    "win-dropper:invoke-webrequest-iex": (
        "PowerShell download-crandle (Invoke-WebRequest piped to "
        "Invoke-Expression) fetches and executes remote code in one line."
    ),
    "win-persist:schtasks": (
        "Windows scheduled-task creation (schtasks /create) installs recurring "
        "execution outside any agent scheduler."
    ),
    "win-persist:run-key": ("Windows Run-key write (reg add ...\\Run) re-executes at every logon."),
    "mac-persist:launchctl": (
        "macOS launchd job install (launchctl load/bootstrap/submit) persists "
        "execution past reboots."
    ),
    "mac-exec:osascript": ("macOS script execution (osascript -e) runs code outside shell review."),
}

_DROPPER_GATE_LITERALS = ("iwr", "schtasks", "reg", "launchctl", "osascript", "invoke-")


def _dropper_vocab_findings(
    rules: dict[str, Rule], rel_path: str, lines: list[str], claimed: list[str]
) -> list[Finding]:
    rule = _rule_of(rules, "LNS-SHL-009")
    if rule is None:
        return []
    declared, extra_tags = _declared_flag(rule, claimed)
    out: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        lowered = line.casefold()
        if not any(literal in lowered for literal in _DROPPER_GATE_LITERALS):
            continue  # necessary-condition gate: no dropper regex can match
        for evidence, regex in _DROPPER_RES:
            if regex.search(line) is None:
                continue
            out.append(
                _build(
                    rule,
                    rel_path,
                    lineno,
                    line.strip(),
                    evidence,
                    _DROPPER_MESSAGES[evidence],
                    declared=declared,
                    extra_tags=extra_tags,
                    confidence=None,
                    effective_severity=None,
                )
            )
    return out


def _persona_kind(label: PathLabel) -> str | None:
    """Persona/memory/persistence classification for a write sink label.

    Returns the kind token: ``self-state`` / ``memory`` / ``home-md`` /
    ``unknown-path`` (persona family, existing contract) or the widened
    persistence family: ``shell-rc`` (shell-startup files — durable code
    execution one terminal open away) and ``authorized-keys`` (appended SSH
    keys are permanent remote entry). ``outside``-labeled rc/authorized_keys
    targets fire too ($HOME rc files are the canonical location); only
    ``inside_skill_root`` stays silent (a skill's own dotfiles).
    """
    if label.label == "unknown-var":
        if label.basename in PERSONA_BASENAMES:
            return "unknown-path"
        if label.basename in PERSISTENCE_RC_BASENAMES:
            return "shell-rc"
        if label.basename == AUTHORIZED_KEYS_BASENAME:
            return "authorized-keys"
        return None
    sub = label.agent_sub if label.is_agent_home else ""
    basename = label.basename
    if label.label == "outside" or label.is_agent_home:
        if basename in PERSISTENCE_RC_BASENAMES:
            return "shell-rc"
        if basename == AUTHORIZED_KEYS_BASENAME:
            return "authorized-keys"
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
    from .base import current_context

    return current_context()


def _finding_sort_key(finding: Finding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


__all__ = [
    "AUTHORIZED_KEYS_BASENAME",
    "ENGINE_NAME",
    "PERSISTENCE_RC_BASENAMES",
    "PERSONA_BASENAMES",
    "RULE_IDS",
    "PathLabel",
    "ShellScanEngine",
    "_is_git_hooks_path",
    "classify_path_literal",
]
