"""E7 secretscan engine — committed credentials, redaction-guaranteed.

Detection per core-pack rule specs (SPEC §4 row E7 / §17 R9):

- **LNS-SEC-001** known key formats over every decodable file (incl. the
  IR's decoded-view promise once the decode ladder lands): AWS access-key
  ids PAIRED with their 40-char secret form in the same file, PEM PRIVATE
  KEY blocks, OpenAI ``sk-`` tokens, Slack ``xox?-`` tokens, and GCP
  service-account JSON (``private_key_id`` + PEM together — classified as
  the more specific GCP shape instead of emitting a second plain-PEM
  finding for the same block, DECISIONS D-024). ``static_only=false``: a
  format-complete credential is usable AS-IS by any reader.
- **LNS-SEC-002** Shannon-entropy windows (>=24 chars at >=4.8 bits/char,
  thresholds pinned by D-014 against this pack's benign corpus) restricted
  to assignment/export/config and bearer/pat contexts; strings inside
  obvious test/example markers are SKIPPED verbatim per the rule spec.

REDACTION GUARANTEE (privacy law "secrets never rendered unredacted"):
snippets carry the matched line with the secret replaced by
:meth:`mask_secret` (prefix + length only); fingerprints bind masked
shapes — never the raw value. A suite test asserts no full secret
substring survives anywhere in a serialized finding.

Example-block policy (DECISIONS D-024): SEC-002 skips marker lines exactly
as its rule spec demands; SEC-001 deliberately has NO example carve-out —
format completeness IS its FP filter (the canonical AWS documentation
placeholders are format-complete by design, and downgrading demonstrated
exposure would hide real leaks).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
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

if TYPE_CHECKING:
    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "secretscan"

RULE_IDS: tuple[str, ...] = ("LNS-SEC-001", "LNS-SEC-002")

# -- LNS-SEC-001 vocabulary ---------------------------------------------------

_AWS_ID_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")
_OPENAI_TOKEN_RE = re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b")
_SLACK_TOKEN_RE = re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b")
_PEM_BEGIN_RE = re.compile(r"-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----")
_PEM_END_RE = re.compile(r"-----END ((?:RSA |EC )?PRIVATE KEY)-----")
_GCP_HINT_RE = re.compile(r"private_key_id")

_SNIPPET_MAX = 200

# -- LNS-SEC-002 vocabulary ---------------------------------------------------

_ENTROPY_THRESHOLD = 4.8
_MIN_TOKEN_CHARS = 24

_TOKEN_CANDIDATE_RE = re.compile(rf"[A-Za-z0-9][A-Za-z0-9+/=_\-]{{{_MIN_TOKEN_CHARS - 1},}}")

#: Rule-spec marker skip: obvious test/example strings never report (SEC-002).
_EXAMPLE_MARKER_RE = re.compile(r"(?i)example|placeholder|xxxxxx|x{4,}|not[-_ ]?real|dummy")

#: Assignment/export/config context: `NAME=<tok>`, `"name": "<tok>"`, YAML
#: `- name: <tok>`. Anchored to the text IMMEDIATELY before the token.
_ASSIGNMENT_PREFIX_RE = re.compile(
    # Optional closing quote between name and separator covers JSON's
    # '"name": "' shape as well as shell/yaml NAME= / name: forms.
    r"""(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*["']?\s*[:=]\s*["']?\s*$""",
)
#: Bearer/pat prefix context (`Authorization: Bearer <tok>` etc.).
_BEARER_PREFIX_RE = re.compile(
    r"""(?i)\b(bearer|token|pat|authorization|api[_-]?key)\b[^A-Za-z0-9]*$"""
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits/char (pure; stable summation order)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in sorted(counts.values()):
        share = count / total
        entropy -= share * math.log2(share)
    return entropy


def mask_secret(value: str) -> str:
    """Prefix + length ONLY — the middle is never rendered (privacy law).

    Short values mask completely; longer ones keep their first four chars
    so humans can tell which credential rotated without any usable suffix
    surviving.
    """
    n = len(value)
    if n <= 8:
        return "*" * n
    return f"{value[:4]}\u2026<{n} chars>"


class SecretScanEngine:
    """E7 implementation — location-reporting, value-redacting scans."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        sec001 = self._rules.get("LNS-SEC-001")
        sec002 = self._rules.get("LNS-SEC-002")
        findings: list[Finding] = []
        for record, text in iter_text_files(bundle_ir, ctx):
            lines = text.splitlines()
            if sec001 is not None:
                findings.extend(self._known_formats(sec001, record.path, lines, text))
            if sec002 is not None:
                findings.extend(self._entropy_windows(sec002, record.path, lines))
        findings.sort(key=finding_sort_key)
        return findings

    # -- LNS-SEC-001 ----------------------------------------------------------

    def _known_formats(
        self, rule: Rule, rel_path: str, lines: list[str], full_text: str
    ) -> list[Finding]:
        aws_ids: list[tuple[int, str]] = []
        aws_secrets: list[tuple[int, str]] = []
        openai_hits: list[tuple[int, str]] = []
        slack_hits: list[tuple[int, str]] = []
        pem_blocks: list[tuple[int, int, str]] = []  # (begin_line, end_line, algo)

        for lineno, line in enumerate(lines, start=1):
            for match in _AWS_ID_RE.finditer(line):
                aws_ids.append((lineno, match.group(1)))
            for match in _AWS_SECRET_RE.finditer(line):
                aws_secrets.append((lineno, match.group(1)))
            for match in _OPENAI_TOKEN_RE.finditer(line):
                openai_hits.append((lineno, match.group(1)))
            for match in _SLACK_TOKEN_RE.finditer(line):
                slack_hits.append((lineno, match.group(1)))
        pem_blocks = _match_pem_blocks(lines)

        findings: list[Finding] = []

        # GCP service-account JSON: private_key_id hint + PEM present ->
        # classify the block as the more specific GCP shape instead of
        # double-reporting it as a plain PEM block (DECISIONS D-024).
        gcp_mode = bool(_GCP_HINT_RE.search(full_text)) and bool(pem_blocks)

        for lineno, value in aws_ids:
            if not aws_secrets:
                break  # pairing REQUIRED: an id alone proves nothing (FP filter)
            snippet = _masked_line(lines[lineno - 1], value)
            findings.append(
                self._sec001_finding(
                    rule,
                    rel_path,
                    f"aws:{mask_secret(value)}",
                    lineno,
                    lineno,
                    snippet,
                    "aws-access-key-pair",
                    "AWS access-key id committed alongside its secret-key form",
                )
            )
        for begin_line, end_line, algo in pem_blocks:
            label = "gcp-service-account-json" if gcp_mode else "pem-private-key"
            evidence = f"{label}:{algo.lower().strip()}:{(end_line and end_line - begin_line + 1)}"
            snippet = _pem_snippet(lines, begin_line, end_line)
            message = (
                "GCP-style service-account private key block committed"
                if gcp_mode
                else "PEM private-key block committed"
            )
            findings.append(
                self._sec001_finding(
                    rule, rel_path, evidence, begin_line, end_line, snippet, label, message
                )
            )
        seen_tokens: set[str] = set()
        for lineno, value in openai_hits:
            if value in seen_tokens:
                continue
            seen_tokens.add(value)
            snippet = _masked_line(lines[lineno - 1], value)
            findings.append(
                self._sec001_finding(
                    rule,
                    rel_path,
                    f"openai:{mask_secret(value)}",
                    lineno,
                    lineno,
                    snippet,
                    "openai-token",
                    "OpenAI-format token committed",
                )
            )
        seen_tokens = set()
        for lineno, value in slack_hits:
            if value in seen_tokens:
                continue
            seen_tokens.add(value)
            snippet = _masked_line(lines[lineno - 1], value)
            findings.append(
                self._sec001_finding(
                    rule,
                    rel_path,
                    f"slack:{mask_secret(value)}",
                    lineno,
                    lineno,
                    snippet,
                    "slack-token",
                    "Slack-format token committed",
                )
            )
        return findings

    def _sec001_finding(
        self,
        rule: Rule,
        rel_path: str,
        normalized_evidence: str,
        start_line: int,
        end_line: int,
        snippet: str,
        kind_tag: str,
        message: str,
    ) -> Finding:
        tags = tuple(rule.tags) + (kind_tag,)
        return Finding(
            fingerprint=finding_fingerprint(rule.id, rule.capability, normalized_evidence),
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
                path=rel_path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet,
                redacted=True,
            ),
            message=message,
            remediation=rule.remediation,
            tags=tags,
        )

    # -- LNS-SEC-002 ----------------------------------------------------------

    def _entropy_windows(self, rule: Rule, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for lineno, line in enumerate(lines, start=1):
            if _EXAMPLE_MARKER_RE.search(line):
                continue  # rule-spec skip: test/example markers never report
            for match in _TOKEN_CANDIDATE_RE.finditer(line):
                token = match.group(0)
                if token in reported:
                    continue
                if not _in_reporting_context(line, match.start()):
                    continue
                entropy = shannon_entropy(token)
                if entropy < _ENTROPY_THRESHOLD:
                    continue
                reported.add(token)
                snippet = _masked_line(line, token)
                evidence = f"window:{len(token)}:{round(entropy, 1)}"
                findings.append(
                    Finding(
                        fingerprint=finding_fingerprint(rule.id, rule.capability, evidence),
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
                            path=rel_path,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=snippet,
                            redacted=True,
                        ),
                        message=(
                            f"high-entropy string ({len(token)} chars, "
                            f"{entropy:.2f} bits/char) in assignment/bearer "
                            "context looks like a bare secret token"
                        ),
                        remediation=rule.remediation,
                        tags=tuple(rule.tags),
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Helpers (module-level = unit-testable, pure)
# ---------------------------------------------------------------------------


def _match_pem_blocks(lines: list[str]) -> list[tuple[int, int, str]]:
    """Sequential BEGIN/END pairing of PEM PRIVATE KEY blocks (stable)."""
    blocks: list[tuple[int, int, str]] = []
    open_algo: str | None = None
    open_line = 0
    for lineno, line in enumerate(lines, start=1):
        if open_algo is None:
            match = _PEM_BEGIN_RE.search(line)
            if match is not None:
                open_algo = match.group(1)
                open_line = lineno
        else:
            if _PEM_BEGIN_RE.search(line):
                # Nested/unterminated begin: keep the outermost open block.
                continue
            match = _PEM_END_RE.search(line)
            if match is not None:
                blocks.append((open_line, lineno, open_algo))
                open_algo = None
    return blocks


def _in_reporting_context(line: str, token_start: int) -> bool:
    """Is the candidate token in an assignment/config or bearer position?"""
    prefix = line[:token_start]
    return bool(_ASSIGNMENT_PREFIX_RE.search(prefix) or _BEARER_PREFIX_RE.search(prefix))


def _masked_line(line: str, secret: str) -> str:
    """The matched line with EVERY occurrence of *secret* masked."""
    masked = line.replace(secret, mask_secret(secret)).strip()
    return masked[:_SNIPPET_MAX]


def _pem_snippet(lines: list[str], begin_line: int, end_line: int) -> str:
    """PEM evidence: markers + withheld body, never key material."""
    begin_marker = lines[begin_line - 1].strip()
    body_lines = max(0, end_line - begin_line - 1)
    return f"{begin_marker} \u2026<{body_lines} lines of key material withheld>"[:_SNIPPET_MAX]


__all__ = [
    "ENGINE_NAME",
    "RULE_IDS",
    "SecretScanEngine",
    "mask_secret",
    "shannon_entropy",
]
