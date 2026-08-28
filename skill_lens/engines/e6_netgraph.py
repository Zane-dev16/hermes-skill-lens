"""E6 netgraph engine — endpoint extraction, host classification, correlation.

Detection per core-pack rule specs (SPEC §4 row E6 / §9.1 emitters / §17 R3,
R7, R12):

- **LNS-NET-012** dead-drop/tunnel/anonymizing endpoint presence: every URL
  host/IP literal (incl. bare host mentions in prose/comments — documentation
  EXAMPLES still fire, the location distinguishes them) is classified against
  bundled host classes: paste sites, dead-drop resolvers (ntfy.sh and kin),
  tunnel providers, webhook sinks, raw-IP http(s) endpoints, and ``.onion``
  names. Presence-only ⇒ MEDIUM, ``static_only`` per the rule.
- **LNS-NET-011** AMOS-precedent exfil correlation: a send sink (curl/wget
  POST-family flags, ``requests.post``, ``fetch`` bodies) in a file that also
  reads a credential source (``.env`` paths, ``~/.ssh``, keychains,
  token-shaped variables) — the v0.9 same-file reachability bar. Host class
  refines CONFIDENCE: a classed covert endpoint (paste site, webhook sink,
  tunnel, dead-drop, raw IP, .onion) confirms at the rule default 0.88;
  an ordinary unclassed external host is the weak-evidence end of the §17
  conservative-treatment band and reports SUSPECTED at 0.55 — the live
  route to the §8.2 suspected-critical ceiling (worked example C′). Both
  shapes still fire: no benign skill posts credentials anywhere. The
  fingerprint binds ``(host-class, source-kind)``, never line numbers.
- **LNS-NET-013** money emitter: payment-rail / blockchain-RPC /
  wallet-drainer host literals fire ``capability=money`` so the undeclared-
  money ceiling (§8.2 worked example G) is exercisable from day one. Class
  membership is DATA below (SPEC-normative hosts included); extend the sets
  without touching rule files.

DECLARED-DISCOUNT interaction (§8.2 ×0.5 ``declared`` modifier): every
finding carries ``declared = is_declared(rule.capability, ir.claims)`` plus a
``declared-capability`` tag when true; the scorer applies the factor.

DETERMINISM LAW: pure functions over decoded text; sorted iteration;
fingerprints bind normalized host/class/kind shapes — never line numbers.
No sockets, no wall-clock, no execution of bundle content.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import TYPE_CHECKING

from ..claims import finding_fingerprint, is_declared
from ..ir import SkillIR
from .base import (
    Finding,
    Location,
    ScanContext,
    claimed_capability_paths,
    iter_text_files,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "netgraph"

RULE_IDS: tuple[str, ...] = ("LNS-NET-011", "LNS-NET-012", "LNS-NET-013")

# ---------------------------------------------------------------------------
# Host-class catalog (DATA — extend here, never in rule files)
# ---------------------------------------------------------------------------

#: Suffix-matched registrable domains per class. SPEC §4 normative members are
#: present verbatim (ntfy.sh; ngrok/trycloudflare/localtunnel/bore.pub;
#: api.stripe.com family; infura.io/alchemy/trongrid/blockchain.info/
#: blockstream.info); sibling entries are the sanctioned "and kin" extensions.
HOST_CLASS_DOMAINS: dict[str, frozenset[str]] = {
    "paste-site": frozenset(
        {
            "pastebin.com",
            "paste.ee",
            "hastebin.com",
            "ghostbin.com",
            "termbin.com",
            "dpaste.org",
            "dpaste.com",
            "controlc.com",
            "ix.io",
            "0x0.st",
            "transfer.sh",
            "file.io",
            "paste.centos.org",
        }
    ),
    "dead-drop-resolver": frozenset({"ntfy.sh"}),
    "tunnel-endpoint": frozenset(
        {
            "ngrok.io",
            "ngrok.com",
            "ngrok-free.app",
            "trycloudflare.com",
            "localtunnel.me",
            "loca.lt",
            "bore.pub",
            "localhost.run",
            "serveo.net",
            "pagekite.me",
        }
    ),
    "webhook-sink": frozenset(
        {
            "webhook.site",
            "requestbin.com",
            "pipedream.net",
            "hookb.in",
            "beeceptor.com",
            "interact.sh",
            "oast.fun",
            "oast.live",
            "oast.site",
        }
    ),
    # Money classes (LNS-NET-013) — SPEC §4 emitter note names rails + RPC +
    # drainers; the ceiling is exercisable because these exact hosts classify.
    "payment-rail": frozenset(
        {
            "stripe.com",
            "paypal.com",
            "razorpay.com",
            "checkout.com",
            "adyen.com",
            "braintreegateway.com",
            "mollie.com",
            "squareup.com",
        }
    ),
    "blockchain-rpc": frozenset(
        {
            "infura.io",
            "alchemy.com",
            "alchemyapi.io",
            "trongrid.io",
            "blockchain.info",
            "blockstream.info",
            "quiknode.pro",
            "moralis.io",
            "ankr.com",
        }
    ),
}

#: Wallet-drainer v1 content: deterministic brand-impersonation SHAPE — a
#: wallet-vendor token riding a NON-official registrable domain. Specific IOC
#: domains land via rule-pack updates; the shape closes today's gap without
#: fabricating IOCs (DECISIONS D-025).
WALLET_BRAND_TOKENS: tuple[str, ...] = (
    "metamask",
    "ledger-live",
    "ledgerlive",
    "trustwallet",
    "phantomwallet",
    "exoduswallet",
    "rabbywallet",
)
WALLET_BRAND_OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    {"metamask.io", "ledger.com", "trustwallet.com", "phantom.app", "exodus.com", "rabby.io"}
)

#: Classes exercised per rule (rule YAML detections are normative).
NET012_CLASSES: tuple[str, ...] = (
    "paste-site",
    "dead-drop-resolver",
    "tunnel-endpoint",
    "webhook-sink",
    "raw-ip",
    "onion",
)
NET013_CLASSES: tuple[str, ...] = ("payment-rail", "blockchain-rpc", "wallet-drainer")

# -- extraction vocabulary ----------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>|`\\)]+")
_TRAILING_JUNK = ")),.;:'\"]"

_IPV4_CORE = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
# Raw IP only counts in ENDPOINT position: scheme'd, or host:port (a bare
# dotted quad in prose is usually a version number).
_IPV4_URL_RE = re.compile(rf"(?://)({_IPV4_CORE})(?=[:/\s]|$)")
_IPV4_PORT_RE = re.compile(rf"(?<![\d.])({_IPV4_CORE}):\d{{2,5}}\b")

_ONION_RE = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.onion\b", re.IGNORECASE)

# Send sinks (same-file correlation sources for LNS-NET-011).
_CURL_SEND_RE = re.compile(
    r"\bcurl\b[^#\n]*?(?:-X\s*(?:POST|PUT)\b|(?:^|\s)-d\b|--data(?:-raw|-binary|-urlencode)?\b"
    r"|-T\b|--upload-file\b)"
)
_WGET_SEND_RE = re.compile(
    r"\bwget\b[^#\n]*?(?:--post-data\b|--post-file\b|--method=(?:POST|PUT)\b)"
)
_PY_SEND_RE = re.compile(r"\b(?:requests|httpx)\.(?:post|put)\s*\(")
_JS_SEND_RE = re.compile(r"\bfetch\s*\([^#\n]*(?:body\s*:|method\s*:\s*['\"](?:POST|PUT)['\"])")
SEND_SINK_RES: tuple[re.Pattern[str], ...] = (
    _CURL_SEND_RE,
    _WGET_SEND_RE,
    _PY_SEND_RE,
    _JS_SEND_RE,
)

# Credential sources (same-file pairing partners for LNS-NET-011), checked in
# this fixed order; first hit names the source-kind in evidence/fingerprint.
_CRED_ENV_FILE_RE = re.compile(r"(?<![\w.-])\.env\b|/\.env\b")
_CRED_SSH_RE = re.compile(r"~/\.ssh/|(?<![\w-])id_rsa\b|authorized_keys\b")
_CRED_KEYCHAIN_RE = re.compile(r"keychain|find-generic-password", re.IGNORECASE)
_CRED_TOKEN_VAR_RE = re.compile(
    r"\$\{?\w*(?:TOKEN|SECRET|PASSWD|PASSWORD|CREDENTIAL)[A-Z_0-9]*\}?"
    r"|\$\{?\w*_KEY(?:ID)?\}?"
)
CRED_SOURCE_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env-file", _CRED_ENV_FILE_RE),
    ("ssh-key", _CRED_SSH_RE),
    ("keychain", _CRED_KEYCHAIN_RE),
    ("token-variable", _CRED_TOKEN_VAR_RE),
)

#: PERF (D-049/D-056 gate family): necessary-condition prefilter for the
#: per-line host extractors. _URL_RE requires ``://``; both IPv4 regexes
#: require a ``digit.digit`` shape (``\d{1,3}\.\d{1,3}``); _ONION_RE requires
#: the letters ``onion`` (case-insensitive — folded via gate semantics, not
#: a casefolded ``in`` check, which could miss ``İ``-folded matches). A line
#: matching none can yield no host from any extractor.
_NET_HOST_GATE_RE = re.compile(r"://|\d\.\d|onion", re.IGNORECASE)

#: Necessary-condition prefilter for the send-sink vocabulary: every
#: SEND_SINK_RES regex is case-SENSITIVE and requires one of these literals,
#: so a plain substring chain is an exact necessary condition.
_SEND_SINK_GATE_LITERALS = ("curl", "wget", "requests", "httpx", "fetch")

_SNIPPET_MAX = 160

_RAW_IP_CLASS = "raw-ip"

#: Confidence for correlations whose endpoint carries NO covert host class
#: (§17 conservative treatment). A paste-site/webhook/tunnel target confirms
#: exfiltration intent at the rule default; an ordinary undeclared host is
#: circumstantial — SUSPECTED (<0.6), arming the §8.2 suspected-critical
#: ceiling (grade ≤D + needs_review) instead of the confirmed ≤F cap.
SUSPECTED_CORRELATION_CONFIDENCE = 0.55


@lru_cache(maxsize=4096)
def _is_raw_ip(host: str) -> bool:
    """Is this extracted host token an IPv4 literal (raw-IP endpoint class)?"""
    return bool(re.fullmatch(_IPV4_CORE, host)) and _valid_ipv4(host)


def _valid_ipv4(literal: str) -> bool:
    parts = literal.split(".")
    # isascii() before int(): str.isdigit() admits Unicode digit characters
    # (e.g. "\u00b2") that int() rejects — never raise on invalid input
    # (advisor-not-gate); ASCII-digit literals classify exactly as before.
    parts_ok = len(parts) == 4
    if parts_ok:
        for part in parts:
            if not (part.isdigit() and part.isascii()):
                return False
            try:
                if not 0 <= int(part) <= 255:
                    return False
            except ValueError:  # pragma: no cover — isdigit()+isascii() precludes it
                return False
    return parts_ok


def host_suffix_match(host: str, domain: str) -> bool:
    """True when *host* is exactly *domain* or a subdomain of it."""
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def classify_host(host: str) -> tuple[str, ...]:
    """Host-class names for a hostname/IP literal (sorted; empty if none).

    Wallet-drainer classification is the brand-impersonation shape: a vendor
    token in the host while the registrable domain is NOT the vendor's own.
    """
    classes: list[str] = []
    lowered = host.lower().rstrip(".")
    for class_name in sorted(HOST_CLASS_DOMAINS):
        for domain in sorted(HOST_CLASS_DOMAINS[class_name]):
            if host_suffix_match(lowered, domain):
                classes.append(class_name)
                break
    tokens = [tok for tok in WALLET_BRAND_TOKENS if tok in lowered]
    official = any(host_suffix_match(lowered, dom) for dom in sorted(WALLET_BRAND_OFFICIAL_DOMAINS))
    if tokens and not official:
        classes.append("wallet-drainer")
    if lowered.endswith(".onion"):
        classes.append("onion")
    return tuple(sorted(classes))


def url_hostname(url: str) -> str:
    """Hostname of a SCHEME'D URL literal — pure string parsing, no urllib.

    Privacy law G1/G3 keeps the default import closure free of network
    modules; ``urllib.parse`` was the lone exception (parser-only, zero I/O,
    but still an import-graph liability). This vendored extractor mirrors
    ``urlparse(url).hostname`` for every shape :data:`_URL_RE` can produce
    (scheme required, single authority): lowercased, userinfo-stripped,
    port-stripped, IPv6 brackets removed, trailing dots preserved.
    Equivalence with urllib is property-tested (tests/test_engine_netgraph)
    so behavior can never silently drift from the stdlib semantics.
    """
    _, sep, rest = url.partition("://")
    if not sep:
        return ""
    for separator in ("/", "?", "#"):
        cut = rest.find(separator)
        if cut != -1:
            rest = rest[:cut]
    if "[" in rest or "]" in rest:
        # Bracket discipline mirrors urllib's "Invalid IPv6 URL" ValueError
        # (old code SKIPPED those literals): brackets are legal ONLY as a
        # leading [ip-literal] (optionally :port, optionally after userinfo)
        # whose content parses as an actual IP address; every other bracket
        # shape yields "" so extract_url_hosts skips the pair identically.
        if rest.count("[") != rest.count("]"):
            return ""
        _, _, hostpart = rest.rpartition("@")
        end = hostpart.find("]")
        if not hostpart.startswith("[") or end == -1:
            return ""
        tail = hostpart[end + 1 :]
        if tail and not (tail.startswith(":") and tail[1:].isdigit()):
            return ""
        literal = hostpart[1:end]
        try:
            ipaddress.ip_address(literal)
        except ValueError:
            return ""
        return literal.lower()
    if "@" in rest:  # userinfo ends at the LAST @ inside the authority
        rest = rest.rsplit("@", 1)[1]
    if ":" in rest:  # host:port — first colon (bare IPv6 never reaches here)
        rest = rest.split(":", 1)[0]
    return rest.lower()


def extract_url_hosts(line: str) -> list[tuple[str, str]]:
    """``(raw_url, host)`` pairs for URL literals on one line (stable order)."""
    pairs: list[tuple[str, str]] = []
    for match in _URL_RE.finditer(line):
        raw = match.group(0)
        trimmed = raw.rstrip(_TRAILING_JUNK)
        try:
            host = url_hostname(trimmed)
        except ValueError:  # pragma: no cover — defensive, parser rarely raises
            continue
        if host:
            pairs.append((trimmed, host))
    return pairs


def extract_raw_ips(line: str) -> list[str]:
    """Endpoint-position IPv4 literals (scheme'd or host:port), validated."""
    found: list[str] = []
    seen: set[str] = set()
    for regex in (_IPV4_URL_RE, _IPV4_PORT_RE):
        for match in regex.finditer(line):
            ip = match.group(1)
            if _valid_ipv4(ip) and ip not in seen:
                seen.add(ip)
                found.append(ip)
    return found


def extract_onion_hosts(line: str) -> list[str]:
    return [match.group(0).lower() for match in _ONION_RE.finditer(line)]


def credential_source_kind(text: str) -> str | None:
    """First credential-source kind present in *text* (fixed order)."""
    for kind, regex in CRED_SOURCE_RES:
        if regex.search(text):
            return kind
    return None


def line_has_send_sink(line: str) -> bool:
    if not (
        "curl" in line or "wget" in line or "requests" in line or "httpx" in line or "fetch" in line
    ):
        return False  # necessary-condition gate: no send regex can match (PERF)
    return any(regex.search(line) for regex in SEND_SINK_RES)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class NetgraphEngine:
    """E6 implementation — extraction, classification, correlation."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        del ctx  # pure text analysis over IR-recorded files only
        claimed = claimed_capability_paths(bundle_ir)
        findings: list[Finding] = []

        net012 = self._rules.get("LNS-NET-012")
        net013 = self._rules.get("LNS-NET-013")
        if net012 is not None or net013 is not None:
            findings.extend(self._classify_literals(bundle_ir, net012, net013, claimed))

        net011 = self._rules.get("LNS-NET-011")
        if net011 is not None:
            findings.extend(self._exfil_correlation(bundle_ir, net011, claimed))

        findings.sort(key=_finding_sort_key)
        return findings

    # -- LNS-NET-012 / LNS-NET-013 -------------------------------------------

    def _classify_literals(
        self,
        bundle_ir: SkillIR,
        net012: Rule | None,
        net013: Rule | None,
        claimed: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for record, text in iter_text_files(bundle_ir, _current_ctx()):
            for lineno, line in enumerate(text.splitlines(), start=1):
                if _NET_HOST_GATE_RE.search(line) is None:
                    continue  # necessary-condition gate: no host extractor can match (PERF)
                hosts: list[str] = [host for _raw, host in extract_url_hosts(line)]
                hosts.extend(extract_raw_ips(line))
                hosts.extend(extract_onion_hosts(line))
                for host in dict.fromkeys(hosts):  # dedupe, keep first-seen order
                    if _is_raw_ip(host):
                        classes: tuple[str, ...] = (_RAW_IP_CLASS,)
                    else:
                        classes = classify_host(host)
                    for class_name in classes:
                        rule = None
                        if net013 is not None and class_name in NET013_CLASSES:
                            rule = net013
                        elif net012 is not None and class_name in NET012_CLASSES:
                            rule = net012
                        if rule is None:
                            continue
                        declared = is_declared(rule.capability, claimed)
                        tags = rule.tags + (("declared-capability",) if declared else ())
                        findings.append(
                            _classified_finding(
                                rule,
                                record.path,
                                lineno,
                                line,
                                host,
                                class_name,
                                declared,
                                tags,
                            )
                        )
        return findings

    # -- LNS-NET-011 ----------------------------------------------------------

    def _exfil_correlation(
        self,
        bundle_ir: SkillIR,
        rule: Rule,
        claimed: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        declared = is_declared(rule.capability, claimed)
        tags = rule.tags + (("declared-capability",) if declared else ())
        for record, text in iter_text_files(bundle_ir, _current_ctx()):
            source_kind = credential_source_kind(text)
            if source_kind is None:
                continue  # pairing REQUIRED: a send sink alone proves nothing
            lines = text.splitlines()
            file_classes: list[str] = []
            for line in lines:
                if "://" not in line:
                    continue  # necessary-condition gate: _URL_RE requires "://"
                for _raw, host in extract_url_hosts(line):
                    for class_name in classify_host(host):
                        if class_name not in file_classes:
                            file_classes.append(class_name)
            for lineno, line in enumerate(lines, start=1):
                if not line_has_send_sink(line):
                    continue
                line_classes: list[str] = []
                for _raw, host in extract_url_hosts(line):
                    line_classes.extend(c for c in classify_host(host) if c not in line_classes)
                host_class = next((c for c in line_classes if c in NET012_CLASSES), None)
                if host_class is None:
                    host_class = next((c for c in file_classes if c in NET012_CLASSES), None)
                if host_class is None:
                    host_class = "external-host"
                confidence = (
                    rule.confidence_default
                    if host_class != "external-host"
                    else SUSPECTED_CORRELATION_CONFIDENCE
                )
                findings.append(
                    _correlation_finding(
                        rule,
                        record.path,
                        lineno,
                        line,
                        host_class,
                        source_kind,
                        declared,
                        tags,
                        confidence=confidence,
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Finding builders (module-level = pure, unit-testable)
# ---------------------------------------------------------------------------


def _snippet(line: str) -> str:
    return line.strip()[:_SNIPPET_MAX]


def _finding_sort_key(finding: Finding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


def _classified_finding(
    rule: Rule,
    rel_path: str,
    lineno: int,
    line: str,
    host: str,
    class_name: str,
    declared: bool,
    tags: tuple[str, ...],
) -> Finding:
    evidence = f"{class_name}:{host.lower()}"
    return Finding(
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
        declared=declared,
        location=Location(
            path=rel_path,
            start_line=lineno,
            end_line=lineno,
            snippet=_snippet(line),
            redacted=False,
        ),
        message=(
            f"{class_name} endpoint '{host}' referenced ({rule.id} presence-only "
            "signal; reviewers decide intent)."
        ),
        remediation=rule.remediation,
        tags=tags,
    )


def _correlation_finding(
    rule: Rule,
    rel_path: str,
    lineno: int,
    line: str,
    host_class: str,
    source_kind: str,
    declared: bool,
    tags: tuple[str, ...],
    *,
    confidence: float | None = None,
) -> Finding:
    evidence = f"correlation:{host_class}:{source_kind}"
    return Finding(
        fingerprint=finding_fingerprint(rule.id, rule.capability, evidence),
        rule_id=rule.id,
        rule_version=rule.rule_version,
        engine=rule.engine,
        title=rule.title,
        capability=rule.capability,
        severity=rule.severity,
        effective_severity=rule.severity,
        confidence=rule.confidence_default if confidence is None else confidence,
        evidence_kind=rule.evidence_kind,
        static_only=rule.static_only,
        declared=declared,
        location=Location(
            path=rel_path,
            start_line=lineno,
            end_line=lineno,
            snippet=_snippet(line),
            redacted=False,
        ),
        message=(
            f"Send sink posts data toward a {host_class} endpoint while the same "
            f"file reads a credential source ({source_kind}) — credential-"
            "exfiltration shape (same-file reachability bar)."
        ),
        remediation=rule.remediation,
        tags=tags,
    )


def _current_ctx() -> ScanContext:
    """Ambient scan context (engines/__init__ installs it around dispatch)."""
    from .base import current_context

    return current_context()


__all__ = [
    "ENGINE_NAME",
    "HOST_CLASS_DOMAINS",
    "NET012_CLASSES",
    "NET013_CLASSES",
    "RULE_IDS",
    "SUSPECTED_CORRELATION_CONFIDENCE",
    "NetgraphEngine",
    "classify_host",
    "credential_source_kind",
    "extract_url_hosts",
    "host_suffix_match",
    "line_has_send_sink",
]
