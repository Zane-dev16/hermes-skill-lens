"""Layered policy engine (SPEC §10) — resolution, merge, application.

Resolution order (NORMATIVE, later wins)::

    builtin defaults
      → profile pack (``street`` | ``lab``)
      → Hermes plugin settings (``plugins.entries.lens.settings.*`` via ctx.get_config)
      → global config file (``$XDG_CONFIG_HOME/lens/policy.toml``)
      → project ``.lens/policy.toml``
      → extra policy files (``--policy F``, read-only)
      → explicit CLI/slash flags

The profile NAME is itself a scalar resolved across the settings/file/flag
layers (later wins); whichever layer names it, the profile's own value-pack
lands at its normative slot — slot 2 — so ordinary layers still override
individual values on top of it. ``street`` is the default everywhere.

Merge semantics (SPEC §10): scalars override; maps deep-merge; lists replace
unless prefixed ``+`` (append). A list where ANY item carries a leading ``+``
appends ALL its items (prefix stripped) to the lower layer's list; a list with
no ``+`` items replaces outright. ``rules.severity_override`` follows map
semantics by ``rule_id`` (later entries win per rule) regardless of TOML shape
(array-of-inline-tables or table), because overrides are keyed data.

Every effective value carries a provenance label naming the layer that last
wrote it (:attr:`EffectivePolicy.provenance`, keyed by dotted path) — rendered
by ``explain-rules`` and doctor. Labels are machine-stable constants: absolute
paths NEVER enter labels (envelope determinism law); file layers use stable
display forms (``project .lens/policy.toml:L12``).

HARD BOUNDARY (task law): policy can override SEVERITY display
(:meth:`EffectivePolicy.severity_override_for` feeds ``effective_severity``;
the pricing tier keeps reading rule-assigned ``severity``, so weights stay
pinned) but NEVER weights, tier caps, ceilings, or grades. The SPEC §10
``[score]`` table is recognized so the normative example parses cleanly;
values equal to the published defaults pass silently, any other value is a
tamper attempt: warning diagnostic + ignored. :class:`EffectivePolicy`
exposes no score fields at all — the scorer keeps using
:data:`skill_lens.scoring` constants unconditionally.

Error lane: an EXISTING policy file that fails to parse or read raises
:class:`PolicyError` — configuration-seam semantics (exit 2 on CLI verbs,
ONE-LINE notice in-session via :func:`policy_failure_notice`; never an
exception into the host). A MISSING file means the layer is simply absent.
Settings mismatches only warn (SPEC §10: "mismatches warn, never fail load").

DETERMINISM LAW: expiry evaluation takes the report date as a PARAMETER
(``report_date=``) — wall-clock never enters decisions here. Iteration over
user data is sorted; pure functions throughout.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .diagnostics import (
    Diagnostic,
    DiagnosticsCollector,
)
from .scoring import (
    CEILING_INTEGRITY,
    CEILING_MONEY,
    CEILING_SUSPECTED_CRITICAL,
    SEVERITY_TIERS,
)

# -- identity -----------------------------------------------------------------

#: Stable diagnostic codes for the policy subsystem.
CODE_POLICY_PARSE = "LNS-POLICY-PARSE"
CODE_POLICY_UNKNOWN_KEY = "LNS-POLICY-UNKNOWN-KEY"
CODE_POLICY_SCORE_TAMPER = "LNS-POLICY-SCORE-TAMPER"
CODE_POLICY_OVERRIDE_INVALID = "LNS-POLICY-OVERRIDE-INVALID"
CODE_POLICY_OVERRIDE_NO_REASON = "LNS-POLICY-OVERRIDE-NO-REASON"
CODE_POLICY_OVERRIDE_EXPIRED = "LNS-POLICY-OVERRIDE-EXPIRED"
CODE_POLICY_BASELINE_ENTRY_INVALID = "LNS-POLICY-BASELINE-INVALID"
CODE_POLICY_SETTING_TYPE = "LNS-POLICY-SETTING-TYPE"

#: Exit code CLI verbs project for policy configuration failures (§18: exit 2
#: is TOTAL error, raised by callers — never synthesized by compute_exit_code).
POLICY_EXIT_CODE = 2

# -- vocabularies -------------------------------------------------------------

PROFILES: tuple[str, ...] = ("street", "lab")
DEFAULT_PROFILE = "street"

#: Severity targets a display override may name: the four rubric tiers (§7/D-021).
OVERRIDE_SEVERITIES: tuple[str, ...] = SEVERITY_TIERS

#: Recognized plugin-settings keys (SPEC §10; validated against manifest
#: config_schema). Keys are PLUGIN-RELATIVE — the host prefixes
#: ``plugins.entries.lens.settings.`` itself (hermes_cli/plugins.py::get_config).
KNOWN_SETTINGS_KEYS: tuple[str, ...] = (
    "profile",
    "watch.poll",
    "discord_spoilers",
    "voice",
    "chat_budget_chars",
)

_SETTINGS_LABEL_BASE = "plugin settings plugins.entries.lens.settings"

#: Machine-visible annotation/flag vocabulary (policy-visible, never secret).
FLAG_ALLOW_MATCHED = "allow_matched"
ANNOTATION_ALLOW_MATCHED = "[policy:allow-matched]"
ANNOTATION_DENIED_BY_POLICY = "DENIED-BY-POLICY"
MARKER_LAB_DECLARED_OFFENSIVE = "[lab:declared-offensive]"

#: Offensive-tooling capability classes whose ``declared`` discount the lab
#: profile unlocks when the bundle declares offensive scope (SPEC §10):
#: ``execute.*``, ``credentials.read`` (RFC1918/doc ranges), ``network.scan``.
OFFENSIVE_CAPABILITY_FAMILIES: tuple[str, ...] = (
    "execute",
    "credentials.read",
    "network.scan",
)

#: Lexicon marking a bundle as declaring offensive scope (SPEC §10:
#: ``pentest|red-team|security testing``).
_OFFENSIVE_SCOPE_RE = re.compile(r"\bpentest\b|\bred[- ]team(?:ing|ed)?\b|\bsecurity testing\b")

_RULE_ID_RE = re.compile(r"^LNS-[A-Z0-9]{2,4}-[0-9]{3}$")

# -- published score constants (read-only mirror used ONLY for tamper checks) --

_PUBLISHED_CEILINGS: dict[str, int] = {
    "suspected_critical_ceiling": CEILING_SUSPECTED_CRITICAL.score_cap,
    "money_ceiling": CEILING_MONEY.score_cap,
    "integrity_ceiling": CEILING_INTEGRITY.score_cap,
}

#: Top-level tables the loader understands. Anything else warns-and-ignores.
_KNOWN_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {"profile", "score", "rules", "network", "baseline", "choir"}
)


class PolicyError(Exception):
    """Structural policy fault on the exit-2 lane (SPEC §18).

    Raised ONLY for existing policy files that cannot be read/parsed (and for
    caller-level misuse like a bad flags mapping). Never raised past scan
    callbacks; in-session surfaces catch it and render ONE line via
    :func:`policy_failure_notice`.
    """

    def __init__(self, message: str, *, path: str | None = None) -> None:
        self.message = _one_line(message)
        self.path = path
        super().__init__(self.message)


def _one_line(text: Any) -> str:
    """Collapse *text* to a single surface-safe line (no control bytes)."""
    return " ".join(str(text).split())[:300]


def policy_failure_notice(error: PolicyError | str, *, path: str | None = None) -> str:
    """The ONE-LINE notice in-session surfaces render on malformed policy.

    Deterministic, single line, no ANSI — safe for slash output and logs.
    """
    if isinstance(error, PolicyError):
        location = f" ({error.path})" if error.path else ""
        return _one_line(f"lens: policy error{location}: {error.message}")
    return _one_line(f"lens: policy error{f' ({path})' if path else ''}: {error}")


# ---------------------------------------------------------------------------
# Merge semantics (SPEC §10): scalars override · maps deep-merge ·
# lists replace unless prefixed "+"
# ---------------------------------------------------------------------------


def is_append_list(items: Sequence[Any]) -> bool:
    """True when any string item in *items* carries the ``+`` append prefix."""
    return any(isinstance(item, str) and item.startswith("+") for item in items)


def strip_append_prefix(item: Any) -> Any:
    """Strip one leading ``+`` from a string item; other values pass through."""
    if isinstance(item, str) and item.startswith("+"):
        return item[1:]
    return item


def merge_policy_values(base: Any, overlay: Any) -> Any:
    """Merge *overlay* over *base* per SPEC §10 semantics. Pure.

    - dict ∩ dict → recursive deep-merge per key;
    - list ∩ list → replace, unless any overlay item is ``+``prefixed, in
      which case ALL overlay items append (prefix stripped) onto *base*;
    - anything else → overlay wins wholesale (scalars override; type
      mismatches degrade to replacement — later layers know what they mean).
    """
    if isinstance(base, Mapping) and isinstance(overlay, Mapping):
        merged = {str(k): v for k, v in base.items()}
        for key in overlay:
            child = base.get(key)
            incoming = overlay[key]
            merged[str(key)] = (
                merge_policy_values(child, incoming) if child is not None else incoming
            )
        return merged
    if isinstance(base, list) and isinstance(overlay, list):
        if is_append_list(overlay):
            return list(base) + [strip_append_prefix(item) for item in overlay]
        return list(overlay)
    return overlay


# ---------------------------------------------------------------------------
# Provenance-tracked layered merge
# ---------------------------------------------------------------------------


def _track_merge(
    base: Any,
    overlay: Mapping[str, Any],
    layer: str,
    provenance: dict[str, str],
    prefix: str = "",
) -> dict[str, Any]:
    """Deep-merge *overlay* into *base*, recording each written dotted path.

    Uses the SPEC §10 semantics (:func:`merge_policy_values`) for every
    non-map value — scalars override, lists replace unless ``+``prefixed —
    so the provenance-tracked loader cannot drift from the pure merge.
    """
    merged = {str(k): v for k, v in base.items()} if isinstance(base, Mapping) else {}
    for key in overlay:
        path = f"{prefix}.{key}" if prefix else str(key)
        existing = merged.get(key)
        incoming = overlay[key]
        if isinstance(existing, Mapping) and isinstance(incoming, Mapping):
            merged[str(key)] = _track_merge(existing, incoming, layer, provenance, path)
        elif existing is not None:
            merged[str(key)] = merge_policy_values(existing, incoming)
            provenance[path] = layer
        else:
            merged[str(key)] = incoming
            provenance[path] = layer
    return merged


def _blank_defaults() -> dict[str, Any]:
    """Fresh builtin-default tree (new list objects every call)."""
    return {
        "profile": DEFAULT_PROFILE,
        "rules": {"disable": [], "severity_override": []},
        "network": {"allow_hosts": [], "allow_ips": [], "deny_hosts": []},
        "baseline": [],
        "choir": {"enabled": False},
    }


# ---------------------------------------------------------------------------
# File reading (strict lane) + line-number provenance
# ---------------------------------------------------------------------------


def read_policy_file(path: str | Path) -> tuple[dict[str, Any], str]:
    """Parse one policy TOML file. Raises :class:`PolicyError` when broken.

    Returns ``(data, raw_text)`` — text feeds ``:L<nn>`` provenance lookup.
    """
    file_path = Path(path)
    label = str(file_path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file: {exc}", path=label) from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in policy file: {exc}", path=label) from exc
    if not isinstance(data, dict):  # pragma: no cover — tomllib always yields dict
        raise PolicyError("policy file must parse to a TOML table", path=label)
    return data, raw


def _key_line_index(raw_text: str) -> dict[str, int]:
    """Best-effort map of dotted key → first 1-based line mentioning it.

    Understands ``[table]`` / ``[[array]]`` headers and ``key =`` lines well
    enough to power ``project .lens/policy.toml:L12`` provenance; keys it
    cannot locate simply have no entry (the label omits ``:L``).
    """
    index: dict[str, int] = {}
    table = ""
    for lineno, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = re.match(r"^\[\[?([^\]\s]+)\]?\]", stripped)
        if header:
            table = header.group(1).strip().strip('"')
            index.setdefault(table, lineno)
            continue
        pair = re.match(r"^([A-Za-z0-9_.\-]+)\s*=", stripped)
        if pair:
            key = pair.group(1)
            full = f"{table}.{key}" if table else key
            index.setdefault(full, lineno)
            index.setdefault(key, lineno)
    return index


def _line_for(lines: Mapping[str, int], dotted_path: str) -> int | None:
    """Line number for a dotted policy path (full path first, then tail)."""
    hit = lines.get(dotted_path)
    if hit is None:
        hit = lines.get(dotted_path.rsplit(".", 1)[-1])
    return hit


# ---------------------------------------------------------------------------
# Plugin-settings layer (lenient lane — warn, never fail)
# ---------------------------------------------------------------------------


def _coerce_setting(key: str, value: Any) -> Any | None:
    """Validate one settings value against its schema shape; None ⇒ mismatch."""
    expectations: dict[str, tuple[type, ...]] = {
        "profile": (str,),
        "watch.poll": (int, float),
        "discord_spoilers": (bool,),
        "voice": (str,),
        "chat_budget_chars": (int,),
    }
    allowed = expectations.get(key)
    if allowed is None:
        return None
    if isinstance(value, bool) and bool not in allowed:
        return None
    if not isinstance(value, allowed):
        return None
    if key == "profile" and value not in PROFILES:
        return None
    if key in ("watch.poll", "chat_budget_chars") and value <= 0:
        return None
    return value


def read_settings_layer(ctx: Any, diag: DiagnosticsCollector | None) -> dict[str, Any]:
    """Read recognized plugin-settings keys via ``ctx.get_config``.

    Keys are plugin-relative; failures and type mismatches produce warnings
    and are skipped — the settings layer never blocks a load (SPEC §10).
    """
    values: dict[str, Any] = {}
    if ctx is None:
        return values
    getter = getattr(ctx, "get_config", None)
    if not callable(getter):
        return values
    for key in KNOWN_SETTINGS_KEYS:
        try:
            raw = getter(key, None)
        except Exception:  # noqa: BLE001 — host seams may raise anything.
            if diag is not None:
                diag.warning(
                    CODE_POLICY_SETTING_TYPE,
                    f"settings key {key!r} unreadable from host context; ignored",
                )
            continue
        if raw is None:
            continue
        coerced = _coerce_setting(key, raw)
        if coerced is None:
            if diag is not None:
                diag.warning(
                    CODE_POLICY_SETTING_TYPE,
                    f"settings key {key!r} has unexpected value {raw!r}; ignored",
                )
            continue
        values[key] = coerced
    return values


# ---------------------------------------------------------------------------
# Entry models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeverityOverride:
    """One rule-keyed severity display override (reason REQUIRED, §10)."""

    rule_id: str
    severity: str
    reason: str
    expires: date | None = None

    def expired_on(self, report_date: date | None) -> bool:
        """Deterministic expiry check against the CALLER-supplied date."""
        if self.expires is None or report_date is None:
            return False
        return report_date > self.expires


@dataclass(frozen=True)
class BaselineEntry:
    """One [[baseline]] fingerprint suppression declared inside policy."""

    fingerprint: str
    reason: str
    expires: date | None = None


@dataclass(frozen=True)
class EffectivePolicy:
    """The resolved, immutable result of the §10 resolution order.

    Carries NO score fields by construction — weights/caps/ceilings/grades
    are unreachable from user-reachable policy (hard boundary, module
    docstring).
    """

    profile: str = DEFAULT_PROFILE
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: Mapping[str, SeverityOverride] = field(default_factory=dict)
    allow_hosts: tuple[str, ...] = ()
    allow_ips: tuple[str, ...] = ()
    deny_hosts: tuple[str, ...] = ()
    baseline_entries: tuple[BaselineEntry, ...] = ()
    choir_enabled: bool = False
    settings: Mapping[str, Any] = field(default_factory=dict)
    sources: tuple[str, ...] = ("built-in",)
    provenance: Mapping[str, str] = field(default_factory=dict)

    # -- lookups ---------------------------------------------------------------

    def is_disabled(self, rule_id: str) -> bool:
        return rule_id in self.disabled_rules

    def severity_override_for(
        self, rule_id: str, report_date: date | None = None
    ) -> SeverityOverride | None:
        """Active override for *rule_id*; expired entries read as absent."""
        override = self.severity_overrides.get(rule_id)
        if override is None:
            return None
        if override.expired_on(report_date):
            return None
        return override

    def baseline_entry_for(self, fingerprint: str) -> BaselineEntry | None:
        for entry in self.baseline_entries:
            if entry.fingerprint == fingerprint:
                return entry
        return None

    @property
    def declared_offensive_unlocked(self) -> bool:
        """Lab unlocks declared-offensive handling; street ignores it."""
        return self.profile == "lab"

    # -- host classification (deny > allow > standard) --------------------------

    def classify_host(self, endpoint: str | None) -> str | None:
        """``"deny"`` | ``"allow"`` | ``None`` for one endpoint token."""
        host = normalize_endpoint(endpoint)
        if host is None:
            return None
        if _host_matches(host, self.deny_hosts):
            return "deny"
        if _host_matches(host, self.allow_hosts, allow_ips=self.allow_ips):
            return "allow"
        return None

    # -- finding application ------------------------------------------------------

    def apply(
        self,
        findings: Iterable[Mapping[str, Any]],
        *,
        report_date: date | None = None,
        diag: DiagnosticsCollector | None = None,
    ) -> tuple[list[dict[str, Any]], tuple[Diagnostic, ...]]:
        """Apply host-list semantics + severity overrides to finding dicts.

        Pure: input dicts are never mutated. Per §10:

        - deny match ⇒ ``DENIED-BY-POLICY`` annotation ONLY (a highlighter,
          never a multiplier — score/severity untouched);
        - allow match ⇒ downgraded to INFO: rubric-inactive via the existing
          suppression wire field (D-021-consistent — no off-rubric severity is
          invented), plus the machine-visible ``allow_matched`` flag and an
          annotation naming the matched endpoint;
        - ``severity_override`` ⇒ ``effective_severity`` rewritten (display);
          the rule-assigned ``severity`` — and therefore every WEIGHT — stays
          pinned (hard boundary).

        Expired overrides are skipped (report-date parameter, never
        wall-clock) with a diagnostic when a collector is provided.
        """
        collector = diag if diag is not None else DiagnosticsCollector()
        applied: list[dict[str, Any]] = []
        for finding in findings:
            row = dict(finding)
            rule_id = str(row.get("rule_id", ""))

            override = self.severity_overrides.get(rule_id)
            if override is not None and override.expired_on(report_date):
                collector.info(
                    CODE_POLICY_OVERRIDE_EXPIRED,
                    "severity_override for "
                    f"{rule_id} expired ({_fmt_date(override.expires)}) and was ignored",
                )
                override = None
            if override is not None:
                annotations = _annotations(row)
                annotations.append(f"[policy:severity-override {rule_id}→{override.severity}]")
                row["effective_severity"] = override.severity
                row["annotations"] = annotations

            host_class = self.classify_host(_finding_endpoint(row))
            if host_class == "deny":
                annotations = _annotations(row)
                annotations.append(ANNOTATION_DENIED_BY_POLICY)
                row["annotations"] = annotations
            elif host_class == "allow":
                row[FLAG_ALLOW_MATCHED] = True
                row["suppressed"] = True
                row["effective_severity"] = "LOW"
                annotations = _annotations(row)
                marker = f"{ANNOTATION_ALLOW_MATCHED} {_finding_endpoint(row)} downgraded to INFO"
                annotations.append(marker)
                row["annotations"] = annotations
            applied.append(row)
        return applied, collector.snapshot()


def _fmt_date(value: date | None) -> str:
    return value.isoformat() if value else "?"


def _annotations(finding: Mapping[str, Any]) -> list[str]:
    existing = finding.get("annotations")
    if isinstance(existing, list):
        return [str(item) for item in existing]
    return []


def _finding_endpoint(finding: Mapping[str, Any]) -> str | None:
    """Best-effort endpoint extraction from a finding dict.

    Reads the conventional ``host`` / ``endpoint`` fields engines attach;
    findings without one are simply never host-classified.
    """
    for key in ("host", "endpoint"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


# ---------------------------------------------------------------------------
# Host matching: anchored globs (the §10 "public-suffix aware" clause)
# ---------------------------------------------------------------------------


def normalize_endpoint(token: str | None) -> str | None:
    """Normalize one endpoint token to a bare lowercase host or IP literal.

    Strips scheme, userinfo, path/query/fragment, ``:port`` (bracket-safe for
    IPv6), and trailing dots. Returns None for empty/non-host tokens.
    """
    if token is None:
        return None
    text = str(token).strip().lower()
    if not text:
        return None
    if "://" in text:
        text = text.partition("://")[2]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):  # [::1]:8443
        end = text.find("]")
        if end == -1:
            return None
        return text[1:end].rstrip(".") or None
    if text.count(":") == 1:  # host:port (a bare IPv6 has several colons)
        text = text.rsplit(":", 1)[0]
    return text.rstrip(".") or None


def _glob_match(host: str, pattern: str) -> bool:
    """Anchored glob match: ``*.github.io`` matches foo.github.io and
    bar.baz.github.io, but NEVER evil.github.io.evil.com (suffix spoof) —
    fnmatch translation anchors both ends (SPEC §10 PSL clause)."""
    try:
        return fnmatch.fnmatchcase(host, pattern.strip().lower())
    except Exception:  # noqa: BLE001 — hostile patterns must never raise.
        return False


def _ip_matches(host: str, ip_patterns: Iterable[str]) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for pattern in ip_patterns:
        try:
            network = ipaddress.ip_network(str(pattern).strip(), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _host_matches(host: str, globs: Iterable[str], *, allow_ips: Iterable[str] = ()) -> bool:
    for pattern in sorted(globs):
        text = str(pattern).strip()
        if text and _glob_match(host, text):
            return True
    if allow_ips and _ip_matches(host, allow_ips):
        return True
    return False


# ---------------------------------------------------------------------------
# Profiles & declared-offensive handling (D-STREETLAB)
# ---------------------------------------------------------------------------


def declares_offensive_scope(text: str | None) -> bool:
    """Does bundle prose declare offensive scope (``pentest|red-team|
    security testing`` lexicon, case-insensitive)?"""
    if not text:
        return False
    return bool(_OFFENSIVE_SCOPE_RE.search(str(text).lower()))


def is_offensive_tooling_capability(capability: str | None) -> bool:
    """Is *capability* one of §10's offensive-tooling classes?

    Capability paths are dotted (``execute.shell``); colon subpaths
    (``persistence:cron_json`` idiom) are cut before family matching.
    """
    if not capability:
        return False
    cap = str(capability).strip().lower().partition(":")[0]
    return cap in OFFENSIVE_CAPABILITY_FAMILIES or cap.partition(".")[0] == "execute"


def lab_declared_offensive(profile: str, capability: str | None, scope_declared: bool) -> bool:
    """Should the §8.2 ``declared`` discount ride the lab scope declaration?

    True ONLY under ``lab`` for offensive-tooling capabilities when the bundle
    declares offensive scope. Street ignores declarations for these rules
    (D-STREETLAB). Annotate positives with :data:`MARKER_LAB_DECLARED_OFFENSIVE`.
    """
    if profile != "lab":
        return False
    return scope_declared and is_offensive_tooling_capability(capability)


# ---------------------------------------------------------------------------
# Section builders (validation produces diagnostics, never crashes)
# ---------------------------------------------------------------------------


def _parse_date(value: Any) -> date | None:
    """Parse an ISO ``YYYY-MM-DD`` (accepting datetime.date passthrough)."""
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except (ValueError, TypeError):
        return None


def _build_overrides(
    raw: Any,
    *,
    source: str,
    diag: DiagnosticsCollector,
) -> dict[str, SeverityOverride]:
    """Normalize ``rules.severity_override`` (list-of-tables OR table shape).

    Missing reason ⇒ diagnostic + entry ignored (never crash). Invalid
    severity/expiry ⇒ same. Later entries win per rule_id (map semantics).
    Expiry evaluation happens at APPLY time against the caller's report date;
    building here only validates parseability.
    """
    merged: dict[str, SeverityOverride] = {}
    if raw is None:
        return merged
    if isinstance(raw, list):
        rows: list[tuple[Any, Any]] = [(None, item) for item in raw]
    elif isinstance(raw, Mapping):
        rows = [(key, item) for key, item in raw.items()]
    else:
        diag.warning(
            CODE_POLICY_OVERRIDE_INVALID,
            f"severity_override must be a list of tables or a table ({source}); ignored",
        )
        return merged
    for key_hint, row in rows:
        if not isinstance(row, Mapping):
            diag.warning(
                CODE_POLICY_OVERRIDE_INVALID,
                f"severity_override entry must be a table ({source}); ignored",
            )
            continue
        rule_id = str(row.get("rule_id", key_hint) or "").strip()
        if not _RULE_ID_RE.match(rule_id):
            diag.warning(
                CODE_POLICY_OVERRIDE_INVALID,
                f"severity_override entry has invalid rule_id {rule_id!r} ({source}); ignored",
            )
            continue
        reason_text = str(row.get("reason") or "").strip()
        if not reason_text:
            diag.warning(
                CODE_POLICY_OVERRIDE_NO_REASON,
                f"severity_override for {rule_id} lacks required reason ({source}); ignored",
            )
            continue
        severity_text = str(row.get("severity") or "").strip().upper()
        if severity_text not in OVERRIDE_SEVERITIES:
            diag.warning(
                CODE_POLICY_OVERRIDE_INVALID,
                f"severity_override for {rule_id} names unknown severity "
                f"{row.get('severity')!r} ({source}); ignored",
            )
            continue
        expires_raw = row.get("expires")
        expires: date | None = None
        if expires_raw is not None:
            parsed = _parse_date(expires_raw)
            if parsed is None:
                diag.warning(
                    CODE_POLICY_OVERRIDE_INVALID,
                    f"severity_override for {rule_id} has unparsable expires "
                    f"{expires_raw!r} ({source}); ignored",
                )
                continue
            expires = parsed
        merged[rule_id] = SeverityOverride(
            rule_id=rule_id, severity=severity_text, reason=reason_text, expires=expires
        )
    return merged


def _build_baseline(
    raw: Any,
    *,
    source: str,
    diag: DiagnosticsCollector,
) -> tuple[BaselineEntry, ...]:
    """Merge [[baseline]] entries; duplicate fingerprints keep EARLIER expiry."""
    entries: list[BaselineEntry] = []
    if raw is None:
        return ()
    rows = raw if isinstance(raw, list) else [raw]
    for row in rows:
        if not isinstance(row, Mapping):
            diag.warning(
                CODE_POLICY_BASELINE_ENTRY_INVALID,
                f"baseline entry must be a table ({source}); ignored",
            )
            continue
        fingerprint = str(row.get("fingerprint") or "").strip()
        reason = str(row.get("reason") or "").strip()
        expires_raw = row.get("expires")
        head = fingerprint[:16] if fingerprint else "<missing>"
        if not fingerprint or not reason:
            diag.warning(
                CODE_POLICY_BASELINE_ENTRY_INVALID,
                f"baseline entry {head}… needs fingerprint and reason ({source}); ignored",
            )
            continue
        if expires_raw is None:
            diag.warning(
                CODE_POLICY_BASELINE_ENTRY_INVALID,
                f"baseline entry {head}… needs mandatory expires ({source}); ignored",
            )
            continue
        expires = _parse_date(expires_raw)
        if expires is None:
            diag.warning(
                CODE_POLICY_BASELINE_ENTRY_INVALID,
                f"baseline entry {head}… has unparsable expires {expires_raw!r} "
                f"({source}); ignored",
            )
            continue
        prior = next((e for e in entries if e.fingerprint == fingerprint), None)
        if prior is not None:
            # SPEC §10: duplicate fingerprints resolve to the EARLIER expiry.
            candidates = [prior, BaselineEntry(fingerprint, reason, expires)]
            winner = min(candidates, key=lambda e: (e.expires or date.min, e.reason))
            entries[entries.index(prior)] = winner
        else:
            entries.append(BaselineEntry(fingerprint, reason, expires))
    return tuple(sorted(entries, key=lambda e: (e.fingerprint, e.expires or date.min, e.reason)))


def _guard_score_table(data: Mapping[str, Any], *, source: str, diag: DiagnosticsCollector) -> None:
    """Hard-boundary guard over ``[score]`` (weights/caps/ceilings out of reach).

    Values equal to the published defaults pass silently; ANY other value (or
    an unknown key under ``[score]``) records a tamper warning and is IGNORED
    — the scorer keeps its immutable constants regardless.
    """
    table = data.get("score")
    if table is None:
        return
    if not isinstance(table, Mapping):
        diag.warning(CODE_POLICY_SCORE_TAMPER, f"[score] must be a table ({source}); ignored")
        return
    for key in sorted(table, key=str):
        value = table[key]
        published = _PUBLISHED_CEILINGS.get(str(key))
        if published is not None and value == published:
            continue
        diag.warning(
            CODE_POLICY_SCORE_TAMPER,
            f"[score].{key} = {value!r} attempts to alter scoring constants "
            f"(weights/caps/ceilings are not user-reachable); ignored",
        )


def _warn_unknown_keys(
    data: Mapping[str, Any],
    *,
    known: frozenset[str],
    diag: DiagnosticsCollector,
    source: str,
) -> None:
    for key in sorted(data, key=str):
        if str(key) not in known:
            diag.info(CODE_POLICY_UNKNOWN_KEY, f"unknown policy key {key!r} ({source}); ignored")


def _build_flags_layer(flags: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project explicit flag VALUES into policy space (final layer)."""
    if not flags:
        return {}
    projected: dict[str, Any] = {}
    profile = flags.get("profile")
    if isinstance(profile, str) and profile:
        projected["profile"] = profile
    return projected


def _project_setting(key: str, value: Any) -> dict[str, Any]:
    """Nest one recognized setting into policy space under ``settings.<key>``."""
    node: dict[str, Any] = {}
    cursor = node
    parts = key.split(".")
    for part in parts[:-1]:
        child: dict[str, Any] = {}
        cursor[part] = child
        cursor = child
    cursor[parts[-1]] = value
    return {"settings": node}


def _walk(data: Mapping[str, Any], dotted: str) -> Any:
    node: Any = data
    for segment in dotted.split("."):
        if not isinstance(node, Mapping) or segment not in node:
            return None
        node = node[segment]
    return node


# ---------------------------------------------------------------------------
# The loader
# ---------------------------------------------------------------------------


def load_policy(
    *,
    ctx: Any = None,
    project_dir: str | Path | None = None,
    global_path: str | Path | None = None,
    extra_files: Sequence[str | Path] = (),
    flags: Mapping[str, Any] | None = None,
    report_date: date | None = None,
    diag: DiagnosticsCollector | None = None,
) -> EffectivePolicy:
    """Resolve the effective policy through the §10 layers (later wins).

    Raises :class:`PolicyError` only when an EXISTING policy file is
    unreadable/unparsable (strict lane → exit 2 on CLI verbs, one-line notice
    in-session). Everything else degrades to diagnostics.
    """
    collector = diag if diag is not None else DiagnosticsCollector()

    # -- collect raw contributions (order = normative layer order) --------------
    settings_values = read_settings_layer(ctx, collector)

    global_data: dict[str, Any] = {}
    global_lines: dict[str, int] = {}
    if global_path is None:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        resolved_global = base / "lens" / "policy.toml"
    else:
        resolved_global = Path(global_path)
    if resolved_global.is_file():
        global_data, global_raw = read_policy_file(resolved_global)
        global_lines = _key_line_index(global_raw)

    project_data: dict[str, Any] = {}
    project_lines: dict[str, int] = {}
    if project_dir is not None:
        project_file = Path(project_dir) / ".lens" / "policy.toml"
        if project_file.is_file():
            project_data, project_raw = read_policy_file(project_file)
            project_lines = _key_line_index(project_raw)

    extras: list[tuple[dict[str, Any], dict[str, int], str]] = []
    for extra in extra_files:
        extra_data, extra_raw = read_policy_file(extra)
        display = Path(extra).name
        extras.append((extra_data, _key_line_index(extra_raw), display))

    flag_values = _build_flags_layer(flags)
    for key in sorted(flags or {}):
        if key != "profile":
            collector.info(
                CODE_POLICY_UNKNOWN_KEY, f"policy flag {key!r} not policy-relevant; ignored"
            )

    # Stable display labels (never absolute paths — envelope determinism law).
    global_label = "global $XDG_CONFIG_HOME/lens/policy.toml"
    project_label = "project .lens/policy.toml"

    # -- resolve the active profile (later-wins across naming layers) ------------
    profile = DEFAULT_PROFILE
    profile_naming_label: str | None = None
    named_layers: list[tuple[str, Mapping[str, Any], str | None]] = [
        ("settings", settings_values, f"{_SETTINGS_LABEL_BASE}.profile"),
        ("global", global_data, global_label),
        ("project", project_data, project_label),
    ]
    named_layers.extend(("extra", data, f"extra {name}") for data, _lines, name in extras)
    named_layers.append(("flags", flag_values, "flags"))
    for layer_name, layer_data, layer_label in named_layers:
        candidate = layer_data.get("profile") if isinstance(layer_data, Mapping) else None
        if isinstance(candidate, str) and candidate in PROFILES:
            profile = candidate
            profile_naming_label = layer_label
        elif candidate is not None:
            collector.warning(
                CODE_POLICY_UNKNOWN_KEY,
                f"profile {candidate!r} named in {layer_name} layer is not one of "
                f"{'|'.join(PROFILES)}; kept {profile!r}",
            )

    # -- fold layers in normative order with provenance ---------------------------
    merged: dict[str, Any] = _blank_defaults()
    provenance: dict[str, str] = {}
    for key in sorted(merged, key=str):
        provenance[str(key)] = "built-in"
    for parent in ("rules", "network", "choir"):
        for child in sorted(merged[parent], key=str):  # type: ignore[index]
            provenance[f"{parent}.{child}"] = "built-in"

    def apply_layer(data: Mapping[str, Any]) -> None:
        nonlocal merged
        merged = _track_merge(merged, data, current_label, provenance)

    current_label = f"profile {profile}"
    apply_layer({"profile": profile})
    if profile_naming_label is not None:
        # The pack lands at slot 2, but provenance names the layer that chose it.
        provenance["profile"] = profile_naming_label
    file_line_indexes: dict[str, dict[str, int]] = {}

    if settings_values:
        for key in sorted(settings_values):
            current_label = f"{_SETTINGS_LABEL_BASE}.{key}"
            apply_layer(_project_setting(key, settings_values[key]))
    if global_data:
        current_label = global_label
        file_line_indexes[global_label] = global_lines
        apply_layer(global_data)
    if project_data:
        current_label = project_label
        file_line_indexes[project_label] = project_lines
        apply_layer(project_data)
    for data, lines, name in extras:
        current_label = f"extra {name}"
        file_line_indexes[current_label] = lines
        apply_layer(data)
    if flag_values:
        current_label = "flags"
        apply_layer(flag_values)

    # File-layer provenance gains :L<nn> where the key is locatable.
    for label, lines in file_line_indexes.items():
        for path, writer in list(provenance.items()):
            if writer != label:
                continue
            line = _line_for(lines, path)
            if line is not None:
                provenance[path] = f"{label}:L{line}"

    # -- hard boundary: [score] can never move math --------------------------------
    guarded: list[tuple[Mapping[str, Any], str]] = [
        (global_data, "global lens/policy.toml"),
        (project_data, "project .lens/policy.toml"),
    ]
    guarded.extend((data, f"extra {name}") for data, _lines, name in extras)
    for data, source in guarded:
        _guard_score_table(data, source=source, diag=collector)

    # -- build typed views ------------------------------------------------------------
    disabled_raw = _walk(merged, "rules.disable")
    disabled = (
        frozenset(str(item).strip() for item in disabled_raw if str(item).strip())
        if isinstance(disabled_raw, list)
        else frozenset()
    )
    for rule_id in sorted(disabled):
        if not _RULE_ID_RE.match(rule_id):
            collector.warning(
                CODE_POLICY_UNKNOWN_KEY,
                f"rules.disable entry {rule_id!r} is not a rule id; kept (inert unless it matches)",
            )

    overrides = _build_overrides(
        _walk(merged, "rules.severity_override"), source="merged policy", diag=collector
    )
    if report_date is not None:
        # Deterministic expiry pre-filter at load: expired display overrides
        # leave the effective set (resurface loudly as a diagnostic), so the
        # stored map already reflects the caller's report date.
        for rule_id in sorted(overrides):
            override = overrides[rule_id]
            if override.expired_on(report_date):
                del overrides[rule_id]
                collector.info(
                    CODE_POLICY_OVERRIDE_EXPIRED,
                    f"severity_override for {rule_id} expired "
                    f"({_fmt_date(override.expires)}) and was ignored",
                )

    network_raw = _walk(merged, "network")
    network_table = network_raw if isinstance(network_raw, Mapping) else {}

    def hosts(key: str) -> tuple[str, ...]:
        values = network_table.get(key)
        if not isinstance(values, list):
            return ()
        seen: list[str] = []
        for item in values:
            text = str(item).strip()
            if text and text not in seen:
                seen.append(text)
        return tuple(sorted(seen))

    baseline_entries = _build_baseline(
        merged.get("baseline"), source="merged policy", diag=collector
    )

    choir_raw = merged.get("choir")
    choir_enabled = isinstance(choir_raw, Mapping) and bool(choir_raw.get("enabled", False))

    known_top = _KNOWN_TOP_LEVEL_KEYS | set(flag_values)
    if settings_values:
        known_top = known_top | {"settings"}
    _warn_unknown_keys(merged, known=frozenset(known_top), diag=collector, source="merged policy")

    # Nested tables get the same warn-and-ignore treatment so typos like a
    # ``weight`` key under [rules] surface instead of vanishing silently.
    nested_known: dict[str, tuple[str, ...]] = {
        "rules": ("disable", "severity_override"),
        "network": ("allow_hosts", "allow_ips", "deny_hosts"),
        "choir": ("enabled",),
        "score": tuple(_PUBLISHED_CEILINGS),
    }
    for table_name, known_children in nested_known.items():
        table = merged.get(table_name)
        if isinstance(table, Mapping):
            _warn_unknown_keys(
                table,
                known=frozenset(known_children),
                diag=collector,
                source=f"merged [{table_name}]",
            )

    sources: list[str] = ["built-in"]
    if profile != DEFAULT_PROFILE:
        sources.append(f"profile {profile}")
    if settings_values:
        sources.append(_SETTINGS_LABEL_BASE)
    if global_data:
        sources.append(global_label)
    if project_data:
        sources.append(project_label)
    sources.extend(f"extra {name}" for _data, _lines, name in extras)
    if flag_values:
        sources.append("flags")

    return EffectivePolicy(
        profile=profile,
        disabled_rules=disabled,
        severity_overrides=overrides,
        allow_hosts=hosts("allow_hosts"),
        allow_ips=hosts("allow_ips"),
        deny_hosts=hosts("deny_hosts"),
        baseline_entries=baseline_entries,
        choir_enabled=choir_enabled,
        settings=dict(settings_values),
        sources=tuple(sources),
        provenance=dict(sorted(provenance.items())),
    )


__all__ = [
    "ANNOTATION_ALLOW_MATCHED",
    "ANNOTATION_DENIED_BY_POLICY",
    "CODE_POLICY_BASELINE_ENTRY_INVALID",
    "CODE_POLICY_OVERRIDE_EXPIRED",
    "CODE_POLICY_OVERRIDE_INVALID",
    "CODE_POLICY_OVERRIDE_NO_REASON",
    "CODE_POLICY_PARSE",
    "CODE_POLICY_SCORE_TAMPER",
    "CODE_POLICY_SETTING_TYPE",
    "CODE_POLICY_UNKNOWN_KEY",
    "DEFAULT_PROFILE",
    "FLAG_ALLOW_MATCHED",
    "KNOWN_SETTINGS_KEYS",
    "MARKER_LAB_DECLARED_OFFENSIVE",
    "OFFENSIVE_CAPABILITY_FAMILIES",
    "OVERRIDE_SEVERITIES",
    "POLICY_EXIT_CODE",
    "PROFILES",
    "BaselineEntry",
    "EffectivePolicy",
    "PolicyError",
    "SeverityOverride",
    "declares_offensive_scope",
    "is_append_list",
    "is_offensive_tooling_capability",
    "lab_declared_offensive",
    "load_policy",
    "merge_policy_values",
    "normalize_endpoint",
    "policy_failure_notice",
    "read_policy_file",
    "strip_append_prefix",
]
