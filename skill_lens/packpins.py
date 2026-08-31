"""Community pack pins — SHA-pinned, local-path-only trust table (SPEC §15).

A ``packs.toml`` file opts a project (or a user, globally) into community
rule packs. SPEC §15 law: community packs are OPT-IN, version+SHA256
pinned; D-RULEOWN/D-012/D-055 keep updates MANUAL-ONLY (no fetch verb
exists and none may be invented) and SPEC §14 G1/G3 keep loading
LOCAL-PATH-ONLY, FOREVER — fetching is the USER's ``git clone``/release
download; lens only ever reads a directory the user already possesses.

Pin storage (two layers, policy-loader layering precedent — later wins
per pack name):

- project:  ``<target>/.lens/packs.toml`` (checked into the consumer repo
  → CI-reproducible trust decisions);
- global:   ``$XDG_CONFIG_HOME/lens/packs.toml``.

Schema (closed field set; unknown keys warn-and-record per D-012 style):

    [[pack]]
    name   = "acme-rules"            # identity token, unique per file
    path   = "./packs/acme"          # LOCAL dir with pack.yaml (never fetched)
    sha256 = "74ce4a0f…"             # REQUIRED pin over packsec canonical digest
    pubkey = "./packs/acme.pub.pem"  # optional trust root (PEM/base64)
    sig    = "./packs/acme.sig"      # optional detached sidecar (packsec format)
    enabled = true                   # default true; false = inert, reported once

Fail-closed at every step (the ratified failure-mode table, both-way
tested):

- malformed pins file / duplicate names / bad hex / pack-count ceiling breach
  → :class:`PackPinError` (a :class:`skill_lens.policy.PolicyError`
  subclass, so both surfaces route it to their exit-2/one-line-notice
  lanes with zero new plumbing);
- loader-rejected pack → :class:`PackPinError` on the scan lane (exit-2
  config seam) and a per-pack FAIL value on ``rules verify``/doctor;
- digest ≠ pin, invalid present signature, id collision with core or
  across external packs → the pack is REJECTED with a loud diagnostic;
  its rules never reach a scan (never silently skipped);
- missing ``sha256`` pin → pack rejected (a pin you wrote is a trust
  decision; its absence is a config fault, not a soft skip) — surfaces
  report it as a WARN-grade rejection (no tamper evidence, but no trust);
- signature declared but no crypto backend → honest WARN; the sha256 pin
  still gates the bytes (mirrors ``verify_core_signature`` semantics).

Governor scope (ratified): the ``packver`` governor governs CORE pack
transitions only; external packs prove themselves at every load through
the pin. Id collisions REJECT the pack loudly (advisor-safest); the
``community/<pack>/LNS-…`` namespacing shape is deferred (needs a
``spec_version`` bump = major territory) — recorded, not silently widened.

Perf: pin parsing is a bounded TOML read; digest verification re-reads
the pack bytes (tens of KB → sub-ms); rule parsing rides the existing
:func:`skill_lens.rules.load_pack` parse-cache (mtime/size snapshot key),
so repeat scans pay ~0. The accepted-pack count is ceiling-bounded
(:data:`MAX_EXTERNAL_PACKS`) and the effective cache key folds every
pack's ACTUAL digest, so any byte flip changes the key and can never be
served from a stale fast-path entry.
"""

from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import PolicyError

#: Stable diagnostic codes for the pack-pin subsystem (loud, greppable).
CODE_PACK_PIN_MISSING = "LNS-PACK-PIN-MISSING"
CODE_PACK_PIN_MISMATCH = "LNS-PACK-PIN-MISMATCH"
CODE_PACK_LOADER_REJECT = "LNS-PACK-LOADER-REJECT"
CODE_PACK_ID_COLLISION = "LNS-PACK-ID-COLLISION"
CODE_PACK_SIG_INVALID = "LNS-PACK-SIG-INVALID"
CODE_PACK_SIG_NO_BACKEND = "LNS-PACK-SIG-NO-BACKEND"
CODE_PACK_INERT = "LNS-PACK-INERT"
CODE_PACK_PIN_UNKNOWN_FIELD = "LNS-PACK-PIN-UNKNOWN-FIELD"

#: Layer file locations (display labels never carry absolute paths — the
#: envelope/provenance determinism law; raw paths are never logged).
GLOBAL_PIN_LABEL = "global $XDG_CONFIG_HOME/lens/packs.toml"
PROJECT_PIN_LABEL = "project .lens/packs.toml"

#: Pack-count ceiling (brief: bounded fan-in keeps cold-scan cost flat).
MAX_EXTERNAL_PACKS = 8

#: sha256 pin shape: exactly 64 lowercase hex chars.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: Known ``[[pack]]`` fields; anything else warns-and-records (D-012 style).
_KNOWN_PACK_FIELDS = frozenset({"name", "path", "sha256", "pubkey", "sig", "enabled"})

#: Top-level keys allowed beside ``[[pack]]`` (reserved for future growth).
_KNOWN_TOP_FIELDS = frozenset({"pack"})


class PackPinError(PolicyError):
    """Structural pack-pin fault (exit-2 config seam, SPEC §18).

    Subclasses :class:`skill_lens.policy.PolicyError` so BOTH surfaces
    route it through their existing config-seam lanes with zero new
    plumbing: the slash safe-handler renders the one-line notice, the CLI
    dispatcher maps it to §18 exit 2 — same wording both lanes (D-SURF).
    """


@dataclass(frozen=True)
class PackPin:
    """One resolved pin-table entry (paths resolved, values validated)."""

    name: str
    #: Path as WRITTEN in the TOML (display form — the user's own words
    #: from the file they own; absolute forms are never reconstructed).
    path_spec: str
    #: Resolved local directory (absolute, user-expanded).
    resolved: Path
    #: 64-hex lowercase pin, or "" when the entry omitted it (missing-pin
    #: fault — the pack is rejected downstream, never soft-skipped).
    sha256: str = ""
    pubkey: Path | None = None
    sig: Path | None = None
    enabled: bool = True
    #: Display label of the layer that supplied this entry.
    layer: str = PROJECT_PIN_LABEL


def global_pins_path() -> Path:
    """``$XDG_CONFIG_HOME/lens/packs.toml`` (default ``~/.config/…``)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "lens" / "packs.toml"


def project_pins_path(project_dir: str | Path) -> Path:
    """``<project_dir>/.lens/packs.toml`` (the consumer-repo layer)."""
    return Path(project_dir) / ".lens" / "packs.toml"


# ---------------------------------------------------------------------------
# Pin loading (structural lane — PackPinError on any malformed file)
# ---------------------------------------------------------------------------


def _read_layer(path: Path, label: str, warnings: list[str]) -> list[dict[str, Any]]:
    """Parse one pins file into raw entry dicts; empty when absent.

    Unknown top-level keys land in *warnings* (warn-and-record, D-012
    style); structural faults raise :class:`PackPinError`.
    """
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackPinError(f"{label}: unreadable: {exc.strerror}", path=label) from exc
    except tomllib.TOMLDecodeError as exc:
        raise PackPinError(f"{label}: malformed TOML: {exc}", path=label) from exc
    if not isinstance(data, dict):
        raise PackPinError(f"{label}: top level must be a TOML table", path=label)
    for key in sorted(set(data) - _KNOWN_TOP_FIELDS):
        warnings.append(f"{label}: unknown top-level field {key!r} tolerated")
    entries = data.get("pack", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise PackPinError(f"{label}: [[pack]] entries must be an array of tables", path=label)
    return entries


def _resolve_entry(
    raw: dict[str, Any],
    *,
    label: str,
    base_dir: Path,
    index: int,
    warnings: list[str],
) -> PackPin:
    """Validate one ``[[pack]]`` table into a :class:`PackPin`."""
    where = f"{label} [[pack]] #{index + 1}"
    for key in sorted(set(raw) - _KNOWN_PACK_FIELDS):
        warnings.append(f"{where}: unknown field {key!r} tolerated and recorded")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PackPinError(
            f"{where}: 'name' is required and must be a non-empty string", path=label
        )
    path_spec = raw.get("path")
    if not isinstance(path_spec, str) or not path_spec.strip():
        raise PackPinError(
            f"{where}: 'path' is required and must be a non-empty string", path=label
        )
    sha256 = raw.get("sha256", "")
    if not isinstance(sha256, str):
        raise PackPinError(f"{where}: 'sha256' must be a 64-hex string", path=label)
    if sha256 and _SHA256_RE.match(sha256) is None:
        raise PackPinError(f"{where}: 'sha256' must be exactly 64 lowercase hex chars", path=label)
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise PackPinError(f"{where}: 'enabled' must be a boolean", path=label)

    def _side(value: Any, field_name: str) -> Path | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise PackPinError(f"{where}: {field_name!r} must be a path string", path=label)
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        return candidate.resolve()

    pubkey = _side(raw.get("pubkey"), "pubkey")
    sig = _side(raw.get("sig"), "sig")
    resolved = Path(path_spec).expanduser()
    if not resolved.is_absolute():
        resolved = base_dir / resolved
    resolved = resolved.resolve()
    return PackPin(
        name=name,
        path_spec=path_spec,
        resolved=resolved,
        sha256=sha256.lower(),
        pubkey=pubkey,
        sig=sig,
        enabled=enabled,
        layer=label,
    )


def load_pack_pins(
    *,
    project_dir: str | Path | None = None,
    global_path: str | Path | None = None,
    warnings: list[str] | None = None,
) -> tuple[PackPin, ...]:
    """Load the effective pin table (global → project, later wins per name).

    Raises :class:`PackPinError` on any structural fault (malformed TOML,
    wrong shapes, duplicate names within one file, pack-count ceiling).
    Unknown fields are tolerated and reported into *warnings* (a caller
    list, so the loader stays collector-agnostic). Absent files contribute
    nothing — an empty table is the default, byte-identical, zero-pack
    state.
    """
    sink: list[str] = []
    resolved_global = Path(global_path) if global_path is not None else global_pins_path()
    global_base = resolved_global.parent
    project_base = Path(project_dir) if project_dir is not None else Path.cwd()
    by_name: dict[str, PackPin] = {}
    for label, entries, base_dir in (
        (
            GLOBAL_PIN_LABEL,
            _read_layer(resolved_global, GLOBAL_PIN_LABEL, sink),
            global_base,
        ),
        (
            PROJECT_PIN_LABEL,
            _read_layer(project_pins_path(project_base), PROJECT_PIN_LABEL, sink),
            project_base,
        ),
    ):
        layer_names: set[str] = set()
        for index, raw in enumerate(entries):
            pin = _resolve_entry(raw, label=label, base_dir=base_dir, index=index, warnings=sink)
            if pin.name in layer_names:
                # Duplicates WITHIN one file are a structural fault; the same
                # name across FILES is the later-wins layering semantic.
                raise PackPinError(
                    f"{label}: duplicate pack name {pin.name!r} — names are "
                    "unique across entries within one file",
                    path=label,
                )
            layer_names.add(pin.name)
            by_name[pin.name] = pin
    if len(by_name) > MAX_EXTERNAL_PACKS:
        raise PackPinError(
            f"{len(by_name)} packs pinned exceeds the ceiling of {MAX_EXTERNAL_PACKS} "
            "(cold-scan cost stays bounded; consolidate your trust table)",
        )
    if warnings is not None:
        warnings.extend(sink)
    return tuple(by_name.values())


# ---------------------------------------------------------------------------
# Verification + resolution (shared by scan, `rules` verb, and doctor)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalPackState:
    """Outcome of resolving the pin table for one scan surface.

    ``packs`` are the ACCEPTED external packs (already loader-validated,
    digest-pinned, collision-checked) ready to merge into a scan;
    ``notices`` are the loud one-line render notes for every pin outcome
    (accepted, warned, or rejected — never silent); ``cache_suffix`` folds
    every enabled pack's ACTUAL digest so any byte flip invalidates
    fast-path answers ("" when no enabled pins: byte-identical keys).
    """

    packs: tuple[Any, ...] = ()  # tuple[RulePack, ...] (loose to avoid a cycle)
    notices: tuple[str, ...] = ()
    cache_suffix: str = ""
    warnings: tuple[str, ...] = ()
    #: Per-enabled-pin outcomes ``(name, status, kind)`` in pin order — the
    #: machine view verbs/doctor map onto §18 exit codes (status "fail" ⇒
    #: exit 2; "warn"/"missing-pin" ⇒ reported, exit 0).
    verdicts: tuple[tuple[str, str, str], ...] = ()


#: Verifier outcome kind → diagnostic code for the shared collector.
_DIAG_CODE_FOR = {
    "missing-pin": CODE_PACK_PIN_MISSING,
    "pin": CODE_PACK_PIN_MISMATCH,
    "loader": CODE_PACK_LOADER_REJECT,
    "sig": CODE_PACK_SIG_INVALID,
    "backend": CODE_PACK_SIG_NO_BACKEND,
}


def resolve_external_packs(
    *,
    pins: tuple[PackPin, ...] | None = None,
    project_dir: str | Path | None = None,
    global_path: str | Path | None = None,
) -> ExternalPackState:
    """Load pins, verify each pack fail-closed, return accepted packs.

    Shared by the scan path, the ``rules`` verb, and doctor check 1 so the
    three surfaces cannot drift (D-055 single-engine precedent). Raises
    :class:`PackPinError` for structural pin faults and for loader-rejected
    packs (both are exit-2 config-seam semantics per the ratified failure
    table); everything else rejects the individual pack as a VALUE with a
    loud notice — never a silent skip.
    """
    from . import packsec
    from .diagnostics import SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_WARNING, DiagnosticsCollector
    from .rules import RulePackError, load_core_pack, load_pack

    warnings: list[str] = []
    if pins is None:
        pins = load_pack_pins(project_dir=project_dir, global_path=global_path, warnings=warnings)
    diags = DiagnosticsCollector()
    for line in warnings:
        diags.warning(CODE_PACK_PIN_UNKNOWN_FIELD, line, path="packs.toml")

    notices: list[str] = []
    digest_rows: list[tuple[str, str]] = []
    enabled = [pin for pin in pins if pin.enabled]
    for pin in pins:
        if pin.enabled:
            continue
        diags.info(CODE_PACK_INERT, f"pack {pin.name} disabled (enabled=false); not loaded")
        notices.append(f"lens packs · {pin.name}: disabled (enabled=false) — inert")

    # Core rule ids gate collisions (advisor-safest: reject loudly, never
    # shadow a core rule).
    core_ids = {rule.id for rule in load_core_pack().rules}

    accepted: list[Any] = []
    taken: set[str] = set()
    verdicts: list[tuple[str, str, str]] = []
    for pin in enabled:
        digest_rows.append((pin.name, _digest_of(pin.resolved) or "<unreadable>"))
        if not pin.sha256:
            diags.warning(
                CODE_PACK_PIN_MISSING,
                f"pack {pin.name} has no sha256 pin — REJECTED (a pin you wrote is a "
                "trust decision; its absence is a config fault)",
                path=pin.path_spec,
                detail={"pack": pin.name},
            )
            notices.append(
                f"lens packs · {pin.name}: REJECTED — missing sha256 pin; "
                "its rules never reach a scan"
            )
            verdicts.append((pin.name, "warn", "missing-pin"))
            continue
        report = packsec.verify_external_pack(
            path=pin.resolved,
            name=pin.name,
            sha256_pin=pin.sha256,
            sig_path=pin.sig,
            pubkey_path=pin.pubkey,
        )
        severity = (
            SEVERITY_ERROR
            if report.status == "fail"
            else (SEVERITY_WARNING if report.status == "warn" else SEVERITY_INFO)
        )
        for line in report.lines:
            diags.record(
                _DIAG_CODE_FOR.get(report.kind, CODE_PACK_PIN_MISMATCH),
                line,
                severity=severity,
                path=pin.path_spec,
                detail={"pack": pin.name},
            )
        verdicts.append((pin.name, report.status, report.kind))
        if not report.accepted:
            if report.kind == "loader":
                # Loader reject = exit-2 config seam on the scan lane (the
                # ratified failure table); the value-object surfaces keep
                # reporting per-pack instead of raising.
                raise PackPinError(
                    f"pack {pin.name!r} failed rule-pack validation: {report.reason}",
                    path=pin.path_spec,
                ) from None
            notices.append(
                f"lens packs · {pin.name}: REJECTED — {report.reason}; its rules never reach a scan"
            )
            continue
        try:
            pack = load_pack(pin.resolved)
        except RulePackError as exc:
            # Loader reject = exit-2 config seam on the scan lane (failure
            # table); the value-object surfaces keep reporting per-pack.
            raise PackPinError(
                f"pack {pin.name!r} failed rule-pack validation: {exc}",
                path=pin.path_spec,
            ) from exc
        collide = sorted(
            {rule.id for rule in pack.rules if rule.id in taken or rule.id in core_ids}
        )
        if collide:
            diags.error(
                CODE_PACK_ID_COLLISION,
                f"pack {pin.name} rejected: rule id collision ({', '.join(collide)}) — "
                "community rules share the LNS- space with core and must not shadow it",
                path=pin.path_spec,
                detail={"pack": pin.name, "ids": collide},
            )
            notices.append(
                f"lens packs · {pin.name}: REJECTED — rule id collision "
                f"({', '.join(collide)}); its rules never reach a scan"
            )
            continue
        taken.update(rule.id for rule in pack.rules)
        accepted.append(pack)
        if report.status == "warn":
            # sig declared, no backend: pin still gates the bytes (honest WARN).
            notices.append(f"lens packs · {pin.name}: loaded on sha256 pin; WARN — {report.reason}")
        else:
            notices.append(f"lens packs · {pin.name}: loaded ({report.reason})")

    return ExternalPackState(
        packs=tuple(accepted),
        notices=tuple(notices),
        cache_suffix=_suffix_for(digest_rows),
        warnings=tuple(warnings),
        verdicts=tuple(verdicts),
    )


def _digest_of(pack_dir: Path) -> str:
    """Canonical pack digest hex, or "" when the bytes cannot be read."""
    from .packsec import PackSecError, canonical_digest, canonical_pack_inputs

    try:
        return canonical_digest(canonical_pack_inputs(pack_dir)).hex()
    except PackSecError:  # unreadable pack = unusable digest
        return ""


def _suffix_for(digests: list[tuple[str, str]]) -> str:
    """``:pk:<16-hex>`` over sorted (name, actual-digest) — "" when empty."""
    if not digests:
        return ""
    blob = "\n".join(f"{name}\x00{digest}" for name, digest in sorted(digests))
    return ":pk:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "CODE_PACK_ID_COLLISION",
    "CODE_PACK_INERT",
    "CODE_PACK_LOADER_REJECT",
    "CODE_PACK_PIN_MISSING",
    "CODE_PACK_PIN_MISMATCH",
    "CODE_PACK_PIN_UNKNOWN_FIELD",
    "CODE_PACK_SIG_INVALID",
    "CODE_PACK_SIG_NO_BACKEND",
    "GLOBAL_PIN_LABEL",
    "ExternalPackState",
    "MAX_EXTERNAL_PACKS",
    "PackPin",
    "PackPinError",
    "PROJECT_PIN_LABEL",
    "global_pins_path",
    "load_pack_pins",
    "project_pins_path",
    "resolve_external_packs",
]
