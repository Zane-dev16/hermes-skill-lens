"""Rule-pack artifact security — canonical build, ed25519 signing, offline verify.

SPEC §15 normative surface: ``release checksums signed``; ``rules verify``
checks; zero network anywhere (verification is OFFLINE CRYPTO only — the
default closure never reaches for a socket, and neither does this module).

Three responsibilities, one deterministic recipe each:

**Canonical pack inputs.``canonical_pack_inputs(dir)`` returns the exact
byte stream the rule loader sees — ``pack.yaml`` plus every YAML under the
declared ``rules_dir``, as sorted ``(relname, bytes)`` pairs hashed with the
same D-HASH recipe :meth:`skill_lens.rules.RulePack.content_checksum` uses
(name \\0 len(u64) data). Signature and checksum therefore bind WHAT SHIPS,
not how it was traversed.

**Deterministic artifacts.``build_artifact(dir)`` zips those same inputs
with frozen metadata (1980 epoch timestamps, 0644 perms, sorted order,
fixed deflate level) so the same pack bytes produce BYTE-IDENTICAL artifacts
on every machine — the property release tagging and SHA-pinning rely on.

**Detached ed25519 signatures.``sign_digest``/``verify_digest`` sign and
verify the raw SHA-256 digest of the canonical stream (or of artifact
bytes — callers hash first). Backends, in preference order (DECISIONS
D-055): ``cryptography`` (Rust-backed, universal wheels) then PyNaCl; both
implement the same raw Ed25519 primitive, so signatures are interoperable.
Key FILES prefer PEM (PKCS8 private / SubjectPublicKeyInfo public); when
only PyNaCl is importable the module falls back to base64 raw-seed files —
the ceremony doc (:doc:`docs/key-ceremony`) owns the formats.

This module never raises past its own API boundary: verification failures
are VALUES (:class:`VerifyResult`), because callers sit on doctor/verb
surfaces that must degrade honestly, not explode.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Fixed zip timestamp (DOS epoch) — wall-clock may never enter artifacts.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Fixed posix mode for every artifact member (0644 regular file, no exec).
_ZIP_MODE = 0o100644 << 16

#: Deflate level pinned so compressor version drift cannot move bytes.
_ZIP_COMPRESSLEVEL = 9


# ---------------------------------------------------------------------------
# Errors and results
# ---------------------------------------------------------------------------


class PackSecError(Exception):
    """Structural pack-security fault (unreadable keys, malformed sig file).

    Configuration-seam semantics: callers translate this into their own
    error lanes (CLI exit 2 / one-line notice) — never raised across a
    host callback.
    """


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of one offline verification attempt (never raises)."""

    ok: bool
    reason: str
    #: Short public-key fingerprint for display ("" when unavailable).
    fingerprint: str = ""


# ---------------------------------------------------------------------------
# Backend selection (lazy; default closure stays stdlib-only until called)
# ---------------------------------------------------------------------------

#: Active backend name ("cryptography" | "pynacl"), probed once, lazily.
_BACKEND_NAME: str | None = None


def _probe_backend() -> str | None:
    """Return the best available ed25519 backend name, or None.

    Preference order (DECISIONS D-055): ``cryptography`` (Rust-backed,
    universal wheels) then PyNaCl. Both implement raw Ed25519 over 32-byte
    keys, so signatures are interoperable; only KEY FILE FORMATS differ
    (PEM needs the cryptography parser — see :func:`_load_seed`).
    """
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401

        return "cryptography"
    except ImportError:
        pass
    try:
        import nacl.signing  # noqa: F401

        return "pynacl"
    except ImportError:
        return None


def backend_name() -> str:
    """Probed backend name; "none" when no ed25519 library is importable."""
    global _BACKEND_NAME
    if _BACKEND_NAME is None:
        _BACKEND_NAME = _probe_backend() or "none"
    return _BACKEND_NAME


def backend_available() -> bool:
    """True when signing/verification can run in this environment."""
    return backend_name() != "none"


# ---------------------------------------------------------------------------
# Raw Ed25519 primitives (uniform over 32-byte seeds / public keys)
# ---------------------------------------------------------------------------


def _ed25519_sign(seed: bytes, digest: bytes) -> bytes:
    """64-byte detached signature over *digest* with a 32-byte seed."""
    if backend_name() == "cryptography":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        return Ed25519PrivateKey.from_private_bytes(seed).sign(digest)
    from nacl.signing import SigningKey

    return bytes(SigningKey(seed).sign(digest).signature)


def _ed25519_verify(pub: bytes, digest: bytes, sig: bytes) -> None:
    """Verify or raise ValueError (uniform failure shape across backends)."""
    if backend_name() == "cryptography":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)
        except InvalidSignature as exc:
            raise ValueError("signature mismatch") from exc
        return
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        VerifyKey(pub).verify(digest, sig)
    except BadSignatureError as exc:
        raise ValueError("signature mismatch") from exc


# ---------------------------------------------------------------------------
# Key loading (PEM via cryptography; base64 raw-seed fallback under PyNaCl)
# ---------------------------------------------------------------------------


def _load_seed(key_bytes: bytes) -> bytes:
    """Parse private key material into the raw 32-byte signing seed.

    PEM input requires the ``cryptography`` parser (PyNaCl cannot read PEM;
    docs/key-ceremony.md tells PyNaCl-only environments to keep base64 seed
    files instead).
    """
    if not backend_available():
        raise PackSecError("no ed25519 backend available (install 'cryptography')")
    if key_bytes.startswith(b"-----BEGIN"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            load_pem_private_key,
        )

        try:
            key = load_pem_private_key(key_bytes, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise PackSecError("private key is not an ed25519 key")
            return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        except PackSecError:
            raise
        except Exception as exc:  # noqa: BLE001 — one honest failure line
            raise PackSecError(f"unreadable private key PEM: {exc}") from exc
    try:
        seed = base64.b64decode(key_bytes.strip(), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise PackSecError(f"unreadable private key (not PEM or base64): {exc}") from exc
    if len(seed) != 32:
        raise PackSecError(f"raw ed25519 seed must be 32 bytes, got {len(seed)}")
    return seed


def _load_public(key_bytes: bytes) -> bytes:
    """Return the raw 32-byte public key from a PEM or base64 file body."""
    if key_bytes.startswith(b"-----BEGIN"):
        if not backend_available():
            raise PackSecError("PEM public keys require the 'cryptography' backend")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )

        try:
            key = load_pem_public_key(key_bytes)
        except Exception as exc:  # noqa: BLE001
            raise PackSecError(f"unreadable public key PEM: {exc}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise PackSecError("public key is not an ed25519 key")
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    try:
        raw = base64.b64decode(key_bytes.strip(), validate=True)
    except Exception:
        # Not base64 text: accept RAW 32-byte key material directly
        # (in-memory callers; a 32-byte binary blob cannot be b64 text).
        if len(key_bytes) == 32:
            return key_bytes
        raise PackSecError("unreadable public key (not PEM or base64)") from None
    if len(raw) != 32:
        raise PackSecError(f"raw ed25519 public key must be 32 bytes, got {len(raw)}")
    return raw


# ---------------------------------------------------------------------------
# Canonical inputs + digests (same recipe as RulePack.content_checksum)
# ---------------------------------------------------------------------------


def canonical_pack_inputs(pack_dir: Path | str) -> list[tuple[str, bytes]]:
    """Sorted ``(relname, bytes)`` inputs of a pack directory (loader parity).

    Mirrors :func:`skill_lens.rules.load_pack` exactly: ``pack.yaml`` plus
    every ``*.yaml`` directly under the declared ``rules_dir``, relnames in
    the loader's ``f"{rules_dir}/{name}"`` form, sorted by name.
    """
    root = Path(pack_dir)
    pack_path = root / "pack.yaml"
    try:
        pack_text = pack_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackSecError(f"pack.yaml unreadable: {exc.strerror}") from exc
    inputs: list[tuple[str, bytes]] = [("pack.yaml", pack_text.encode("utf-8"))]
    rules_dir = "rules"
    for line in pack_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("rules_dir:"):
            value = stripped.split(":", 1)[1].strip().strip("\"'")
            if value:
                rules_dir = value
            break
    rules_root = root / rules_dir
    if not rules_root.is_dir():
        raise PackSecError(f"rules directory not found: {rules_root}")
    for rule_path in sorted(rules_root.glob("*.yaml")):
        if rule_path.is_file():
            try:
                inputs.append((f"{rules_dir}/{rule_path.name}", rule_path.read_bytes()))
            except OSError as exc:
                raise PackSecError(
                    f"rule file unreadable ({rule_path.name}): {exc.strerror}"
                ) from exc
    return inputs


def canonical_digest(inputs: list[tuple[str, bytes]]) -> bytes:
    """Raw SHA-256 over the D-HASH stream: name \\0 len(u64 BE) data, sorted."""
    digest = hashlib.sha256()
    for name, data in sorted(inputs, key=lambda item: item[0]):
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.digest()


def digest_label(digest: bytes) -> str:
    """The ``sha256:<hex>`` display form used across doctor/report surfaces."""
    return "sha256:" + digest.hex()


def fingerprint(public_pem_or_raw: bytes) -> str:
    """Stable short identity of a public key: ``SHA256:<first-16-hex>…``.

    Hashes the RAW 32-byte public key so PEM and base64 files carrying the
    same key share one fingerprint.
    """
    raw = _load_public(public_pem_or_raw)
    return "SHA256:" + hashlib.sha256(raw).hexdigest()[:16] + "…"


# ---------------------------------------------------------------------------
# Deterministic artifact builder
# ---------------------------------------------------------------------------


def build_artifact(pack_dir: Path | str) -> bytes:
    """Build the canonical release artifact: a byte-deterministic zip.

    Members are exactly :func:`canonical_pack_inputs` (sorted), each stamped
    with frozen DOS-epoch timestamps, fixed 0644 modes, no extra fields, at
    a pinned deflate level — identical inputs yield identical bytes on any
    machine, which is what SHA-pinners and verifiers rely on.
    """
    inputs = canonical_pack_inputs(pack_dir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(inputs, key=lambda item: item[0]):
            info = zipfile.ZipInfo(filename=name, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = _ZIP_MODE
            info.internal_attr = 0
            info.create_system = 3  # unix
            zf.writestr(info, data, compresslevel=_ZIP_COMPRESSLEVEL)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------


def sign_digest(private_key_bytes: bytes, digest: bytes) -> bytes:
    """Produce the 64-byte detached ed25519 signature over *digest*."""
    return _ed25519_sign(_load_seed(private_key_bytes), digest)


def verify_digest(public_key_bytes: bytes, digest: bytes, sig: bytes) -> VerifyResult:
    """Offline verification; NEVER raises — failures come back as values."""
    if not backend_available():
        return VerifyResult(False, "no ed25519 backend available (install 'cryptography')")
    try:
        pub = _load_public(public_key_bytes)
    except PackSecError as exc:
        return VerifyResult(False, str(exc))
    if len(sig) != 64:
        return VerifyResult(False, f"signature must be 64 bytes, got {len(sig)}")
    try:
        _ed25519_verify(pub, digest, sig)
    except ValueError as exc:
        return VerifyResult(False, str(exc), fingerprint(public_key_bytes))
    return VerifyResult(True, "signature verifies", fingerprint(public_key_bytes))


#: Signature-file header written by the ceremony tooling (self-describing).
SIG_FILE_HEADER = "# Skill Lens detached ed25519 pack signature\n"


def write_sig_file(path: Path | str, digest: bytes, sig: bytes) -> None:
    """Write a self-describing ``.sig`` sidecar (comment + digest + b64 sig).

    The ``#digest:`` comment lets verifiers diagnose a STALE signature
    against a recomputed pack digest before spending crypto on it.
    """
    payload = (
        SIG_FILE_HEADER
        + f"#digest: {digest_label(digest)}\n"
        + base64.b64encode(sig).decode("ascii")
        + "\n"
    )
    Path(path).write_text(payload, encoding="utf-8")


def read_sig_file(path: Path | str) -> tuple[bytes, bytes]:
    """Parse a ``.sig`` sidecar → ``(digest_bytes, sig_bytes)``.

    Comment lines (``#``) are ignored; exactly one base64 signature line is
    required. The ``#digest:`` comment, when present, is returned as the
    digest so verifiers can cross-check it against the recomputed digest
    BEFORE burning crypto on a stale signature (loud stale-sig diagnosis).
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PackSecError(f"signature file unreadable: {exc.strerror}") from exc
    digest: bytes | None = None
    sig: bytes | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if stripped.startswith("#digest:"):
                label = stripped.split(":", 1)[1].strip()
                if label.startswith("sha256:"):
                    digest = bytes.fromhex(label[len("sha256:") :])
            continue
        if sig is not None:
            raise PackSecError("signature file carries more than one signature line")
        try:
            sig = base64.b64decode(stripped, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise PackSecError(f"signature line is not valid base64: {exc}") from exc
    if sig is None:
        raise PackSecError("signature file carries no signature line")
    return (digest if digest is not None else b""), sig


def load_public_key_file(path: Path | str) -> bytes:
    """Read a public-key file (PEM or base64) as opaque bytes."""
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise PackSecError(f"public key unreadable: {exc.strerror}") from exc


def load_private_key_file(path: Path | str) -> bytes:
    """Read a private-key file as opaque bytes (parsed later, never logged)."""
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise PackSecError(f"private key unreadable: {exc.strerror}") from exc


# ---------------------------------------------------------------------------
# Core-pack signature location (shared by doctor check 1 + `rules verify`)
# ---------------------------------------------------------------------------

#: Committed public key (repo-relative to the plugin root).
CORE_PUBKEY_RELPATH = "keys/pack-signing.pub.pem"

#: Glob (relative to plugin root) for the current core-pack signature.
CORE_SIG_GLOB = "keys/core-pack-*.sig"


def plugin_root() -> Path:
    """Repo/plugin root: the directory CONTAINING the skill_lens package.

    Works under both layouts (top-level ``skill_lens`` and the host's
    ``hermes_plugins.<key>.skill_lens``) because both keep ``keys/`` beside
    the package at the plugin-dir root (D-053 layout law).
    """
    from .rules import core_pack_path

    # core_pack_path -> <root>/skill_lens/rules/core ; root is three up.
    return core_pack_path().parents[2]


def locate_core_keys(root: Path | None = None) -> tuple[Path | None, Path | None]:
    """Locate ``(pubkey, sig)`` for the embedded core pack under *root*.

    Either may be None (dev trees, pre-ceremony states). When several sig
    files exist the lexicographically LAST wins (release tooling keeps
    exactly one; the tiebreak stays deterministic).

    Package-data fallback (v1.0 packaging): when the plugin-root layout
    carries no ``keys/pack-signing.pub.pem`` (installed wheels —
    ``site-packages`` has no ``keys/`` beside the package), the committed
    PUBLIC key shipped as package data (``skill_lens/keys/``) keeps
    offline provenance checking alive. Per-release ``.sig`` sidecars do
    NOT ship, so installed copies land on the honest WARN lane (checksum
    pins bytes, not origin).
    """
    base = plugin_root() if root is None else root
    pub = base / CORE_PUBKEY_RELPATH
    if not pub.is_file() and root is None:
        try:
            from importlib.resources import files

            packaged = (
                Path(str(files(__package__ or "skill_lens") / "keys"))
                / Path(CORE_PUBKEY_RELPATH).name
            )
            if packaged.is_file():
                pub = packaged
        except (ImportError, TypeError, OSError):
            pass
    sigs = sorted(base.glob(CORE_SIG_GLOB))
    return (pub if pub.is_file() else None), (sigs[-1] if sigs else None)


@dataclass(frozen=True)
class CoreSignatureReport:
    """Doctor/verb-grade outcome of verifying the embedded core pack."""

    #: "pass" (verified) | "warn" (unsigned / unverifiable environment) |
    #: "fail" (PRESENT signature does not match — tamper or stale sig).
    status: str
    lines: tuple[str, ...]
    checksum: str  # pack content_checksum (display form)
    sig_path: str = ""
    fingerprint_short: str = ""


def verify_core_signature(
    *,
    root: Path | None = None,
    pack: Any = None,
) -> CoreSignatureReport:
    """Verify the embedded core pack against the committed pubkey (offline).

    Shared by doctor check 1 and the ``rules verify`` verb so the two
    surfaces cannot drift. Outcomes:
      * pubkey+sig present and valid  → PASS (provenance proven);
      * anything missing              → WARN (honest: checksum proves bytes,
        not who shipped — dev-tree/pre-ceremony states);
      * signature present but INVALID → FAIL LOUDLY (hard-failure lane:
        tampered bytes or a stale signature after an authorized pack change;
        both demand human attention, never a silent pass).
    """
    if pack is None:
        from .rules import load_core_pack

        pack = load_core_pack()
    checksum = pack.content_checksum()
    digest = bytes.fromhex(checksum[len("sha256:") :])
    pub_path, sig_path = locate_core_keys(root)
    if pub_path is None or sig_path is None:
        missing = []
        if pub_path is None:
            missing.append(CORE_PUBKEY_RELPATH)
        if sig_path is None:
            missing.append(CORE_SIG_GLOB.replace("*", "<version>"))
        return CoreSignatureReport(
            "warn",
            (
                f"v{pack.version} · unsigned — missing {' and '.join(missing)}",
                "checksum pins bytes but proves no origin; run scripts/sign_core_pack.py",
            ),
            checksum,
        )
    if not backend_available():
        return CoreSignatureReport(
            "warn",
            (
                f"v{pack.version} · signature present but no crypto backend "
                "(pip install cryptography) — verification skipped honestly",
                checksum,
            ),
            checksum,
            str(sig_path),
        )
    try:
        sig_digest, sig = read_sig_file(sig_path)
    except PackSecError as exc:
        return CoreSignatureReport(
            "fail",
            (f"v{pack.version} · signature unreadable: {exc}",),
            checksum,
            str(sig_path),
        )
    if sig_digest and sig_digest != digest:
        return CoreSignatureReport(
            "fail",
            (
                "SIGNATURE MISMATCH — pack bytes do not match the committed "
                f"signature ({sig_path.name})",
                f"pack   {checksum}",
                f"signed {digest_label(sig_digest)}",
                "tamper or stale signature: re-run scripts/sign_core_pack.py "
                "only after authorizing the pack change",
            ),
            checksum,
            str(sig_path),
        )
    result = verify_digest(pub_path.read_bytes(), digest, sig)
    if result.ok:
        short = f"{checksum[:15]}…{checksum[-6:]}"
        return CoreSignatureReport(
            "pass",
            (
                f"v{pack.version} · signed · verified against committed pubkey "
                f"({result.fingerprint}) · {short}",
            ),
            checksum,
            str(sig_path),
            result.fingerprint,
        )
    return CoreSignatureReport(
        "fail",
        (
            f"SIGNATURE REJECTED — {result.reason} ({sig_path.name})",
            f"pack {checksum}",
            "verification FAILED loudly: treat these pack bytes as untrusted",
        ),
        checksum,
        str(sig_path),
    )


# ---------------------------------------------------------------------------
# External (community) pack verification — shared value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalPackReport:
    """Doctor/verb-grade outcome of verifying one EXTERNAL (community) pack.

    Same value-object discipline as :class:`CoreSignatureReport`: never
    raises, so the three consuming surfaces (scan registration, ``rules
    verify``, doctor check 1) cannot drift. ``status`` follows the core
    vocabulary ("pass" | "warn" | "fail") and ``accepted`` states the
    load decision outright — a WARN with ``accepted=False`` (missing pin)
    is a rejection without tamper evidence, while a WARN with
    ``accepted=True`` (signature declared, no crypto backend) keeps the
    pack usable because the sha256 pin still gates the bytes.
    """

    status: str
    lines: tuple[str, ...]
    name: str
    #: Machine reason kind: missing-pin | pin (digest mismatch) | loader |
    #: sig | backend | empty string (clean pass). Mapped to stable
    #: diagnostic codes by the caller.
    kind: str = ""
    reason: str = ""
    accepted: bool = False
    checksum: str = ""
    fingerprint_short: str = ""


def verify_external_pack(
    *,
    path: Path | str,
    name: str,
    sha256_pin: str,
    sig_path: Path | str | None = None,
    pubkey_path: Path | str | None = None,
) -> ExternalPackReport:
    """Verify one external pack against its pin (offline; never raises).

    Order is normative (SPEC §15 flow): structural load, digest-vs-pin,
    then the OPTIONAL detached signature. Every step fails closed:

    1. loader fault (bad YAML/dup id/unknown engine/…) → FAIL ("loader");
    2. canonical digest over :func:`canonical_pack_inputs` MUST equal
       *sha256_pin* byte-for-byte → mismatch = FAIL ("pin", the
       tamper lane); an empty pin = WARN-grade rejection ("missing-pin");
    3. signature OPTIONAL: present-but-invalid = FAIL ("sig"); declared
       but no crypto backend = WARN ("backend") with the pack still
       accepted on its pin; absent = clean pass with a note.
    """
    from .rules import RulePackError, load_pack

    label = f"pack {name}"
    try:
        load_pack(path)
    except RulePackError as exc:
        return ExternalPackReport(
            "fail",
            (f"{label}: LOADER REJECTED — {exc}",),
            name,
            kind="loader",
            reason=f"loader rejected ({exc})",
        )
    try:
        digest = canonical_digest(canonical_pack_inputs(path)).hex()
    except PackSecError as exc:
        return ExternalPackReport(
            "fail",
            (f"{label}: digest unreadable — {exc}",),
            name,
            kind="pin",
            reason=f"digest unreadable ({exc})",
        )
    checksum = digest_label(bytes.fromhex(digest))
    if not sha256_pin:
        return ExternalPackReport(
            "warn",
            (
                f"{label}: no sha256 pin — REJECTED (a pin you wrote is a trust "
                "decision; its absence is a config fault)",
                checksum,
            ),
            name,
            kind="missing-pin",
            reason="missing sha256 pin",
            checksum=checksum,
        )
    if digest != sha256_pin.lower():
        return ExternalPackReport(
            "fail",
            (
                f"{label}: PIN MISMATCH — pack bytes do not match the pinned digest",
                f"pinned  sha256:{sha256_pin}",
                f"actual  {checksum}",
                "treat these pack bytes as untrusted; re-pin only after authorizing "
                "the change (manual-only updates, D-RULEOWN)",
            ),
            name,
            kind="pin",
            reason="digest does not match the pinned sha256",
            checksum=checksum,
        )
    if sig_path is None:
        return ExternalPackReport(
            "pass",
            (
                f"{label}: pin-match ok · {checksum[:15]}… (unsigned — checksum "
                "pins bytes, not origin)",
            ),
            name,
            reason="sha256 pin verified",
            accepted=True,
            checksum=checksum,
        )
    if not backend_available():
        return ExternalPackReport(
            "warn",
            (
                f"{label}: pin-match ok · {checksum[:15]}…; signature present but no "
                "crypto backend — accepted on its sha256 pin, origin unproven",
            ),
            name,
            kind="backend",
            reason="signature present but no ed25519 backend (install 'cryptography')",
            accepted=True,
            checksum=checksum,
        )
    pub_bytes: bytes | None = None
    if pubkey_path is not None:
        try:
            pub_bytes = load_public_key_file(pubkey_path)
        except PackSecError as exc:
            return ExternalPackReport(
                "fail",
                (f"{label}: trust root unreadable — {exc}",),
                name,
                kind="sig",
                reason=f"pubkey unreadable ({exc})",
                checksum=checksum,
            )
    else:
        default_pub, _ = locate_core_keys()
        if default_pub is not None:
            pub_bytes = default_pub.read_bytes()
    if pub_bytes is None:
        return ExternalPackReport(
            "fail",
            (f"{label}: signature declared but no public key available",),
            name,
            kind="sig",
            reason="signature declared but no pubkey (pass one via the pin)",
            checksum=checksum,
        )
    try:
        sig = read_sig_file(sig_path)[1]
    except PackSecError as exc:
        return ExternalPackReport(
            "fail",
            (f"{label}: SIGNATURE REJECTED — {exc}", checksum),
            name,
            kind="sig",
            reason=f"signature unreadable ({exc})",
            checksum=checksum,
        )
    result = verify_digest(pub_bytes, bytes.fromhex(digest), sig)
    if result.ok:
        return ExternalPackReport(
            "pass",
            (f"{label}: pin-match ok · signature verified ({result.fingerprint})",),
            name,
            reason="sha256 pin + signature verified",
            accepted=True,
            checksum=checksum,
            fingerprint_short=result.fingerprint,
        )
    return ExternalPackReport(
        "fail",
        (
            f"{label}: SIGNATURE REJECTED — {result.reason}",
            checksum,
            "verification FAILED loudly: treat these pack bytes as untrusted",
        ),
        name,
        kind="sig",
        reason=f"signature rejected ({result.reason})",
        checksum=checksum,
    )


__all__ = [
    "CORE_PUBKEY_RELPATH",
    "CORE_SIG_GLOB",
    "CoreSignatureReport",
    "PackSecError",
    "VerifyResult",
    "backend_name",
    "ExternalPackReport",
    "build_artifact",
    "canonical_digest",
    "canonical_pack_inputs",
    "digest_label",
    "fingerprint",
    "locate_core_keys",
    "load_private_key_file",
    "load_public_key_file",
    "plugin_root",
    "read_sig_file",
    "sign_digest",
    "verify_core_signature",
    "verify_digest",
    "verify_external_pack",
    "write_sig_file",
]
