"""Phase 5 — pack artifact security (skill_lens.packsec, SPEC §15).

Covers the canonical digest (loader parity), deterministic artifact bytes,
ed25519 sign/verify round-trip and REJECTION lanes, sig-file parsing, and
the shared core-signature report consumed by doctor check 1 + ``rules
verify``. Tamper tests prove a flipped byte in ANY pack file is rejected
LOUDLY.
"""

from __future__ import annotations

import base64
import shutil
import zipfile
from pathlib import Path

import pytest

from skill_lens import packsec
from skill_lens.rules import load_core_pack, load_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def ceremony(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """A throwaway ed25519 keypair via the real cryptography backend."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return {"priv": priv, "pub": pub}


# ---------------------------------------------------------------------------
# Canonical inputs / digest — loader parity
# ---------------------------------------------------------------------------


def test_canonical_digest_matches_loader_checksum() -> None:
    from skill_lens.rules import core_pack_path

    pack = load_core_pack()
    inputs = packsec.canonical_pack_inputs(core_pack_path())
    assert packsec.digest_label(packsec.canonical_digest(inputs)) == pack.content_checksum()


def test_canonical_inputs_sorted_and_complete() -> None:
    from skill_lens.rules import core_pack_path

    inputs = packsec.canonical_pack_inputs(core_pack_path())
    names = [name for name, _ in inputs]
    assert names == sorted(names)
    assert names[0] == "pack.yaml"
    # 41 rule files + manifest at the time of writing; the invariant that
    # matters: every rules/*.yaml on disk is present exactly once.
    on_disk = sorted(p.name for p in (core_pack_path() / "rules").glob("*.yaml"))
    assert [n[len("rules/") :] for n in names[1:]] == on_disk


# ---------------------------------------------------------------------------
# Deterministic artifact builder
# ---------------------------------------------------------------------------


def test_artifact_is_byte_deterministic_and_sorted() -> None:
    from skill_lens.rules import core_pack_path

    root = core_pack_path()
    first = packsec.build_artifact(root)
    second = packsec.build_artifact(root)
    assert first == second
    zf = zipfile.ZipFile(__import__("io").BytesIO(first))
    names = zf.namelist()
    assert names == sorted(names)
    for info in zf.infolist():
        assert info.date_time == (1980, 1, 1, 0, 0, 0), "wall-clock in artifact"
        assert info.external_attr == 0o100644 << 16


# ---------------------------------------------------------------------------
# Sign / verify — round trip and rejection lanes
# ---------------------------------------------------------------------------


def test_sign_verify_roundtrip(ceremony: dict[str, object]) -> None:
    pack = load_core_pack()
    digest = bytes.fromhex(pack.content_checksum()[7:])
    sig = packsec.sign_digest(ceremony["priv"], digest)  # type: ignore[arg-type]
    result = packsec.verify_digest(ceremony["pub"], digest, sig)  # type: ignore[arg-type]
    assert result.ok, result.reason
    assert result.fingerprint.startswith("SHA256:")


def test_verify_rejects_flipped_digest(ceremony: dict[str, object]) -> None:
    digest = b"\x00" * 32
    other = bytes(b ^ 1 for b in digest)
    sig = packsec.sign_digest(ceremony["priv"], digest)  # type: ignore[arg-type]
    result = packsec.verify_digest(ceremony["pub"], other, sig)  # type: ignore[arg-type]
    assert not result.ok
    assert "mismatch" in result.reason.lower()


def test_fingerprint_is_backend_format_stable(ceremony: dict[str, object]) -> None:
    """PEM and raw-base64 files carrying one key share a fingerprint."""
    raw = packsec._load_public(ceremony["pub"])  # type: ignore[arg-type]
    as_b64 = base64.b64encode(raw)
    assert packsec.fingerprint(as_b64) == packsec.fingerprint(raw)


def test_sig_file_roundtrip_and_stale_detection(
    ceremony: dict[str, object], tmp_path: Path
) -> None:
    digest = b"\x11" * 32
    sig = packsec.sign_digest(ceremony["priv"], digest)  # type: ignore[arg-type]
    path = tmp_path / "x.sig"
    packsec.write_sig_file(path, digest, sig)
    back_digest, back_sig = packsec.read_sig_file(path)
    assert back_digest == digest and back_sig == sig
    # A stale digest comment is surfaced so verifiers can diagnose BEFORE crypto.
    stale_path = tmp_path / "stale.sig"
    stale_sig = packsec.sign_digest(ceremony["priv"], b"\x22" * 32)  # type: ignore[arg-type]
    packsec.write_sig_file(stale_path, b"\x22" * 32, stale_sig)  # type: ignore[arg-type]
    assert packsec.read_sig_file(stale_path)[0] == b"\x22" * 32


# ---------------------------------------------------------------------------
# verify_core_signature — the shared doctor/verb engine
# ---------------------------------------------------------------------------


def _mirror_tree(root: Path) -> Path:
    """Copy the embedded core pack + committed keys into *root* (same layout)."""
    from skill_lens.rules import core_pack_path

    dst = root / "skill_lens" / "rules" / "core"
    shutil.copytree(core_pack_path(), dst)
    if (REPO_ROOT / "keys").is_dir():
        shutil.copytree(REPO_ROOT / "keys", root / "keys")
    return dst


def test_core_signature_passes_on_committed_tree() -> None:
    if not (REPO_ROOT / "keys" / "pack-signing.pub.pem").is_file():
        pytest.skip("ceremony keys not present in this tree")
    report = packsec.verify_core_signature(root=REPO_ROOT)
    assert report.status == "pass"
    assert any("verified" in line for line in report.lines)


def test_tampered_rule_file_is_rejected_loudly(tmp_path: Path) -> None:
    """THE Phase-5 tamper law: flipping a byte in ANY pack file ⇒ FAIL."""
    if not (REPO_ROOT / "keys" / "core-pack-2026.08.6.sig").is_file():
        pytest.skip("committed signature not present in this tree")
    dst = _mirror_tree(tmp_path)
    target = dst / "rules" / "LNS-NET-011.yaml"
    original = target.read_text()
    target.write_text(original.replace("title:", "title :", 1))
    tampered = load_pack(dst)
    report = packsec.verify_core_signature(root=tmp_path, pack=tampered)
    assert report.status == "fail"
    joined = "\n".join(report.lines)
    assert "SIGNATURE MISMATCH" in joined or "REJECTED" in joined
    assert report.checksum != load_core_pack().content_checksum()


def test_missing_keys_degrade_to_honest_warn(tmp_path: Path) -> None:
    empty = tmp_path / "bare"
    empty.mkdir()
    report = packsec.verify_core_signature(root=empty, pack=load_core_pack())
    assert report.status == "warn"
    assert any("unsigned" in line for line in report.lines)


def test_wrong_pubkey_rejects_valid_looking_signature(
    tmp_path: Path, ceremony: dict[str, object]
) -> None:
    """Signature made with the RIGHT key but checked under a WRONG pubkey."""
    dst = _mirror_tree(tmp_path)
    (tmp_path / "keys").mkdir(exist_ok=True)
    # Committed sig stays; swap ONLY the pubkey to a foreign one.
    (tmp_path / "keys" / "pack-signing.pub.pem").write_bytes(
        ceremony["pub"]  # type: ignore[arg-type]
    )
    report = packsec.verify_core_signature(root=tmp_path, pack=load_pack(dst))
    assert report.status == "fail"


def test_stale_signature_rejected(tmp_path: Path, ceremony: dict[str, object]) -> None:
    """Right key, right pubkey, signature over DIFFERENT bytes."""
    dst = _mirror_tree(tmp_path)
    pack = load_pack(dst)
    digest = bytes.fromhex(pack.content_checksum()[7:])
    forged_digest = bytes(a ^ 0xFF for a in digest)
    sig = packsec.sign_digest(ceremony["priv"], forged_digest)  # type: ignore[arg-type]
    sig_path = tmp_path / "keys" / "core-pack-forged.sig"
    packsec.write_sig_file(sig_path, forged_digest, sig)
    report = packsec.verify_core_signature(root=tmp_path, pack=load_pack(dst))
    assert report.status == "fail"
