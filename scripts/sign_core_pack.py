#!/usr/bin/env python3
"""Core-pack signing tool — the operational half of docs/key-ceremony.md.

Subcommands
-----------
generate-key <private-out> [--pubkey-out PATH]
    Ceremony step 1: create a fresh ed25519 keypair. Writes PKCS8 PEM for
    the private seed (NEVER commit; keep under build-state/keys/, which is
    gitignored) and SubjectPublicKeyInfo PEM for the public half (committed
    at keys/pack-signing.pub.pem).

sign [--key PATH] [--pack DIR]
    Ceremony step 2 (repeated after every authorized pack change): compute
    the canonical core-pack digest (same recipe as the loader's
    content_checksum), sign it, and write keys/core-pack-<version>.sig,
    removing any stale core-pack-*.sig so exactly one signature ships.

show
    Print the current pack version, canonical digest, committed public-key
    fingerprint, and whether they verify — a human-readable pre-flight.

Exit codes: 0 success · 2 structural failure (missing/invalid keys, unreadable
pack). Zero network; pure offline crypto.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from skill_lens import packsec  # noqa: E402

DEFAULT_PRIVATE = REPO_ROOT / "build-state" / "keys" / "pack-signing.pem"
DEFAULT_PUBLIC = REPO_ROOT / "keys" / "pack-signing.pub.pem"


def _cmd_generate_key(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    out = Path(args.private_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(priv_pem)
    out.chmod(0o600)
    print(f"private key written: {out}  (mode 0600 — NEVER commit)")
    if args.pubkey_out:
        pub_path = Path(args.pubkey_out)
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.write_bytes(pub_pem)
        print(f"public key written: {pub_path}")
    print(f"public fingerprint: {packsec.fingerprint(pub_pem)}")
    return 0


def _locate_pubkey() -> Path:
    pub, _ = packsec.locate_core_keys(REPO_ROOT)
    if pub is None:
        raise packsec.PackSecError("committed public key missing: keys/pack-signing.pub.pem")
    return pub


def _cmd_sign(args: argparse.Namespace) -> int:
    key_path = Path(args.key) if args.key else DEFAULT_PRIVATE
    if not key_path.is_file():
        print(
            f"error: private key not found at {key_path} — see docs/key-ceremony.md",
            file=sys.stderr,
        )
        return 2
    priv = packsec.load_private_key_file(key_path)
    pub = _locate_pubkey()
    pack_dir = Path(args.pack) if args.pack else REPO_ROOT / "skill_lens" / "rules" / "core"
    inputs = packsec.canonical_pack_inputs(pack_dir)
    digest = packsec.canonical_digest(inputs)
    sig = packsec.sign_digest(priv, digest)

    pack_version = ""
    for line in inputs[0][1].decode("utf-8").splitlines():
        if line.startswith("version:"):
            pack_version = line.split(":", 1)[1].strip().strip("\"'")
            break
    keys_dir = REPO_ROOT / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    stale = sorted(keys_dir.glob("core-pack-*.sig"))
    for old in stale:
        old.unlink()
    sig_path = keys_dir / f"core-pack-{pack_version}.sig"
    packsec.write_sig_file(sig_path, digest, sig)
    result = packsec.verify_digest(Path(pub).read_bytes(), digest, sig)
    print(f"signed core pack {pack_version}")
    print(f"digest:      {packsec.digest_label(digest)}")
    print(f"fingerprint: {packsec.fingerprint(Path(pub).read_bytes())}")
    verdict = "self-verifies OK" if result.ok else "SELF-CHECK FAILED"
    print(f"signature:   {sig_path.relative_to(REPO_ROOT)} ({verdict})")
    return 0 if result.ok else 2


def _cmd_show(_args: argparse.Namespace) -> int:
    report = packsec.verify_core_signature(root=REPO_ROOT)
    for line in report.lines:
        print(line)
    print(f"status: {report.status}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate-key", help="ceremony step 1: fresh ed25519 keypair")
    gen.add_argument("private_out", nargs="?", default=str(DEFAULT_PRIVATE))
    gen.add_argument("--pubkey-out", default=None)
    gen.set_defaults(func=_cmd_generate_key)

    sign = sub.add_parser("sign", help="sign the embedded core pack (step 2)")
    sign.add_argument(
        "--key",
        default=None,
        help="private PEM (default build-state/keys/pack-signing.pem)",
    )
    sign.add_argument("--pack", default=None, help="pack dir (default skill_lens/rules/core)")
    sign.set_defaults(func=_cmd_sign)

    show = sub.add_parser("show", help="verify status of the committed pair")
    show.set_defaults(func=_cmd_show)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except packsec.PackSecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
