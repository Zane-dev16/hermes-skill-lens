#!/usr/bin/env python3
"""Release engineering for Hermes Skill Lens (PLAN §5 distribution row).

Subcommands
-----------
verify-core
    Offline verification of the embedded core pack against the committed
    public key + detached signature (same engine as doctor check 1 /
    ``rules verify``). Exit 0 verified-or-warn · 2 rejected.

check-signature-fresh
    Rebuild the canonical digest from the WORKING TREE and compare with the
    committed ``keys/core-pack-*.sig`` (digest comment + crypto verify).
    Exit 0 fresh · 1 stale (authorized re-sign needed) · 2 structural.

artifact [--out DIST]
    Build the byte-deterministic pack artifact ``lens-core-pack-<ver>.zip``
    plus its detached ``.sig`` into DIST (default ``dist/``, gitignored —
    artifacts ride GitHub Releases, never git).

cut --plugin-version X.Y.Z [--tag|--no-tag] [--dry-run] [--notes PATH]
    Cut one tagged plugin version (engine + pack pins move TOGETHER,
    D-RULEOWN):
      1. require clean tracked tree + FRESH core-pack signature;
      2. bump ``version:`` in plugin.yaml AND ``version =`` in pyproject.toml;
      3. build the signed artifact;
      4. emit release-notes skeleton (repo changelog head + pack changelog
         head + artifact SHA256 + pubkey fingerprint);
      5. commit the bump ("release: vX.Y.Z (core pack YYYY.MM.N)") and
         create annotated tag ``vX.Y.Z`` whose message PINS the pack
         version + artifact digest — downgrade = install the older tag,
         which carries ITS matching pack by construction (SPEC §15:
         "travels version-pinned with the plugin via git tags").

Compatibility law (D-RULEOWN): there is no separate engine-vs-pack matrix
to drift — the core pack SHIPS INSIDE each tagged tree, so a tag always
loads its own pack; external/community packs are refused at load when their
spec_version is newer than the engine understands (RulePackError → §18
exit-2 lane). Updates stay manual-only; no network anywhere in this tool.

Exit codes mirror §18: 0 ok · 1 gate violation (stale sig, dirty tree) ·
2 structural error.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from skill_lens import packsec  # noqa: E402
from skill_lens.rules import load_core_pack  # noqa: E402

PLUGIN_YAML = REPO_ROOT / "plugin.yaml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
DIST_DEFAULT = REPO_ROOT / "dist"


def _git(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _pack_version() -> str:
    return load_core_pack().version


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_verify_core(_args: argparse.Namespace) -> int:
    report = packsec.verify_core_signature(root=REPO_ROOT)
    for line in report.lines:
        print(line)
    print(f"status: {report.status}")
    return 0 if report.status != "fail" else 2


def cmd_check_signature_fresh(_args: argparse.Namespace) -> int:
    pub, sig_path = packsec.locate_core_keys(REPO_ROOT)
    if pub is None or sig_path is None:
        print(
            "error: committed pubkey/signature missing — run scripts/sign_core_pack.py",
            file=sys.stderr,
        )
        return 2
    pack = load_core_pack()
    digest = bytes.fromhex(pack.content_checksum()[len("sha256:") :])
    try:
        sig_digest, sig_bytes = packsec.read_sig_file(sig_path)
    except packsec.PackSecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if sig_digest and sig_digest != digest:
        print(
            f"signature STALE: committed sig covers {packsec.digest_label(sig_digest)} "
            f"but working-tree pack hashes to {packsec.digest_label(digest)}"
        )
        print("re-sign after authorizing the change: python3 scripts/sign_core_pack.py")
        return 1
    result = packsec.verify_digest(pub.read_bytes(), digest, sig_bytes)
    if not result.ok:
        print(f"signature REJECTED: {result.reason}")
        return 1
    print(f"signature fresh over {packsec.digest_label(digest)} ({result.fingerprint})")
    return 0


def cmd_artifact(args: argparse.Namespace) -> int:
    out_dir = Path(args.out) if args.out else DIST_DEFAULT
    out_dir.mkdir(parents=True, exist_ok=True)
    pv = _pack_version()
    artifact = packsec.build_artifact(REPO_ROOT / "skill_lens" / "rules" / "core")
    zip_path = out_dir / f"lens-core-pack-{pv}.zip"
    zip_path.write_bytes(artifact)
    sha256 = hashlib.sha256(artifact).hexdigest()

    key_path = (
        Path(args.key) if args.key else REPO_ROOT / "build-state" / "keys" / "pack-signing.pem"
    )
    pub, _ = packsec.locate_core_keys(REPO_ROOT)
    if pub is None:
        print("error: committed public key missing", file=sys.stderr)
        return 2
    if not key_path.is_file():
        print(f"error: private signing key not found at {key_path}", file=sys.stderr)
        return 2
    digest = bytes.fromhex(load_core_pack().content_checksum()[7:])
    sig = packsec.sign_digest(packsec.load_private_key_file(key_path), digest)
    sig_path = out_dir / f"lens-core-pack-{pv}.zip.sig"
    packsec.write_sig_file(sig_path, digest, sig)

    print(f"artifact:  {zip_path} ({len(artifact)} bytes)")
    print(f"sha256:    {sha256}")
    print(f"signature: {sig_path}")
    print(f"fingerprint: {packsec.fingerprint(pub.read_bytes())}")
    return 0


def _bump_plugin_yaml(version: str) -> None:
    text = PLUGIN_YAML.read_text(encoding="utf-8")
    new_text, count = re.subn(r'(?m)^version: "[^"]*"$', f'version: "{version}"', text)
    if count != 1:
        raise RuntimeError(f"plugin.yaml: expected exactly one version line, found {count}")
    PLUGIN_YAML.write_text(new_text, encoding="utf-8")


def _bump_pyproject(version: str) -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    new_text, count = re.subn(r"(?m)^version = \"[^\"]*\"$", f'version = "{version}"', text)
    if count != 1:
        raise RuntimeError(f"pyproject.toml: expected exactly one version line, found {count}")
    PYPROJECT.write_text(new_text, encoding="utf-8")


def _release_notes(plugin_version: str, artifact_sha: str, fingerprint: str) -> str:
    pv = _pack_version()
    lines = [
        f"# Skill Lens v{plugin_version}",
        "",
        f"Core rule pack pin: **{pv}** (engine + pack travel together, D-RULEOWN).",
        "",
        "## Pack highlights (head changelog entry)",
        "",
    ]
    pack = load_core_pack()
    if pack.changelog:
        head = pack.changelog[0]
        for note in head.get("notes") or []:
            lines.append("- " + " ".join(str(note).split()))
        rationale = head.get("rationale")
        if rationale:
            lines.append("")
            lines.append("Rationale (§15 minor-bump requirement):")
            items = [rationale] if isinstance(rationale, str) else rationale
            for item in items:
                lines.append(f"  - {' '.join(str(item).split())}")
    lines += [
        "",
        "## Verification (offline)",
        "",
        f"- Pack content checksum: `{pack.content_checksum()}`",
        f"- Release artifact: `lens-core-pack-{pv}.zip`",
        f"- Artifact SHA256: `{artifact_sha}`",
        f"- Signing key fingerprint: `{fingerprint}` (committed at `keys/pack-signing.pub.pem`)",
        "- Verify after install: `hermes lens rules verify`",
        "",
        "## Upgrade / downgrade",
        "",
        "- Upgrade: `hermes plugins update` then confirm `hermes lens doctor` shows the",
        "  new signed pack (check 1 PASS).",
        "- Downgrade: reinstall the older tag — it carries ITS OWN matching pack by",
        "  construction; external packs whose schema is newer than the engine are",
        "  refused at load (loud diagnostic, never silently enabled).",
        "",
        "Advisor, not bouncer: static analysis only; clean scan ≠ safe skill.",
    ]
    return "\n".join(lines) + "\n"


def cmd_cut(args: argparse.Namespace) -> int:
    version = args.plugin_version
    if not re.match(r"^\d+\.\d+\.\d+(?:a\d+|b\d+|rc\d+)?$", version):
        print(f"error: plugin version {version!r} is not X.Y.Z[abN/rcN]", file=sys.stderr)
        return 2
    pv = _pack_version()

    dirty = _git("status", "--porcelain")
    # build-state/, dist/, .hypothesis etc. may be dirty; only TRACKED files block.
    tracked_dirty = [ln for ln in dirty.splitlines() if not ln.startswith("??")]
    if tracked_dirty and not args.dry_run:
        print("error: tracked working tree is dirty — commit or stash first:", file=sys.stderr)
        for ln in tracked_dirty:
            print(f"  {ln}", file=sys.stderr)
        return 1

    fresh = cmd_check_signature_fresh(argparse.Namespace())
    if fresh != 0:
        print("error: refusing to cut a release whose pack signature is not fresh", file=sys.stderr)
        return fresh

    if args.dry_run:
        print(f"dry-run: would bump plugin.yaml + pyproject.toml to {version}")
        print(f"dry-run: would build dist/lens-core-pack-{pv}.zip + .sig (already fresh)")
        print(f"dry-run: would commit 'release: v{version} (core pack {pv})' and tag v{version}")
        return 0

    _bump_plugin_yaml(version)
    _bump_pyproject(version)

    art = cmd_artifact(argparse.Namespace(out=None, key=args.key))
    if art != 0:
        return art
    zip_path = DIST_DEFAULT / f"lens-core-pack-{pv}.zip"
    artifact_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    _, sig_file = packsec.locate_core_keys(REPO_ROOT)
    pub = REPO_ROOT / packsec.CORE_PUBKEY_RELPATH
    fingerprint = packsec.fingerprint(pub.read_bytes())

    notes_path = Path(args.notes) if args.notes else DIST_DEFAULT / f"release-notes-v{version}.md"
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text(_release_notes(version, artifact_sha, fingerprint), encoding="utf-8")

    _git("add", "plugin.yaml", "pyproject.toml")
    # Identity comes from repo config ONLY (/standard-commit law; no -c/env
    # overrides — D-058 records the incident this fix closes).
    _git("commit", "-m", f"release: v{version} (core pack {pv})")
    if args.tag:
        tag_message = (
            f"Skill Lens v{version}\n"
            f"\n"
            f"Core rule pack pin: {pv}\n"
            f"Pack checksum: {load_core_pack().content_checksum()}\n"
            f"Artifact SHA256: {artifact_sha}\n"
            f"Signing key fingerprint: {fingerprint}\n"
        )
        _git("tag", "-a", f"v{version}", "-m", tag_message)
    print(f"cut v{version}: bumped pins to plugin {version} / pack {pv}")
    print(f"release notes: {notes_path.relative_to(REPO_ROOT)}")
    print("downgrade story: older tags carry their own matching pack (D-RULEOWN)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("verify-core", help="offline verification of the embedded core pack")
    fresh = sub.add_parser("check-signature-fresh", help="working tree vs committed signature")
    # The check is ALWAYS strict (stale/rejected => exit 1); --strict exists so
    # the CI contract in .github/workflows/rule-pack.yml parses cleanly.
    fresh.add_argument(
        "--strict",
        action="store_true",
        help="accepted for CI compatibility; the check is always strict",
    )

    art = sub.add_parser("artifact", help="build deterministic signed artifact into dist/")
    art.add_argument("--out", default=None)
    art.add_argument("--key", default=None)

    cut = sub.add_parser("cut", help="cut one tagged plugin version (engine+pack together)")
    cut.add_argument("--plugin-version", required=True)
    cut.add_argument("--tag", dest="tag", action="store_true", default=True)
    cut.add_argument("--no-tag", dest="tag", action="store_false")
    cut.add_argument("--dry-run", action="store_true")
    cut.add_argument("--notes", default=None)
    cut.add_argument("--key", default=None)

    args = parser.parse_args(argv)
    handler = {
        "verify-core": cmd_verify_core,
        "check-signature-fresh": cmd_check_signature_fresh,
        "artifact": cmd_artifact,
        "cut": cmd_cut,
    }[args.cmd]
    try:
        return handler(args)
    except (RuntimeError, packsec.PackSecError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
