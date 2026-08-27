# Key ceremony — rule-pack signing (SPEC §15)

The core rule pack ships **signed**: every release carries a detached
ed25519 signature over the pack's canonical content digest, verifiable
offline against the committed public key (`keys/pack-signing.pub.pem`).
Doctor check 1 and `hermes lens rules verify` both run this verification;
a mismatching signature is a LOUD hard failure, never a warning.

## Trust model in one paragraph

The PUBLIC key is committed to the repository; the PRIVATE key never is.
Anyone with repo access can verify that the pack bytes they run are exactly
the bytes the signing key authorized. Anyone WITHOUT the private key cannot
produce such a signature. This proves provenance of pack bytes, not the
honesty of whoever holds the key — key custody IS the trust root, which is
why production custody belongs to the owner alone.

## This environment holds a DEV key

**The keypair generated for this development environment is a dev key,
generated and kept locally under `build-state/keys/` (gitignored). It signs
development-time pack states so the verification lane is exercised for
real, but it confers no production trust.** The PRODUCTION ceremony is
owner-run: the owner generates a fresh keypair on a machine they control,
publishes the public half, and keeps the private half offline. The dev
public key below is a placeholder until the owner rotates it via the same
procedure.

- Dev public fingerprint: `SHA256:9802d3c8e6ca921b…`
  (full value: `keys/pack-signing.pub.pem`)
- Dev private key: `build-state/keys/pack-signing.pem` — mode 0600,
  NEVER committed (`.gitignore` enforces `build-state/keys/`).

## Production ceremony (owner-run)

1. **Generate** on a trusted, offline-capable machine:

   ```bash
   python3 scripts/sign_core_pack.py generate-key /secure/pack-signing.pem \
       --pubkey-out keys/pack-signing.pub.pem
   ```

   Records: PKCS8 PEM private seed (keep offline, mode 0600) +
   SubjectPublicKeyInfo PEM public half (committed). Note the printed
   `SHA256:…` fingerprint; publish it wherever releases are announced so
   downstreams can pin it.

2. **Commit the public key** as its own commit. The commit message should
   name the fingerprint. Rotating a compromised key = new keypair + new
   commit + re-signed packs; old artifacts stay verifiable against the OLD
   pubkey recorded in the tags that shipped them.

3. **Sign** after every authorized pack change (this must happen before any
   release cut — `scripts/release.py cut` refuses to run on a stale
   signature):

   ```bash
   python3 scripts/sign_core_pack.py sign     # writes keys/core-pack-<ver>.sig
   git add keys/ && git commit -m "sign: core pack <ver> (fingerprint SHA256:…)"
   ```

4. **Verify anywhere, forever offline**:

   ```bash
   hermes lens rules verify          # installed plugin
   python3 scripts/release.py verify-core
   ```

## What is signed, exactly

The canonical digest from `skill_lens.packsec`: sorted
`(relname, len(u64 BE), bytes)` stream over `pack.yaml` plus every YAML in
the declared `rules_dir` — the same recipe as
`RulePack.content_checksum()`. Signature: raw Ed25519 (64 bytes) over the
raw SHA-256 digest. The `.sig` sidecar embeds a `#digest:` comment so stale
signatures diagnose instantly. Any byte flipped anywhere in the pack
changes the digest and is rejected.

## Backend notes

Primary backend is `cryptography` (declared in `plugin.yaml`
python_dependencies); PyNaCl works as a fallback for raw base64 seed files.
PEM parsing requires `cryptography`. See `skill_lens/packsec.py` (D-055).
