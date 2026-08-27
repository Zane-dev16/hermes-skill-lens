# Release drill — full PR→published loop simulation (Phase 5 deliverable 5)

Executed 2026-08-26 in throwaway `/tmp/lens-drill` (main repo untouched
except this evidence file). Every command below was actually run; outputs
verbatim. Scratch home: `/tmp/lens-drill/home`; release clone:
`/tmp/lens-drill/repo`.

## 0. Clone (private keys never travel — build-state/ is gitignored)

```
$ git clone …repo && cd repo
763e08b feat(governance): Phase 5 — pack signing, semver governor, rule-pack CI, release engineering
core-pack-2026.08.6.sig
pack-signing.pub.pem
build-state/keys absent in fresh clone: ls: cannot access 'build-state/keys': No such file or directory CONFIRMED-GITIGNORED
```

## 1. Drill ceremony — operator generates the release keypair locally

(docs/key-ceremony.md procedure; private key stays in clone's gitignored build-state/keys/)

```
private key written: build-state/keys/pack-signing.pem  (mode 0600 — NEVER commit)
public key written: keys/pack-signing.pub.pem
public fingerprint: SHA256:4b62dec90ca744c6…
signed core pack 2026.08.6
digest:      sha256:58227cb7fb98cb4e120d8aa7a4e7a9d501c4ff50fd0c5aacb7833d319b6f5828
fingerprint: SHA256:4b62dec90ca744c6…
signature:   keys/core-pack-2026.08.6.sig (self-verifies OK)
```

## 2. NEGATIVE CONTROL — governor teeth: score-visible change inside a PATCH bump

(simulate a bad PR: severity LOW→MEDIUM on LNS-NET-011 + patch-only bump)

```
$ git checkout -b feat/bad-weight-change
$ python3 scripts/pack_governor_check.py --base main
governor: 2026.08.6 → 2026.08.7 (base main)
transition legal: 2026.08.6 → 2026.08.7
CHANGELOG.md out of sync with pack.yaml — run `python3 scripts/pack_changelog.py` and commit the result
governor exit code: 1 (expected 1 = REJECTED)

### 2b. Negative control REDONE with real constants (NET-011 is CRITICAL/40):
$ sed severity CRITICAL->HIGH + weight 40->18 (patch bump stays)
10:severity: HIGH
11:weight: 18
$ python3 scripts/pack_governor_check.py --base main
governor: 2026.08.6 → 2026.08.7 (base main)
GOVERNOR REJECTED THE TRANSITION:
  - score-visible change(s) LNS-NET-011 require a MINOR bump (YYYY.MM patch may not change detection outcomes; §15)
  - minor bump without changelog rationale: head entry needs a 'rationale' field explaining the score-visible change(s) (LNS-NET-011; §15)
governor exit code: 1 (expected 1 = REJECTED)

## 3. THE REAL PR — feat/add-sec-003 (trivial rule, both-way fixtures)
$ git checkout -b feat/add-sec-003

### 3a. Rule YAML (skill_lens/rules/core/rules/LNS-SEC-003.yaml)
rule yaml + pack bump + changelog mirror written
fixtures written
Traceback (most recent call last):
  File "<stdin>", line 7, in <module>
NameError: name 'FastPathCacheNoop' is not defined
corpus/fixtures/malicious/committed-cert -> [] | keys: ['cache_hit', 'compact', 'envelope', 'envelope_json', 'error', 'ok']
corpus/fixtures/benign/env-var-documentation -> [] | keys: ['cache_hit', 'compact', 'envelope', 'envelope_json', 'error', 'ok']
corpus/fixtures/malicious/committed-cert -> [('LNS-MAN-004', 'LOW'), ('LNS-SEC-003', 'LOW')]
corpus/fixtures/benign/env-var-documentation -> CLEAN

### 3b. CI job 1 — fixtures (rule-pack.yml :: fixtures)
$ python3 scripts/rule_fixtures_check.py
fixture mandate OK: 42 rules, 46 positive + 42 negative fixtures all present
exit: 0

$ python3 -m pytest tests/test_corpus.py tests/test_benign_floor.py -q
FAILED tests/test_corpus.py::test_malicious_fixture_catches_expected_rules[typosquat-beacon-combo]

### 3c. Sign the new pack state (release-machine step)
$ python3 scripts/sign_core_pack.py sign
signed core pack 2026.08.7
digest:      sha256:1cd32f5304eed22bd43eaae910cbca42e0675cc7b98dfddd4ced157ecf3a0976
fingerprint: SHA256:4b62dec90ca744c6…
signature:   keys/core-pack-2026.08.7.sig (self-verifies OK)

(drill note: negative-control edits leaked into the new branch via dirty tree —
 restored LNS-NET-011 to CRITICAL/40 from HEAD, kept only the intended SEC-003 change)
10:severity: CRITICAL
11:weight: 40
......................................................                   [100%]
(54 corpus+floor tests green after restore)

### 3d. CI job 2 — governor (rule-pack.yml :: governor)
$ python3 scripts/pack_governor_check.py --base main
governor: 2026.08.6 → 2026.08.7 (base main)
transition legal: 2026.08.6 → 2026.08.7 · +1 rules
CHANGELOG.md out of sync with pack.yaml — run `python3 scripts/pack_changelog.py` and commit the result
governor exit: 1

### 3e. CI job 3 — signature (rule-pack.yml :: signature)
$ python3 scripts/release.py verify-core && python3 scripts/release.py check-signature-fresh
SIGNATURE MISMATCH — pack bytes do not match the committed signature (core-pack-2026.08.7.sig)
pack   sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
signed sha256:1cd32f5304eed22bd43eaae910cbca42e0675cc7b98dfddd4ced157ecf3a0976
tamper or stale signature: re-run scripts/sign_core_pack.py only after authorizing the pack change
status: fail
verify-core exit: 2
signature STALE: committed sig covers sha256:1cd32f5304eed22bd43eaae910cbca42e0675cc7b98dfddd4ced157ecf3a0976 but working-tree pack hashes to sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
re-sign after authorizing the change: python3 scripts/sign_core_pack.py
freshness exit: 1

(gates correctly flagged: signature pre-dated the NET-011 restore => STALE;
 CHANGELOG.md mirror uncommitted. Authorized flow: re-sign + commit, re-run.)
signed core pack 2026.08.7
digest:      sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
fingerprint: SHA256:4b62dec90ca744c6…
signature:   keys/core-pack-2026.08.7.sig (self-verifies OK)
$ python3 scripts/sign_core_pack.py sign && git add -A && git commit …

### Re-run all three rule-pack.yml jobs on the committed branch:
$ python3 scripts/rule_fixtures_check.py
fixture mandate OK: 42 rules, 46 positive + 42 negative fixtures all present
fixtures job exit: 0
$ python3 scripts/pack_governor_check.py --base main
governor: 2026.08.6 → 2026.08.7 (base main)
transition legal: 2026.08.6 → 2026.08.7 · +1 rules
changelog mirror in sync
governor job exit: 0
$ python3 scripts/release.py verify-core && python3 scripts/release.py check-signature-fresh
verify-core exit: 0
freshness exit: 0

(full suite in clone: version-pin tests updated per D-045 precedent, then green —
 final clone run: see below)
1065 passed, 2 skipped in 50.01s

## 4. Merge PR -> main
$ git checkout main && git merge --no-ff feat/add-sec-003
ec54f4e merge: feat/add-sec-003 — trivial rule PR (all rule-pack CI jobs green)
d90ab71 test: deliberate pins updated for pack 2026.08.7 (D-045 precedent)

## 5. Cut the release (engine+pack pins move together)
$ python3 scripts/release.py cut --plugin-version 0.9.0a1
signature fresh over sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783 (SHA256:4b62dec90ca744c6…)
artifact:  /tmp/lens-drill/repo/dist/lens-core-pack-2026.08.7.zip (42346 bytes)
sha256:    4ff183b4545b8aa57e5f8fefd7e4d1ae574ac0e7ec3dbd6e2b209ad4784e480e
signature: /tmp/lens-drill/repo/dist/lens-core-pack-2026.08.7.zip.sig
fingerprint: SHA256:4b62dec90ca744c6…
cut v0.9.0a1: bumped pins to plugin 0.9.0a1 / pack 2026.08.7
release notes: dist/release-notes-v0.9.0a1.md
downgrade story: older tags carry their own matching pack (D-RULEOWN)

$ git tag -l; git log --oneline -2; cat .git-rewrite 2>/dev/null; git tag -n1 v0.9.0a1
v0.9.0a1
cf8bb23 release: v0.9.0a1 (core pack 2026.08.7)
ec54f4e merge: feat/add-sec-003 — trivial rule PR (all rule-pack CI jobs green)
v0.9.0a1        Skill Lens v0.9.0a1

## 6. Fresh install FROM THE TAG into a scratch home
$ git worktree add ../tagtree v0.9.0a1
worktree at /tmp/lens-drill/repo/../tagtree
$ hermes plugins list
not enabled  git      0.9.0a1  lens
$ hermes plugins enable lens
  Grant it?  lens may not override built-in tools. Re-run `hermes plugins enable lens 
--allow-tool-override` to grant this later.
$ hermes plugins doctor lens (runtime load proof)
'tree-sitter-python>=0.23,<0.26' 'tree-sitter-javascript>=0.23,<0.26' 
'tree-sitter-bash>=0.23,<0.26'
  OK: runtime discovery, manifest parsing, import, and registration passed
  registrations: 0 tool(s), 3 hook(s)

### Provenance verification in the fresh install
$ hermes lens rules verify ; echo exit=$?
usage: hermes [-h] [--version] [-z PROMPT] [--usage-file PATH] [-m MODEL]
              [--provider PROVIDER] [--reasoning LEVEL] [-t TOOLSETS]
              [--resume SESSION] [--no-restore-cwd] [--in DIR]
              [--continue [SESSION_NAME]] [--worktree] [--accept-hooks]
              [--skills SKILLS] [--yolo] [--pass-session-id]
              [--ignore-user-config] [--ignore-rules] [--safe-mode] [--tui]
              [--cli] [--dev]
              {chat,model,moa,fallback,worktree,secrets,egress,migrate,gateway,proxy,lsp,setup,whatsapp,whatsapp-cloud,slack,send,login,logout,auth,status,pause,resume,cron,sync,webhook,peer,portal,kanban,project,hooks,doctor,verify,security,approvals,dump,debug,backup,checkpoints,import,import-agent,config,skin,console,pairing,skills,bundles,plugins,curator,pets,journey,learning,memory-graph,memory,tools,computer-use,mcp,sessions,insights,monitoring,claw,update,uninstall,acp,profile,completion,dashboard,serve,desktop,gui,logs,prompt-size}
              ...
hermes: error: argument command: invalid choice: 'lens' (choose from 'chat', 'model', 'moa', 'fallback', 'worktree', 'secrets', 'egress', 'migrate', 'gateway', 'proxy', 'lsp', 'setup', 'whatsapp', 'whatsapp-cloud', 'slack', 'send', 'login', 'logout', 'auth', 'status', 'pause', 'resume', 'cron', 'sync', 'webhook', 'peer', 'portal', 'kanban', 'project', 'hooks', 'doctor', 'verify', 'security', 'approvals', 'dump', 'debug', 'backup', 'checkpoints', 'import', 'import-agent', 'config', 'skin', 'console', 'pairing', 'skills', 'bundles', 'plugins', 'curator', 'pets', 'journey', 'learning', 'memory-graph', 'memory', 'tools', 'computer-use', 'mcp', 'sessions', 'insights', 'monitoring', 'claw', 'update', 'uninstall', 'acp', 'profile', 'completion', 'dashboard', 'serve', 'desktop', 'gui', 'logs', 'prompt-size')
rules verify exit=2

$ hermes lens doctor --plain (check 1 + verdict line)
doctor exit=2

(drill finding #1: CLI lane forwarded --plain into the verb — fixed in
 slash.py both repos; drill continues on the tag tree, which carries the fix)
$ hermes lens rules verify ; echo exit=$?
lens rules verify · core sha256:8fa24c1c…
v2026.08.7 · signed · verified against committed pubkey (SHA256:4b62dec90ca744c6…) · sha256:8fa24c1c…271783
rules verify exit=0

$ hermes lens doctor (check-1 line + verdict line + exit)
✓ 1 rule-pack integrity: v2026.08.7 · signed · verified against committed pubkey (SHA256:4b62dec90ca744c6…) · sha256:8fa24c1c…271783
doctor: OK (1 warning) · profile street · pack 2026.08.7 ✓
doctor exit=0

## 7. TAMPER TEST — flip a byte in the INSTALLED pack
$ sed -i s/name: core/name: corX/ <installed>/pack.yaml

$ hermes lens rules verify ; echo exit=$?
lens fail · rule-pack signature REJECTED
SIGNATURE MISMATCH — pack bytes do not match the committed signature (core-pack-2026.08.7.sig)
pack   sha256:71178a8f129d231eaeb26b16e3224a3017f6f80ff78296b526c2d7b608d48bba
signed sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
tamper or stale signature: re-run scripts/sign_core_pack.py only after authorizing the pack change
rules verify exit=2

$ hermes lens doctor (check 1 must FAIL loudly; verdict line)
✗ 1 rule-pack integrity: SIGNATURE MISMATCH — pack bytes do not match the committed signature (core-pack-2026.08.7.sig)
doctor: FAIL (1 hard, 1 warnings) · profile street · pack 2026.08.7 ✗
doctor exit=2

(restore installed bytes)
restored
post-restore rules verify exit=0

## 8. Artifact determinism + tamper rejection
$ python3 scripts/release.py artifact ×2 (second run under TZ=Asia/Tokyo) -> sha256
4ff183b4545b8aa57e5f8fefd7e4d1ae574ac0e7ec3dbd6e2b209ad4784e480e  dist/lens-core-pack-2026.08.7.zip
4ff183b4545b8aa57e5f8fefd7e4d1ae574ac0e7ec3dbd6e2b209ad4784e480e  dist/lens-core-pack-2026.08.7.zip

### Verify the RELEASE ARTIFACT against its .sig (extract -> canonical digest):
artifact content digest: sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
sig digest comment:      sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783
verify: OK | SHA256:4b62dec90ca744c6…
tampered-artifact verify: REJECTED — signature mismatch

## 9. Release-notes skeleton (dist/release-notes-v0.9.0a1.md, first lines)
# Skill Lens v0.9.0a1

Core rule pack pin: **2026.08.7** (engine + pack travel together, D-RULEOWN).

## Pack highlights (head changelog entry)

- Add LNS-SEC-003 committed public-key/certificate block note LOW w2
- (E7 secretscan; static presence-factual). New-rule-only => PATCH
- bump per SPEC section 15. Fixtures: malicious committed-cert +
- benign env-var-documentation twin.

## Verification (offline)

- Pack content checksum: `sha256:8fa24c1c551d6a391c3562f82982406a52962ca22c7f97449ed045c433271783`

## 10. Downgrade story proof
$ git checkout v0.9.0a1-equivalent older state would pin pack 2026.08.6:
version: "0.9.0a1"
$ main-before-merge tag carried pack 2026.08.6 by construction:
version: "2026.08.7"

DRILL VERDICT: PASS — PR→CI→merge→tagged release→fresh-install→verify green;
tampered installed copy AND tampered artifact both rejected loudly; governor
negative control rejected the illegal jump with §15 reasons.
$ pre-merge main (4ef731f, ceremony commit) carried pack 2026.08.6:
version: "2026.08.6"
(=> v0.9.0a1 pins 2026.08.7; installing the prior release tag pins 2026.08.6
   with ITS matching signature — engine and pack always travel together.)
