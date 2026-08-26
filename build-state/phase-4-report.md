# Phase 4 Gate Report — triggers, async UX, watcher, hub view, doctor

**Auditor:** Phase 4 gate audit & commit (independent re-run of PLAN §1 Phase-4 exit criteria)
**Date:** 2026-08-26 · **Repo:** hermes-skill-lens · **Rule pack:** `core` `2026.08.6`
**Scope audited:** all Phase 4 deliverables landed uncommitted by five build tasks plus the
fixer pass — trigger wiring (D-triggers), async delivered-results UX + hub quarantine view
(D-051), drift watcher (D-052), host-launch import blocker fix (D-053), doctor. This audit
re-executed every exit criterion itself before committing anything.

## Verdict: **PASS — 6/6 exit criteria** · One auditor fix landed pre-commit

Authoritative gates at the audited tree, re-run by the auditor:
**pytest 1030 passed, 0 failed/skipped-error**, **ruff clean** (`ruff check .` → "All checks
passed!"), **vectors A–G byte-exact** (`tests/test_vectors_golden.py`: 14 passed),
import-contract suite green (layout-law static scan + subprocess host-layout probe).

One gap found and fixed during the audit: the `hermes lens` argparse grammar (CLI lane) was
missing the `hub` and `watch` subcommands that D-051/D-052 added to the shared slash dispatch
— live host run `hermes lens watch status` failed with `invalid choice`. Fixed in
`skill_lens/cli.py` (`setup_parser` + `_tokens_for` reconstruction branches routed into the
same shared dispatch) and pinned with two parser-parity tests; live re-verified after the fix.

---

## Criterion (a) — Real `hermes skills install` completes normally, installer untouched ✅

Executed against a **fresh scratch home** `/tmp/lens-gate` with the repo symlinked as the
user plugin and **Lens enabled** (`hermes plugins enable lens`; auto-declined
`--allow-tool-override`, advisor law held). A benign fixture skill
(`remember-all-notes`) was served over loopback HTTP and installed through the REAL CLI:

```
hermes skills install http://127.0.0.1:8399/SKILL.md --yes
→ Quarantined to .hub/quarantine/remember-all-notes → skills_guard scan SAFE
→ Decision: ALLOWED → Installed: remember-all-notes      [real time 13.7 s]
```

Installer path untouched by construction and by observation: `do_install` fires NO plugin
hooks (host ground truth, `docs/host-contract.md` §5 — zero `invoke_hook` calls in
`tools/skills_hub.py`), Lens registered zero blocking hooks, and the install transcript shows
no Lens interference. Post-install state verified: `skills/remember-all-notes/SKILL.md`
present, quarantine drained, `.hub/lock.json` provenance written (url source · community ·
scan safe · content hash).

## Criterion (b) — ≤200 ms cached line / silent queue + `/lens` surfacing ✅

Live one-process probe under a host-style plugin load (`hermes_plugins.lens_gate`,
mirroring `PluginManager._load_directory_module`) bound to the real scratch home:

1. Verbatim `installed` lifecycle emit (exact `skill_usage.py:829-840` kwargs incl.
   injected `telemetry_schema_version`) → cold miss ⇒ **silent queue, returned `None` in
   17.3 ms** (advisor stance; format-B line mirrored to `events.ndjson`).
2. Worker delivered in-process: job `ready`.
3. Second emit (`used`) answered **inline from the fast-path cache in 4.7 ms < 200 ms**
   (budget asserted in the probe; perf harness p95 cached 4.0 ms stands).
4. Registered CLI handler surfaced the full report from cache:
   `hermes lens report remember-all-notes` → grade A 99/100 clean · 1 low, exit 0.

Cross-process surfacing also verified live: after the real install, a NEW session's startup
sweep replayed the while-away gap exactly once (see (d)), queued silently, delivered, and the
format-A line `lens ok remember-all-notes · A 99/100 · clean · 1 low · /lens report` is
mirrored in `events.ndjson` (§11.5 pull lane verbatim; H13 worker-print limitation documented
in `docs/limitations.md` L1).

## Criterion (c) — Doctor catches deliberately broken + deliberately-blocking wirings ✅

Run verbosely (`pytest tests/test_doctor.py -v -k "negative or malformed or corrupt"` — 8 passed):

```
test_check2_malformed_policy_file_fails_hard PASSED
test_check4_corrupt_hub_lock_is_a_problem PASSED
test_negative_unwritable_plugin_data_dir_fails_check3_loudly PASSED
test_negative_corrupt_jobs_json_fails_check3_loudly PASSED
test_negative_job_quota_breach_fails_check3 PASSED
test_negative_blocking_wiring_injection_fails_check5_loudly PASSED   ← pre_tool_call = loud FAIL
test_negative_unknown_hook_outside_valid_hooks_fails_audit PASSED
test_negative_isolation_guard_trips_on_socket_use PASSED
```

All nine checks present, ordered per SPEC §11.9, and rendered on both lanes — verified LIVE
via `hermes lens doctor`: pack v2026.08.6 + sha256, policy sources, data dirs, environment,
wiring audit vs live host `VALID_HOOKS`, socket-deny network self-test, lifecycle canary,
parse health (honest AST-degraded WARN), render sanity; verdict line last; results mirrored
to `events.ndjson`.

## Criterion (d) — Watcher survives churn; replays restart drift exactly once ✅

Tests run verbosely (`tests/test_watcher.py -v -k "churn or restart or replay or rename or
storm or real_thread"` — 11 passed): create/rename(=delete+create)/delete storms converge to
one settled diff per bundle; persisted-hash compare replays the while-away gap EXACTLY ONCE
across a simulated restart (`test_drift_replays_exactly_once_across_restart`); the
`replayed:true` marker blocks replay even when hash persist fails; real-thread end-to-end
churn detection green.

Live spot-check in the scratch home: edited `SKILL.md` → next session's sweep detected the
drift, enqueued **one** scan (new hash `0c6bf3a3…`, queued→started→ready in events.ndjson);
a subsequent register (`hermes lens doctor`) added **zero** re-scans — exactly-once holds
across real process restarts. `hermes lens watch status` reports polling off (opt-in) ·
inotify-accelerated · tracking 1 skills.

## Criterion (e) — Agent-created skill write triggers post_tool_call path ✅

Host-contract tests replay VERBATIM emit-site shapes (`tests/test_triggers.py`; shapes
transcribed in `docs/host-contract.md` §2/§3 from `model_tools.py:1172-1187` /
`:1563-1577`, including `telemetry_schema_version` injection): self-filter to
`skill_manage` returns instantly for other tools; mutating actions (create/edit/patch/
write_file/remove_file) enqueue; non-mutating (delete/read) ignored; error-status payloads
still scan current bytes; transform lane appends ONE sober ≤160-char notice preserving the
result bytes, kill-switched by `notify:false`, idempotent while pending; hostile/truncated
payloads never raise; handlers return None-or-str only; zero `pre_tool_call` registrations
after double register. Full batch green verbosely (60+ parametrized cases).

## Criterion (f) — Suite/ruff/vectors green; nine doctor checks rendered ✅

```
python3 -m pytest --tb=short  →  1030 passed        ruff check .  →  All checks passed!
tests/test_vectors_golden.py  →  14 passed (A–G byte-exact)
tests/test_import_contract.py →  layout law + privacy proofs green
```

---

## Commits (landed after this report)

Atomic conventional commits, identity Irell Zane <itsirellzane@gmail.com> (verified via
`git config` + `git log`), pushed to origin main:

1. `refactor(core)` — relative intra-package imports across engines/pipeline modules (D-053 law)
2. `feat(triggers)` — observer trigger lanes + fast path + host-contract docs
3. `feat(watcher)` — drift watcher + startup sweep
4. `feat(hub)` — quarantine review view
5. `feat(doctor)` — nine-check self-diagnostic
6. `feat(bootstrap)` — wire observer hooks + startup sweep; slash/cli verb glue; layout-law regression tests; CLI parity for hub/watch
7. `docs(build)` — this report + STATUS ledger + D-054
