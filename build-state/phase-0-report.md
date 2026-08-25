# Phase 0 Gate Report — Hermes Skill Lens v0.9

Auditor: Phase 0 gate audit & commit run (independent re-run of all exit criteria).
Date: 2026-08-25. Exit criteria source: `PLAN.md` §1 Phase 0 **Exit** (lines 65–67).

**GATE VERDICT: PASS (4/4 criteria).**

---

## Criterion (a) — Real-home scan is byte-identical twice — **PASS**

Command (two separate processes, real home, no shared state):

```bash
python3 - <<'EOF'   # run twice
from pathlib import Path
from skill_lens.canonical import canonical_dumps
from skill_lens.inventory import scan_inventory
env = scan_inventory(Path.home() / ".hermes")
Path("runN.json").write_text(canonical_dumps(env), encoding="utf-8")
EOF
sha256sum run1.json run2.json && cmp run1.json run2.json
```

Result:

```
e6e630597600ed0bf8100de3cf7f8a0ca0d0ae9b7a3e89c3b138a1bfb6933a72  run1.json
e6e630597600ed0bf8100de3cf7f8a0ca0d0ae9b7a3e89c3b138a1bfb6933a72  run2.json
BYTE-IDENTICAL: YES        (cmp silent; identical hashes)
```

Scope: 95 bundles discovered under the real `~/.hermes/skills` tree; exactly one
discovery diagnostic (`LNS-PROV-LOCK`, severity=info — hub lockfile absent,
provenance not enriched; expected on this machine, degrade-not-fail behavior).
Also enforced permanently by `tests/test_snapshot_golden.py::test_scan_inventory_is_byte_identical_across_runs`.

## Criterion (b) — Scratch-home load/enable/disable loop — **PASS**

Setup:

```bash
HERMES_HOME=/tmp/lens-dev
cp -r {plugin.yaml,__init__.py,skill_lens} /tmp/lens-dev/plugins/lens/
```

Enable/disable via the real host CLI:

```
$ hermes plugins enable lens --no-allow-tool-override
✓ Plugin lens enabled. Takes effect on next session.
$ hermes plugins list          → lens │ enabled │ 0.9.0a0 │ Skill Lens … │ user
config.yaml: plugins.enabled=[lens]; entries.lens.allow_tool_override=false
$ hermes plugins disable lens
⊘ Plugin lens disabled. Takes effect on next session.
```

Load proof under the REAL `PluginManager` (not a fake), `HERMES_HOME=/tmp/lens-dev`:

| State | Evidence |
| --- | --- |
| enabled | `LoadedPlugin.enabled=True`, `module` loaded, host log `INFO lens: Skill Lens 0.9.0a0 registered (advisor mode; zero blocking hooks)`; manifest parsed with key=`lens`, deps satisfied (`PyYAML`) |
| disabled | `LoadedPlugin.enabled=False`, `error='disabled via config'`, `module=None` — register() never invoked (tombstone kept for reporting); discovery summary counts it out ("56 found, 49 enabled") |

Notes: zero hooks/commands registered is the DESIGNED Phase 0 spine state
(`__init__.py`: "Phase 0 spine: zero hook registrations; triggers land in a later
phase"); `provides_hooks` remains declaration-only per D-005/host contract. The
host prompts interactively about `allow_tool_override` for user plugins unless
`--no-allow-tool-override` / `--allow-tool-override` is passed — automation must
pass the flag explicitly.

## Criterion (c) — Quarantine dir vanishing mid-walk degrades to logged skip — **PASS**

Test exists: `tests/test_ingest_edges.py:41`
`test_quarantine_dir_vanishing_mid_walk_degrades_to_skip` — docstring literally
cites "PHASE 0 EXIT CRITERION"; simulates an external rmtree landing after the
discovery snapshot and asserts logged skip diagnostics + surviving bundles intact.
Sibling test at :83 covers a bundle *subdir* vanishing mid-walk (partial IR +
diagnostic, no crash).

Run:

```
$ python3 -m pytest -q tests/test_ingest_edges.py -k vanish -v
1 passed, 28 deselected in 0.16s
```

## Criterion (d) — pytest + ruff green — **PASS**

```
python3 -m pytest -q      → ........ [100%] 80 passed (exit 0)
ruff check .              → All checks passed! (exit 0)
```

---

## Artifacts cut (Phase 0)

| File | Role |
| --- | --- |
| `plugin.yaml` | Manifest v2, known fields only; name/key `lens`; provides_hooks = {on_skill_lifecycle, post_tool_call, transform_tool_result} |
| `__init__.py` | Host entry point `register(ctx)` — fully exception-contained, lazy relative import |
| `skill_lens/__init__.py` | Package root, `__version__="0.9.0a0"` |
| `skill_lens/context.py` | `PluginContextView` defensive wrapper over host seams (D-006) |
| `skill_lens/bootstrap.py` | `register_plugin()` wiring (advisor mode) |
| `skill_lens/diagnostics.py` | Structured diagnostics collector |
| `skill_lens/canonical.py` | Canonical JSON byte form (D-007) |
| `skill_lens/ir.py` | SkillIR `ir/1` frozen dataclasses + canonical_dict (D-008, D-010) |
| `skill_lens/ingest.py` | Discovery (categorized + quarantine corridor, zip targets), tolerant frontmatter, git-URL guard `LNS-ING-NET` (D-011) |
| `skill_lens/inventory.py` | Whole-tree deterministic inventory + dogfood CLI (`python3 -m skill_lens.inventory`) |
| `pyproject.toml` | Packaging metadata, ruff/pytest config |
| `README.md`, `docs/dev-loop.md` | Quickstart + scratch-home dev loop |
| `.github/workflows/ci.yml` | CI scaffold |
| `tests/` | 80 tests across 6 modules (+ conftest fakes of host PluginContext) |

## Observations / escalations

No open questions block Phase 0; all unpinned choices are pinned in DECISIONS
D-005..D-011. Minor observations recorded for later phases:
host emits a cosmetic `capability_check tools.override decision=deny` INFO line on
every user-plugin load (host-side, not actionable by us); real home has no
`.hub/lock.json`, so provenance enrichment is untested against live hub data until
the hub lane runs (fixture-covered only).
