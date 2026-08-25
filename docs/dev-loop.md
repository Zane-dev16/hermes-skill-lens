# Skill Lens dev loop — scratch HERMES_HOME

Daily loop per PLAN §1 Phase 0 ("Scratch `HERMES_HOME` test loop"): load → enable →
unload the plugin against a throwaway home, never touching the real `~/.hermes`.

Verified working 2026-08-25 against Hermes 0.20.x (`hermes_cli/plugins.py` in
`/usr/local/lib/hermes-agent`). Both lanes below load **this repo in place via a
symlink** — no copy, edits are live.

## Lane A (primary): user plugins + scratch home

The user lane scans `$HERMES_HOME/plugins/<name>/`; a symlink makes our repo the
plugin dir. Registry key = directory name = manifest `name` = `lens`.

```bash
export HERMES_HOME=/tmp/lens-dev            # throwaway home
mkdir -p $HERMES_HOME/plugins
ln -s /root/hermes-skill-lens/hermes-skill-lens $HERMES_HOME/plugins/lens

hermes plugins list                          # discover: 'lens' appears
hermes plugins enable lens                   # writes plugins.enabled: [lens] to $HERMES_HOME/config.yaml
hermes plugins doctor lens                   # REAL runtime proof:
#   OK: runtime discovery, manifest parsing, import, and registration passed
#   registrations: 0 tool(s), 0 hook(s)
#   (WARN "declares hook ... but registration did not add it" is EXPECTED in
#    Phase 0 — triggers are wired in Phase 4.)

hermes plugins disable lens                  # unload cleanly (next session)
hermes plugins enable lens                   # re-enable for iteration
```

Notes:

- `enable` auto-declines `--allow-tool-override` — keep it that way (advisor law).
- `doctor` validates at the discovered path regardless of enabled state; its
  "runtime ... import and registration" line is the load proof.
- To watch discovery verbosely: prefix commands with `HERMES_PLUGINS_DEBUG=1`.
- Reset everything: `rm -rf /tmp/lens-dev` and recreate from the snippet above.

## Lane B (repo-local): project plugins

Scans `<cwd>/.hermes/plugins/`, opt-in via env var. Useful when iterating from an
arbitrary working directory without touching any `$HERMES_HOME`:

```bash
mkdir -p /tmp/lens-proj/.hermes/plugins
ln -s /root/hermes-skill-lens/hermes-skill-lens /tmp/lens-proj/.hermes/plugins/lens
cd /tmp/lens-proj
export HERMES_ENABLE_PROJECT_PLUGINS=1 HERMES_HOME=/tmp/lens-dev
hermes plugins list --plain --no-bundled     # -> enabled  git  0.9.0a0  lens
```

## Host facts these commands rely on

- Flat-plugin registry key == manifest `name` (`PluginManager._parse_manifest`);
  key drives `plugins.enabled`, `plugins.entries.lens.settings.*`, data-dir ns.
- Directory plugins import as `hermes_plugins.<slug>` with the plugin dir as
  package path → root `__init__.py` uses relative imports only
  (`from .skill_lens.bootstrap import ...`).
- Durable state seam is `ctx.state.data_dir` → `<HERMES_HOME>/plugin-data/lens/`.
- `register(ctx)` failures must never escape; `doctor` surfaces them loudly.
