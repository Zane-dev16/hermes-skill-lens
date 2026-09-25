# Notes

## Development

Tests and lint run from the repo root:

```bash
python3 -m pytest -q
python3 -m ruff check .
```

Iterate against a throwaway home so the real `~/.hermes` stays untouched:

```bash
export HERMES_HOME=/tmp/lens-dev
mkdir -p $HERMES_HOME/plugins
ln -s "$PWD" $HERMES_HOME/plugins/lens
hermes plugins enable lens
hermes plugins doctor lens
```

## Rule packs

The core pack ships signed and version-pinned with the plugin. Updates are manual. Community packs stay opt-in and SHA-pinned through `.lens/packs.toml`.

```bash
hermes lens rules verify
```
