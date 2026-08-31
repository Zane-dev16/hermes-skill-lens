"""Shared test fixtures for the Skill Lens suite.

Provides:

- ``FakePluginContext`` — a fake of the host ``PluginContext`` implementing
  exactly the seams Skill Lens uses (ground truth:
  ``hermes_cli/plugins.py``): register_hook / register_command /
  register_cli_command record their calls; get_config/set_config read and
  write a settings dict; the durable-state facade exposes a data_dir under
  tmp_path.
- ``host_valid_hooks()`` — the REAL ``VALID_HOOKS`` from hermes_cli.plugins
  when importable (system install at /usr/local/lib/hermes-agent), else the
  cited fallback literal in ``tests/fixtures/host_hooks.py``.
- ``plugin_module`` — loads the repo-root plugin package exactly the way the
  host does (importlib spec with ``submodule_search_locations``, namespace
  parent ``hermes_plugins``), mirroring PluginManager._load_directory_module.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Candidate locations of the hermes-agent source tree on this machine.
_HERMES_SOURCE_CANDIDATES = (
    "/usr/local/lib/hermes-agent",
    str(Path.home() / "hermes-agent"),
)


# ---------------------------------------------------------------------------
# Host module access
# ---------------------------------------------------------------------------


def load_host_plugins_module() -> types.ModuleType | None:
    """Import the real ``hermes_cli.plugins`` if possible, else None.

    Tries a plain import first; falls back to adding the known system source
    tree to sys.path. Never raises.
    """
    # importlib.import_module keeps this a dynamic probe: the host tree is an
    # optional runtime dependency of the suite, never a hard import edge.
    try:
        return importlib.import_module("hermes_cli.plugins")
    except ImportError:
        pass
    for candidate in _HERMES_SOURCE_CANDIDATES:
        if not Path(candidate).is_dir():
            continue
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
        try:
            return importlib.import_module("hermes_cli.plugins")
        except Exception:  # noqa: BLE001 — best effort only.
            continue
    return None


def host_valid_hooks() -> frozenset[str]:
    """REAL host VALID_HOOKS, or the cited fallback literal."""
    mod = load_host_plugins_module()
    if mod is not None and hasattr(mod, "VALID_HOOKS"):
        return frozenset(mod.VALID_HOOKS)
    from tests.fixtures.host_hooks import FALLBACK_VALID_HOOKS

    return FALLBACK_VALID_HOOKS


@pytest.fixture(scope="session")
def host_hooks() -> frozenset[str]:
    return host_valid_hooks()


@pytest.fixture(scope="session")
def host_plugins_module() -> types.ModuleType | None:
    return load_host_plugins_module()


# ---------------------------------------------------------------------------
# FakePluginContext
# ---------------------------------------------------------------------------


class _FakeManifest:
    """Just enough of PluginManifest for identity checks."""

    def __init__(self) -> None:
        self.key = "lens"
        self.name = "lens"
        self.version = "0.9.0a0"


class _FakePluginState:
    """Mimics hermes_cli/plugins.py PluginState.data_dir."""

    def __init__(self, root: Path) -> None:
        self._root = root

    @property
    def data_dir(self) -> Path:
        path = self._root / "plugin-data" / "lens"
        path.mkdir(parents=True, exist_ok=True)
        return path


class FakePluginContext:
    """Fake of the host PluginContext covering the seams Skill Lens uses.

    Records every registration so tests can assert the advisor contract
    (zero blocking hooks, hooks within VALID_HOOKS).
    """

    def __init__(
        self,
        data_root: Path,
        settings: dict[str, Any] | None = None,
    ) -> None:
        self.manifest = _FakeManifest()
        self.plugin_id = "lens"
        self._settings: dict[str, Any] = dict(settings or {})
        self.registered_hooks: list[tuple[str, Callable[..., Any]]] = []
        self.commands: dict[str, dict[str, Any]] = {}
        self.cli_commands: dict[str, dict[str, Any]] = {}
        self._state = _FakePluginState(data_root)
        self._llm: Any | None = None
        self._llm_present = False

    @property
    def llm(self) -> Any | None:  # type: ignore[no-redef]
        if not self._llm_present:
            raise AttributeError("llm")
        return self._llm

    @llm.setter
    def llm(self, value: Any | None) -> None:
        self._llm = value
        self._llm_present = True

    @llm.deleter
    def llm(self) -> None:
        self._llm = None
        self._llm_present = False

    # -- hook/command seams ----------------------------------------------------

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> object:
        self.registered_hook_names.append(hook_name)
        self.registered_hooks.append((hook_name, callback))
        return object()

    def register_command(
        self,
        name: str,
        handler: Callable[[str], str | None],
        description: str = "",
        args_hint: str = "",
    ) -> object:
        self.commands[name] = {
            "handler": handler,
            "description": description,
            "args_hint": args_hint,
        }
        return object()

    def register_cli_command(
        self,
        name: str,
        help: str,  # noqa: A002 — matches the real host signature.
        setup_fn: Callable[[Any], None],
        handler_fn: Callable[..., Any] | None = None,
        description: str = "",
    ) -> object:
        self.cli_commands[name] = {
            "help": help,
            "setup_fn": setup_fn,
            "handler_fn": handler_fn,
            "description": description,
        }
        return object()

    # -- config seam -------------------------------------------------------------

    def get_config(self, key: str, default: Any = None) -> Any:
        node: Any = self._settings
        for segment in key.split("."):
            if isinstance(node, dict) and segment in node:
                node = node[segment]
            else:
                return default
        return node

    def set_config(self, key: str, value: Any) -> None:
        segments = key.split(".")
        node = self._settings
        for segment in segments[:-1]:
            child = node.get(segment)
            if not isinstance(child, dict):
                child = {}
                node[segment] = child
            node = child
        node[segments[-1]] = value

    # -- state seam ----------------------------------------------------------------

    @property
    def state(self) -> _FakePluginState:
        return self._state

    # -- inspection helpers ------------------------------------------------------

    @property
    def registered_hook_names(self) -> list[str]:
        return [name for name, _callback in self.registered_hooks]


@pytest.fixture
def fake_ctx(tmp_path: Path) -> FakePluginContext:
    return FakePluginContext(data_root=tmp_path)


@pytest.fixture
def plugin_module(request: pytest.FixtureRequest) -> types.ModuleType:
    """Load the repo-root plugin package exactly like the host does.

    Mirrors PluginManager._load_directory_module: synthetic namespace parent
    ``hermes_plugins``, slug-derived module name, submodule_search_locations
    pointing at the plugin dir. Returns the executed module exposing
    ``register(ctx)``.
    """
    ns_name = "hermes_plugins"
    if ns_name not in sys.modules:
        ns_pkg = types.ModuleType(ns_name)
        ns_pkg.__path__ = []  # type: ignore[attr-defined]
        ns_pkg.__package__ = ns_name
        sys.modules[ns_name] = ns_pkg

    module_name = f"{ns_name}.lens_test_spine"
    stale_prefix = f"{module_name}."
    for stale in [n for n in sys.modules if n == module_name or n.startswith(stale_prefix)]:
        del sys.modules[stale]

    init_file = REPO_ROOT / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        module_name,
        init_file,
        submodule_search_locations=[str(REPO_ROOT)],
    )
    assert spec is not None and spec.loader is not None, (
        "cannot create import spec for plugin __init__.py"
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = module_name
    module.__path__ = [str(REPO_ROOT)]  # type: ignore[attr-defined]
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        for stale in [n for n in sys.modules if n == module_name or n.startswith(stale_prefix)]:
            del sys.modules[stale]
        raise

    def _evict() -> None:
        """Cleanup so later tests re-import fresh."""
        for stale in [
            n for n in list(sys.modules) if n == module_name or n.startswith(stale_prefix)
        ]:
            del sys.modules[stale]

    request.addfinalizer(_evict)
    return module


# Make ``tests.fixtures.host_hooks`` importable regardless of invocation cwd.
sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# SkillIR sample factory (ir / canonical tests)
# ---------------------------------------------------------------------------


def make_sample_ir(**overrides: Any):
    """Build a representative Phase 0 SkillIR for tests.

    Uses only $HERMES_HOME-normalized, bundle-relative paths so the
    deterministic payload stays free of absolute host paths. Keyword
    overrides replace top-level SkillIR fields wholesale.
    """
    from skill_lens.diagnostics import DiagnosticsCollector
    from skill_lens.ir import (
        BundleIdentity,
        DecodedView,
        FileRecord,
        HermesMetadata,
        Provenance,
        ResolvedFrontmatter,
        SkillIR,
    )

    defaults: dict[str, Any] = {
        "identity": BundleIdentity(
            name="web-design-guidelines",
            category="tools",
            path="~/.hermes/skills/tools/web-design-guidelines",
            layout="categorized",
        ),
        "source_kind": "dir",
        "bundle_hash": "sha256:" + "ab" * 32,
        "files": (
            FileRecord(
                path="scripts/sync.sh",
                size=1042,
                sha256="sha256:" + "cd" * 32,
                encoding="utf-8",
                role="script",
                language="bash",
                decode_layers=("raw",),
            ),
            FileRecord(
                path="SKILL.md",
                size=38912,
                sha256="sha256:" + "ef" * 32,
                encoding="utf-8-sig",
                role="doc",
                decode_layers=("raw",),
            ),
        ),
        "provenance": Provenance(
            source_class="installed",
            identifier="@vercel-labs/agent-skills",
            trust_level="trusted",
            resolved_from="hub_lock",
            install_path="~/.hermes/skills/tools/web-design-guidelines",
        ),
        "frontmatter": ResolvedFrontmatter(
            name="web-design-guidelines",
            description_raw="Ship accessible interfaces.",
            allowed_tools=("read_file", "bash"),
            compatibility="Hermes >= 0.20",
            vendor_fields={"disable-model-invocation": False},
            hermes=HermesMetadata(
                tags=("design",),
                related_skills=(),
                category="tools",
                requires_toolsets=(),
                fallback_for_toolsets=(),
                requires_tools=("read_file",),
                fallback_for_tools=(),
                config={},
            ),
            unknown_fields={"future-unknown-key": {"nested": [1, 2]}},
        ),
        "claims": (),
        "decoded_views": (
            DecodedView(file="SKILL.md", view="ghost_text", hidden_codepoint_count=3),
        ),
        "notes": ("partial_analysis: assets/big.bin projected to first 16 MiB",),
        "diagnostics": DiagnosticsCollector(),
    }
    defaults.update(overrides)
    return SkillIR(**defaults)


@pytest.fixture()
def sample_ir_factory():
    return make_sample_ir
