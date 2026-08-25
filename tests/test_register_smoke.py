"""Phase 0 register() smoke tests — the advisor contract, verified.

Loads the repo-root plugin package exactly the way the host does
(``hermes_plugins.<slug>`` with ``submodule_search_locations``) and asserts:

- ``register(fake_ctx)`` does not raise and stores a defensive view;
- zero ``pre_tool_call`` hooks are ever registered (advisor law);
- every hook we declare in plugin.yaml is within host VALID_HOOKS;
- the manifest is a well-formed v2 manifest over known fields only;
- the PluginContextView seams behave against FakePluginContext.
"""

from __future__ import annotations

import importlib
import logging
import sys
import types
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

#: The repo root (parent of tests/) — computed locally, never imported.
REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PROVIDES_HOOKS = ("on_skill_lifecycle", "post_tool_call", "transform_tool_result")

PluginModule = types.ModuleType


def _skill_lens_version() -> str:
    """Import skill_lens dynamically from the repo root (no static edge)."""
    return str(_skill_lens_package().__version__)


def _skill_lens_package() -> types.ModuleType:
    """The top-level ``skill_lens`` package, imported from the repo root."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("skill_lens")


@pytest.fixture
def manifest_data() -> dict[str, Any]:
    return yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# register() contract
# ---------------------------------------------------------------------------


def test_register_does_not_raise(fake_ctx: Any, plugin_module: PluginModule) -> None:
    plugin_module.register(fake_ctx)  # must not raise, ever
    view = plugin_module.skill_lens.bootstrap.get_context()
    assert view is not None
    assert view.plugin_id() == "lens"


def test_register_survives_malformed_context(
    plugin_module: PluginModule, caplog: pytest.LogCaptureFixture
) -> None:
    """register(hostile ctx) must swallow everything AND log it (advisor law).

    A silently-no-op register would be indistinguishable from a crash-free
    success; we pin that the hostile seam failure surfaces in the ``lens``
    log, no ``pre_tool_call`` registration is ever ATTEMPTED, and the
    defensive view is still installed (present-but-inert plugin).
    """
    module = plugin_module

    class Boom:
        def __init__(self) -> None:
            self.hook_attempts: list[str] = []

        @property
        def state(self) -> Any:
            raise RuntimeError("host context is hostile")

        def get_config(self, key: str, default: Any = None) -> Any:
            raise RuntimeError("no")

        def register_hook(self, hook_name: str, callback: Any) -> Any:
            self.hook_attempts.append(hook_name)
            raise RuntimeError("no registrations today")

        def register_command(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("no registrations today")

    boom = Boom()
    with caplog.at_level(logging.WARNING, logger="lens"):
        module.register(boom)  # no exception may escape...

    # ...and the swallowed failure is logged, never silently ignored.
    messages = [record.getMessage() for record in caplog.records]
    assert any("register_command" in message and "failed" in message for message in messages), (
        f"hostile-seam failure not logged; got: {messages}"
    )

    # Advisor law holds even against a hostile host: zero blocking-hook
    # attempts, and the defensive view is still installed for later phases.
    assert "pre_tool_call" not in boom.hook_attempts
    view = module.skill_lens.bootstrap.get_context()
    assert view is not None  # present-but-inert, not vanished


def test_zero_pre_tool_call_registrations(fake_ctx: Any, plugin_module: PluginModule) -> None:
    plugin_module.register(fake_ctx)
    assert fake_ctx.registered_hook_names.count("pre_tool_call") == 0


def test_registered_hooks_within_host_valid_hooks(
    fake_ctx: Any,
    plugin_module: PluginModule,
    host_hooks: frozenset[str],
) -> None:
    plugin_module.register(fake_ctx)
    assert set(fake_ctx.registered_hook_names) <= host_hooks


# ---------------------------------------------------------------------------
# Manifest contract
# ---------------------------------------------------------------------------


def test_manifest_is_v2_with_pinned_api_version(manifest_data: dict[str, Any]) -> None:
    assert manifest_data["manifest_version"] == 2
    assert isinstance(manifest_data["api_version"], int)
    assert isinstance(manifest_data["version"], str) and manifest_data["version"]
    assert manifest_data["name"] == "lens"  # registry key drives enable/config namespaces


def test_manifest_provides_hooks_exact(manifest_data: dict[str, Any]) -> None:
    hooks = tuple(manifest_data["provides_hooks"])
    assert sorted(hooks) == sorted(EXPECTED_PROVIDES_HOOKS)


def test_manifest_provides_hooks_are_valid(
    manifest_data: dict[str, Any], host_hooks: frozenset[str]
) -> None:
    assert set(manifest_data["provides_hooks"]) <= host_hooks


def test_manifest_uses_only_known_fields(
    manifest_data: dict[str, Any], host_plugins_module: Any
) -> None:
    if host_plugins_module is None:  # pragma: no cover — host tree absent
        pytest.skip("hermes_cli.plugins not importable; known-field census unavailable")
    known = host_plugins_module._KNOWN_MANIFEST_FIELDS
    unknown = sorted(set(manifest_data) - known)
    assert not unknown, f"manifest ships fields unknown to this host: {unknown}"


# ---------------------------------------------------------------------------
# Version consistency across artifacts
# ---------------------------------------------------------------------------


def test_versions_agree(manifest_data: dict[str, Any]) -> None:
    version = _skill_lens_version()
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert manifest_data["version"] == version
    assert f'version = "{version}"' in pyproject_text


# ---------------------------------------------------------------------------
# PluginContextView seams against the fake
# ---------------------------------------------------------------------------


def test_plugin_data_dir_lives_under_tmp(
    fake_ctx: Any, plugin_module: PluginModule, tmp_path: Path
) -> None:
    plugin_module.register(fake_ctx)
    view = plugin_module.skill_lens.bootstrap.get_context()
    data_dir = Path(str(view.plugin_data_dir()))
    assert data_dir.is_dir()
    assert tmp_path in data_dir.parents or data_dir.is_relative_to(tmp_path)


def test_get_config_roundtrip_and_default(fake_ctx: Any, plugin_module: PluginModule) -> None:
    plugin_module.register(fake_ctx)
    view = plugin_module.skill_lens.bootstrap.get_context()
    assert view.get_config("missing.key", "fallback") == "fallback"
    fake_ctx.set_config("watch.poll", False)  # host set_config returns None
    assert view.get_config("watch.poll") is False


def test_view_registration_methods_degrade_safely(plugin_module: PluginModule) -> None:
    """A ctx missing all seams logs and returns defaults instead of raising."""

    class Bare:
        pass

    context_mod = importlib.import_module("skill_lens.context")
    view = context_mod.PluginContextView(Bare())
    assert view.plugin_id() == "lens"
    assert view.register_hook("post_tool_call", lambda **kw: None) is None
    assert view.register_command("lens", lambda raw: None) is None
    assert view.get_config("profile", "street") == "street"
    assert view.set_config("profile", "lab") is False


def test_reset_context_between_tests(plugin_module: PluginModule) -> None:
    del plugin_module  # fixture still proves the module loads cleanly
    bootstrap = importlib.import_module("skill_lens.bootstrap")
    bootstrap.reset_context()
    assert bootstrap.get_context() is None
