"""Phase 5 — ``rules verify`` verb wiring on both surfaces (§15 / §18).

Pins: the slash lane renders pass/warn/fail lanes from ONE shared engine
(packsec.verify_core_signature); the CLI grammar reconstructs canonical
tokens into the same dispatch; exit codes follow §18 (verified/warn ⇒ 0,
rejected signature ⇒ 2 total error); usage/help stays fenced and sober.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from skill_lens.cache import FastPathCache
from skill_lens.cli import _tokens_for
from skill_lens.cli import setup_parser as cli_setup_parser
from skill_lens.context import PluginContextView
from skill_lens.slash import dispatch_verb, shared_cache


def _view(tmp_path: Path) -> PluginContextView:
    from tests.conftest import FakePluginContext

    return PluginContextView(FakePluginContext(data_root=tmp_path))


@pytest.fixture
def cache() -> FastPathCache:
    return shared_cache()


def _keys_present() -> bool:
    return (Path(__file__).resolve().parents[1] / "keys" / "pack-signing.pub.pem").is_file()


# ---------------------------------------------------------------------------
# Slash lane
# ---------------------------------------------------------------------------


def test_slash_rules_verify_pass_lane(tmp_path: Path, cache: FastPathCache) -> None:
    if not _keys_present():
        pytest.skip("ceremony keys not present")
    out = dispatch_verb("rules verify", view=_view(tmp_path), cache=cache)
    assert out.startswith("lens rules verify · core")
    assert "verified against committed pubkey" in out


def test_slash_rules_verify_warn_lane_without_keys(
    tmp_path: Path, cache: FastPathCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    import skill_lens.packsec as packsec

    monkeypatch.setattr(packsec, "locate_core_keys", lambda root=None: (None, None))
    sink: dict[str, object] = {}
    out = dispatch_verb("rules verify", view=_view(tmp_path), cache=cache, sink=sink)
    assert "unsigned" in out
    assert sink["rules_exit"] == 0  # honest warn is not a total error


def test_slash_rules_external_pack_structural_check(
    tmp_path: Path, cache: FastPathCache
) -> None:
    from skill_lens.rules import core_pack_path

    target = tmp_path / "community-pack"
    shutil.copytree(core_pack_path(), target)
    out = dispatch_verb(
        f"rules verify {target}", view=_view(tmp_path), cache=cache
    )
    assert "2026.08.6" in out
    assert "sha256:" in out
    assert "structural load only" in out


def test_slash_rules_unreadable_path_is_fail_line(
    tmp_path: Path, cache: FastPathCache
) -> None:
    sink: dict[str, object] = {}
    out = dispatch_verb(
        f"rules verify {tmp_path}/nope", view=_view(tmp_path), cache=cache, sink=sink
    )
    assert out.startswith("lens fail")
    assert sink["rules_exit"] == 2


def test_slash_rules_usage_and_unknown_action(tmp_path: Path, cache: FastPathCache) -> None:
    assert "MANUAL ONLY" in dispatch_verb("rules help", view=_view(tmp_path), cache=cache)
    bad = dispatch_verb("rules frobnicate", view=_view(tmp_path), cache=cache)
    assert bad.startswith("lens fail")
    assert "unknown action" in bad


# ---------------------------------------------------------------------------
# CLI lane — grammar parity (D-043/D-054 one-shared-dispatch law)
# ---------------------------------------------------------------------------


def test_cli_tokens_reconstruction() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    cli_setup_parser(parser)
    cases = [
        (["--plain"], ["rules", "--plain"]),
        ([], ["rules"]),
        (["verify"], ["rules"]),
        (["verify", "/tmp/pack"], ["rules", "verify", "/tmp/pack"]),
        (
            ["verify", "/tmp/pack", "--sig", "a.sig", "--pubkey", "k.pem"],
            ["rules", "verify", "/tmp/pack", "--sig", "a.sig", "--pubkey", "k.pem"],
        ),
    ]
    for argv, expected in cases:
        ns = parser.parse_args(["rules", *argv])
        got = _tokens_for("rules", ns)
        # Default-action elision: bare `rules` == `rules verify` semantics.
        assert got == expected or got == ["rules", *expected[1:]], (argv, got)


def test_cli_exit_code_zero_on_verified_pack(tmp_path: Path) -> None:
    """Full CLI seam: register → parse → handler exits 0 when verification passes."""
    if not _keys_present():
        pytest.skip("ceremony keys not present")
    import argparse

    from tests.conftest import FakePluginContext

    ctx = FakePluginContext(data_root=tmp_path)
    view = PluginContextView(ctx)
    from skill_lens.cli import register_cli

    assert register_cli(view) is True
    registration = ctx.cli_commands["lens"]
    parser = argparse.ArgumentParser(prog="hermes lens")
    registration["setup_fn"](parser)

    ns = parser.parse_args(["rules"])
    with pytest.raises(SystemExit) as excinfo:
        registration["handler_fn"](ns)
    assert excinfo.value.code == 0


def test_cli_exit_code_two_on_rejected_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tampered pack bytes under a committed sig pair ⇒ §18 exit 2."""
    import argparse

    from skill_lens.rules import core_pack_path
    from tests.conftest import FakePluginContext

    if not _keys_present():
        pytest.skip("ceremony keys not present")
    import skill_lens.packsec as packsec

    root = tmp_path / "plugin"
    (root / "skill_lens" / "rules").mkdir(parents=True)
    shutil.copytree(core_pack_path(), root / "skill_lens" / "rules" / "core")
    shutil.copytree(Path(__file__).resolve().parents[1] / "keys", root / "keys")
    target = root / "skill_lens" / "rules" / "core" / "pack.yaml"
    target.write_text(target.read_text(encoding="utf-8").replace("name: core", "name: corX", 1))

    monkeypatch.setattr(packsec, "plugin_root", lambda: root)
    # locate_core_keys defaults its base via plugin_root(); rebind explicitly.
    # Simulate the REAL tamper scenario: the tampered files ARE the package
    # data of the installed plugin, so load_core_pack() must resolve there.
    import skill_lens.rules as rules_mod

    tampered = rules_mod.load_pack(root / "skill_lens" / "rules" / "core")
    monkeypatch.setattr(rules_mod, "load_core_pack", lambda: tampered)

    ctx = FakePluginContext(data_root=tmp_path / "state")
    view = PluginContextView(ctx)
    from skill_lens.cli import register_cli

    assert register_cli(view) is True
    registration = ctx.cli_commands["lens"]
    parser = argparse.ArgumentParser(prog="hermes lens")
    registration["setup_fn"](parser)

    ns = parser.parse_args(["rules"])
    with pytest.raises(SystemExit) as excinfo:
        registration["handler_fn"](ns)
    assert excinfo.value.code == 2
