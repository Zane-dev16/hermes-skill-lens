"""Packaging proofs for the v1.0 distribution (deliverable b).

Fast, no-build proofs of the manifest law: the committed public key ships
byte-identical as package data, the console-script entry is declared, the
AST/SIG extras mirror plugin.yaml's declared ranges, and the sdist/wheel
exclusions are pinned in pyproject (the CI packaging job builds and
proves the actual artifacts; these tests pin the SOURCE of truth).
"""

from __future__ import annotations

import pathlib
import tomllib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_packaged_pubkey_is_byte_identical_to_committed_key() -> None:
    committed = REPO_ROOT / "keys" / "pack-signing.pub.pem"
    packaged = REPO_ROOT / "skill_lens" / "keys" / "pack-signing.pub.pem"
    assert committed.is_file() and packaged.is_file()
    assert committed.read_bytes() == packaged.read_bytes()


def test_console_script_entry_declared() -> None:
    scripts = _pyproject()["project"].get("scripts") or {}
    assert scripts.get("lens") == "skill_lens.console:main"


def test_extras_mirror_plugin_yaml_ranges() -> None:
    plugin = (REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8")
    extras = _pyproject()["project"]["optional-dependencies"]
    for dep in ("tree-sitter>=0.24,<0.27", "tree-sitter-python>=0.23,<0.26"):
        assert dep in extras["ast"]  # declared range mirrored, not invented
        assert dep in plugin
    assert "cryptography>=42" in extras["sig"]
    assert "cryptography>=42" in plugin


def test_wheel_manifest_law_pinned_in_pyproject() -> None:
    data = _pyproject()["tool"]["setuptools"]["package-data"]["skill_lens"]
    assert "rules/core/pack.yaml" in data  # offline core pack (D-RULEOWN)
    assert "keys/pack-signing.pub.pem" in data  # offline provenance pubkey
    assert "skill_lens.enrich" in _pyproject()["tool"]["setuptools"]["packages"]
