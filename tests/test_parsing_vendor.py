"""Vendored-wheel delivery lane (D-PARSE lane 2) — pins and extraction.

The declared ``python_dependencies`` lane is primary; these tests guard the
fallback so it can never become a supply-chain hole or a silent lie:

- every wheel shipped under ``wheels/`` MUST be SHA256-pinned in
  ``skill_lens.parsing._WHEEL_SHA256`` and match its pin (a swapped wheel
  without a pin update fails CI here);
- extraction is idempotent, appends real dirs (native .so needs files,
  zipimport cannot load extensions), and skips hash-mismatched wheels
  WITHOUT executing them;
- the public :func:`ensure_vendored_wheels` never raises and degrades to [].
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from skill_lens.parsing import (
    _WHEEL_SHA256,
    _extract_wheels,
    ensure_vendored_wheels,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WHEELS_DIR = REPO_ROOT / "wheels"

PINNED_NAMES = {name for name, _ in _WHEEL_SHA256}


def test_every_shipped_wheel_is_pinned_and_matches() -> None:
    """No unpinned wheel may ship; every pin must match reality."""
    shipped = {p.name for p in WHEELS_DIR.glob("*.whl")}
    assert shipped == PINNED_NAMES, (
        f"wheels/ vs pins drift: unpinned={shipped - PINNED_NAMES} "
        f"stale-pins={PINNED_NAMES - shipped}"
    )
    for name, digest in _WHEEL_SHA256:
        actual = hashlib.sha256((WHEELS_DIR / name).read_bytes()).hexdigest()
        assert actual == digest, f"wheel {name} does not match its pin"


def test_extraction_appends_real_dirs_and_is_idempotent(tmp_path: Path) -> None:
    """First call extracts+pins all four wheels; re-call adds nothing new."""
    cache = tmp_path / "cache"
    first = _extract_wheels(WHEELS_DIR, cache)
    assert len(first) == len(_WHEEL_SHA256)
    for target in first:
        assert target.is_dir()
        assert (target / ".extracted").is_file()
        assert str(target) in __import__("sys").path
        # native binding really present (the whole point of extraction)
        assert any(target.rglob("*.so"))
    second = _extract_wheels(WHEELS_DIR, cache)
    assert second == []


def test_hash_mismatched_wheel_is_skipped_not_executed(
    tmp_path: Path,
) -> None:
    """A wheel failing its pin never extracts, never lands on sys.path."""
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    name, digest = sorted(_WHEEL_SHA256)[0]
    with zipfile.ZipFile(wheels / name, "w") as zf:
        zf.writestr("tree_sitter/__init__.py", "raise SystemExit('tampered')")
    cache = tmp_path / "cache"
    appended = _extract_wheels(wheels, cache)
    assert appended == []
    assert not (cache / Path(name).stem).exists()


def test_ensure_vendored_wheels_never_raises(tmp_path: Path) -> None:
    """Missing wheels dir ⇒ [] (degraded), never an exception."""
    assert ensure_vendored_wheels(wheels_dir=tmp_path / "absent") == []
