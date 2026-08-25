"""Ingestion edge cases — races, symlinks, ceilings, targets, provenance.

Covers the failure-mode contract: every pathology degrades to a structured
diagnostic plus partial IR, never an exception (SPEC §5.1, PLAN Phase 0).
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.ingest import (
    CODE_INGEST_DEPTH,
    CODE_INGEST_ENCODING,
    CODE_INGEST_FILE_CAP,
    CODE_INGEST_FILE_SIZE,
    CODE_INGEST_NET,
    CODE_INGEST_RACE,
    CODE_INGEST_SIZE_CAP,
    CODE_INGEST_SYMLINK,
    CODE_INGEST_TARGET,
    CODE_INGEST_ZIP,
    CODE_PROV_LOCK,
    Ceilings,
    discover_bundles,
    home_label,
    load_bundle,
    looks_like_git_url,
)
from skill_lens.inventory import build_inventory

# ---------------------------------------------------------------------------
# rmtree race — vanishing dirs degrade to logged skip diagnostics
# ---------------------------------------------------------------------------


def test_quarantine_dir_vanishing_mid_walk_degrades_to_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PHASE 0 EXIT CRITERION: quarantine disappearance ⇒ logged skip, no crash."""
    skills = tmp_path / "skills"
    doomed = skills / ".hub" / "quarantine" / "victim"
    doomed.mkdir(parents=True)
    (doomed / "SKILL.md").write_text("---\nname: victim\n---\n", encoding="utf-8")
    survivor = skills / ".hub" / "quarantine" / "survivor"
    survivor.mkdir(parents=True)
    (survivor / "SKILL.md").write_text("---\nname: survivor\n---\n", encoding="utf-8")
    other = skills / "tools" / "keeper"
    other.mkdir(parents=True)
    (other / "SKILL.md").write_text("---\nname: keeper\n---\n", encoding="utf-8")

    real_scandir = None
    from skill_lens.ingest import _scandir_sorted

    real_scandir = _scandir_sorted

    def racing_scandir(path: Path):
        # Simulate the gate's rmtree landing AFTER our listing snapshot:
        # quarantine is captured (victim included), then vanishes before the
        # walker descends into it.
        entries = real_scandir(path)
        if path.name == "quarantine":
            import shutil

            shutil.rmtree(doomed, ignore_errors=True)
        return entries

    monkeypatch.setattr("skill_lens.ingest._scandir_sorted", racing_scandir)

    diags = DiagnosticsCollector()
    refs = discover_bundles(tmp_path, diagnostics=diags)
    names = {ref.name for ref in refs}
    assert {"survivor", "keeper"} <= names  # walk continued past the loss
    race_diags = [d for d in diags if d.code == CODE_INGEST_RACE]
    assert len(race_diags) >= 1


def test_load_bundle_dir_race_degrades(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bundle subdir disappearing mid-walk yields partial IR + diagnostic."""
    root = tmp_path / "bundle"
    sub = root / "scripts"
    sub.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: bundle\n---\n", encoding="utf-8")

    from skill_lens.ingest import _scandir_sorted as real_scandir

    def racing_scandir(path: Path):
        entries = real_scandir(path)
        if path.name == "bundle":
            import shutil

            shutil.rmtree(sub, ignore_errors=True)
        return entries

    monkeypatch.setattr("skill_lens.ingest._scandir_sorted", racing_scandir)
    diags = DiagnosticsCollector()
    ir = load_bundle(root, diagnostics=diags)
    assert ir.file_count == 1  # SKILL.md survived; vanished dir logged
    assert any(d.code == CODE_INGEST_RACE for d in diags)


# ---------------------------------------------------------------------------
# Symlink safety
# ---------------------------------------------------------------------------


def test_symlink_loop_is_terminated_with_diagnostics(tmp_path: Path) -> None:
    """A symlinked directory cycle must not hang or crash discovery."""
    parent = tmp_path / "skills" / "tools" / "loopy"
    (parent / "inner").mkdir(parents=True)
    (parent / "SKILL.md").write_text("---\nname: loopy\n---\n", encoding="utf-8")
    (parent / "loop").symlink_to(parent)  # cycle: parent -> loop -> parent
    (parent / "inner" / "SKILL.md").write_text("---\nname: inner\n---\n", encoding="utf-8")

    diags = DiagnosticsCollector()
    refs = discover_bundles(tmp_path, diagnostics=diags)
    assert {ref.name for ref in refs} == {"loopy"}  # inner owned by loopy
    symlink_diags = [d for d in diags if d.code == CODE_INGEST_SYMLINK]
    assert len(symlink_diags) == 1


def test_bundle_symlinked_file_skipped(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: b\n---\n", encoding="utf-8")
    secret = tmp_path / "outside.txt"
    secret.write_text("leak", encoding="utf-8")
    (root / "link.txt").symlink_to(secret)

    diags = DiagnosticsCollector()
    ir = load_bundle(root, diagnostics=diags)
    assert ir.file_count == 1
    assert any(d.code == CODE_INGEST_SYMLINK for d in diags)


# ---------------------------------------------------------------------------
# Resource ceilings (SPEC §5.1 exact numbers, shrunk for tests)
# ---------------------------------------------------------------------------


def test_file_count_ceiling_stops_walk_with_diagnostic(tmp_path: Path) -> None:
    root = tmp_path / "many"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: many\n---\n", encoding="utf-8")
    for i in range(6):
        (root / f"f{i}.txt").write_text("x", encoding="utf-8")

    tiny = Ceilings(max_files=3, max_depth=32, max_total_bytes=1 << 20, max_file_bytes=1 << 16)
    diags = DiagnosticsCollector()
    ir = load_bundle(root, ceilings=tiny, diagnostics=diags)
    assert ir.file_count == 3
    codes = [d.code for d in diags]
    assert codes.count(CODE_INGEST_FILE_CAP) == 1


def test_single_file_projection_over_16mib_ceiling(tmp_path: Path) -> None:
    root = tmp_path / "big"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: big\n---\n", encoding="utf-8")
    big = Ceilings(max_files=100, max_depth=32, max_total_bytes=1 << 30, max_file_bytes=1024)
    (root / "assets").mkdir()
    (root / "assets/blob.bin").write_bytes(bytes(2048))

    diags = DiagnosticsCollector()
    ir = load_bundle(root, ceilings=big, diagnostics=diags)
    blob = next(f for f in ir.files if f.path == "assets/blob.bin")
    assert blob.partial is True
    assert blob.size == 1024  # bounded projection
    assert blob.sha256 is not None
    assert any("partial_analysis" in note for note in ir.notes)
    assert [d.code for d in diags].count(CODE_INGEST_FILE_SIZE) == 1


def test_total_bytes_ceiling_stops_ingest(tmp_path: Path) -> None:
    root = tmp_path / "heavy"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: heavy\n---\n", encoding="utf-8")
    (root / "a.bin").write_bytes(b"a" * 600)
    (root / "b.bin").write_bytes(b"b" * 600)
    caps = Ceilings(max_files=10, max_depth=32, max_total_bytes=1000, max_file_bytes=4096)

    diags = DiagnosticsCollector()
    ir = load_bundle(root, ceilings=caps, diagnostics=diags)
    paths = {f.path for f in ir.files}
    assert "a.bin" in paths and "b.bin" not in paths
    assert [d.code for d in diags].count(CODE_INGEST_SIZE_CAP) == 1


def test_traversal_depth_ceiling(tmp_path: Path) -> None:
    root = tmp_path / "deep"
    deep = root
    for i in range(6):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: deep\n---\n", encoding="utf-8")
    (deep / "bottom.txt").write_text("bottom", encoding="utf-8")
    caps = Ceilings(max_files=10, max_depth=3, max_total_bytes=1 << 20, max_file_bytes=1 << 16)

    diags = DiagnosticsCollector()
    ir = load_bundle(root, ceilings=caps, diagnostics=diags)
    assert all(not f.path.startswith("d0/") for f in ir.files)
    assert [d.code for d in diags].count(CODE_INGEST_DEPTH) == 1


def test_zip_member_caps_and_bomb_resistance(tmp_path: Path) -> None:
    zip_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("SKILL.md", "---\nname: bomb\n---\n")
        zf.writestr("huge.bin", b"H" * 5000)
        zf.writestr("tail.bin", b"T" * 100)
    caps = Ceilings(max_files=10, max_depth=32, max_total_bytes=2000, max_file_bytes=1024)

    diags = DiagnosticsCollector()
    ir = load_bundle(zip_path, ceilings=caps, diagnostics=diags)
    sizes = sorted(f.size for f in ir.files)
    assert sizes[0] <= 1024  # member projection respected
    assert sum(sizes) <= 2000  # cumulative ceiling respected
    codes = [d.code for d in diags]
    assert CODE_INGEST_FILE_SIZE in codes or CODE_INGEST_SIZE_CAP in codes


def test_corrupt_zip_yields_error_diagnostic_not_crash(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 definitely not a zip")
    diags = DiagnosticsCollector()
    ir = load_bundle(bad, diagnostics=diags)
    assert ir.file_count == 0
    assert any(d.code == CODE_INGEST_ZIP and d.severity == "error" for d in diags)


# ---------------------------------------------------------------------------
# Target dispatch
# ---------------------------------------------------------------------------


def test_git_url_target_refused_offline() -> None:
    """Privacy G1: remote targets produce LNS-ING-NET, zero fetch attempts."""
    for url in (
        "https://github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "ssh://git@host/owner/repo",
    ):
        assert looks_like_git_url(url)
        diags = DiagnosticsCollector()
        ir = load_bundle(url, diagnostics=diags)
        assert ir.source_kind == "git"
        assert ir.file_count == 0
        net = [d for d in diags if d.code == CODE_INGEST_NET]
        assert len(net) == 1
        assert "remote targets unsupported" in net[0].message


@pytest.mark.parametrize("not_url", ["local/path", "./repo", "skills/x"])
def test_plain_paths_are_not_remote(not_url: str) -> None:
    assert not looks_like_git_url(not_url)


def test_missing_target_yields_target_error_ir(tmp_path: Path) -> None:
    diags = DiagnosticsCollector()
    ir = load_bundle(tmp_path / "ghost", diagnostics=diags)
    assert ir.file_count == 0
    assert any(d.code == CODE_INGEST_TARGET and d.severity == "error" for d in diags)


def test_unsupported_file_type_yields_target_error(tmp_path: Path) -> None:
    plain = tmp_path / "notes.txt"
    plain.write_text("hi", encoding="utf-8")
    diags = DiagnosticsCollector()
    ir = load_bundle(plain, diagnostics=diags)
    assert ir.file_count == 0
    assert any(d.code == CODE_INGEST_TARGET for d in diags)


def test_lone_skill_md_single_file_layout(tmp_path: Path) -> None:
    doc_dir = tmp_path / "solo"
    doc_dir.mkdir()
    doc = doc_dir / "SKILL.md"
    doc.write_text("---\nname: solo-skill\n---\nbody\n", encoding="utf-8")
    ir = load_bundle(doc, diagnostics=DiagnosticsCollector())
    assert ir.identity.layout == "single_file"
    assert ir.identity.name == "solo"
    assert ir.frontmatter is not None and ir.frontmatter.name == "solo-skill"


def test_zip_roundtrip_full(tmp_path: Path) -> None:
    zip_path = tmp_path / "skill.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("root/SKILL.md", "---\nname: zipped\nallowed-tools: [bash]\n---\n")
        zf.writestr("root/scripts/go.sh", "#!/bin/sh\necho go\n")
    ir = load_bundle(zip_path, diagnostics=DiagnosticsCollector())
    assert ir.source_kind == "zip"
    assert ir.file_count == 2
    assert ir.frontmatter is not None
    assert ir.frontmatter.name == "zipped"  # nested SKILL.md found as manifest
    assert list(ir.frontmatter.allowed_tools) == ["bash"]
    roles = {f.path: f.role for f in ir.files}
    assert roles["root/scripts/go.sh"] == "script"


# ---------------------------------------------------------------------------
# Frontmatter robustness
# ---------------------------------------------------------------------------


def test_unknown_fields_tolerated_and_recorded(tmp_path: Path) -> None:
    from skill_lens.ir import CODE_FRONTMATTER_UNKNOWN

    root = tmp_path / "odd"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\n"
        "name: odd\n"
        "description: ok\n"
        "future_field:\n"
        "  nested: [1, 2]\n"
        "metadata:\n"
        "  hermes:\n"
        "    tags: [t]\n"
        "    brand_new_key: 42\n"
        "---\n",
        encoding="utf-8",
    )
    diags = DiagnosticsCollector()
    ir = load_bundle(root, diagnostics=diags)
    fm = ir.frontmatter
    assert fm is not None
    assert set(fm.unknown_fields) == {"future_field"}
    assert fm.hermes is not None
    assert set(fm.hermes.unknown_fields) == {"brand_new_key"}
    unknown_codes = [d.code for d in diags if d.code == CODE_FRONTMATTER_UNKNOWN]
    assert len(unknown_codes) == 2  # one per unknown key, stable order


def test_wrong_shaped_values_become_validation_errors(tmp_path: Path) -> None:
    root = tmp_path / "wrongshape"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\n"
        "name: [not, a, string]\n"
        "description: 7\n"
        "allowed-tools: bash-and-more\n"
        "compatibility: {dict: true}\n"
        "metadata:\n"
        "  hermes:\n"
        "    tags: {bad: shape}\n"
        "    config: [also, bad]\n"
        "---\n",
        encoding="utf-8",
    )
    ir = load_bundle(root, diagnostics=DiagnosticsCollector())
    fm = ir.frontmatter
    assert fm is not None
    assert any("must be a string" in err for err in fm.validation_errors)
    assert fm.description_raw == "7"  # tolerated coercion
    assert list(fm.allowed_tools) == ["bash-and-more"]  # comma-string tolerance
    assert fm.hermes is not None
    assert any("tags" in err for err in fm.hermes.validation_errors)
    assert dict(fm.hermes.config) == {}


def test_description_bounded_to_1024_chars(tmp_path: Path) -> None:
    root = tmp_path / "verbose"
    root.mkdir()
    long_desc = "x" * 3000
    (root / "SKILL.md").write_text(
        f"---\nname: verbose\ndescription: {long_desc}\n---\n", encoding="utf-8"
    )
    ir = load_bundle(root, diagnostics=DiagnosticsCollector())
    assert ir.frontmatter is not None
    assert len(ir.frontmatter.description_raw) == 1024


def test_utf16_skill_md_parses(tmp_path: Path) -> None:
    root = tmp_path / "wide"
    root.mkdir()
    (root / "SKILL.md").write_bytes(
        "---\nname: wide\ndescription: utf-16 encoded\n---\n".encode("utf-16")
    )
    diags = DiagnosticsCollector()
    ir = load_bundle(root, diagnostics=diags)
    record = next(f for f in ir.files if f.path == "SKILL.md")
    assert record.encoding == "utf-16"
    assert ir.frontmatter is not None and ir.frontmatter.name == "wide"


def test_binary_asset_info_not_warning(tmp_path: Path) -> None:
    root = tmp_path / "bin"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: bin\n---\n", encoding="utf-8")
    (root / "assets").mkdir()
    (root / "assets/img.png").write_bytes(b"\x89PNG\r\n\x00\x00binaryish")
    diags = DiagnosticsCollector()
    ir = load_bundle(root, diagnostics=diags)
    img = next(f for f in ir.files if f.path == "assets/img.png")
    assert img.encoding == "binary"
    enc = [d for d in diags if d.path == "assets/img.png" and d.code == CODE_INGEST_ENCODING]
    assert len(enc) == 1 and enc[0].severity == "info"


# ---------------------------------------------------------------------------
# Provenance enrichment (annotation-only)
# ---------------------------------------------------------------------------


def _write_lock(home: Path, installed: dict) -> None:
    hub = home / "skills" / ".hub"
    hub.mkdir(parents=True, exist_ok=True)
    (hub / "lock.json").write_text(
        json.dumps({"version": 1, "installed": installed}), encoding="utf-8"
    )


def test_provenance_enrichment_happy_path(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = home / "skills" / "tools" / "widget"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: widget\n---\n", encoding="utf-8")
    _write_lock(
        home,
        {
            "widget": {
                "source": "official",
                "identifier": "@openai/skills/widget",
                "trust_level": "trusted",
                "content_hash": "sha256:" + "33" * 32,
                "install_path": "tools/widget",
                "scan_provenance": {"verdict": "allow"},
            }
        },
    )
    ir = load_bundle(root, home=home, diagnostics=DiagnosticsCollector())
    prov = ir.provenance
    assert prov is not None
    assert prov.resolved_from == "hub_lock"
    assert prov.identifier == "@openai/skills/widget"
    assert prov.trust_level == "trusted"
    assert prov.hub_source == "official"
    assert prov.content_hash == "sha256:" + "33" * 32
    assert prov.scan_provenance == {"verdict": "allow"}
    assert prov.install_path is not None and prov.install_path.endswith("tools/widget")


def test_provenance_absent_lock_is_info_skip(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = home / "skills" / "tools" / "widget"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: widget\n---\n", encoding="utf-8")
    diags = DiagnosticsCollector()
    ir = load_bundle(root, home=home, diagnostics=diags)
    assert ir.provenance is None
    lock_diags = [d for d in diags if d.code == CODE_PROV_LOCK]
    assert len(lock_diags) == 1 and lock_diags[0].severity == "info"


def test_provenance_corrupt_lock_warns_and_skips(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = home / "skills" / "tools" / "widget"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: widget\n---\n", encoding="utf-8")
    hub = home / "skills" / ".hub"
    hub.mkdir(parents=True)
    (hub / "lock.json").write_text("{not json", encoding="utf-8")
    diags = DiagnosticsCollector()
    ir = load_bundle(root, home=home, diagnostics=diags)
    assert ir.provenance is None
    lock_diags = [d for d in diags if d.code == CODE_PROV_LOCK]
    assert lock_diags and lock_diags[0].severity == "warning"


def test_provenance_agent_created_source_class(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = home / "skills" / "tools" / "handmade"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: handmade\n---\n", encoding="utf-8")
    _write_lock(
        home,
        {
            "handmade": {
                "source": "local",
                "trust_level": "agent-created",
                "install_path": "tools/handmade",
            }
        },
    )
    ir = load_bundle(root, home=home, diagnostics=DiagnosticsCollector())
    assert ir.provenance is not None
    assert ir.provenance.source_class == "agent_created"


# ---------------------------------------------------------------------------
# Label normalization + inventory-level determinism on scratch homes
# ---------------------------------------------------------------------------


def test_home_label_conventions(tmp_path: Path) -> None:
    real_home = Path.home() / ".hermes"
    assert home_label(real_home / "skills" / "tools" / "w", real_home) == (
        "~/.hermes/skills/tools/w"
    )
    scratch = tmp_path / "lens-dev"
    assert home_label(scratch / "skills" / "t" / "w", scratch) == "~/skills/t/w"
    outside = tmp_path / "elsewhere"
    assert home_label(outside, scratch) == str(outside)  # as-given passthrough


def test_inventory_scratch_home_byte_identical(tmp_path: Path) -> None:
    """PLAN exit restated at inventory level for a non-default home."""
    from skill_lens.canonical import canonical_dumps
    from tests.fixtures.synthetic_home import make_synthetic_home

    home = tmp_path / "scratch-home"
    make_synthetic_home(home)
    first = canonical_dumps(build_inventory(home).envelope)
    second = canonical_dumps(build_inventory(home).envelope)
    assert first == second
