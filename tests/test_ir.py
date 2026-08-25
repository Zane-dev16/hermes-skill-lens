"""SkillIR dataclass + inventory-renderer tests (Phase 0, task ir-canonical).

Covers the SPEC §5.2 contract surface that has no canonical-JSON overlap:
freeze semantics, unknown-field tolerance-and-record, SPEC key fidelity of
``canonical_dict``, the empty Phase 1 claim shell, and render stability.
"""

from __future__ import annotations

import dataclasses

import pytest

from skill_lens.diagnostics import SEVERITY_WARNING, DiagnosticsCollector
from skill_lens.ir import (
    CODE_FRONTMATTER_UNKNOWN,
    IR_SPEC_VERSION,
    TOOL_NAME,
    BundleIdentity,
    DecodedView,
    FileRecord,
    HermesMetadata,
    Provenance,
    ResolvedFrontmatter,
    extract_claims,
    render_inventory,
    tool_version,
)

# conftest-provided factory
from tests.conftest import make_sample_ir  # noqa: TID252 (tests package is fixed)

# ---------------------------------------------------------------------------
# Freeze semantics
# ---------------------------------------------------------------------------


def test_frozen_rebinding_rejected() -> None:
    ir = make_sample_ir()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ir.source_kind = "zip"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        ir.identity.name = "other"  # type: ignore[misc]


def test_mapping_fields_are_defensively_copied() -> None:
    vendor = {"disable-model-invocation": False}
    unknown = {"rogue-key": 1}
    hermes_unknown: dict[str, object] = {"surprise": [1]}
    fm = ResolvedFrontmatter(
        name="x",
        vendor_fields=vendor,
        unknown_fields=unknown,
        hermes=HermesMetadata(unknown_fields=hermes_unknown),
    )
    vendor["disable-model-invocation"] = True
    unknown["rogue-key"] = 2
    hermes_unknown["surprise"] = "mutated"
    assert fm.vendor_fields == {"disable-model-invocation": False}
    assert fm.unknown_fields == {"rogue-key": 1}
    assert fm.hermes is not None and fm.hermes.unknown_fields == {"surprise": [1]}


def test_derived_counts_match_files() -> None:
    ir = make_sample_ir()
    assert ir.file_count == 2
    assert ir.total_bytes == 1042 + 38912


# ---------------------------------------------------------------------------
# Unknown frontmatter tolerance
# ---------------------------------------------------------------------------


def test_unknown_frontmatter_recorded_as_stable_ordered_warnings() -> None:
    collector = DiagnosticsCollector()
    fm = ResolvedFrontmatter(
        name="x",
        unknown_fields={"zebra": True, "alpha": {"deep": 1}, "middle": None},
    )
    from skill_lens.ir import report_unknown_fields

    created = report_unknown_fields(fm.unknown_fields, collector, path="SKILL.md")

    assert [diag.detail["key"] for diag in created] == ["alpha", "middle", "zebra"]
    assert all(diag.code == CODE_FRONTMATTER_UNKNOWN for diag in created)
    assert all(diag.severity == SEVERITY_WARNING for diag in created)
    # Values are NOT copied wholesale — only their JSON type name.
    assert created[0].detail == {"key": "alpha", "value_kind": "dict"}
    # Re-running yields the identical sequence (determinism fingerprint).
    again = report_unknown_fields(fm.unknown_fields, DiagnosticsCollector(), path="SKILL.md")
    assert [diag.to_dict() for diag in again] == [diag.to_dict() for diag in created]


# ---------------------------------------------------------------------------
# Canonical dict shape (SPEC §5.2 key fidelity)
# ---------------------------------------------------------------------------


def test_canonical_dict_top_level_spec_keys() -> None:
    payload = make_sample_ir().canonical_dict()
    assert set(payload) == {
        "spec_version",
        "tool",
        "bundle",
        "manifest",
        "claims",
        "decoded_views",
        "notes",
        "diagnostics",
    }
    assert payload["spec_version"] == IR_SPEC_VERSION
    assert payload["tool"] == {"name": TOOL_NAME, "version": tool_version()}
    bundle_keys = {
        "root_label",
        "category",
        "path_as_given",
        "layout",
        "source_kind",
        "bundle_hash",
        "file_count",
        "total_bytes",
        "provenance",
        "files",
    }
    assert set(payload["bundle"]) == bundle_keys
    manifest_keys = {
        "name",
        "description_raw",
        "allowed_tools",
        "compatibility",
        "vendor_fields",
        "hermes",
        "validation_errors",
        "unknown_fields",
    }
    assert set(payload["manifest"]) == manifest_keys


def test_provenance_annotation_only_shape() -> None:
    """D-PROV: provenance serializes fully but carries no arithmetic hooks."""
    prov = Provenance().to_dict()
    assert set(prov) == {
        "source_class",
        "identifier",
        "trust_level",
        "resolved_from",
        "install_path",
        # Additive ir/1 enrichment from .hub/lock.json (SPEC §5.1, D-010).
        "hub_source",
        "content_hash",
        "scan_provenance",
    }
    assert all(value is None for value in prov.values())


def test_file_record_serialization_round_shape() -> None:
    record = FileRecord(path="a/b.sh", size=3).to_dict()
    assert record["decode_layers"] == ["raw"]
    assert record["path_labels"] == ["inside_skill_root"]
    assert record["partial"] is False
    assert record["sha256"] is None


# ---------------------------------------------------------------------------
# Claims shell
# ---------------------------------------------------------------------------


def test_extract_claims_is_empty_until_phase_1() -> None:
    ir = make_sample_ir()
    assert extract_claims(ir) == ()
    assert ir.canonical_dict()["claims"] == []


# ---------------------------------------------------------------------------
# Inventory renderer
# ---------------------------------------------------------------------------


def test_render_inventory_is_sorted_and_repeatable() -> None:
    shuffled = make_sample_ir(
        files=(
            FileRecord(path="z-last.txt", size=5),
            FileRecord(path="SKILL.md", size=100),
            FileRecord(path="a/first.sh", size=7),
        )
    )
    ordered = make_sample_ir(
        files=(
            FileRecord(path="SKILL.md", size=100),
            FileRecord(path="a/first.sh", size=7),
            FileRecord(path="z-last.txt", size=5),
        )
    )
    first_render = render_inventory(shuffled)
    assert first_render == render_inventory(ordered)
    assert first_render == render_inventory(shuffled)  # pure function
    paths = [
        line.split(" ")[1].removesuffix(" [")
        for line in first_render.splitlines()
        if line.startswith("  - ")
    ]
    assert paths == sorted(paths)


def test_render_inventory_surface_contents(sample_ir_factory) -> None:
    text = render_inventory(sample_ir_factory())
    assert "bundle: web-design-guidelines" in text
    assert "layout: categorized (category=tools)" in text
    assert "~/.hermes/skills/tools/web-design-guidelines" in text
    assert "files: 2 (39954 bytes)" in text
    assert "claims: 0" in text
    assert "diagnostics: 0 (0 warning/error)" in text
    assert text.endswith("\n")


def test_render_inventory_reports_diagnostics_count() -> None:
    ir = make_sample_ir()
    ir.diagnostics.warning(CODE_FRONTMATTER_UNKNOWN, "unknown field tolerated")
    text = render_inventory(ir)
    assert "diagnostics: 1 (1 warning/error)" in text


def test_decoded_view_shell_serializes() -> None:
    view = DecodedView(file="SKILL.md", view="ghost_text", hidden_codepoint_count=37)
    assert view.to_dict() == {
        "file": "SKILL.md",
        "view": "ghost_text",
        "hidden_codepoint_count": 37,
        "blocks": [],
    }


def test_bundle_identity_defaults_are_advisor_safe() -> None:
    identity = BundleIdentity(name="solo-skill", path="~/skills/solo-skill")
    assert identity.category is None
    assert identity.layout == "flat"
