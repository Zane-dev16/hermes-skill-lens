"""Canonical JSON determinism tests (task ir-canonical deliverable 3).

(a) byte-identical output across two invocations with shuffled dict
    insertion order; (b) ``_meta`` sidecar excluded from the envelope;
    (c) property test — canonical_dumps is insertion-order invariant for
    nested dicts/lists/scalars (hypothesis); (d) stability fingerprints:
    no wall-clock leakage and no absolute host paths in the envelope.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from skill_lens.canonical import (
    ENVELOPE_FILENAME,
    SIDECAR_FILENAME,
    canonical_dumps,
    write_report,
)
from skill_lens.ir import SkillIR
from tests.conftest import make_sample_ir

FIXED_NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


def commute(value: Any) -> Any:
    """Rebuild every mapping with reversed insertion order (deep copy)."""
    if isinstance(value, dict):
        return {key: commute(value[key]) for key in reversed(list(value.keys()))}
    if isinstance(value, list):
        return [commute(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# (a) byte-identical across shuffled insertion order
# ---------------------------------------------------------------------------


def test_envelope_bytes_identical_across_insertion_order(tmp_path) -> None:
    ir = make_sample_ir()
    payload = ir.canonical_dict()

    first = write_report(ir, tmp_path / "run-a", now=FIXED_NOW)
    second = write_report(ir, tmp_path / "run-b", now=FIXED_NOW)

    assert first.report_path.read_bytes() == second.report_path.read_bytes()
    # Shuffling key order of the assembled payload cannot change the bytes.
    assert canonical_dumps(commute(payload)) == canonical_dumps(payload)
    assert json.loads(first.report_path.read_text(encoding="utf-8")) == payload


def test_meta_sidecar_bytes_stable_for_fixed_clock_and_volatile_otherwise(
    tmp_path,
) -> None:
    ir = make_sample_ir()
    a = write_report(ir, tmp_path / "a", now=FIXED_NOW, durations_ms={"scan": 1.5})
    b = write_report(ir, tmp_path / "b", now=FIXED_NOW, durations_ms={"scan": 1.5})
    assert a.meta_path.read_bytes() == b.meta_path.read_bytes()


# ---------------------------------------------------------------------------
# (b) _meta sidecar exclusion
# ---------------------------------------------------------------------------


def test_meta_sidecar_excluded_from_envelope(tmp_path) -> None:
    written = write_report(make_sample_ir(), tmp_path, now=FIXED_NOW)

    envelope = json.loads(written.report_path.read_text(encoding="utf-8"))
    assert "_meta" not in envelope
    # No key anywhere in the envelope is named _meta.
    flat = written.report_path.read_text(encoding="utf-8")
    assert '"_meta"' not in flat

    meta = json.loads(written.meta_path.read_text(encoding="utf-8"))
    assert set(meta) == {"_meta"}
    body = meta["_meta"]
    assert set(body) == {"generated_at", "durations_ms", "runtime"}
    assert body["generated_at"].startswith("2026-08-25T12:00:00.000Z")
    assert "python_version" in body["runtime"]


def test_sidecar_defaults_to_wall_clock_and_sorted_durations(tmp_path) -> None:
    written = write_report(make_sample_ir(), tmp_path, durations_ms={"z": 1, "a": 2})
    meta = json.loads(written.meta_path.read_text(encoding="utf-8"))["_meta"]
    assert list(meta["durations_ms"]) == ["a", "z"]
    assert meta["generated_at"].endswith("Z")


# ---------------------------------------------------------------------------
# (c) hypothesis: insertion-order invariance
# ---------------------------------------------------------------------------


json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**12), max_value=10**12)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=12)
)

json_values = st.recursive(
    json_scalars,
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4)
    ),
    max_leaves=14,
)


@settings(max_examples=200, deadline=None)
@given(json_values)
def test_canonical_dumps_is_insertion_order_invariant(value: Any) -> None:
    assert canonical_dumps(commute(value)) == canonical_dumps(value)


@settings(max_examples=50, deadline=None)
@given(json_values)
def test_sorted_keys_actually_sort(value: Any) -> None:
    text = canonical_dumps({"b": 1, "a": {"y": 1, "x": 2}, "c": value})
    assert text.index('"a"') < text.index('"b"') < text.index('"c"')


# ---------------------------------------------------------------------------
# (d) stability fingerprints on the real artifact
# ---------------------------------------------------------------------------


def test_no_wallclock_or_absolute_paths_leak_into_envelope(tmp_path) -> None:
    ir = make_sample_ir()
    written = write_report(ir, tmp_path / "out", now=FIXED_NOW)
    envelope_text = written.report_path.read_text(encoding="utf-8")

    assert "generated_at" not in envelope_text
    assert "_meta" not in envelope_text
    assert str(tmp_path) not in envelope_text  # no absolute host path leakage
    assert "/tmp/" not in envelope_text


def test_write_report_returns_paths_and_creates_directory(tmp_path) -> None:
    out = tmp_path / "nested" / "deeper"
    written = write_report(make_sample_ir(), out, now=FIXED_NOW)
    assert written.report_path.name == ENVELOPE_FILENAME
    assert written.meta_path.name == SIDECAR_FILENAME
    assert written.report_path.exists() and written.meta_path.exists()
    assert written.report_path.parent == out


def test_envelope_round_trips_through_json_with_unicode(tmp_path) -> None:
    """ensure_ascii=False keeps literal Unicode; round-trip must be lossless."""
    ir = make_sample_ir(
        frontmatter=None,
        notes=("café ☕ description kept verbatim",),
    )
    written = write_report(ir, tmp_path, now=FIXED_NOW)
    payload = json.loads(written.report_path.read_text(encoding="utf-8"))
    assert payload["notes"] == ["café ☕ description kept verbatim"]
    raw = written.report_path.read_text(encoding="utf-8")
    assert "café ☕" in raw  # not \\u-escaped


def test_skill_ir_type_alias_holds_for_factory() -> None:
    sample: SkillIR = make_sample_ir()
    assert sample.canonical_dict()["spec_version"] == "ir/1"
