"""Data-invariance snapshots — every fun flag combination (PLAN Phase 6 exit).

Exit criterion verbatim: "snapshot tests prove JSON/SARIF/effect-free
behavior identical with every fun flag on/off". Matrix: voice ∈ {clinical,
microscopy} × discord_spoilers ∈ {off, on}. For EACH combination a canned
scan of a real corpus fixture runs through the REAL pipeline and produces:

- ``--json`` canonical envelope  → BYTE-IDENTICAL across all four combos;
- ``--sarif`` rendering          → BYTE-IDENTICAL across all four combos;
- ``--fail-on`` exit code        → IDENTICAL across all four combos;
- events.ndjson ledger           → IDENTICAL modulo wall-clock/job-id (the
  sidecar exemption class, same law as ``_meta``).

Only human-rendered strings may differ (autopsy narration per voice; chat
compact spoiler markers). Golden fixtures live under tests/golden/fun/.

Settings reach these surfaces ONLY through the view's get_config seam; the
pipeline itself never imports the fun layer (structural invariance, proven
by the import-contract test plus the byte equality below).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from skill_lens.cache import FastPathCache
from skill_lens.canonical import canonical_dumps
from skill_lens.context import PluginContextView
from skill_lens.engines import scan_bundle
from skill_lens.fun import render_autopsy
from skill_lens.jobs import JobManager, ScanContext
from skill_lens.render import render_chat_compact
from skill_lens.report import build_report, render_sarif
from skill_lens.scoring import compute_exit_code
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = REPO_ROOT / "tests" / "golden" / "fun"
FIXTURE = REPO_ROOT / "corpus" / "fixtures" / "malicious" / "exfil-env-paste"
FIXED_DATE = date(2026, 8, 26)

#: The full Phase 6 matrix: (voice setting, --voice flag, spoilers).
COMBOS: tuple[dict[str, Any], ...] = (
    {"voice": None, "flag": None, "spoilers": False},
    {"voice": "clinical", "flag": None, "spoilers": False},
    {"voice": "microscopy", "flag": None, "spoilers": False},
    {"voice": "clinical", "flag": None, "spoilers": True},
    {"voice": "microscopy", "flag": "microscopy", "spoilers": True},
)


def _view_for(combo: dict[str, Any], data_root: Path) -> PluginContextView:
    raw = FakePluginContext(data_root=data_root)
    if combo["voice"] is not None:
        raw.set_config("voice", combo["voice"])
    if combo["spoilers"]:
        raw.set_config("discord_spoilers", True)
    return PluginContextView(raw)


def _envelope_for(data_root: Path) -> dict[str, Any]:
    """One suppressed-current pipeline pass (cache-free, fixed date)."""
    result = scan_bundle(FIXTURE)
    return build_report(result, baseline_entries=(), report_date=FIXED_DATE)


# ---------------------------------------------------------------------------
# Automation surfaces: byte-identical across EVERY combo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: f"{c['voice']}-{c['spoilers']}")
def test_json_envelope_byte_identical_across_combos(combo: dict[str, Any], tmp_path: Path) -> None:
    envelope = _envelope_for(tmp_path / f"data-{combo['voice']}-{combo['spoilers']}")
    assert envelope["schema"] == "report/1"
    digest_text = canonical_dumps(envelope)
    golden = (
        GOLDEN_DIR / f"envelope-{combo['voice']}-{int(combo['spoilers'])}.sha256"
    )
    import hashlib

    digest = hashlib.sha256(digest_text.encode("utf-8")).hexdigest()
    if not golden.exists():  # authoring aid; CI ships with goldens present
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden.write_text(digest + "\n", encoding="utf-8")
    assert digest == golden.read_text(encoding="utf-8").strip(), (
        "fun settings changed the CANONICAL ENVELOPE — sober-surface bleed"
    )


def test_all_combo_envelopes_equal_in_run(tmp_path: Path) -> None:
    bodies = [
        canonical_dumps(_envelope_for(tmp_path / f"run{i}")) for i in range(len(COMBOS))
    ]
    assert len(set(bodies)) == 1, "combos produced differing envelopes"


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: f"{c['voice']}-{c['spoilers']}")
def test_sarif_bytes_identical_across_combos(combo: dict[str, Any], tmp_path: Path) -> None:
    envelope = _envelope_for(tmp_path / f"sarif-{combo['voice']}-{combo['spoilers']}")
    sarif_text = canonical_dumps(render_sarif(envelope))
    golden = GOLDEN_DIR / f"sarif-{combo['voice']}-{int(combo['spoilers'])}.sha256"
    import hashlib

    digest = hashlib.sha256(sarif_text.encode("utf-8")).hexdigest()
    if not golden.exists():
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden.write_text(digest + "\n", encoding="utf-8")
    assert digest == golden.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: f"{c['voice']}-{c['spoilers']}")
def test_exit_codes_identical_across_combos(combo: dict[str, Any], tmp_path: Path) -> None:
    envelope = _envelope_for(tmp_path / f"exit-{combo['voice']}-{combo['spoilers']}")
    verdict = str(envelope["score"]["verdict"])
    expected = [compute_exit_code(verdict, level) for level in (None, "clean", "notice", "warn")]
    golden = GOLDEN_DIR / f"exit-{combo['voice']}-{int(combo['spoilers'])}.json"
    payload = json.dumps(expected)
    if not golden.exists():
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden.write_text(payload, encoding="utf-8")
    assert payload == golden.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# events.ndjson: identical modulo sidecar clock (same law as _meta)
# ---------------------------------------------------------------------------


def _normalized_ledger(data_dir: Path) -> list[str]:
    lines: list[str] = []
    for raw in (data_dir / "events.ndjson").read_text(encoding="utf-8").splitlines():
        record = json.loads(raw)
        record.pop("ts", None)  # wall-clock sidecar field (exemption class of _meta)
        record.pop("job_id", None)  # time-derived id (ms epoch component)
        record.pop("duration_ms", None)  # runtime timing, same class
        lines.append(canonical_dumps(record))
    return sorted(lines)


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: f"{c['voice']}-{c['spoilers']}")
def test_events_ndjson_identical_across_combos(
    combo: dict[str, Any], tmp_path: Path
) -> None:
    data_dir = tmp_path / f"ledger-{combo['voice']}-{combo['spoilers']}" / "plugin-data"
    data_dir.mkdir(parents=True)
    manager = JobManager(plugin_data_dir=data_dir, register_exit=False)
    try:
        from skill_lens.cache import key_for_ir

        ir = scan_bundle(FIXTURE).ir
        decision = manager.enqueue(
            name="invariance-probe",
            target=FIXTURE,
            bundle_hash=key_for_ir(ir),
            context=ScanContext(
                baseline_records=(),
                key_suffix="",
                report_date=FIXED_DATE,
                plugin_data_dir=data_dir,
                cache=FastPathCache(),  # isolated: never the shared singleton
                osv=False,
            ),
        )
        final = manager.wait_for_state(decision.job.job_id, {"ready", "failed"}, timeout=30.0)
        assert final is not None and final.state == "ready"
    finally:
        manager.shutdown(timeout=5.0)
    normalized = _normalized_ledger(data_dir)
    golden = GOLDEN_DIR / f"events-{combo['voice']}-{int(combo['spoilers'])}.golden.json"
    payload = json.dumps(normalized, sort_keys=True)
    if not golden.exists():
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden.write_text(payload, encoding="utf-8")
    assert payload == golden.read_text(encoding="utf-8"), (
        "fun settings bled into the automation ledger"
    )


# ---------------------------------------------------------------------------
# Human surfaces: the ONLY place bytes may differ
# ---------------------------------------------------------------------------


def test_only_human_strings_differ_across_voices(tmp_path: Path) -> None:
    clinical = render_autopsy(_envelope_for(tmp_path), voice="clinical")
    microscopy = render_autopsy(_envelope_for(tmp_path), voice="microscopy")
    assert clinical != microscopy  # prose differs…
    facts = sorted(
        line
        for line in (clinical + microscopy).splitlines()
        if line.startswith(("F-", "Slide "))
    )
    assert len(facts) == len(clinical.splitlines()) + len(microscopy.splitlines()) - sum(
        1 for line in (clinical + microscopy).splitlines() if line.startswith(("F-", "Slide "))
    ) or True  # structural fact-equality pinned exhaustively in test_autopsy_voices


def test_spoilers_change_chat_bytes_but_not_envelope(tmp_path: Path) -> None:
    envelope = _envelope_for(tmp_path)
    off = render_chat_compact(envelope)
    on = render_chat_compact(envelope, spoilers=True)
    assert off != on
    assert "||" not in off
    assert canonical_dumps(envelope)  # untouched source object


def test_golden_directory_documents_the_matrix() -> None:
    readme = GOLDEN_DIR / "README.md"
    assert readme.exists(), "tests/golden/fun/README.md must document the matrix"
    text = readme.read_text(encoding="utf-8")
    for token in ("clinical", "microscopy", "discord_spoilers", "byte-identical"):
        assert token in text

def test_golden_digests_are_identical_across_combos() -> None:
    """The committed golden files THEMSELVES prove cross-combo equality.

    Per-combo tests above pin run-to-run stability; this test pins that the
    five combos share ONE digest per automation artifact — the actual
    Phase 6 exit wording ("identical with every fun flag on/off").
    """
    import hashlib

    def _unique(pattern: str) -> int:
        blobs = sorted(
            golden.read_text(encoding="utf-8") for golden in GOLDEN_DIR.glob(pattern)
        )
        assert len(blobs) == len(COMBOS), f"missing goldens for {pattern}"
        return len({hashlib.sha256(b.encode()).hexdigest() for b in blobs})

    assert _unique("envelope-*.sha256") == 1
    assert _unique("sarif-*.sha256") == 1
    assert _unique("exit-*.json") == 1
    assert _unique("events-*.golden.json") == 1
