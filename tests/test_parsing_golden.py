"""Degradation goldens — the line-scanner contract is FIRST-CLASS (D-PARSE).

PLAN §3 item 7: line-scanner fallback output is golden-tested per engine so
missing-grammar installs behave identically everywhere. These goldens pin the
ENGINE-FACING degraded surface of :class:`skill_lens.parsing.ParserGateway` —
exactly what the A2/E4-pyscan, A3/E5-jsscan and E3-bash-upgrade line scanners
must consume — and enforce the core guarantee:

    degraded output NEVER depends on WHY you are degraded.

For each engine slot, the serialized surface must be byte-for-byte identical
whether the grammar was **absent** (ImportError on both delivery lanes) or
**failed to load** (module present but ``language()``/``Language`` blew up).
Reason codes are deliberately EXCLUDED from the golden surface — they are
honest WHY-telemetry (a separate assertion proves they differ between the two
scenarios); everything an engine branches on is pinned.

When A2/A3 land, their engines route degraded parses through
:func:`skill_lens.parsing.line_tokens`; these files are the byte oracle that
keeps the fallback from drifting into a shadow mode.
"""

from __future__ import annotations

import types
from collections.abc import Callable
from pathlib import Path

import pytest

from skill_lens.canonical import canonical_dumps
from skill_lens.parsing import (
    REASON_LOAD_FAILED,
    REASON_UNAVAILABLE,
    ParserGateway,
    line_tokens,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = REPO_ROOT / "tests" / "golden" / "degraded"
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "parsing"

#: engine slot → (gateway language, contract sample). Slots mirror the §4
#: catalog names the AST tasks own; bash upgrades E3's existing line scanner.
ENGINE_SAMPLES: dict[str, tuple[str, str]] = {
    "e4_pyscan": ("python", "sample_skill_main.py"),
    "e5_jsscan": ("javascript", "sample_skill_worker.js"),
    "e3_shellscan_bash": ("bash", "sample_skill_setup.sh"),
}


def _absent_loader(module_name: str) -> object:
    """Simulate BOTH delivery lanes missing (declared + vendored)."""
    raise ImportError(f"simulated absent grammar: no module named {module_name!r}")


def _broken_module_loader(module_name: str) -> object:
    """Simulate the grammar importing but failing to build its Language."""

    def _language() -> object:
        raise RuntimeError("simulated native language() failure")

    return types.SimpleNamespace(language=_language)


def _degraded_surface(engine_slot: str, gateway: ParserGateway, source_text: str) -> str:
    """Serialize the engine-facing degraded surface for one engine slot.

    This IS the line-scanner input contract: mode (never reason), the full
    line-token stream, gateway status, and crash-loop telemetry. Engines
    derive their findings from nothing else in degraded mode.
    """
    language = ENGINE_SAMPLES[engine_slot][0]
    outcome = gateway.parse(language, source_text)
    assert outcome.mode == "degraded", "scenario must simulate degradation"
    assert outcome.tree is None
    health = gateway.health()
    return (
        canonical_dumps(
            {
                "engine_slot": engine_slot,
                "language": language,
                "outcome": {"mode": outcome.mode},
                "line_tokens": line_tokens(source_text),
                "gateway_status": health["languages"][language]["status"],
                "health_status": health["status"],
                "consecutive_failures": health["consecutive_failures"],
            }
        )
        + "\n"
    )


def _surface_bytes(engine_slot: str, loader: Callable[[str], object]) -> tuple[str, str]:
    language, sample = ENGINE_SAMPLES[engine_slot]
    source = (SAMPLES_DIR / sample).read_text(encoding="utf-8")
    gateway = ParserGateway(import_fn=loader)
    return _degraded_surface(engine_slot, gateway, source), outcome_reason(
        gateway, language, source
    )


def outcome_reason(gateway: ParserGateway, language: str, source: str) -> str:
    outcome = gateway.parse(language, source)
    assert outcome.reason is not None
    return outcome.reason


# ---------------------------------------------------------------------------
# The golden assertions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("engine_slot", sorted(ENGINE_SAMPLES))
def test_degraded_surface_matches_golden(engine_slot: str) -> None:
    """Absent vs failed-to-load produce BYTE-IDENTICAL surfaces == golden."""
    absent_bytes, absent_reason = _surface_bytes(engine_slot, _absent_loader)
    failed_bytes, failed_reason = _surface_bytes(engine_slot, _broken_module_loader)

    # Core D-PARSE guarantee: degradation cause is invisible to engines.
    assert absent_bytes == failed_bytes

    golden_path = GOLDEN_DIR / f"{engine_slot}.golden.json"
    assert golden_path.is_file(), f"missing golden contract file {golden_path}"
    expected = golden_path.read_text(encoding="utf-8")
    assert absent_bytes == expected


@pytest.mark.parametrize("engine_slot", sorted(ENGINE_SAMPLES))
def test_reason_telemetry_stays_honest(engine_slot: str) -> None:
    """WHY-telemetry distinguishes absence from load failure (not golden'd).

    Engines must not branch on this; the doctor may report it. Pinning the
    distinction HERE keeps someone from 'simplifying' reasons away silently.
    """
    _, absent_reason = _surface_bytes(engine_slot, _absent_loader)
    _, failed_reason = _surface_bytes(engine_slot, _broken_module_loader)
    assert absent_reason == REASON_UNAVAILABLE
    assert failed_reason == REASON_LOAD_FAILED


@pytest.mark.parametrize("engine_slot", sorted(ENGINE_SAMPLES))
def test_golden_files_carry_real_content(engine_slot: str) -> None:
    """Guard against vacuous goldens: token streams must be non-trivial."""
    payload = (GOLDEN_DIR / f"{engine_slot}.golden.json").read_text(encoding="utf-8")
    assert len(payload) > 800  # full sample tokenized, not a stub
