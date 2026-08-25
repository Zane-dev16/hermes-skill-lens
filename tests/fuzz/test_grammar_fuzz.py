"""Grammar-input fuzz corpus — normative per D-PROC caveat (PLAN §1 P1.5).

Vendored tree-sitter grammars are NATIVE code parsing adversarial bytes
inside the agent process; Python exception isolation cannot catch a
segfault. This harness is the shipped mitigation seam:

- hypothesis-generated adversarial inputs (binary soup, unicode stego
  alphabets, nested/malformed constructs, truncations of valid programs)
  go through :class:`skill_lens.parsing.ParserGateway` for every language;
- NO unhandled exception may escape the gateway (degradation contract);
- each parse is time-bounded (crash/hang detection at test granularity);
- health counters stay consistent (the Phase 4 doctor reads
  ``skill_lens.parsing.health()`` to report parse-crash loops).

Deterministic seam tests below pin counter semantics (increment on
consecutive failures, reset on success) without hypothesis.
"""

from __future__ import annotations

import importlib
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from skill_lens.parsing import (
    DEGRADED_REASONS,
    GRAMMAR_MODULES,
    REASON_TOO_LARGE,
    ParserGateway,
)

# file is tests/fuzz/test_grammar_fuzz.py → parents[2] is the repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "parsing"

#: Per-parse wall-clock ceiling. Tiny adversarial inputs must parse in
#: milliseconds; anything near this bound signals a pathological grammar
#: path (or a wedged native state) and fails the suite.
PARSE_TIME_BOUND_SECONDS = 5.0

_FUZZ_SAMPLES = {
    "python": SAMPLES_DIR / "sample_skill_main.py",
    "javascript": SAMPLES_DIR / "sample_skill_worker.js",
    "bash": SAMPLES_DIR / "sample_skill_setup.sh",
}

# Unicode alphabets chosen to stress E2-adjacent codepoints THROUGH the
# parser lane: zero-width, bidi controls, Tags-block edges, astral planes,
# private use, plus format chars that break naive byte handling.
_SOUP_ALPHABET = (
    "\u200b\u200c\u200d\u200e\u202a\u202e\ufeff\ue000\uf8ff"
    "\U000e0001\U000e007f\U0001f600\u00e9\u4e2d\u6587\t\r\n\x00\\\"'`$();{}[]"
)


def _nested_constructs() -> st.SearchStrategy[bytes]:
    """Deeply nested / malformed source shapes per language family."""
    nesting = st.integers(min_value=0, max_value=64)
    junk = st.text(alphabet=_SOUP_ALPHABET, max_size=64)
    shapes = (
        st.tuples(nesting, junk, nesting).map(lambda t: ("(" * t[0]) + t[1] + (")" * t[2])),
        st.tuples(nesting, junk).map(
            lambda t: "def f():\n" + ("    if x:\n" * t[0]) + "        " + t[1]
        ),
        st.tuples(nesting, junk).map(lambda t: "function f(){" * max(1, t[0] // 4 + 1) + t[1]),
        st.tuples(junk, nesting).map(lambda t: t[0] + " | sh #curl" + ("\\" * t[1])),
    )
    return st.one_of(shapes).map(lambda s: s.encode("utf-8", "ignore"))


def _truncated_valid_programs() -> st.SearchStrategy[bytes]:
    """Random prefixes of valid programs (mid-token truncation included)."""
    cut = st.integers(min_value=0, max_value=800)

    def _slice(pair: tuple[str, int]) -> bytes:
        text, n = pair
        return text.encode("utf-8")[:n]

    return st.tuples(
        st.sampled_from([p.read_text(encoding="utf-8") for p in sorted(_FUZZ_SAMPLES.values())]),
        cut,
    ).map(_slice)


def _adversarial_bytes() -> st.SearchStrategy[bytes]:
    return st.one_of(
        st.binary(max_size=2048),  # raw binary soup
        st.text(alphabet=_SOUP_ALPHABET, max_size=512).map(lambda s: s.encode("utf-8", "ignore")),
        _nested_constructs(),
        _truncated_valid_programs(),
    )


def _assert_outcome_wellformed(gateway: ParserGateway, language: str, data: bytes) -> None:
    outcome = gateway.parse(language, data)
    assert outcome.mode in ("ast", "degraded")
    assert outcome.language == language
    if outcome.mode == "degraded":
        assert outcome.tree is None
        assert outcome.reason in DEGRADED_REASONS
    else:
        assert outcome.tree is not None
        assert outcome.reason is None


@pytest.mark.parametrize("language", sorted(GRAMMAR_MODULES))
@settings(max_examples=60, deadline=None)
@given(_adversarial_bytes())
def test_fuzz_no_exception_escapes_and_time_bounded(language: str, data: bytes) -> None:
    """No input may raise out of the gateway; every parse stays bounded."""
    gateway = ParserGateway()
    start = time.perf_counter()
    _assert_outcome_wellformed(gateway, language, data)
    elapsed = time.perf_counter() - start
    assert elapsed < PARSE_TIME_BOUND_SECONDS, (
        f"{language} parse of {len(data)}B took {elapsed:.3f}s (bound {PARSE_TIME_BOUND_SECONDS}s)"
    )
    # Health consistency after exactly one attempt on a fresh gateway.
    failures = gateway.health()["consecutive_failures"][language]
    status = gateway.status(language)
    assert (status == "active") == (failures == 0)


@pytest.mark.parametrize("language", sorted(GRAMMAR_MODULES))
def test_fuzz_corpus_smoke(language: str) -> None:
    """The deterministic slice of the corpus always runs (CI floor)."""
    gateway = ParserGateway()
    for sample in sorted(_FUZZ_SAMPLES.values()):
        data = sample.read_bytes()
        start = time.perf_counter()
        _assert_outcome_wellformed(gateway, language, data)
        assert time.perf_counter() - start < PARSE_TIME_BOUND_SECONDS


# ---------------------------------------------------------------------------
# Crash-loop seam (deterministic; doctor contract)
# ---------------------------------------------------------------------------


def _always_import_error(module_name: str) -> object:
    raise ImportError(f"no module named {module_name!r}")


def test_crash_loop_counters_increment_then_reset() -> None:
    """Consecutive failures climb per failed parse; success resets to 0."""
    gateway = ParserGateway(import_fn=_always_import_error)
    for expected in (1, 2, 3):
        outcome = gateway.parse("python", b"x = 1\n")
        assert outcome.reason == "grammar-unavailable"
        assert gateway.health()["consecutive_failures"]["python"] == expected
    assert gateway.health()["status"] == "degraded"

    gateway._import_fn = importlib.import_module  # lane 'recovers'
    outcome = gateway.parse("python", b"x = 1\n")
    assert outcome.mode == "ast"
    assert gateway.health()["consecutive_failures"]["python"] == 0
    assert gateway.health()["languages"]["python"]["status"] == "active"


def test_oversize_input_degrades_without_native_attempt() -> None:
    """The size ceiling degrades WITHOUT touching grammar state/counters."""
    gateway = ParserGateway(import_fn=_always_import_error, max_bytes=8)
    outcome = gateway.parse("python", b"0123456789")
    assert outcome.mode == "degraded"
    assert outcome.reason == REASON_TOO_LARGE
    health = gateway.health(probe=False)  # observe state, no probing side-effect
    assert health["consecutive_failures"]["python"] == 0  # never attempted
    assert health["languages"]["python"] == {"status": "unprobed", "reason": None}
