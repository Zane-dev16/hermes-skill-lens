"""Parser gateway — tree-sitter delivery lane with first-class degradation.

D-PARSE disposition (PLAN §0/§1 Phase 1.5): the tree-sitter lane is dual —

1. **Declared lane (primary):** grammar packages are declared in
   ``plugin.yaml`` ``python_dependencies``. Ground truth
   (``hermes_cli/plugins.py::_warn_python_dependencies``, lines 4679-4720,
   invoked at line 4027): the host validates and warns-but-continues; it
   NEVER auto-installs. A host venv without the grammars is an expected,
   supported state — not an error.
2. **Vendored lane (fallback):** built wheels travel in the repo under
   ``wheels/`` (platform-clean: cp313 core + cp310-abi3 grammars). When a
   plain import fails, :func:`ensure_vendored_wheels` SHA256-verifies each
   pinned wheel, extracts it to a local cache dir, and appends the dir to
   ``sys.path`` so the native bindings import. Local-only: no network is
   touched at runtime (grammar bytes ride the git install).

:class:`ParserGateway` lazily loads one grammar per language and NEVER lets
a grammar failure raise into engines: every failure collapses to a
degraded :class:`ParseOutcome` carrying a stable reason code. Degraded mode
is first-class output, not shadow mode — the line-scanner fallback contract
is golden-tested in ``tests/golden/degraded/`` so engine output is
byte-identical whether a grammar was never installed or failed to load.

Crash-loop seam (D-PROC caveat): vendored grammars are NATIVE code parsing
adversarial bytes inside the agent process; Python exception isolation
(``skill_lens.engines.base.run_engine``) cannot catch a segfault.
Mitigations shipped here: grammar-input fuzzing is normative
(``tests/fuzz/test_grammar_fuzz.py``), per-language consecutive-failure
counters are exposed via :func:`health` for the Phase 4 doctor to report,
and **subprocess parse-isolation remains the documented v1.0 escape hatch**
(each parse dispatched to a short-lived worker process so a native crash
kills the worker, not the agent; cost = IPC + cold grammar load per call,
so it stays opt-in until field data demands it).

DETERMINISM LAW: parsing is local-only and pure — same source bytes plus
same grammar availability give the same outcome. Failure counters are
process telemetry for the doctor; they never enter findings, scores, or
fingerprints.
"""

from __future__ import annotations

import hashlib
import importlib
import sys
import tempfile
import threading
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Languages the gateway can front. Keys are the stable engine-facing names;
#: values are the official binding module names (PyPI ``tree-sitter-*``).
GRAMMAR_MODULES: dict[str, str] = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "bash": "tree_sitter_bash",
}

#: Stable degraded-mode reason codes (engine-facing contract; goldens pin
#: everything EXCEPT these — reasons are honest WHY-telemetry and may
#: legitimately differ between "never installed" and "failed to load").
REASON_UNAVAILABLE = "grammar-unavailable"  # import failed on both lanes
REASON_LOAD_FAILED = "grammar-load-failed"  # imported but Language() build raised
REASON_PARSE_FAILED = "parser-failed"  # Parser()/parse() raised at use time
REASON_TOO_LARGE = "input-too-large"  # defensive ceiling, not a grammar failure

DEGRADED_REASONS = frozenset(
    {REASON_UNAVAILABLE, REASON_LOAD_FAILED, REASON_PARSE_FAILED, REASON_TOO_LARGE}
)

#: Mirrors the ingest single-file projection ceiling (engines/base.py): the
#: gateway refuses native parses beyond what ingest could have recorded.
MAX_PARSE_BYTES = 16 * 1024 * 1024

# Vendored-wheel fallback (delivery lane 2) -------------------------------

_WHEELS_DIR = Path(__file__).resolve().parent.parent / "wheels"

#: SHA256 pins for every wheel we ship (supply-chain hygiene, PLAN risk 9
#: posture): a wheel that does not match its pin is skipped, never executed.
# (wheel filename, SHA256) pairs — filenames are too long for dict-literal
# keys within the 100-col law, so the pin table stays a sorted tuple list.
_WHEEL_SHA256: tuple[tuple[str, str], ...] = (
    (
        "tree_sitter-0.26.0-cp313-cp313-manylinux2014_x86_64"
        ".manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
        "7075ef857ef86f327dbb72d1e2574dda78db5754b3a1fca6506acd7fe5d561a7",
    ),
    (
        "tree_sitter_python-0.25.0-cp310-abi3-manylinux1_x86_64"
        ".manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl",
        "86f118e5eecad616ecdb81d171a36dde9bef5a0b21ed71ea9c3e390813c3baf5",
    ),
    (
        "tree_sitter_javascript-0.25.0-cp310-abi3-manylinux1_x86_64"
        ".manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl",
        "9dc04ba91fc8583344e57c1f1ed5b2c97ecaaf47480011b92fbeab8dda96db75",
    ),
    (
        "tree_sitter_bash-0.25.1-cp310-abi3-manylinux2014_x86_64"
        ".manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
        "3f484c4bb8796cde7a87ca351e6116f09653edac0eb3c6d238566359dd28b117",
    ),
)

_vendor_lock = threading.Lock()
_vendor_done = False


def ensure_vendored_wheels(
    wheels_dir: Path = _WHEELS_DIR, cache_root: Path | None = None
) -> list[Path]:
    """Extract repo-vendored wheels and append them to ``sys.path``.

    Best-effort and idempotent (per process, per default cache root); runs
    only when the declared lane already failed to import. Each wheel is
    extracted once into a shared temp-dir cache (native ``.so`` files need
    real files — zipimport cannot load extensions), keyed by wheel name and
    verified against its SHA256 pin. Returns the paths appended by THIS or
    any earlier call; [] when the vendored lane is unusable (missing wheels /
    hash mismatch / unwritable cache). Never raises.
    """
    global _vendor_done
    appended: list[Path] = []
    with _vendor_lock:
        if _vendor_done:
            return []
        try:
            root = cache_root or Path(tempfile.gettempdir()) / "skill-lens-wheel-cache"
            appended = _extract_wheels(wheels_dir, root)
        except Exception:  # noqa: BLE001 — fallback lane must never raise
            return []
        else:
            _vendor_done = True
    return appended


def _extract_wheels(wheels_dir: Path, cache_root: Path) -> list[Path]:
    """Verify + extract every pinned wheel found in ``wheels_dir``.

    Testable core of :func:`ensure_vendored_wheels` (injectable dirs; no
    process-global state). Hash-mismatched wheels are skipped, never executed.
    """
    appended: list[Path] = []
    cache_root.mkdir(parents=True, exist_ok=True)
    for name, digest in sorted(_WHEEL_SHA256):
        wheel = wheels_dir / name
        if not wheel.is_file():
            continue
        target = cache_root / wheel.stem
        marker = target / ".extracted"
        if not marker.is_file():
            if _sha256(wheel) != digest:
                continue  # tampered/unexpected wheel: skip, never execute
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(wheel) as zf:
                zf.extractall(target)
            marker.write_text(digest + "\n", encoding="utf-8")
        if str(target) not in sys.path:
            sys.path.append(str(target))
            appended.append(target)
    return appended


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


# Gateway -----------------------------------------------------------------


@dataclass(frozen=True)
class ParseOutcome:
    """Result of one gateway parse — safe to hand straight to an engine.

    ``mode`` is ``"ast"`` (``tree`` holds a ``tree_sitter.Tree``) or
    ``"degraded"`` (``tree`` is None and ``reason`` carries one of
    :data:`DEGRADED_REASONS`). Engines branch on ``outcome.mode`` /
    ``outcome.tree is None`` and run their golden-tested line scanner in
    the degraded branch; they must NOT branch on the reason code.
    """

    language: str
    mode: str  # "ast" | "degraded"
    tree: Any | None  # tree_sitter.Tree when active (typed Any: optional dep)
    reason: str | None  # degraded reason code; None when ast


@dataclass
class _LanguageState:
    status: str = "unprobed"  # unprobed | active | degraded
    reason: str | None = None
    consecutive_failures: int = 0
    grammar: Any | None = None  # tree_sitter.Language when active


class ParserGateway:
    """Lazy per-language tree-sitter loader; failures degrade, never raise.

    One instance per scan keeps failure counters scoped (the corpus harness
    constructs fresh gateways; production shares :data:`GATEWAY`). All
    public methods are exception-safe: the worst outcome is a degraded
    status/outcome, matching the D-CRASH containment posture one layer up.
    """

    def __init__(
        self,
        import_fn: Callable[[str], object] | None = None,
        max_bytes: int = MAX_PARSE_BYTES,
    ) -> None:
        self._import_fn = import_fn or importlib.import_module
        self._max_bytes = max_bytes
        self._states: dict[str, _LanguageState] = {
            name: _LanguageState() for name in GRAMMAR_MODULES
        }
        self._lock = threading.Lock()

    # -- probing / loading -------------------------------------------------

    def _load(self, language: str) -> _LanguageState:
        """(Re)attempt the full load ladder for one language. Never raises."""
        state = self._states[language]
        module_name = GRAMMAR_MODULES[language]
        module = None
        try:
            module = self._import_fn(module_name)
        except ImportError:
            # Declared lane absent → try the vendored-wheel lane once per
            # process, then re-attempt the import from the appended paths.
            ensure_vendored_wheels()
            try:
                module = self._import_fn(module_name)
            except ImportError:
                state.status, state.reason, state.grammar = (
                    "degraded",
                    REASON_UNAVAILABLE,
                    None,
                )
                state.consecutive_failures += 1
                return state
        except Exception:  # noqa: BLE001 — any loader blow-up degrades
            state.status, state.reason, state.grammar = (
                "degraded",
                REASON_LOAD_FAILED,
                None,
            )
            state.consecutive_failures += 1
            return state
        try:
            language_obj = _build_language(module)
            state.status, state.reason = "active", None
            state.grammar = language_obj
            state.consecutive_failures = 0
        except Exception:  # noqa: BLE001 — ABI drift / broken binding degrades
            state.status, state.reason, state.grammar = (
                "degraded",
                REASON_LOAD_FAILED,
                None,
            )
            state.consecutive_failures += 1
        return state

    def _state_for_use(self, language: str) -> _LanguageState:
        state = self._states[language]
        if state.status != "active":
            with self._lock:
                if self._states[language].status != "active":
                    state = self._load(language)
        return state

    # -- public surface ----------------------------------------------------

    def parse(self, language: str, source: bytes | str) -> ParseOutcome:
        """Parse ``source``, degrading instead of raising on any failure."""
        if language not in GRAMMAR_MODULES:
            raise ValueError(f"unknown parser language: {language!r}")
        if isinstance(source, str):
            source = source.encode("utf-8")
        if len(source) > self._max_bytes:
            return ParseOutcome(language, "degraded", None, REASON_TOO_LARGE)
        state = self._state_for_use(language)
        if state.status != "active":
            return ParseOutcome(language, "degraded", None, state.reason)
        try:
            # Dynamic import: tree-sitter is an optional dependency and the
            # degraded contract must hold when it is absent entirely.
            tree_sitter = importlib.import_module("tree_sitter")

            parser = tree_sitter.Parser(state.grammar)
            tree = parser.parse(source)
        except Exception:  # noqa: BLE001 — use-time failure degrades + counts
            with self._lock:
                state.status, state.reason, state.grammar = (
                    "degraded",
                    REASON_PARSE_FAILED,
                    None,
                )
                state.consecutive_failures += 1
            return ParseOutcome(language, "degraded", None, REASON_PARSE_FAILED)
        with self._lock:
            state.consecutive_failures = 0
        return ParseOutcome(language, "ast", tree, None)

    def status(self, language: str) -> str:
        """``"active"`` | ``"degraded"`` for one language (probes lazily)."""
        if language not in GRAMMAR_MODULES:
            raise ValueError(f"unknown parser language: {language!r}")
        state = self._states[language]
        if state.status == "unprobed":
            with self._lock:
                state = self._states[language]
                if state.status == "unprobed":
                    self._load(language)
        return self._states[language].status

    def health(self, *, probe: bool = True) -> dict[str, Any]:
        """Doctor-facing snapshot (Phase 4 check 8 reads this).

        ``{"status": overall, "languages": {name: {"status", "reason"}},
        "consecutive_failures": {name: n}}`` where overall is ``active``
        iff every language is active. Counters rise on consecutive failed
        attempts and reset on any success — a crash-loop signature without
        any auto-disabling (retry-every-call keeps outcomes deterministic).

        ``probe=True`` (default) lazily loads unprobed grammars so the
        doctor reports ground truth; ``probe=False`` observes cached state
        WITHOUT side effects (unprobed languages report status
        ``"unprobed"`` and count toward a conservative overall
        ``"degraded"``).
        """
        languages: dict[str, dict[str, Any]] = {}
        failures: dict[str, int] = {}
        for name in GRAMMAR_MODULES:
            st = self.status(name) if probe else self._states[name].status
            state = self._states[name]
            languages[name] = {"status": st, "reason": state.reason}
            failures[name] = state.consecutive_failures
        overall = (
            "active" if all(v["status"] == "active" for v in languages.values()) else "degraded"
        )
        return {
            "status": overall,
            "languages": languages,
            "consecutive_failures": failures,
        }


def _build_language(module: object) -> Any:
    """Build a ``tree_sitter.Language`` from an official binding module.

    Handles the modern capsule-returning ``language()`` API (0.22+); older
    pointer-based bindings degrade upstream via the caller's except.
    """
    getter = getattr(module, "language", None)
    if getter is None:
        raise AttributeError(f"{getattr(module, '__name__', module)} exposes no language()")
    tree_sitter = importlib.import_module("tree_sitter")
    return tree_sitter.Language(getter())


#: Process-wide gateway (production default; tests construct fresh ones).
GATEWAY = ParserGateway()


def health() -> dict[str, Any]:
    """Module-level doctor seam: ``ParserGateway.health()`` of :data:`GATEWAY`."""
    return GATEWAY.health()


# Degraded-mode substrate --------------------------------------------------


def line_tokens(text: str) -> list[dict[str, Any]]:
    """The shared line-scanner substrate degraded engines consume.

    Contract (golden-pinned, byte-stable): one token per physical line,
    keys ``line`` (1-based), ``indent`` (count of leading spaces/tabs),
    ``text`` (verbatim content sans line terminators). E3/E4/E5 fallbacks
    match their sink patterns over ``token["text"]`` ONLY — no regex over
    whole files, no AST assumptions — so degraded findings derive entirely
    from this stream and stay byte-identical across degradation causes.
    """
    tokens: list[dict[str, Any]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = len(raw) - len(raw.lstrip(" \t"))
        tokens.append({"line": number, "indent": stripped, "text": raw})
    return tokens
