"""O3 guard + personality defaults — the surfaces that must NOT exist.

HARD_QUESTIONS O3 (owner arbitration 2026-08-23): share cards are REJECTED
outright — no SVG posters, no plates/themes, no ``/lens card``, no
``--card`` flag, no ``card_theme`` setting, in v0.9 or ANY release. This
guard test makes the rejection mechanically checkable: the package source
must never grow card/poster/theme codepaths. Only the owner editing
HARD_QUESTIONS.md revives the feature; if that ever happens, this test is
edited in the SAME commit that builds the surface — never silently.

Also pins the FUN defaults (SPEC §16): voices = clinical+microscopy only
(noir deferred usage-gated per O4), default voice clinical (sober),
discord_spoilers default OFF, kill-switch beats flags.
"""

from __future__ import annotations

from pathlib import Path

from skill_lens.context import PluginContextView
from skill_lens.fun import (
    DEFAULT_VOICE,
    DEFERRED_VOICES,
    VOICES,
    resolve_voice,
    validate_voice_choice,
)
from skill_lens.render import spoiler_wrap
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "skill_lens"

#: Tokens that must never appear in shipped plugin source. Kept precise to
#: avoid false positives on prose comments (e.g. DECISIONS quotes live in
#: *.md, which is out of scope here).
FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "card_theme",
    "--card",
    "--svg",
    "lens card",
    "share_card",
    "share-card",
    '.svg"',
    "'.svg'",
    "render_poster",
    "poster_plate",
)

#: File extensions that could carry image/card artifacts.
FORBIDDEN_SUFFIXES: tuple[str, ...] = (
    ".svg",
    ".png",
    ".jpg",
)


def _package_sources() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


# ---------------------------------------------------------------------------
# O3 guard: card/poster/theme surfaces do not exist
# ---------------------------------------------------------------------------


def test_o3_no_card_poster_theme_codepaths_in_source() -> None:
    """Share cards were CUT outright (HQ O3) — the code must prove it."""
    offenders: list[str] = []
    for path in _package_sources():
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_SUBSTRINGS:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {token!r}")
    assert not offenders, "O3 violation — card/poster/theme surface found:\n" + "\n".join(offenders)


def test_o3_no_image_artifact_files_ship_in_package() -> None:
    """No poster/card image assets travel with the plugin."""
    stray = [
        str(path.relative_to(PACKAGE_ROOT))
        for suffix in FORBIDDEN_SUFFIXES
        for path in PACKAGE_ROOT.rglob(f"*{suffix}")
    ]
    assert not stray


def test_o3_settings_vocabulary_has_no_theme_key() -> None:
    """The settings table must never learn a card_theme-style key."""
    from skill_lens.policy import KNOWN_SETTINGS_KEYS

    for key in KNOWN_SETTINGS_KEYS:
        assert "card" not in key and "theme" not in key and "poster" not in key, key


# ---------------------------------------------------------------------------
# Voice register defaults (SPEC §16 / FUN.md F-1 / HQ O4)
# ---------------------------------------------------------------------------


def test_voice_register_is_exactly_clinical_and_microscopy() -> None:
    """Cap is three forever; v1 ships two; noir stays deferred."""
    assert VOICES == ("clinical", "microscopy")
    assert DEFAULT_VOICE == "clinical"
    assert "noir" in DEFERRED_VOICES
    assert not set(DEFERRED_VOICES) & set(VOICES)


def test_noir_request_is_refused_usage_gated() -> None:
    error = validate_voice_choice("noir")
    assert error is not None
    assert "deferred" in error and "O4" in error
    # Shipped choices pass; junk fails loudly.
    assert validate_voice_choice("clinical") is None
    assert validate_voice_choice("microscopy") is None
    assert validate_voice_choice("camp") is not None


def test_default_voice_resolution_is_clinical_without_any_config() -> None:
    view = PluginContextView(FakePluginContext(data_root=REPO_ROOT / "build-state"))
    voice, notice = resolve_voice(view, None)
    assert voice == "clinical"
    assert notice is None


def test_kill_switch_beats_flags_and_settings(tmp_path: Path) -> None:
    raw = FakePluginContext(data_root=tmp_path)
    raw.set_config("fun.allow_voices", False)
    raw.set_config("voice", "microscopy")
    view = PluginContextView(raw)

    # Setting alone cannot escape the kill-switch…
    voice, notice = resolve_voice(view, None)
    assert voice == "clinical"
    assert notice is None  # silent pin when nothing was requested
    # …and an explicit non-default flag is REFUSED with a notice.
    voice, notice = resolve_voice(view, "microscopy")
    assert voice == "clinical"
    assert notice is not None and "refused" in notice and "kill-switch" in notice
    # Clinical requests stay clean under the switch.
    voice, notice = resolve_voice(view, "clinical")
    assert voice == "clinical" and notice is None


def test_kill_switch_setting_coercion_rejects_junk() -> None:
    from skill_lens.policy import _coerce_setting

    assert _coerce_setting("fun.allow_voices", True) is True
    assert _coerce_setting("fun.allow_voices", False) is False
    assert _coerce_setting("fun.allow_voices", "false") is None  # wrong type ⇒ ignored
    assert _coerce_setting("fun.allow_voices", 0) is None  # strict bool-only (house law)
    assert _coerce_setting("fun.allow_voices", "yes") is None


def test_spoiler_wrap_is_opt_in_marker_only() -> None:
    assert spoiler_wrap("evidence row") == "||evidence row||"
