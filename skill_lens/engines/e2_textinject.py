"""E2 textinject engine — pure-Python Unicode/ghost-stream/injection scan.

Detection per core-pack rule specs (rule YAMLs are normative; SPEC §4 row E2;
§17 rows R1/R2/R7/H1/H2/H7). Scope is EVERY decodable text view in the IR
("all decoded text views"), scanned through :func:`iter_text_files` in IR
order. Closes the gap the Hermes host guard leaves open beyond its 18
invisible characters: this engine's class set is wider (Tags block, word
joiner, bidi isolates, mid-file BOM/ZWNBSP) AND it decodes what it finds.

**No grammar dependency — degraded mode IS the primary mode.** Every other
AST engine branches on a ``ParserGateway.parse`` outcome because parse TREES
carry their evidence. E2's evidence is codepoint classes and byte patterns:
binary facts of the decoded text that no grammar lane produces or could
improve. There is therefore nothing to degrade — the same scanner runs in
every environment, which is why ``scan()`` has no AST/degraded split at all.
The engine still carries the uniform gateway constructor seam and answers
the doctor's health surface through it (probe=False, cached state only) so
Phase 4 can report every engine slot uniformly; gateway status can NEVER
gate, alter, or annotate E2 findings (asserted by tests).

Rule map (ids owned here):

- **LNS-TXT-001** hidden Unicode steganography channel: zero-width
  (U+200B–U+200D), word joiner U+2060, mid-text BOM U+FEFF, direction
  marks/overrides U+200E/U+200F + U+202A–U+202E + U+2066–U+2069, and the
  Tags block U+E0000–U+E007F. Presence is MEDIUM (a binary fact; lone paste
  artifacts exist). Engine-side escalation to effective HIGH when the
  channel is IN ACTIVE USE: a Tags payload decodes to instruction-bearing
  ASCII, or a bidi control sits between non-space chars mid-line (the RLO
  filename/command spoofing shape). Sanctioned uses never fire: BOM at text
  start, ZWJ between astral emoji (emoji ZWJ sequences), variation
  selectors (out of scope entirely), ZWNJ inside Indic/Arabic typography.
- **LNS-TXT-002** homoglyph/confusable impersonation (TR39-style skeleton):
  a token whose skeleton equals a protected vocabulary term (persona
  basenames, agent identity words) while differing from it raw, or a single
  token mixing Latin with Cyrillic/Greek letters. Skeleton = NFKC →
  casefold → hand-curated confusable map (DECISIONS D-037 cites sources).
- **LNS-TXT-003** terminal escape-sequence covert channels: OSC (incl. 8
  hyperlinks / 777 notifications), DCS, APC, PM, SOS packet injection per
  SPEC ghost-text stream. Cosmetic SGR color (CSI … m) stays exempt —
  colored CLI output is ordinary; smuggling data through non-printing
  terminal channels is not.
- **LNS-TXT-004** prompt-injection grammar: chat-template role-tag spoofing
  (``<|im_start|>``, ``[INST]``, ``<<SYS>>``, tool-call tags), fake system
  prompt constructions, override imperatives ("ignore previous
  instructions"), and extraction demands. MEDIUM uncorroborated cap (§4:
  instruction semantics capped MED without corroboration).
- **LNS-TXT-005** self-state instructional directives: imperative prose
  variants targeting agent self-state ("edit your SOUL", "remember that you
  must…", "create a cron job that…") at the §17 prose band (conf ≤0.55,
  static) — sink-side writes remain E3/E4/E5 territory.

Views scanned (SPEC §5.1 decode ladder): the RAW lines, the CLEAN view
(invisible codepoints stripped), and the DECODED ghost payload (Tags-block
codepoints mapped back to ASCII). Identical normalized evidence across views
collapses via shared fingerprints — hiding an instruction by splitting it
with zero-width chars changes WHERE it hides, not whether it is found.

SANITIZATION LAW: findings are report cargo, so every snippet/message/
evidence string passes :func:`safe_text` — each Cc/Cf/Co/Cs codepoint is
replaced by its ``\\uXXXX`` ASCII escape BEFORE any Finding exists. No raw
control, format, surrogate, or private-use byte can reach canonical JSON
(proven per-run by the test suite).

DETERMINISM LAW: evidence tokens carry shapes/classes/basenames only — no
line numbers, no absolute paths, no wall-clock. Findings sort by
``(rule_id, path, start_line)``; fingerprints stay stable across line shifts.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

from skill_lens.claims import finding_fingerprint, is_declared
from skill_lens.engines.base import (
    Finding,
    Location,
    ScanContext,
    claimed_capability_paths,
    current_context,
    iter_text_files,
)
from skill_lens.ir import SkillIR
from skill_lens.parsing import GATEWAY, ParserGateway

if TYPE_CHECKING:
    from skill_lens.rules import Rule

#: Engine catalog binding (SPEC §4). REGISTRY keys must equal this.
ENGINE_NAME = "textinject"

RULE_IDS: tuple[str, ...] = (
    "LNS-TXT-001",
    "LNS-TXT-002",
    "LNS-TXT-003",
    "LNS-TXT-004",
    "LNS-TXT-005",
)

#: Escalated effective severity for TXT-001 when the covert channel is in
#: active use (decoded-instruction payload or inline bidi spoofing).
ESCALATED_SEVERITY = "HIGH"

_SNIPPET_MAX = 200


# ---------------------------------------------------------------------------
# Invisible-codepoint classes (SPEC §4 row E2 + task mandate)
# ---------------------------------------------------------------------------

#: Codepoint ranges treated as invisible-channel suspects, with stable
#: class tokens used in evidence/fingerprints. Order matters only for the
#: histogram sort (sorted at emission).
CLASS_ZWSP = "zwsp"  # U+200B zero-width space
CLASS_ZWNJ = "zwnj"  # U+200C zero-width non-joiner (typographic exemptions apply)
CLASS_ZWJ = "zwj"  # U+200D zero-width joiner OUTSIDE emoji-join position
CLASS_WJ = "wj"  # U+2060 word joiner
CLASS_BOM = "bom"  # U+FEFF ZERO WIDTH NO-BREAK SPACE past position 0
CLASS_LRM = "lrm"  # U+200E LEFT-TO-RIGHT MARK
CLASS_RLM = "rlm"  # U+200F RIGHT-TO-LEFT MARK
CLASS_BIDI = "bidi"  # U+202A–U+202E overrides/embeds
CLASS_ISOLATE = "isolate"  # U+2066–U+2069 directional isolates
CLASS_TAGS = "tags"  # U+E0000–U+E007F Tags block (stego channel)

#: Single source of truth: class token -> sorted tuple of codepoint ranges.
INVISIBLE_CLASSES: dict[str, tuple[tuple[int, int], ...]] = {
    CLASS_ZWSP: ((0x200B, 0x200B),),
    CLASS_ZWNJ: ((0x200C, 0x200C),),
    CLASS_ZWJ: ((0x200D, 0x200D),),
    CLASS_WJ: ((0x2060, 0x2060),),
    CLASS_BOM: ((0xFEFF, 0xFEFF),),
    CLASS_LRM: ((0x200E, 0x200E),),
    CLASS_RLM: ((0x200F, 0x200F),),
    CLASS_BIDI: ((0x202A, 0x202E),),
    CLASS_ISOLATE: ((0x2066, 0x2069),),
    CLASS_TAGS: ((0xE0000, 0xE007F),),
}

_CLASS_OF: dict[int, str] = {
    cp: klass
    for klass, ranges in INVISIBLE_CLASSES.items()
    for lo, hi in ranges
    for cp in range(lo, hi + 1)
}

_TAGS_LO, _TAGS_HI = 0xE0000, 0xE007F

#: Emoji-join position: both neighbors astral (>= U+1F000). Covers ZWJ
#: emoji sequences (families, professions, flags-with-keycaps) exactly.
_EMOJI_FLOOR = 0x1F000

#: Scripts whose orthographies legitimately use ZWNJ between letters
#: (typographic exemption; narrow by design).
_ZWNJ_SCRIPT_RANGES: tuple[tuple[int, int], ...] = (
    (0x0600, 0x06FF),  # Arabic
    (0x0590, 0x05FB),  # Hebrew
    (0x0900, 0x097F),  # Devanagari
    (0x0980, 0x09FF),  # Bengali
    (0x0A00, 0x0A7F),  # Gurmukhi
    (0x0A80, 0x0AFF),  # Gujarati
    (0x0B00, 0x0B7F),  # Oriya
    (0x0B80, 0x0BFF),  # Tamil
    (0x0C00, 0x0C7F),  # Telugu
    (0x0C80, 0x0CFF),  # Kannada
    (0x0D00, 0x0D7F),  # Malayalam
    (0x1800, 0x18AA),  # Mongolian
)


def classify_codepoint(cp: int) -> str | None:
    """Stable class token for one codepoint, or ``None`` when unsuspicious."""
    return _CLASS_OF.get(cp)


def _in_ranges(cp: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _emoji_side(line: str, idx: int, step: int) -> bool:
    """Does the neighbor at ``idx + step`` (skipping variation selectors)
    reach astral emoji range? VS16/VS15 join sequences like the rainbow
    flag (U+1F3F3 U+FE0F U+200D U+1F308) count as emoji joins."""
    pos = idx + step
    if not 0 <= pos < len(line):
        return False
    ch = line[pos]
    if ch in "\ufe0e\ufe0f":
        pos += step
        if not 0 <= pos < len(line):
            return False
        ch = line[pos]
    return ord(ch) >= _EMOJI_FLOOR


def _is_emoji_join(line: str, idx: int) -> bool:
    """ZWJ sanctioned position: BOTH neighbors astral emoji (VS-skipping)."""
    return _emoji_side(line, idx, -1) and _emoji_side(line, idx, 1)


def _is_typographic_zwnj(prev: str, nxt: str) -> bool:
    """ZWNJ sanctioned position: between letters of the same exempt script."""
    if not prev or not nxt:
        return False
    for lo, hi in _ZWNJ_SCRIPT_RANGES:
        if lo <= ord(prev) <= hi:
            return lo <= ord(nxt) <= hi
    return False


def sanitize_invisible(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(line_no, col, class_token)`` for every counted codepoint.

    Sanctioned positions are skipped HERE so callers see exactly the set
    that counts toward findings: BOM only past text position 0, emoji-join
    ZWJ, typographic ZWNJ. Deterministic left-to-right sweep.

    PERF (Phase 3 budgets): every counted codepoint lives at ≥ U+200B
    (INVISIBLE_CLASSES is the single source), so pure-ASCII text can never
    yield — skip the O(bytes) Python-level sweep entirely. Output-identical
    by construction; vectors/corpus goldens pin the equivalence empirically.
    """
    if text.isascii():
        return
    first = True
    for line_no, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line):
            klass = _CLASS_OF.get(ord(ch))
            if klass is None:
                continue
            prev = line[col - 1] if col > 0 else ""
            nxt = line[col + 1] if col + 1 < len(line) else ""
            if ch == "\ufeff":
                if first and col == 0:
                    continue  # BOM heading the decoded text is legitimate
                klass = CLASS_BOM
            elif ch == "\u200d":
                if _is_emoji_join(line, col):
                    continue
            elif ch == "\u200c":
                if _is_typographic_zwnj(prev, nxt):
                    continue
            yield line_no, col, klass
        first = False


def strip_invisible(text: str) -> str:
    """The CLEAN view: every counted invisible codepoint removed (§5.1)."""
    counted = {(line_no, col) for line_no, col, _ in sanitize_invisible(text)}
    if not counted:
        return text
    out_lines: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        kept = [ch for col, ch in enumerate(line) if (line_no, col) not in counted]
        out_lines.append("".join(kept))
    return "\n".join(out_lines)


def ghost_stream(text: str) -> str:
    """The GHOST view: extracted invisible codepoints, in order (§5.1).

    Same ASCII short-circuit as :func:`sanitize_invisible` — no counted
    codepoint is ASCII, so an ASCII input always extracts to ``""``.
    """
    if text.isascii():
        return ""
    ordered: list[tuple[tuple[int, int], str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line):
            if ord(ch) in _CLASS_OF:
                ordered.append(((line_no, col), ch))
    ordered.sort(key=lambda item: item[0])
    return "".join(ch for _, ch in ordered)


def decode_tags_payload(text: str) -> str:
    """ASCII decoded from Tags-block codepoints (U+E0000..U+E007F → 0..0x7F).

    Non-ASCII results (NUL, control rows) are dropped; printable runs below
    :data:`_MIN_DECODED_RUN` are noise, not a channel, and come back empty.

    PERF: the Tags block sits at U+E0000+, so ASCII input can never decode
    to anything — skip the per-character sweep (output-identical shortcut).
    """
    if text.isascii():
        return ""
    raw = "".join(chr(ord(ch) - 0xE0000) for ch in text if _TAGS_LO <= ord(ch) <= _TAGS_HI)
    printable = "".join(ch for ch in raw if 0x20 <= ord(ch) <= 0x7E)
    runs = [run.strip() for run in re.split(r"\s{2,}", printable)]
    kept = [run for run in runs if len(run) >= _MIN_DECODED_RUN]
    return " ".join(kept)


_MIN_DECODED_RUN = 4


# ---------------------------------------------------------------------------
# SANITIZATION LAW — rendered-safe evidence
# ---------------------------------------------------------------------------


def safe_text(value: str) -> str:
    """Escape every non-renderable codepoint as ASCII ``\\uXXXX`` text.

    Covers Cc (controls), Cf (format/invisible), Co (private use — the Tags
    block), and Cs (surrogates); DEL 0x7F included explicitly. Applied to
    EVERY snippet, message, and evidence string this engine emits, so no
    raw control byte can reach canonical JSON (test-proven per run).
    """
    out: list[str] = []
    for ch in value:
        cp = ord(ch)
        if cp == 0x7F or unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs"}:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _snippet(raw_line: str) -> str:
    return safe_text(raw_line.strip())[:_SNIPPET_MAX]


# ---------------------------------------------------------------------------
# LNS-TXT-002 — TR39-style confusable skeleton (subset table; D-037)
# ---------------------------------------------------------------------------

#: Hand-curated lookalike → Latin skeleton mapping. Sources: the Unicode
#: Consortium ``confusables.txt`` intent (UCD security data), restricted to
#: the Cyrillic/Greek/fullwidth letters that actually appear in homoglyph
#: attacks against Latin identifiers. Fullwidth forms collapse earlier via
#: NFKC, so the table only needs script-mixed lookalikes.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "ԁ": "d",
    "ɡ": "g",
    "Ь": "b",
    "К": "k",
    "М": "m",
    "Н": "h",
    "Т": "t",
    "В": "b",
    "А": "a",
    "Е": "e",
    "О": "o",
    "Р": "p",
    "С": "c",
    "У": "y",
    "Х": "x",
    "Ѕ": "s",
    "Ј": "j",
    "І": "i",
    # Greek
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "ς": "s",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "Α": "a",
    "Β": "b",
    "Ε": "e",
    "Ζ": "z",
    "Η": "h",
    "Ι": "i",
    "Κ": "k",
    "Μ": "m",
    "Ν": "n",
    "Ο": "o",
    "Ρ": "p",
    "Τ": "t",
    "Υ": "y",
    "Χ": "x",
}

_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

#: Protected vocabulary (lowercase): persona basenames §17 H1/H2 + identity
#: terms an injected prompt would impersonate. Skeleton hits against these
#: while raw differs = impersonation.
PROTECTED_VOCAB: frozenset[str] = frozenset(
    {
        "soul.md",
        "agents.md",
        "claude.md",
        ".cursorrules",
        ".hermes.md",
        "memory.md",
        "user.md",
        "system",
        "assistant",
        "developer",
        "administrator",
        "hermes",
    }
)

_TOKEN_RE = re.compile(r"[^\W_]+(?:[.\-/][^\W_]+)*", re.UNICODE)
_LATIN_RE = re.compile(r"[A-Za-z]")
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
_GREEK_RE = re.compile(r"[\u0370-\u03FF]")


def skeleton(token: str) -> str:
    """TR39-style skeleton (subset): NFKC → casefold → confusable map."""
    return unicodedata.normalize("NFKC", token).casefold().translate(_CONFUSABLE_TABLE)


def confusable_hits(line: str) -> list[tuple[str, str]]:
    """``(raw_token, vocab_term)`` impersonation pairs on one line (stable)."""
    hits: list[tuple[str, str]] = []
    for token in _TOKEN_RE.findall(line):
        folded = skeleton(token)
        if folded != token.casefold() and folded in PROTECTED_VOCAB:
            hits.append((token, folded))
        elif _LATIN_RE.search(token) and (_CYRILLIC_RE.search(token) or _GREEK_RE.search(token)):
            # Mixed-script identifier (Latin + Cyrillic/Greek in ONE token):
            # the classic homoglyph attack marker even without a vocab match.
            hits.append((token, "*mixed-script*"))
    return hits


# ---------------------------------------------------------------------------
# LNS-TXT-003 — terminal escape-sequence covert channels
# ---------------------------------------------------------------------------

_ESC = "\x1b"
#: OSC ... BEL | OSC ... ST (incl. OSC 8 hyperlinks, OSC 777 notify)
_OSC_RE = re.compile(r"\x1b\]([^\x07\x1b]*)(?:\x07|\x1b\\)")
#: DCS / APC / PM / SOS packet bodies ... ST
_PACKET_RE = re.compile(r"\x1b[P_^X]([^\x1b]*)\x1b\\")
_OSC_NUMBER_RE = re.compile(r"^(\d+)[;:]?")


def escape_channel_hits(text: str) -> list[tuple[int, str]]:
    """``(line_no, evidence_token)`` per covert terminal sequence (stable).

    Line attribution = the line where the sequence STARTS. Evidence carries
    the channel kind + numeric OSC selector when parsable — shapes only,
    never packet body bytes (those may hide instructions; the body is run
    through the injection grammars instead, and only its verdict recorded).
    """
    hits: list[tuple[int, str]] = []

    def line_of(offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    for match in _OSC_RE.finditer(text):
        number = _OSC_NUMBER_RE.match(match.group(1))
        selector = number.group(1) if number else "?"
        hits.append((line_of(match.start()), f"osc:{selector}"))
    for match in _PACKET_RE.finditer(text):
        kind = {
            _ESC + "P": "dcs",
            _ESC + "_": "apc",
            _ESC + "^": "pm",
            _ESC + "X": "sos",
        }.get(text[match.start() : match.start() + 2], "packet")
        hits.append((line_of(match.start()), kind))
    return sorted(hits, key=lambda item: (item[0], item[1]))


# ---------------------------------------------------------------------------
# LNS-TXT-004 — prompt-injection grammar
# ---------------------------------------------------------------------------

#: Stable pattern ids ride evidence tokens (fingerprints survive wording
#: tweaks of the regexes themselves).
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Chat-template role-tag spoofing (OpenAI/Qwen-style sentinels).
    (
        "roletag",
        re.compile(
            r"<\|(?:im_start|im_end|endoftext|system|user|assistant|tool_call|python_tag)"
            r"\|>"
        ),
    ),
    ("roletag-inst", re.compile(r"\[/?(?:INST|SYS)\]")),
    ("roletag-gemma", re.compile(r"<start_of_turn>|<end_of_turn>")),
    # Fake system-prompt framing.
    (
        "fake-system",
        re.compile(r"(?im)^(?:#{1,6}\s*)?(?:SYSTEM|ASSISTANT|DEVELOPER)\s*(?:PROMPT)?\s*[:=]\s*\S"),
    ),
    (
        "you-are-unbound",
        re.compile(
            r"(?i)\byou\s+are\s+(?:now\s+|hereby\s+)?(?:a\s+|an\s+)?"
            r"(?:jailbroken|unrestricted|unfiltered|uncensored|liberated)\b"
        ),
    ),
    (
        "you-are-no-longer",
        re.compile(r"(?i)\byou\s+are\s+no\s+longer\s+(?:bound|restricted|limited)\b"),
    ),
    # Override imperatives.
    (
        "override-ignore",
        re.compile(
            r"(?i)\bignore\s+(?:all|any|your|the|these)?\s*"
            r"(?:previous|prior|earlier|original|above|preceding)\s*"
            r"(?:instructions|prompts|rules|directives|constraints)"
        ),
    ),
    (
        "override-disregard",
        re.compile(
            r"(?i)\bdisregard\s+(?:all\s+|your\s+|the\s+|any\s+)?"
            r"(?:previous|prior|initial|original|conflicting|above)\s*"
            r"(?:instructions|rules|prompts|guidance|directives)"
        ),
    ),
    (
        "new-instructions",
        re.compile(r"(?i)\bnew\s+(?:standing\s+)?instructions\s*:|\bimportant\s+update\s*:"),
    ),
    (
        "from-now-on",
        re.compile(r"(?i)\bfrom\s+now\s+on[, ]\s*(?:you\s+(?:are|will|must|ignore)|always\b)"),
    ),
    # Extraction demands.
    (
        "extraction",
        re.compile(
            r"(?i)\b(?:reveal|print|repeat|show|output|leak)\s+(?:your\s+|the\s+|its\s+)?"
            r"(?:full\s+|initial\s+|original\s+|exact\s+)?(?:system\s+)?"
            r"(?:prompt|instructions|directive)s?\b"
        ),
    ),
)

_INJECTION_TAG = "prompt-injection"


def grammar_hits(text_view: str) -> list[tuple[str, str]]:
    """``(pattern_id, normalized_span)`` pairs over one text view (stable).

    Normalized span = sanitized, lowercased, whitespace-collapsed — the
    fingerprint vocabulary. Long spans clip to 64 chars (shape, not quote).
    """
    hits: list[tuple[str, str]] = []
    for pattern_id, pattern in _INJECTION_PATTERNS:
        for match in pattern.finditer(text_view):
            span = re.sub(r"\s+", " ", safe_text(match.group(0)).strip().casefold())
            hits.append((pattern_id, span[:64]))
    return hits


# ---------------------------------------------------------------------------
# LNS-TXT-005 — self-state instructional directives
# ---------------------------------------------------------------------------

_SELF_STATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "soul-edit",
        re.compile(
            r"(?i)\b(?:edit|update|modify|rewrite|overwrite|replace|change)\s+"
            r"(?:your|the|its)\s+(?:own\s+|current\s+|core\s+)?"
            r"(?:soul(?:\.md)?|persona|identity|memories?\b|memory\b)"
        ),
    ),
    (
        "memory-implant",
        re.compile(r"(?i)\bremember\s+(?:that\s+)?you\s+(?:are|must|should|will\s+always)\b"),
    ),
    (
        "cron-directive",
        re.compile(r"(?i)\bcreate\s+(?:a\s+)?cron\s+job(?:\s+that)?\b"),
    ),
    (
        "self-write-directive",
        re.compile(
            r"(?i)\bwrite\s+(?:this|that|it)?\s*(?:directive|instruction|note|reminder)\s+"
            r"(?:to|into)\s+(?:your\s+)?(?:soul|memory|memories|persona)"
        ),
    ),
)

_SELF_STATE_TAG = "self-state-directive"


def self_state_hits(text_view: str) -> list[tuple[str, str]]:
    """``(pattern_id, normalized_span)`` self-state directive hits (stable)."""
    hits: list[tuple[str, str]] = []
    for pattern_id, pattern in _SELF_STATE_PATTERNS:
        for match in pattern.finditer(text_view):
            span = re.sub(r"\s+", " ", safe_text(match.group(0)).strip().casefold())
            hits.append((pattern_id, span[:64]))
    return hits


# ---------------------------------------------------------------------------
# TXT-001 escalation predicates (channel in ACTIVE use)
# ---------------------------------------------------------------------------


def bidi_inline_positions(lines: list[str]) -> list[int]:
    """1-based lines where a bidi control sits BETWEEN non-space characters.

    The RLO/PDF filename-and-command spoofing shape: direction controls
    embedded mid-token flip visual order of executable-looking text. Marks
    flanking whitespace-only gaps (whole-line RTL prose helpers) stay silent.
    """
    bidi_set = {cp for cp in range(0x202A, 0x202F)} | {cp for cp in range(0x2066, 0x206A)}
    bidi_set |= {0x200E, 0x200F}
    flagged: list[int] = []
    for line_no, line in enumerate(lines, start=1):
        for idx, ch in enumerate(line):
            if ord(ch) not in bidi_set:
                continue
            before = line[:idx].rstrip()
            after = line[idx + 1 :].lstrip()
            if before and after and not before[-1].isspace() and not after[0].isspace():
                flagged.append(line_no)
                break
    return flagged


def stego_evidence(hist: dict[str, int], escalations: Iterable[str]) -> str:
    """Normalized TXT-001 evidence token: class histogram + escalation marks.

    Sorted ``class:count`` pairs joined with ``;``; escalation markers sort
    after and carry a ``+`` prefix. Content-shaped only — stable across line
    shifts, identical across files carrying the same channel load.
    """
    parts = [f"{klass}:{hist[klass]}" for klass in sorted(hist)]
    parts.extend(f"+{mark}" for mark in sorted(set(escalations)))
    return ";".join(parts)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TextInjectEngine:
    """E2 implementation — grammar-free Unicode/ghost-stream/injection scan."""

    name = ENGINE_NAME
    RULE_IDS = RULE_IDS

    def __init__(self, rules: Iterable[Rule], gateway: ParserGateway | None = None) -> None:
        self._rules: dict[str, Rule] = {rule.id: rule for rule in rules if rule.id in RULE_IDS}
        # Uniform doctor seam (see module docstring): observed read-only via
        # probe=False; NEVER gates, alters, or annotates findings — E2 has
        # no grammar dependency, so gateway status cannot change output.
        self._gateway = gateway if gateway is not None else GATEWAY

    @property
    def parser_health(self) -> dict[str, Any]:
        """Uniform Phase-4 doctor surface (cached state, no side effects)."""
        return self._gateway.health(probe=False)

    def scan(self, bundle_ir: SkillIR, ctx: ScanContext) -> list[Finding]:
        del ctx  # context flows through the ambient slot (base.iter_text_files)
        claimed = claimed_capability_paths(bundle_ir)
        findings: list[Finding] = []
        for record, text in iter_text_files(bundle_ir, current_context()):
            findings.extend(self._scan_file(record.path, text, claimed))
        findings.sort(key=_finding_sort_key)
        return findings

    def _scan_file(self, rel_path: str, text: str, claimed: list[str]) -> list[Finding]:
        lines = text.splitlines()

        findings: list[Finding] = []
        txt001 = self._rules.get("LNS-TXT-001")
        txt002 = self._rules.get("LNS-TXT-002")
        txt003 = self._rules.get("LNS-TXT-003")
        txt004 = self._rules.get("LNS-TXT-004")
        txt005 = self._rules.get("LNS-TXT-005")

        if txt001 is not None:
            findings.extend(self._stego_findings(txt001, rel_path, lines, text))
        if txt002 is not None:
            seen: set[str] = set()
            for line_no, line in enumerate(lines, start=1):
                for raw_token, vocab in confusable_hits(line):
                    token_key = f"{vocab}:{skeleton(raw_token)}"
                    if token_key in seen:
                        continue
                    seen.add(token_key)
                    findings.append(
                        self._finding(
                            txt002,
                            rel_path,
                            line_no,
                            _snippet(line),
                            f"impersonation:{vocab}:{skeleton(raw_token)}",
                            "Homoglyph-confusable token impersonates protected term "
                            f"'{vocab}' ({safe_text(raw_token)})",
                            declared=is_declared(txt002.capability, claimed),
                        )
                    )
        if txt003 is not None:
            for line_no, token in dict.fromkeys(escape_channel_hits(text)):
                findings.append(
                    self._finding(
                        txt003,
                        rel_path,
                        line_no,
                        _snippet(lines[line_no - 1]) if line_no <= len(lines) else "",
                        f"escape:{token}",
                        f"Terminal escape-sequence covert channel ({token}) embeds "
                        "hidden data in rendered output",
                        declared=False,
                    )
                )

        # Injection grammars run over ALL views inside _grammar_findings
        # (raw lines, clean lines, decoded ghost payload); shared evidence
        # collapses via fingerprint dedup.
        if txt004 is not None:
            findings.extend(
                self._grammar_findings(
                    txt004,
                    rel_path,
                    lines,
                    grammar_hits,
                    _INJECTION_TAG,
                    extra_views=(decode_tags_payload(text),),
                )
            )
        if txt005 is not None:
            findings.extend(
                self._grammar_findings(
                    txt005,
                    rel_path,
                    lines,
                    self_state_hits,
                    _SELF_STATE_TAG,
                    extra_views=(decode_tags_payload(text),),
                )
            )
        return findings

    def _stego_findings(
        self, rule: Rule, rel_path: str, lines: list[str], text: str
    ) -> list[Finding]:
        hist: dict[str, int] = {}
        first_line: int | None = None
        for line_no, _col, klass in sanitize_invisible(text):
            hist[klass] = hist.get(klass, 0) + 1
            if first_line is None:
                first_line = line_no
        if not hist:
            return []

        escalations: list[str] = []
        decoded = decode_tags_payload(text)
        if decoded and (grammar_hits(decoded) or self_state_hits(decoded)):
            escalations.append("decoded-instruction")
        elif decoded:
            escalations.append("decoded-payload")
        inline_bidi = bidi_inline_positions(lines)
        if inline_bidi:
            escalations.append("bidi-inline")

        effective = ESCALATED_SEVERITY if escalations else rule.severity
        message = "Hidden Unicode channel present: " + ", ".join(
            f"{klass} x{count}" for klass, count in sorted(hist.items())
        )
        if escalations:
            message += "; channel in active use (" + ", ".join(sorted(set(escalations))) + ")"
            if decoded:
                message += f"; decoded ghost text: {safe_text(decoded[:80])}"
        return [
            self._finding(
                rule,
                rel_path,
                first_line if first_line is not None else 1,
                _snippet(lines[first_line - 1]) if first_line and first_line <= len(lines) else "",
                stego_evidence(hist, escalations),
                message,
                severity_override=effective,
                declared=False,
            )
        ]

    def _grammar_findings(
        self,
        rule: Rule,
        rel_path: str,
        lines: list[str],
        hit_fn: Any,
        tag: str,
        *,
        extra_views: tuple[str, ...] = (),
    ) -> list[Finding]:
        """One finding per distinct evidence token across all views.

        Views: raw lines, clean lines (zero-width-split instructions), the
        joined clean text (multi-line constructs like fake-system headers),
        and caller-supplied extra views (the DECODED Tags payload).
        Identical normalized spans collapse to one finding.
        """
        clean_lines = strip_invisible("\n".join(lines)).splitlines()
        views = [*lines, *clean_lines, "\n".join(clean_lines), *extra_views]
        seen: set[str] = set()
        findings: list[Finding] = []
        for view_index, view in enumerate(views):
            for pattern_id, span in hit_fn(view):
                key = f"{pattern_id}:{span}"
                if key in seen:
                    continue
                seen.add(key)
                line_no = _locate_line(lines, span)
                findings.append(
                    self._finding(
                        rule,
                        rel_path,
                        line_no,
                        _snippet(lines[line_no - 1]) if line_no <= len(lines) else "",
                        key,
                        f"{rule.title}: {tag} pattern '{pattern_id}' matched "
                        f'"{span}"' + (" (ghost-text view)" if view_index >= len(lines) else ""),
                        declared=False,
                    )
                )
        return findings

    def _finding(
        self,
        rule: Rule,
        rel_path: str,
        line_no: int,
        snippet: str,
        evidence: str,
        message: str,
        *,
        severity_override: str | None = None,
        declared: bool,
    ) -> Finding:
        effective = severity_override or rule.severity
        tags = rule.tags + (("declared-capability",) if declared else ())
        return Finding(
            fingerprint=finding_fingerprint(rule.id, rule.capability, evidence),
            rule_id=rule.id,
            rule_version=rule.rule_version,
            engine=rule.engine,
            title=rule.title,
            capability=rule.capability,
            severity=rule.severity,
            effective_severity=effective,
            confidence=rule.confidence_default,
            evidence_kind=rule.evidence_kind,
            static_only=rule.static_only,
            declared=declared,
            location=Location(
                path=rel_path,
                start_line=line_no,
                end_line=line_no,
                snippet=snippet,
                redacted=False,
            ),
            message=message,
            remediation=rule.remediation,
            tags=tags,
        )


def _locate_line(lines: list[str], span: str) -> int:
    """First 1-based line containing the (sanitized, casefolded) span."""
    needle = span.casefold()
    for line_no, line in enumerate(lines, start=1):
        if needle in safe_text(line).strip().casefold():
            return line_no
    return 1


def _finding_sort_key(finding: Finding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        finding.location.path,
        finding.location.start_line if finding.location.start_line is not None else 0,
    )


__all__ = [
    "ENGINE_NAME",
    "ESCALATED_SEVERITY",
    "INVISIBLE_CLASSES",
    "PROTECTED_VOCAB",
    "RULE_IDS",
    "TextInjectEngine",
    "classify_codepoint",
    "confusable_hits",
    "decode_tags_payload",
    "escape_channel_hits",
    "ghost_stream",
    "grammar_hits",
    "safe_text",
    "skeleton",
    "strip_invisible",
]
