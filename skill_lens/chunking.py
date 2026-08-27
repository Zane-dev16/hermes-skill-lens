"""Fence-safe chat chunk splitting (SPEC §11.3 delivery contract).

§11.3 normative: chat budgets are soft 1200 / hard 1800 chars, and "the
shared chunker preserves code fences across splits" — a returned string that
must traverse Discord's 2000-char message cap (≈1900 split reserve) may be
cut into segments, and every segment must keep its fenced blocks intact so
mrkdwn/MarkdownV2 renderers never see an unbalanced fence.

Skill Lens renders stay under the hard budget by construction (every chat
surface runs the §11.3 collapse ladder), so the HOST chunker rarely has
anything to do. This module is the reference implementation of that split,
shipped in-repo for three reasons:

1. **Verification** — tests feed pathological long reports (> hard budget)
   through :func:`split_chat` and prove every segment obeys the budget with
   balanced fences (PLAN Phase 6 exit: "fence-safe chunking").
2. **One strategy** — "longest legal fence segment": greedy fill to the
   budget, preferring breaks OUTSIDE fences; a break forced inside a fence
   closes it before the boundary and reopens after (bare ```` ``` ````),
   so each segment renders self-contained.
3. **No host coupling** — the plugin never calls host delivery internals
   (advisor containment); if a future surface must pre-split, it uses this
   exact code.

Deterministic: pure function of (text, limit) — same input, same segments.

Algorithm note (D-CHUNK): the fill is a MONOTONIC two-index sweep — the
next boundary is searched forward from the last one, lines are never
pushed back onto a work queue — so termination is structural, not hoped
for: every emitted segment consumes ≥ 1 piece. A forced in-fence break
appends a closing ```` ``` ```` to the finished segment and marks the next
one to open with a bare ```` ``` ```` (:func:`rejoin` recognizes exactly
those SYNTHETIC pairs because both halves must be present together).

Degenerate budgets (< :data:`FULL_BALANCE_MIN`) cannot honor the marker
machinery (an empty fenced block already costs 9 bytes). Below that floor
the splitter degrades to plain greedy packing: byte ceilings still hold on
every multi-line segment, atomic fence-marker lines longer than the budget
travel solo (unavoidable; single-line chunks are inert to mrkdwn), and
inter-segment fence balance is sacrificed — physically impossible there.
"""

from __future__ import annotations

import re

#: The §11.3 hard ceiling this splitter defaults to. Kept here rather than
#: imported from ``render`` so the module stays import-cycle-free.
HARD_BUDGET_DEFAULT = 1800

_FENCE_LINE = re.compile(r"^\s*(`{3,}|~{3,}).*$")

#: Synthetic fence markers are always exactly this literal — see rejoin().
_SYNTHETIC_FENCE = "```"

#: Worst-case per-segment overhead reserved when pre-splitting oversized
#: lines: reopen marker + newline (4) + close marker + newline (4) + margin.
_LINE_RESERVE = 12

#: Budgets at or above this many chars run the full synthetic-pair
#: machinery (close-on-break + reopen). Below it: degenerate packing.
FULL_BALANCE_MIN = 24


def _is_fence_line(line: str) -> bool:
    return bool(_FENCE_LINE.match(line))


def _parity(text: str) -> int:
    """Number of fence-marker lines in *text* (fence-parity check helper)."""
    return sum(1 for line in text.split("\n") if _is_fence_line(line))


def _pieces_of(text: str, safe_cap: int) -> list[str]:
    """Split *text* into atomic pieces: lines, char-splitting overlong ones.

    Fence-marker lines stay WHOLE at any size — cutting one would destroy
    the marker that keeps subsequent segments balanced.
    """
    pieces: list[str] = []
    for raw in text.split("\n"):
        if _is_fence_line(raw) or len(raw) <= safe_cap:
            pieces.append(raw)
        else:
            pieces.extend(raw[i : i + safe_cap] for i in range(0, len(raw), safe_cap))
    return pieces


def _pack_degenerate(pieces: list[str], hard_limit: int) -> list[str]:
    """Plain greedy packing (no synthetic markers); degenerate budgets only."""
    chunks: list[str] = []
    current = ""
    for piece in pieces:
        candidate = f"{current}\n{piece}" if current else piece
        if current and len(candidate) > hard_limit:
            chunks.append(current)
            current = piece
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def split_chat(text: str, hard_limit: int = HARD_BUDGET_DEFAULT) -> list[str]:
    """Split *text* into segments each ≤ *hard_limit*, fences balanced.

    Monotonic greedy longest-legal-segment strategy: pieces fill a segment
    until the next piece would breach the budget. A break forced while
    inside a fenced block appends a closing fence to the finished segment
    and opens the next one with a bare ```` ``` ```` — :func:`rejoin`
    undoes exactly those synthetic PAIRS (both halves seen together).
    Oversized single non-fence lines are char-split up front (never a
    fence-marker line); an atomic fence-marker line larger than the whole
    budget travels as its own single-line segment (the one sanctioned
    overshoot — an unclosable budget otherwise loops forever). Never
    raises on any input; always returns at least one segment.
    """
    if hard_limit <= 0:  # defensive: caller misuse degrades to whole text
        return [text]
    if len(text) <= hard_limit:
        return [text]

    safe_cap = max(1, hard_limit - _LINE_RESERVE)
    pieces = _pieces_of(text, safe_cap)

    if hard_limit < FULL_BALANCE_MIN:
        return [chunk for chunk in _pack_degenerate(pieces, hard_limit) if chunk.strip("\n")] or [
            ""
        ]

    # Rendered byte model for a candidate segment [i, e):
    #   parts = optional leading marker + pieces + optional closing marker,
    #   bytes = sum(len(piece)) + one newline per ADJACENT part pair.
    # Both synthetic markers cost 4 bytes each (marker + joining newline).
    chunks: list[str] = []
    count_total = len(pieces)
    index = 0
    mid_fence = False  # synthetic debt: previous segment force-closed a fence
    while index < count_total:
        body_len = 0  # sum(len(piece)) over pieces[index:end]
        body_count = 0  # number of pieces in the candidate segment
        fences = 0  # content fence-marker lines consumed so far
        end = index
        while end < count_total:
            piece = pieces[end]
            next_body_len = body_len + len(piece)
            next_count = body_count + 1
            next_fences = fences + (1 if _is_fence_line(piece) else 0)
            lead_bytes = 4 if mid_fence else 0
            tail_bytes = 4 if (mid_fence ^ bool(next_fences % 2)) else 0
            joins = (next_count - 1) + (1 if lead_bytes else 0) + (1 if tail_bytes else 0)
            projected = next_body_len + joins + lead_bytes + tail_bytes
            forced_minimum = end == index  # every segment consumes ≥ 1 piece
            if not forced_minimum and projected > hard_limit:
                break
            body_len, body_count, fences = next_body_len, next_count, next_fences
            end += 1

        closes_needed = mid_fence ^ bool(fences % 2)
        segment_parts = ([_SYNTHETIC_FENCE] if mid_fence else []) + pieces[index:end]
        rendered = "\n".join(segment_parts)
        if closes_needed:
            rendered += f"\n{_SYNTHETIC_FENCE}"
        chunks.append(rendered)
        mid_fence = closes_needed
        index = end
    # Blank-line pieces make empty segments possible (text ending "\n");
    # drop them like every other host-visible split must (D-CHUNK contract:
    # zero-size deliveries carry no information and confuse chunkers).
    return [chunk for chunk in chunks if chunk]


def rejoin(chunks: list[str]) -> str:
    """Undo :func:`split_chat`'s synthetic markers (verification helper).

    Removes exactly the synthetic close/reopen PAIRS the splitter added —
    a trailing bare ```` ``` ```` on one segment paired with a leading
    bare ```` ``` ```` on the next. Content fences are untouched: a stripe
    is removed only when BOTH halves of the pair are present (guards the
    degenerate mode, which adds no synthetics at all).
    """
    if len(chunks) <= 1:
        return "\n".join(chunks)
    lines: list[str] = []
    for index, chunk in enumerate(chunks):
        chunk_lines = chunk.split("\n")
        start = 0
        end = len(chunk_lines)
        prev_pairs = (
            index > 0
            and chunks[index - 1].split("\n")
            and chunks[index - 1].split("\n")[-1] == _SYNTHETIC_FENCE
        )
        if index > 0 and prev_pairs and chunk_lines and chunk_lines[0] == _SYNTHETIC_FENCE:
            start = 1
        next_leads = (
            index < len(chunks) - 1
            and chunk_lines
            and chunks[index + 1].split("\n")[0] == _SYNTHETIC_FENCE
        )
        if next_leads and chunk_lines and chunk_lines[-1] == _SYNTHETIC_FENCE:
            end -= 1
        lines.extend(chunk_lines[start:end])
    return "\n".join(lines)


def fences_balanced(segment: str) -> bool:
    """True when every fence opened in *segment* is also closed there."""
    return _parity(segment) % 2 == 0


__all__ = [
    "FULL_BALANCE_MIN",
    "HARD_BUDGET_DEFAULT",
    "fences_balanced",
    "rejoin",
    "split_chat",
]
