"""Lexicon v1 data tables (SPEC §9.2 group 2) — the deterministic verb lexicon.

This module is DATA ONLY: no matching logic, no I/O, no imports beyond the
standard library typing/dataclasses. All matching semantics live in
:mod:`skill_lens.claims` (``LexiconExtractor``); keeping the vocabulary here
means the advisor-conservative bias is auditable as a table, not buried in
code (DECISIONS D-038).

Why this table exists and why it is conservative
------------------------------------------------

SPEC §9.2 lists example words per capability family but leaves exact token
semantics unpinned. Claims REDUCE overreach surface (a claim discounts a
finding ×0.5 and shrinks the actual∧¬claimed diff), so over-eager extraction
softens verdicts without the author ever disclosing anything. The bias is
therefore **only confident matches count**:

- Every family requires a VERB stem occurrence (SPEC's own words, stemmed).
- Families whose §9.2 entry names explicit objects (``watch files``,
  ``env/key/token``, ``wallet/crypto``, ``clipboard``, ``soul/memory``) ALSO
  require an object stem within :data:`OBJECT_WINDOW_TOKENS` tokens AFTER the
  verb — so vector G's "Tracks your crypto wallet balances" (verb ``track``
  is not a money verb) claims NOTHING and stays an undeclared money-touch.
- Object-only families (credentials.read, surveillance) pair their nouns
  with :data:`ANY_ACTION_VERB_STEMS` — the union of SPEC's base-list verbs —
  rather than minting on bare noun mentions.

Tie-breaks (deterministic, D-038): earliest verb occurrence wins per
capability; the description region is mined before the body region; suffix
recognition is a closed whitelist (:data:`VERB_SUFFIXES`) — ``ready`` never
matches ``read``, ``running`` conservatively does not match ``run``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LexiconFamily:
    """One verb→claim mapping row.

    ``verbs`` are lowercase stems; an empty tuple means "any verb from
    :data:`ANY_ACTION_VERB_STEMS`". ``objects`` are required object stems
    that must appear inside the post-verb window; an empty tuple means the
    verb alone constitutes a confident match (SPEC lists bare verbs for
    these families).
    """

    capability: str  # §9.1 path minted (family or family:subpath)
    verbs: tuple[str, ...]
    objects: tuple[str, ...] = ()


#: Closed suffix whitelist appended to a stem to recognize inflections.
#: Anything else ("ready" vs ``read``, "running" vs ``run``) does NOT match —
#: deliberate conservatism over recall (D-038 tie-break).
VERB_SUFFIXES: tuple[str, ...] = ("", "s", "es", "ed", "d", "ing", "er", "ers")

#: How many raw tokens after a verb may carry its object (small window =
#: fewer accidental pairings across clause boundaries).
OBJECT_WINDOW_TOKENS = 6

#: Union of the SPEC §9.2 base-list verb stems. Used by object-only families
#: (credentials.read, surveillance) instead of bare-noun minting.
ANY_ACTION_VERB_STEMS: tuple[str, ...] = (
    "command",
    "download",
    "execut",
    "fetch",
    "generat",
    "invoic",
    "install",
    "open",
    "pay",
    "post",
    "publish",
    "push",
    "read",
    "retriev",
    "run",
    "save",
    "scan",
    "send",
    "shell",
    "sync",
    "upload",
    "watch",
    "webhook",
    "write",
)

#: The §9.2 lexicon v1 table (base list + Hermes extensions), sorted by
#: capability path then by object-specificity so reading order is stable.
LEXICON_FAMILIES: tuple[LexiconFamily, ...] = (
    # -- §9.2 base list -----------------------------------------------------
    LexiconFamily(
        capability="credentials.read",
        verbs=(),  # any action verb + credential noun (no bare-noun minting)
        objects=("env", ".env", "key", "token", "credential", "secret", "password"),
    ),
    LexiconFamily(
        capability="execute.shell",
        verbs=("command", "execut", "install", "run", "shell"),
        objects=(),
    ),
    LexiconFamily(
        capability="filesystem.read",
        verbs=("open", "read", "scan", "watch"),
        objects=("file",),  # §9.2 writes the objects into the phrase: "watch files"
    ),
    LexiconFamily(
        capability="filesystem.write",
        verbs=("generat", "save", "write"),
        objects=("file",),
    ),
    LexiconFamily(
        capability="money",
        verbs=("invoic", "pay"),  # noun mentions alone must NOT mint (vector G is law)
        objects=("crypto", "cryptocurrency", "payment", "wallet"),
    ),
    LexiconFamily(
        capability="network.read",
        verbs=("download", "fetch", "retriev", "sync"),
        objects=(),
    ),
    LexiconFamily(
        capability="network.send",
        verbs=("post", "publish", "push", "send", "upload", "webhook"),
        objects=(),
    ),
    LexiconFamily(
        capability="surveillance",
        verbs=(),  # any action verb + clipboard
        objects=("clipboard",),
    ),
    # -- Hermes extensions (§9.2) -------------------------------------------
    LexiconFamily(
        capability="network.send:messaging_human",
        verbs=("announc", "dm", "notif"),
        objects=(),
    ),
    LexiconFamily(
        capability="network.send:messaging_human",
        verbs=("post", "push", "send"),  # "send a message / notify a channel"
        objects=("channel", "dm", "message", "msg", "notification"),
    ),
    LexiconFamily(
        capability="persistence:scheduler",
        verbs=("recurr", "remind", "schedul", "timer"),
        objects=(),
    ),
    LexiconFamily(
        capability="persona.write",
        verbs=("edit", "updat"),
        objects=("memories", "memory", "memory.md", "persona", "soul", "soul.md", "user.md"),
    ),
)

__all__ = [
    "ANY_ACTION_VERB_STEMS",
    "LexiconFamily",
    "LEXICON_FAMILIES",
    "OBJECT_WINDOW_TOKENS",
    "VERB_SUFFIXES",
]
