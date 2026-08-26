"""Claims, capabilities, and overreach — the product thesis stage (SPEC §9).

Field-direct claim extraction (§9.2 group 1): exact frontmatter fields map
to §9.1 capability paths — ``allowed-tools`` entries, ``compatibility``
phrases, and Hermes ``metadata.hermes`` hint fields (related_skills chains,
fallback declarations, scheduling/messaging tag clusters). Quote spans are
preserved verbatim; line numbers resolve only when the raw SKILL.md text is
supplied (the ingest path always supplies it). **No LLM here** — and the
lexicon extractor below is equally prose-free: it is a deterministic
verb-object table match.

Lexicon v1 extraction (§9.2 group 2, live as of Phase 1.5): verb-object
mining over the description and body regions against the pure-data table in
:mod:`skill_lens.lexicon`. Matches are advisor-conservative — every family
needs a SPEC-listed verb stem, and families whose SPEC entry names objects
also require the object inside a small post-verb window — so "Tracks your
crypto wallet balances" claims nothing while "Reads your API tokens" claims
``credentials.read``. Spans carry verbatim quotes plus character offsets
into the mined string; the §8.2 ``declared`` ×0.5 modifier applies from
these claims exactly as from field-direct ones (SPEC §8.2 pins the modifier
to "frontmatter/description/allowed-tools"; PLAN Phase 1.5 states it
directly).

Overreach primitive: a bundle overreaches exactly where actual capability
evidence exists that its claims never cover (actual ∧ ¬claimed). When the
claim set is empty the basis becomes ``no-claims-made`` ("undisclosed
capability") instead of ``contradicts_claim`` (§9.2 wording distinction).

Explanation without LLM (§9.3): deterministic templates cite claim span,
evidence span, and weight line. SPEC pins the network.send ``because``
clause verbatim; sibling clauses follow its pattern (DECISIONS D-019).

This module also hosts rule LNS-MAN-004 (vague-description) until the E1
manifest engine lands and takes ownership unchanged (DECISIONS D-020) —
see :func:`run_claim_stage`, probed by the corpus harness via
:data:`CLAIM_STAGE_RULE_IDS`.

DETERMINISM LAW honored throughout: sorted iteration, stable ids, no
wall-clock, no randomness, zero network.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from .ir import (
    CLAIM_KIND_ALLOWED_TOOLS,
    CLAIM_KIND_COMPATIBILITY,
    CLAIM_KIND_DESCRIPTION_PHRASE,
    CLAIM_KIND_FRONTMATTER_FIELD,
    EXTRACTOR_FIELD_DIRECT,
    EXTRACTOR_LEXICON_V1,
    ClaimRecord,
    ClaimSpan,
    ResolvedFrontmatter,
    SkillIR,
)
from .lexicon import (
    ANY_ACTION_VERB_STEMS,
    LEXICON_FAMILIES,
    OBJECT_WINDOW_TOKENS,
    VERB_SUFFIXES,
)

# ---------------------------------------------------------------------------
# Vocabulary (§9.1 ontology paths used by field-direct sources)
# ---------------------------------------------------------------------------

#: ``allowed-tools``/tool-name → capability map. Exact normalized-token match
#: ONLY — unknown tools claim nothing (advisor-safest: fewer, honest claims).
TOOL_CAPABILITY_MAP: dict[str, str] = {
    # execute.shell family
    "bash": "execute.shell",
    "sh": "execute.shell",
    "shell": "execute.shell",
    "terminal": "execute.shell",
    "command": "execute.shell",
    "run_command": "execute.shell",
    "execute_command": "execute.shell",
    # filesystem.read / filesystem.write
    "read_file": "filesystem.read",
    "read_files": "filesystem.read",
    "view_file": "filesystem.read",
    "write_file": "filesystem.write",
    "edit_file": "filesystem.write",
    "create_file": "filesystem.write",
    "replace_file": "filesystem.write",
    # network.read / network.send
    "fetch": "network.read",
    "web_fetch": "network.read",
    "download": "network.read",
    "http_get": "network.read",
    "curl": "network.read",
    "post": "network.send",
    "upload": "network.send",
    "send": "network.send",
    "webhook": "network.send",
}

#: Coarse toolset tokens for ``metadata.hermes.fallback_for_toolsets``.
TOOLSET_TOKEN_MAP: dict[str, str] = {
    "shell": "execute.shell",
    "terminal": "execute.shell",
    "command": "execute.shell",
    "web": "network.read",
    "network": "network.read",
    "http": "network.read",
    "fetch": "network.read",
    "browser": "network.read",
    "file": "filesystem.write",
    "files": "filesystem.write",
    "fs": "filesystem.write",
    "filesystem": "filesystem.write",
    "editor": "filesystem.write",
}

#: ``compatibility`` phrase → claimed families. A network-access phrase
#: claims BOTH directions (SPEC §9.2: such phrases claim ``network.*``).
#: ``filesystem access`` likewise claims the FILESYSTEM FAMILY GROUP
#: (read/write/outside) — an author who writes those words has disclosed
#: filesystem reach broadly, so honest cleanup/lab skills earn the §8.2
#: declared discount on SHL-003-style evidence (golden vector D).
COMPATIBILITY_PHRASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("network access", ("network.read", "network.send")),
    ("internet access", ("network.read", "network.send")),
    ("network connection", ("network.read", "network.send")),
    ("shell access", ("execute.shell",)),
    ("command execution", ("execute.shell",)),
    (
        "filesystem access",
        ("filesystem.read", "filesystem.write", "filesystem.outside"),
    ),
)

RELATED_SKILLS_CAPABILITY = "spawn.agent:skill_ref"  # §17 H3 chaining declaration
SCHEDULER_CLAIM_CAPABILITY = "persistence:scheduler"  # §9.2 Hermes extension
MESSAGING_CLAIM_CAPABILITY = "network.send:messaging_human"  # §8.2 discount-eligible

SCHEDULER_TAG_TOKENS = frozenset(
    {
        "cron",
        "crons",
        "cronjob",
        "cronjobs",
        "schedule",
        "scheduler",
        "scheduling",
        "recurring",
        "reminder",
        "reminders",
        "timer",
        "timers",
        "periodic",
    }
)
MESSAGING_TAG_TOKENS = frozenset(
    {
        "notify",
        "notifies",
        "notification",
        "notifications",
        "message",
        "messages",
        "messaging",
        "announce",
        "announces",
        "announcement",
        "channel",
        "channels",
        "discord",
        "telegram",
        "slack",
    }
)

# ---------------------------------------------------------------------------
# Claim-stage hosting of LNS-MAN-004 (interim until engine E1 lands, D-020)
# ---------------------------------------------------------------------------

CLAIM_STAGE_RULE_ID = "LNS-MAN-004"
CLAIM_STAGE_RULE_IDS: frozenset[str] = frozenset({CLAIM_STAGE_RULE_ID})
VAGUE_DESCRIPTION_MESSAGE = "description states no concrete capabilities"

#: Frontmatter states where the description was never READ (missing doc,
#: unparsable YAML). Those bundles already carry their own structured
#: diagnostics; MAN-004 must not pile a second finding onto an unreadable
#: manifest — advisor-safest is to flag silence, not blindness.
_UNASSESSABLE_FRONTMATTER_ERRORS: tuple[str, ...] = (
    "frontmatter missing or unparsable",
    "SKILL.md missing, unreadable, or not valid text",
)

_ANCHOR_BY_KIND: dict[str, tuple[str, ...]] = {
    CLAIM_KIND_ALLOWED_TOOLS: ("allowed-tools", "allowed_tools"),
    CLAIM_KIND_COMPATIBILITY: ("compatibility",),
}

_HERMES_ANCHORS: dict[str, tuple[str, ...]] = {
    RELATED_SKILLS_CAPABILITY: ("related_skills", "related-skills"),
    SCHEDULER_CLAIM_CAPABILITY: ("tags",),
    MESSAGING_CLAIM_CAPABILITY: ("tags",),
}

# ---------------------------------------------------------------------------
# Capability-cue stems (shared with the LNS-MAN-004 vagueness heuristic).
# NOT the lexicon extractor: these gate "did the description state anything
# concrete at all"; they never mint ClaimRecords (D-020).
# ---------------------------------------------------------------------------

CAPABILITY_CUES: dict[str, tuple[str, ...]] = {
    "credentials.read": ("credential", "password", "secret", "token", "key", "env", ".env"),
    "execute.shell": ("run", "execut", "install", "command", "shell", "script", "sudo"),
    "filesystem.read": ("read", "open", "scan", "watch", "view"),
    "filesystem.write": (
        "write",
        "save",
        "generat",
        "creat",
        "append",
        "edit",
        "format",
        "export",
    ),
    "integrity.override": ("bypass", "override"),
    "money": (
        "pay",
        "invoice",
        "wallet",
        "crypto",
        "bitcoin",
        "ethereum",
        "stripe",
        "paypal",
        "checkout",
        "purchase",
        "transaction",
        "billing",
    ),
    "network.read": ("fetch", "download", "retriev", "sync", "curl"),
    "network.send": ("upload", "post", "publish", "push", "send", "webhook", "notify", "announce"),
    "obfuscation": ("base64", "encrypt", "decrypt", "encode", "decode", "obfusc"),
    "persona.write": ("soul", "persona", "memory", "memories"),
    "persistence": ("schedul", "recurring", "remind", "timer", "cron", "periodic", "interval"),
    "spawn.agent": ("subagent", "orchestrat", "dispatch", "chain"),
    "surveillance": ("clipboard", "screen", "keystroke", "microphone", "camera", "webcam"),
}

_ALL_CUES: tuple[str, ...] = tuple(
    sorted({cue for cues in CAPABILITY_CUES.values() for cue in cues})
)
_WORD_RE = re.compile(r"[a-z0-9_.]+")

# Multilingual precision extension (D-047, FP-as-fixture closure): the Latin
# stem table above tokenizes ``[a-z0-9_.]+`` ONLY, so a genuinely concrete
# CJK/Arabic description tokenized to nothing and false-positived LNS-MAN-004.
# The fix stays inside the rule's own semantics — cue-based concreteness,
# conservative bias — and never touches the lexicon claim extractor (non-Latin
# text still mints NO ClaimRecords; declared discounts remain a Latin-language
# surface for now).
#
# Semantics per script: CJK text has no spaces, so cues are matched as
# SUBSTRINGS of each ideograph/kana/hangul run; Arabic attaches clitics
# (و / ال / ب …) directly to the stem, so substring matching absorbs them too.
# Every cue is a full capability verb/noun morpheme (2+ letters), never a
# single letter, so accidental containment inside marketing copy stays rare —
# and the rule is LOW/static advisory regardless (heuristic band, D-FP cap).
_CJKV_RUN_RE = re.compile("[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]+")
_ARABIC_RUN_RE = re.compile("[\u0600-\u06ff\u0750-\u077f\ufb50-\ufdff\ufe70-\ufeff]+")

#: CJKV capability morphemes (zh/ja shared kanji forms + hangul words).
CJKV_CAPABILITY_CUES: tuple[str, ...] = (
    "保存",
    "备份",
    "同步",
    "搜索",
    "整理",
    "导出",
    "下载",
    "上传",
    "发送",
    "提醒",
    "记录",
    "管理",
    "生成",
    "转换",
    "翻译",
    "安装",
    "执行",
    "扫描",
    "读取",
    "写入",
    "저장",
    "검색",
    "관리",
    "생성",
    "변환",
    "전송",
    "다운로드",
    "업로드",
    "백업",
    "알림",
    "실행",
    "설치",
    "기록",
    "번역",
)

#: Arabic capability stems (matched inside clitic-attached tokens).
ARABIC_CAPABILITY_CUES: tuple[str, ...] = (
    "حفظ",
    "بحث",
    "إدارة",
    "إنشاء",
    "تحويل",
    "تنزيل",
    "رفع",
    "إرسال",
    "تذكير",
    "مزامنة",
    "ترجمة",
    "تنفيذ",
    "تثبيت",
    "فحص",
    "قراءة",
    "كتابة",
)


def _multilingual_cue_match(text: str) -> bool:
    """Substring-cue concreteness for CJKV/Arabic runs (D-047). Pure."""
    for run in _CJKV_RUN_RE.findall(text):
        if any(cue in run for cue in CJKV_CAPABILITY_CUES):
            return True
    for run in _ARABIC_RUN_RE.findall(text):
        if any(cue in run for cue in ARABIC_CAPABILITY_CUES):
            return True
    return False


def description_states_concrete_capability(description_raw: str | None) -> bool:
    """True when *description_raw* contains at least one §9.2-family cue.

    Stem/prefix match over lowercased words (so "environment" hits the
    ``env`` credential stem and "Generates" hits ``generat``). CJK/Arabic
    descriptions are checked against the multilingual morpheme tables
    (D-047) so genuinely concrete non-English skills stay silent. Empty,
    missing, and pure-marketing descriptions return False — precisely the
    §9.2 vague-copy population LNS-MAN-004 addresses.
    """
    raw = description_raw or ""
    words = _WORD_RE.findall(raw.lower())
    if any(word.startswith(cue) for word in words for cue in _ALL_CUES):
        return True
    return _multilingual_cue_match(raw)


# ---------------------------------------------------------------------------
# Field-direct extraction (SPEC §9.2 group 1)
# ---------------------------------------------------------------------------


def _normalize_token(value: str) -> str:
    return value.strip().lower()


def extract_field_direct_claims(
    frontmatter: ResolvedFrontmatter,
    *,
    manifest_path: str = "SKILL.md",
    skill_md_text: str | None = None,
) -> tuple[ClaimRecord, ...]:
    """Extract §9.2 group-1 claims from typed frontmatter (deterministic).

    Sources, collected in fixed field order then id-stable sorted:
    allowed-tools entries, compatibility phrases, hermes related_skills,
    fallback_for_toolsets, fallback_for_tools, and scheduler/messaging tag
    clusters. ``requires_*`` lists deliberately claim NOTHING — SPEC §9.2
    names only fallback_for_* as claim feeders (DECISIONS D-017). Duplicate
    ``(kind, capability, quote)`` triples collapse; ids are assigned after
    sorting by ``(capability, kind, quote)`` so they never depend on field
    order.
    """
    fm = frontmatter
    candidates: list[tuple[str, str, str, tuple[str, ...]]] = []

    allowed_anchors = _ANCHOR_BY_KIND[CLAIM_KIND_ALLOWED_TOOLS]
    for tool in fm.allowed_tools:
        capability = TOOL_CAPABILITY_MAP.get(_normalize_token(tool))
        if capability is not None:
            candidates.append((CLAIM_KIND_ALLOWED_TOOLS, capability, tool, allowed_anchors))

    compat = (fm.compatibility or "").strip()
    if compat:
        compat_lower = compat.lower()
        compat_anchors = _ANCHOR_BY_KIND[CLAIM_KIND_COMPATIBILITY]
        for phrase, capabilities in COMPATIBILITY_PHRASES:
            if phrase in compat_lower:
                for capability in capabilities:
                    candidates.append(
                        (CLAIM_KIND_COMPATIBILITY, capability, compat, compat_anchors)
                    )

    hermes = fm.hermes
    if hermes is not None:
        related_anchor = _HERMES_ANCHORS[RELATED_SKILLS_CAPABILITY]
        tags_anchor = _HERMES_ANCHORS[SCHEDULER_CLAIM_CAPABILITY]
        for name in hermes.related_skills:
            candidates.append(
                (CLAIM_KIND_FRONTMATTER_FIELD, RELATED_SKILLS_CAPABILITY, name, related_anchor)
            )
        for toolset in hermes.fallback_for_toolsets:
            capability = TOOLSET_TOKEN_MAP.get(_normalize_token(toolset))
            if capability is not None:
                candidates.append((CLAIM_KIND_FRONTMATTER_FIELD, capability, toolset, (toolset,)))
        for tool in hermes.fallback_for_tools:
            capability = TOOL_CAPABILITY_MAP.get(_normalize_token(tool))
            if capability is not None:
                candidates.append((CLAIM_KIND_FRONTMATTER_FIELD, capability, tool, (tool,)))
        for tag in hermes.tags:
            token = _normalize_token(tag)
            if token in SCHEDULER_TAG_TOKENS:
                candidates.append(
                    (CLAIM_KIND_FRONTMATTER_FIELD, SCHEDULER_CLAIM_CAPABILITY, tag, tags_anchor)
                )
            elif token in MESSAGING_TAG_TOKENS:
                candidates.append(
                    (CLAIM_KIND_FRONTMATTER_FIELD, MESSAGING_CLAIM_CAPABILITY, tag, tags_anchor)
                )

    ordered: list[tuple[str, str, str, tuple[str, ...]]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = candidate[:3]
        if key not in seen:
            seen.add(key)
            ordered.append(candidate)
    ordered.sort(key=lambda item: (item[1], item[0], item[2]))

    locator = _SpanLocator(skill_md_text)
    records: list[ClaimRecord] = []
    for index, (kind, capability, quote, anchors) in enumerate(ordered, start=1):
        records.append(
            ClaimRecord(
                id=f"C-{index}",
                kind=kind,
                capability=capability,
                span=ClaimSpan(
                    path=manifest_path,
                    line=locator.locate(quote, anchors),
                    quote=quote,
                ),
                extractor=EXTRACTOR_FIELD_DIRECT,
            )
        )
    return tuple(records)


class _SpanLocator:
    """First-match line finder over the frontmatter block (pure, tolerant).

    Anchored searches start at the source key's line and scan that key's
    indented block, so a tag named like body prose cannot mislocate. Without
    text every lookup yields ``None`` (quote stays verbatim; line unknown).
    """

    def __init__(self, skill_md_text: str | None) -> None:
        lines = skill_md_text.splitlines() if skill_md_text is not None else []
        end = len(lines)
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                end = idx
                break
        self._lines: tuple[str, ...] = tuple(lines[:end])

    def locate(self, quote: str, anchors: tuple[str, ...] = ()) -> int | None:
        if not self._lines:
            return None
        if anchors:
            start = self._anchor_start(anchors)
            if start is not None:
                hit = self._search_window(start, quote)
                if hit is not None:
                    return hit
        for idx, line in enumerate(self._lines, start=1):
            if quote in line:
                return idx
        return None

    def _anchor_start(self, anchors: tuple[str, ...]) -> int | None:
        for anchor in anchors:
            for idx, line in enumerate(self._lines, start=1):
                stripped = line.strip()
                if stripped.startswith(anchor) and ":" in stripped:
                    return idx
        return None

    def _search_window(self, start: int, quote: str) -> int | None:
        last = min(len(self._lines), start + 64)
        for idx in range(start, last + 1):
            line = self._lines[idx - 1]
            stripped = line.strip()
            if idx > start and stripped and not stripped.startswith("-") and not line[:1].isspace():
                break  # next top-level key: window closed
            if quote in line:
                return idx
        return None


# ---------------------------------------------------------------------------
# Lexicon v1 extraction (SPEC §9.2 group 2) — verb-object mining
# ---------------------------------------------------------------------------

#: Token charset for lexicon mining. Dots stay inside tokens (``.env``,
#: ``soul.md`` are single objects); hyphens likewise, so ``read-only`` is
#: never mistaken for the verb ``read``.
_LEXICON_TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")


@dataclass(frozen=True)
class _LexToken:
    """One lowercased token with its character span in the mined string.

    ``text`` is the raw slice (offsets stay exact); ``norm`` strips trailing
    sentence punctuation so ``tokens.`` still matches the stem ``token``.
    Internal dots survive (``.env``, ``soul.md`` remain single objects).
    """

    text: str
    start: int
    end: int

    @property
    def norm(self) -> str:
        return self.text.rstrip(".,;:!?'\"")


def _stem_match(token: str, stem: str) -> bool:
    """``True`` iff *token* is *stem* plus one closed whitelisted suffix.

    "ready" never matches "read"; "running" conservatively misses "run".
    """
    return any(token == stem + suffix for suffix in VERB_SUFFIXES)


def _split_manifest_body(skill_md_text: str) -> tuple[str, int]:
    """Body region after the closing ``---`` fence as (text, 1-based line).

    No fences ⇒ the whole document is body. An UNTERMINATED fence mines
    nothing (malformed manifest — parse diagnostics already own that signal;
    advisor-safest is silence over guessing region boundaries).
    """
    lines = skill_md_text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return skill_md_text, 1
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            offset = sum(len(line) for line in lines[: idx + 1])
            return skill_md_text[offset:], idx + 2
    return "", len(lines) + 1


class LexiconExtractor:
    """Deterministic verb-object miner over description/body (§9.2 group 2).

    Pure function of (frontmatter, raw text): same input ⇒ identical claims.
    One claim per capability — the earliest confident match wins, with the
    description region mined before the body (tie-break documented in
    :mod:`skill_lens.lexicon` and DECISIONS D-038).
    """

    def mine_region(self, text: str) -> dict[str, tuple[int, int]]:
        """Capability → (start, end) char offsets of its best confident match.

        Tie-breaks (D-038): verb-alone families take the EARLIEST verb
        occurrence; object-paired families take the SHORTEST verb→object
        span (tightest quote), earliest start on equal length. Deterministic
        either way.
        """
        tokens = [
            _LexToken(match.group(0), match.start(), match.end())
            for match in _LEXICON_TOKEN_RE.finditer(text.lower())
        ]
        found: dict[str, tuple[int, int]] = {}
        for family in LEXICON_FAMILIES:
            verb_stems = family.verbs if family.verbs else ANY_ACTION_VERB_STEMS
            best: tuple[int, int] | None = None
            for index, token in enumerate(tokens):
                if not any(_stem_match(token.norm, verb) for verb in verb_stems):
                    continue
                if not family.objects:
                    best = (token.start, token.end)
                    break  # earliest occurrence wins for verb-alone families
                span = self._pair_object(tokens, index, family.objects)
                if span is not None and (
                    best is None
                    or (span[1] - span[0], span[0])
                    < (
                        best[1] - best[0],
                        best[0],
                    )
                ):
                    best = span
            if best is not None:
                found[family.capability] = best
        return found

    def _pair_object(
        self,
        tokens: list[_LexToken],
        verb_index: int,
        objects: tuple[str, ...],
    ) -> tuple[int, int] | None:
        """Verb→object span inside the post-verb window, or ``None``."""
        window = tokens[verb_index + 1 : verb_index + 1 + OBJECT_WINDOW_TOKENS]
        for follower in window:
            if any(_stem_match(follower.norm, obj) for obj in objects):
                return (tokens[verb_index].start, follower.end)
        return None

    def extract(
        self,
        frontmatter: ResolvedFrontmatter,
        *,
        manifest_path: str = "SKILL.md",
        skill_md_text: str | None = None,
    ) -> tuple[ClaimRecord, ...]:
        """Mine both regions into id-assigned ``description_phrase`` claims.

        Offsets point into the exact string each span was mined from (the
        description text / the body region); lines resolve against the full
        manifest when available, folding multi-line descriptions forward.
        Records sort by ``(capability,)`` before id assignment.
        """
        candidates: list[tuple[str, str, int | None, int | None, int | None]] = []
        description = frontmatter.description_raw
        if description.strip():
            for capability, (start, end) in self.mine_region(description).items():
                line = frontmatter.description_line
                if line is not None:
                    line += description.count("\n", 0, start)
                candidates.append((capability, description[start:end], line, start, end))
        if skill_md_text is not None:
            body, body_line = _split_manifest_body(skill_md_text)
            if body.strip():
                for capability, (start, end) in self.mine_region(body).items():
                    candidates.append(
                        (
                            capability,
                            body[start:end],
                            body_line + body.count("\n", 0, start),
                            start,
                            end,
                        )
                    )
        first_per_capability: dict[str, tuple[str, str, int | None, int | None, int | None]] = {}
        for candidate in candidates:
            first_per_capability.setdefault(candidate[0], candidate)
        ordered = sorted(first_per_capability.values(), key=lambda item: item[0])
        return tuple(
            ClaimRecord(
                id=f"C-{index}",
                kind=CLAIM_KIND_DESCRIPTION_PHRASE,
                capability=capability,
                span=ClaimSpan(
                    path=manifest_path,
                    line=line,
                    quote=quote,
                    start_offset=start,
                    end_offset=end,
                ),
                extractor=EXTRACTOR_LEXICON_V1,
            )
            for index, (capability, quote, line, start, end) in enumerate(ordered, start=1)
        )


def extract_lexicon_claims(
    frontmatter: ResolvedFrontmatter,
    *,
    manifest_path: str = "SKILL.md",
    skill_md_text: str | None = None,
) -> tuple[ClaimRecord, ...]:
    """§9.2 group-2 claims alone (lexicon:v1 / description_phrase records)."""
    return LexiconExtractor().extract(
        frontmatter,
        manifest_path=manifest_path,
        skill_md_text=skill_md_text,
    )


def extract_all_claims(
    frontmatter: ResolvedFrontmatter,
    *,
    manifest_path: str = "SKILL.md",
    skill_md_text: str | None = None,
) -> tuple[ClaimRecord, ...]:
    """Field-direct ∪ lexicon claims — THE ingest seam (D-038).

    A lexicon candidate whose capability a field-direct claim already covers
    (:func:`is_declared` semantics) is dropped: duplicate coverage adds noise
    without changing any declared-discount decision. Survivors merge with the
    field-direct pool, deduplicate on ``(kind, capability, quote)``, sort by
    ``(capability, kind, quote)`` (D-016 law, now across BOTH pools), and
    share one id sequence so ids never depend on which extractor spoke first.
    """
    field_direct = extract_field_direct_claims(
        frontmatter,
        manifest_path=manifest_path,
        skill_md_text=skill_md_text,
    )
    covered = [claim.capability for claim in field_direct]
    merged: list[ClaimRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for claim in (
        *field_direct,
        *extract_lexicon_claims(
            frontmatter, manifest_path=manifest_path, skill_md_text=skill_md_text
        ),
    ):
        if is_declared(claim.capability, covered) and claim.extractor == EXTRACTOR_LEXICON_V1:
            continue
        key = (claim.kind, claim.capability, claim.span.quote)
        if key in seen:
            continue
        seen.add(key)
        merged.append(claim)
    merged.sort(key=lambda item: (item.capability, item.kind, item.span.quote))
    return tuple(replace(claim, id=f"C-{index}") for index, claim in enumerate(merged, start=1))


# ---------------------------------------------------------------------------
# Overreach primitive (§9.2): actual ∧ ¬claimed
# ---------------------------------------------------------------------------

BASIS_NO_CLAIMS_MADE = "no-claims-made"
BASIS_CONTRADICTS_CLAIM = "contradicts_claim"


def parse_capability(capability_path: str) -> tuple[str, str | None]:
    """Split a §9.1 path into ``(family, subpath|None)`` (tolerant)."""
    family, sep, subpath = capability_path.strip().partition(":")
    if not sep:
        return family, None
    return family, subpath.strip() or None


def is_declared(capability_path: str, claimed_paths: Iterable[str]) -> bool:
    """Does any claim cover *capability_path*?

    Semantics (DECISIONS D-018): a family-level claim covers every subpath;
    a subpath-bearing claim covers only its own family+subpath pair.
    ``persistence:scheduler`` therefore declares scheduling but not
    ``persistence:cron_json``, while bare ``network.send`` declares both
    ``network.send`` and ``network.send:messaging_human`` evidence.
    """
    family, subpath = parse_capability(capability_path)
    for claimed in claimed_paths:
        claim_family, claim_subpath = parse_capability(claimed)
        if claim_family == family and (claim_subpath is None or claim_subpath == subpath):
            return True
    return False


@dataclass(frozen=True)
class OverreachEvidence:
    """Actual-behavior pointer attached to an overreach record."""

    path: str
    line: int | None = None
    snippet: str = ""


@dataclass(frozen=True)
class WeightNote:
    """Scoring trace for the §9.3 weight line (every number traces, T3)."""

    points: int  # positive magnitude; rendered with U+2212 per template
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW
    dynamic: bool = True
    declared: bool = False


@dataclass(frozen=True)
class OverreachRecord:
    """One undeclared actual capability (SPEC §9.2/§9.3)."""

    capability: str
    basis: str  # BASIS_* constant
    claim: ClaimRecord | None = None
    evidence: OverreachEvidence | None = None
    weight: WeightNote | None = None


def compute_overreach(
    claimed_paths: Iterable[str],
    actual_paths: Iterable[str],
) -> tuple[OverreachRecord, ...]:
    """Records for actual capabilities no claim covers, sorted by path.

    When *claimed_paths* is empty every record carries
    :data:`BASIS_NO_CLAIMS_MADE` (the §9.2 "undisclosed capability"
    wording); otherwise :data:`BASIS_CONTRADICTS_CLAIM`. Claimed ∩ actual is
    structurally never reported (property-tested).
    """
    claimed = [str(path) for path in claimed_paths]
    basis = BASIS_NO_CLAIMS_MADE if not claimed else BASIS_CONTRADICTS_CLAIM
    unique_actual: list[str] = []
    for actual in actual_paths:
        text = str(actual)
        if text not in unique_actual:
            unique_actual.append(text)
    return tuple(
        OverreachRecord(capability=path, basis=basis)
        for path in sorted(unique_actual)
        if not is_declared(path, claimed)
    )


def build_overreach_reports(
    claims: Iterable[ClaimRecord],
    actual_evidence: Mapping[str, OverreachEvidence],
    *,
    weights: Mapping[str, WeightNote] | None = None,
) -> tuple[OverreachRecord, ...]:
    """Join claim spans + engine evidence into fully-renderable records.

    The contradicted claim attached (when one exists) is the same-family
    claim with the lowest id — deterministic and narrative-appropriate.
    """
    claim_list = list(claims)
    actual_paths = sorted(actual_evidence)
    records: list[OverreachRecord] = []
    for path in actual_paths:
        if is_declared(path, [claim.capability for claim in claim_list]):
            continue
        family, _sub = parse_capability(path)
        contradicted = next(
            (claim for claim in claim_list if parse_capability(claim.capability)[0] == family),
            None,
        )
        basis = BASIS_NO_CLAIMS_MADE if not claim_list else BASIS_CONTRADICTS_CLAIM
        records.append(
            OverreachRecord(
                capability=path,
                basis=basis,
                claim=contradicted,
                evidence=actual_evidence[path],
                weight=None if weights is None else weights.get(path),
            )
        )
    return tuple(records)


# ---------------------------------------------------------------------------
# Deterministic explanation templates (§9.3)
# ---------------------------------------------------------------------------

_NOTHING_CLAIMED = "(nothing — description makes no capability statements)"

#: Family → ``because`` clause. ONLY the network.send clause is pinned by
#: SPEC §9.3 verbatim; siblings follow its pattern (DECISIONS D-019).
BECAUSE_CLAUSES: dict[str, str] = {
    "credentials.read": "the bundle reads credentials the manifest never mentions",
    "execute.code": "the bundle executes dynamic code the manifest never mentions",
    "execute.shell": "the bundle runs commands the manifest never mentions",
    "filesystem.outside": "the bundle writes outside the skill root the manifest never mentions",
    "filesystem.read": "the bundle reads files the manifest never mentions",
    "filesystem.write": "the bundle writes files the manifest never mentions",
    "integrity.override": (
        "the bundle overrides agent integrity controls the manifest never mentions"
    ),
    "money": "the bundle moves money the manifest never mentions",
    "network.read": "the bundle fetches remote content the manifest never mentions",
    "network.send": "the bundle performs an upload the manifest never mentions",
    "obfuscation": "the bundle layers encoding to dodge review the manifest never mentions",
    "persona.write": "the bundle edits agent self-state the manifest never mentions",
    "persistence": "the bundle schedules persistence the manifest never mentions",
    "secrets.exfil": "the bundle sends collected secrets out the manifest never mentions",
    "spawn.agent": "the bundle chains further agent execution the manifest never mentions",
    "surveillance": "the bundle watches device surfaces the manifest never mentions",
}
_DEFAULT_BECAUSE = "the manifest never mentions this capability"


def _because_clause(capability_path: str) -> str:
    family, _sub = parse_capability(capability_path)
    return BECAUSE_CLAUSES.get(family, _DEFAULT_BECAUSE)


def _loc(path: str, line: int | None) -> str:
    return f"{path}:{line}" if line is not None else path


def _template_row(label: str, value: str, width: int, location: str | None) -> str:
    padded = value.ljust(width)
    if location:
        return f"{label} {padded}   [{location}]"
    return f"{label} {padded}".rstrip()


def explain_overreach(record: OverreachRecord) -> str:
    """Render the §9.3 template exactly (deterministic, snapshot-pinned).

    Missing pieces degrade honestly: no claim ⇒ the template's literal
    nothing-claimed line; no evidence ⇒ the capability path stands in; no
    weight ⇒ the weight line is omitted rather than fabricated.
    """
    if record.claim is not None:
        claimed_value = record.claim.span.quote
        claimed_loc = _loc(record.claim.span.path, record.claim.span.line)
    else:
        claimed_value = _NOTHING_CLAIMED
        claimed_loc = None

    if record.evidence is not None:
        actual_value = record.evidence.snippet or record.capability
        actual_loc = _loc(record.evidence.path, record.evidence.line)
    else:
        actual_value = record.capability
        actual_loc = None

    width = max(len(claimed_value), len(actual_value))
    lines = [
        f"OVERREACH: {record.capability}",
        _template_row("  claimed :", claimed_value, width, claimed_loc),
        _template_row("  actual  :", actual_value, width, actual_loc),
        f"  because : {_because_clause(record.capability)}",
    ]
    if record.weight is not None:
        weight = record.weight
        lines.append(
            f"  weight  : \u2212{weight.points} "
            f"({weight.severity}, {'dynamic' if weight.dynamic else 'static'} "
            f"evidence, {'declared' if weight.declared else 'undeclared'})"
        )
    return "\n".join(lines)


def render_overreach_section(
    claimed_paths: Iterable[str],
    actual_paths: Iterable[str],
) -> str:
    """Compact overreach block for report/inventory seams (paths only).

    Full §9.3 templates need evidence snippets; this section renders the
    deterministic skeleton so surfaces can show the diff before engines
    attach locations.
    """
    records = compute_overreach(claimed_paths, actual_paths)
    if not records:
        return "overreach: 0 undisclosed"
    lines = [f"overreach: {len(records)} undisclosed"]
    for record in records:
        lines.append(f"  OVERREACH: {record.capability} ({record.basis})")
        lines.append(f"  because : {_because_clause(record.capability)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LNS-MAN-004 detector (claims-stage host until E1 takes ownership, D-020)
# ---------------------------------------------------------------------------


def finding_fingerprint(rule_id: str, capability: str, normalized_evidence: str) -> str:
    """``sha256(rule_id ‖ capability ‖ normalized-evidence)`` (D-HASH).

    Deliberately excludes line numbers so fingerprints stay stable across
    line shifts. Shared shape with the engines seam (single definition lives
    here until the scoring phase unifies helpers).
    """
    digest = hashlib.sha256()
    digest.update(rule_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(capability.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(normalized_evidence.encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def vague_description_finding(
    frontmatter: ResolvedFrontmatter,
    rule: Any,
    *,
    manifest_path: str = "SKILL.md",
    description_line: int | None = None,
) -> dict[str, Any] | None:
    """§7-shaped LNS-MAN-004 finding, or ``None`` when not applicable.

    Silent when the description states concrete capability cues AND when the
    frontmatter was never readable in the first place (the parse failure has
    its own diagnostic; see ``_UNASSESSABLE_FRONTMATTER_ERRORS``).
    """
    if any(err in frontmatter.validation_errors for err in _UNASSESSABLE_FRONTMATTER_ERRORS):
        return None
    if description_states_concrete_capability(frontmatter.description_raw):
        return None
    description = frontmatter.description_raw or ""
    collapsed = " ".join(description.split())
    return {
        "rule_id": rule.id,
        "rule_version": rule.rule_version,
        "engine": rule.engine,
        "title": rule.title,
        "capability": rule.capability,
        "severity": rule.severity,
        "effective_severity": rule.severity,
        "confidence": rule.confidence_default,
        "evidence_kind": rule.evidence_kind,
        "static_only": True,
        "declared": False,
        "overreach": False,
        "location": {
            "path": manifest_path,
            "start_line": description_line,
            "end_line": description_line,
            "snippet": description[:100],
            "redacted": False,
        },
        "claim_ref": None,
        "message": VAGUE_DESCRIPTION_MESSAGE,
        "remediation": rule.remediation,
        "tags": list(rule.tags),
        "fingerprint": finding_fingerprint(rule.id, rule.capability, collapsed[:200]),
        "suppressed": False,
        "suppressed_by": None,
        "llm_touched": False,
    }


def run_claim_stage(
    ir: SkillIR,
    rules: Iterable[Any],
    diagnostics: Any = None,
) -> list[dict[str, Any]]:
    """Corpus/orchestration seam: findings hosted by the claims stage.

    Only rules listed in :data:`CLAIM_STAGE_RULE_IDS` are handled here; once
    the bound engine registers in ``skill_lens.engines``, the corpus harness
    stops routing those rules here (no double emission). Never raises into
    callers; ``diagnostics`` is accepted for seam-shape symmetry.
    """
    del diagnostics  # seam symmetry; the stage currently emits no diagnostics
    if ir.frontmatter is None:
        return []
    produced: list[dict[str, Any]] = []
    for rule in sorted(rules, key=lambda item: getattr(item, "id", "")):
        if getattr(rule, "id", None) != CLAIM_STAGE_RULE_ID:
            continue
        finding = vague_description_finding(
            ir.frontmatter,
            rule,
            manifest_path=_manifest_rel(ir),
            description_line=ir.frontmatter.description_line,
        )
        if finding is not None:
            produced.append(finding)
    return produced


def _manifest_rel(ir: SkillIR) -> str:
    """Shallowest SKILL.md rel-path in the bundle (display label)."""
    best: tuple[int, str] | None = None
    for record in ir.files:
        if record.path.rsplit("/", 1)[-1] == "SKILL.md":
            depth_key = (record.path.count("/"), record.path)
            if best is None or depth_key < best:
                best = depth_key
    return best[1] if best is not None else "SKILL.md"


__all__ = [
    "BASIS_CONTRADICTS_CLAIM",
    "BASIS_NO_CLAIMS_MADE",
    "BECAUSE_CLAUSES",
    "CAPABILITY_CUES",
    "CLAIM_STAGE_RULE_ID",
    "CLAIM_STAGE_RULE_IDS",
    "COMPATIBILITY_PHRASES",
    "ARABIC_CAPABILITY_CUES",
    "CJKV_CAPABILITY_CUES",
    "MESSAGING_CLAIM_CAPABILITY",
    "RELATED_SKILLS_CAPABILITY",
    "SCHEDULER_CLAIM_CAPABILITY",
    "TOOLSET_TOKEN_MAP",
    "TOOL_CAPABILITY_MAP",
    "VAGUE_DESCRIPTION_MESSAGE",
    "OverreachEvidence",
    "OverreachRecord",
    "WeightNote",
    "LexiconExtractor",
    "build_overreach_reports",
    "compute_overreach",
    "description_states_concrete_capability",
    "explain_overreach",
    "extract_all_claims",
    "extract_field_direct_claims",
    "extract_lexicon_claims",
    "finding_fingerprint",
    "is_declared",
    "parse_capability",
    "render_overreach_section",
    "run_claim_stage",
    "vague_description_finding",
]
