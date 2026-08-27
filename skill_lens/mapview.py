"""``lens map`` — the SkillIR tree view (§11.2: "what did I agree to").

Renders one bundle's IR as a stable, collapsed chat/CLI surface:

- **tree** — files grouped under their categorized-layout directories,
  ascending path order (the DETERMINISM LAW key), roles + sizes;
- **claims** — every verbatim capability claim with its span;
- **capabilities graph** — claimed vs observed families per row:
  ``claimed · observed`` / ``claimed · not observed`` /
  ``UNDECLARED · observed``. Observed families come from ACTIVE engine
  findings only; suppressed ones price nothing and observe nothing here.
- **provenance** — hub annotation rendered ANNOTATION-ONLY (D-PROV): never
  read by arithmetic (this module computes no scores at all).

Two renderers, strictly apart (same split as render.py):

- :func:`render_map_chat` — fenced, surface-neutral, §11.3 budget ladder
  (full ≤ soft → drop tree leaves / cap claims ≤ hard → head+graph+pointer
  with the full text persisted beside the report artifacts);
- :func:`render_map_panel` — the CLI box-drawing panel (§12.1 house style),
  printed through the CLI lane's ``_emit`` so NO_COLOR/--plain strip it.

No ANSI ever enters the chat variant; no pipe tables anywhere.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .ir import SkillIR
from .render import (
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
    persist_full_text,
)

#: Row caps for the ladder rungs (mirrors the §11.3 collapse discipline).
#: The FULL rung is unbounded — it targets the soft budget and, when over,
#: becomes the PERSISTED ARTIFACT, which must carry the complete tree.
_TREE_LEAVES_FULL = 1 << 30
_CLAIMS_FULL = 1 << 30
_CLAIMS_COLLAPSED = 4
_TREE_LEAVES_COLLAPSED = 0  # collapsed rung shows directory rows only


def _hash_head(bundle_hash: str | None) -> str:
    if not bundle_hash or not bundle_hash.startswith("sha256:"):
        return "unhashed"
    hexpart = bundle_hash[len("sha256:") :]
    if len(hexpart) <= 7:
        return f"sha256:{hexpart}"
    return f"sha256:{hexpart[:3]}…{hexpart[-3:]}"


def _family(capability: str) -> str:
    return capability.split(":", 1)[0]


def _provenance_bits(envelope: Mapping[str, Any]) -> str | None:
    provenance = envelope.get("provenance") or {}
    bits = [
        str(provenance[key])
        for key in ("identifier", "trust_level", "resolved_from", "source_class")
        if provenance.get(key)
    ]
    return " · ".join(bits) if bits else None


def _tree_rows(ir: SkillIR, max_leaves: int) -> tuple[list[str], int]:
    """Directory-grouped file rows in ascending path order."""
    records = sorted(ir.files, key=lambda rec: rec.path)
    dirs: dict[str, int] = {}
    leaf_rows: list[tuple[str, str]] = []
    for record in records:
        parts = record.path.split("/")
        if len(parts) > 1:
            dir_name = "/".join(parts[:-1])
            dirs[dir_name] = dirs.get(dir_name, 0) + 1
        role = record.role if record.role != "unknown" else "file"
        kb = max(1, round(record.size / 1024))
        leaf_rows.append((record.path, f"{role} · {kb} KB"))
    lines: list[str] = []
    shown = 0
    emitted_dirs: set[str] = set()
    for path, detail in leaf_rows:
        parent = "/".join(path.split("/")[:-1])
        if parent and parent not in emitted_dirs:
            emitted_dirs.add(parent)
            count = dirs[parent]
            lines.append(f"  {parent}/  ({count} " + ("file" if count == 1 else "files") + ")")
        if shown >= max_leaves:
            continue
        indent = "    " * (path.count("/"))
        lines.append(f"{indent}  {path}  — {detail}")
        shown += 1
    hidden = len(leaf_rows) - shown
    if hidden > 0:
        lines.append(f"  … {hidden} more files in the full map")
    return lines, len(records)


def _claim_rows(envelope: Mapping[str, Any], cap: int) -> tuple[list[str], int]:
    claims = envelope.get("claims") or ()
    rows: list[str] = []
    for claim in claims[:cap]:
        span = claim.get("span") or {}
        quote = str(span.get("quote", ""))
        if len(quote) > 40:
            quote = quote[:39] + "…"
        line = span.get("line")
        if isinstance(line, int):
            at = f"{span.get('path', '?')}:{line}"
        else:
            at = str(span.get("path", "?"))
        rows.append(f'  {claim.get("id", "?")} {claim.get("capability", "?")} — {at} "{quote}"')
    return rows, len(claims)


def _capability_rows(envelope: Mapping[str, Any]) -> list[str]:
    claimed: set[str] = set()
    for claim in envelope.get("claims") or ():
        family = _family(str(claim.get("capability", "")))
        if family:
            claimed.add(family)
    observed: set[str] = set()
    for finding in envelope.get("findings", ()):
        if finding.get("suppressed", False):
            continue
        family = _family(str(finding.get("capability", "")))
        if family:
            observed.add(family)
    rows = []
    for family in sorted(claimed | observed):
        if family in claimed and family in observed:
            state = "claimed · observed"
        elif family in claimed:
            state = "claimed · not observed"
        else:
            state = "UNDECLARED · observed"
        rows.append(f"  {family:<14} {state}")
    return rows


def _map_sections(
    envelope: Mapping[str, Any],
    ir: SkillIR,
    *,
    tree_leaves: int,
    claims_cap: int,
) -> list[list[str]]:
    target = envelope.get("target") or {}
    category = target.get("category")
    layout = target.get("layout", "flat")
    title = str(target.get("name", "?"))
    where = f"{category}/{title}" if category else title
    head = [
        f"MAP · {title} ({where} · {layout})" if category else f"MAP · {title} ({layout})",
        f"bundle  : {_hash_head(target.get('bundle_hash'))} · "
        f"{target.get('file_count', 0)} files · "
        f"{max(1, round(int(target.get('total_bytes') or 0) / 1024))} KB",
    ]
    prov = _provenance_bits(envelope)
    head.append(f"provenance: {prov} (annotation)" if prov else "provenance: none recorded")

    tree_lines, file_count = _tree_rows(ir, tree_leaves)
    sections = [head]
    if tree_lines:
        sections.append(["tree:", *tree_lines])

    claim_lines, total_claims = _claim_rows(envelope, claims_cap)
    if total_claims:
        block = [f"claims ({total_claims}):"]
        block.extend(claim_lines)
        if total_claims > claims_cap:
            block.append(f"  … {total_claims - claims_cap} more claims in the full map")
        sections.append(block)

    graph = _capability_rows(envelope)
    if graph:
        graph_block = ["capabilities (claimed vs observed):", *graph]
    else:
        graph_block = ["capabilities: none"]
    sections.append(graph_block)
    return sections


def _assemble(
    sections: list[list[str]],
    *,
    pointer: str | None = None,
    name: str = "",
) -> str:
    tail = [f"next: /lens autopsy {name} · /lens report".strip()]
    if pointer:
        tail.insert(0, f"full map: {pointer}")
    sections = [*sections, tail]
    inner = "\n\n".join("\n".join(section) for section in sections).strip("\n")
    inner += "\n" + COVERAGE_FOOTER
    return f"```\n{inner}\n```\n"


def render_map_chat(
    envelope: Mapping[str, Any],
    ir: SkillIR,
    *,
    plugin_data_dir: Path | str | None = None,
    soft_budget: int | None = None,
) -> str:
    """Fenced collapsed map (§11.3 ladder; never raises, never emits ANSI).

    Rungs: full tree+claims → tree leaves dropped & claims capped →
    head + capabilities graph + persisted-full pointer.
    """
    soft = CHAT_SOFT_BUDGET
    if soft_budget is not None:
        soft = max(200, min(int(soft_budget), CHAT_HARD_BUDGET))
    name = str((envelope.get("target") or {}).get("name", ""))
    full_sections = _map_sections(
        envelope, ir, tree_leaves=_TREE_LEAVES_FULL, claims_cap=_CLAIMS_FULL
    )
    full_text = _assemble(full_sections, name=name)
    if len(full_text) <= soft:
        return full_text

    def collapsed_body(tree_leaves: int, claims_cap: int, pointer: str | None) -> str:
        body = _assemble(
            _map_sections(envelope, ir, tree_leaves=tree_leaves, claims_cap=claims_cap),
            pointer=pointer,
            name=name,
        )
        return body

    pointer = persist_full_text(plugin_data_dir, "map", envelope, full_text)
    body = collapsed_body(_TREE_LEAVES_COLLAPSED, _CLAIMS_COLLAPSED, pointer)
    if len(body) <= CHAT_HARD_BUDGET:
        return body
    # Extreme overflow: keep the identity + graph, point at the artifact.
    minimal = _map_sections(envelope, ir, tree_leaves=0, claims_cap=0)
    kept = [minimal[0], minimal[-1]]
    return _assemble(kept, pointer=pointer, name=name)


def render_map_panel(envelope: Mapping[str, Any], ir: SkillIR) -> str:
    """Box-drawing CLI panel (§12.1 style; color is the host's business).

    Printed through cli._emit so --plain/NO_COLOR translate box drawing to
    ASCII. Never wired to slash surfaces (§11.3 keeps that lane fenced).
    """
    width = 80
    title = " SKILL LENS MAP "

    def row(text: str) -> str:
        return f"│ {text.ljust(width - 4)[: width - 4]} │"

    lines = [f"┌{title.center(width - 2, '─')}┐"]
    for section_index, section in enumerate(
        _map_sections(envelope, ir, tree_leaves=_TREE_LEAVES_FULL, claims_cap=_CLAIMS_FULL)
    ):
        if section_index:
            lines.append(f"├{'─' * (width - 2)}┤")
        for line in section:
            lines.append(row(line))
    autopsy_name = str((envelope.get("target") or {}).get("name", ""))
    lines += [
        f"├{'─' * (width - 2)}┤",
        row(f"next: lens autopsy {autopsy_name} · lens report"),
        f"└{'─' * (width - 2)}┘",
        COVERAGE_FOOTER,
    ]
    return "\n".join(lines)


__all__ = [
    "render_map_chat",
    "render_map_panel",
]
