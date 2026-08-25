"""Renderer contracts — chat compact (§11.3/§12.2), one-liners (§11.4), footer.

The coverage footer is BYTE-FROZEN (SPEC §12.6/R5): the literal below must
equal the SPEC text exactly, and every report surface carries it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from skill_lens.canonical import canonical_dumps
from skill_lens.render import (
    CHAT_HARD_BUDGET,
    CHAT_SOFT_BUDGET,
    COVERAGE_FOOTER,
    capability_line,
    counts_phrase,
    fast_line_fail,
    fast_line_ok,
    fast_line_scan_queued,
    fast_line_skip,
    render_chat_compact,
    render_terminal_panel,
    worst_findings,
)

# ---------------------------------------------------------------------------
# Envelope factory (report/1 shape, minimal but realistic)
# ---------------------------------------------------------------------------


def make_envelope(**overrides: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "schema": "report/1",
        "tool": {"name": "lens", "version": "0.9.0a0"},
        "target": {
            "bundle_hash": "sha256:" + "9f" * 32,
            "name": "web-design-guidelines",
            "category": "tools",
            "path_as_given": "~/.hermes/skills/tools/web-design-guidelines",
            "layout": "categorized",
            "source_kind": "dir",
            "file_count": 6,
            "total_bytes": 38912,
        },
        "provenance": {
            "identifier": "@vercel-labs/agent-skills",
            "trust_level": "trusted",
            "source_class": "installed",
        },
        "policy": {"profile": "street", "sources": ["built-in"]},
        "rule_pack": {"name": "core", "version": "2026.08.2", "checksum": "sha256:aa"},
        "score": {
            "value": 82,
            "grade": "B",
            "verdict": "notice",
            "needs_review": False,
            "ceilings_applied": [],
            "score_math": [],
        },
        "findings": [
            _finding("F-1", "LNS-NET-011", "HIGH", "posts data externally"),
            _finding("F-2", "LNS-OBS-002", "MEDIUM", "base64 blob decoded at runtime"),
        ],
        "suppressed_count": 0,
        "claims": [
            {
                "id": "C-1",
                "kind": "allowed_tools",
                "capability": "network.read",
                "span": {"path": "SKILL.md", "line": 5, "quote": "fetch"},
                "extractor": "field-direct",
            }
        ],
        "notes": [],
    }
    envelope.update(overrides)
    return envelope


def _finding(
    fid: str,
    rule_id: str,
    severity: str,
    message: str,
    *,
    declared: bool = False,
    confidence: float = 0.93,
    path: str = "scripts/sync.sh",
    line: int = 42,
) -> dict[str, Any]:
    return {
        "id": fid,
        "fingerprint": f"sha256:{abs(hash(rule_id)):064x}",
        "rule_id": rule_id,
        "severity": severity,
        "effective_severity": severity,
        "confidence": confidence,
        "evidence_kind": "crossref",
        "static_only": False,
        "declared": declared,
        "capability": "network.send",
        "suppressed": False,
        "location": {"path": path, "start_line": line},
        "message": message,
    }


# ---------------------------------------------------------------------------
# Footer law (R5)
# ---------------------------------------------------------------------------


def test_coverage_footer_is_byte_frozen() -> None:
    assert COVERAGE_FOOTER == (
        "· static analysis only — runtime-injected instructions "
        "(tool output) are out of scope · lens explain coverage"
    )


def test_chat_render_carries_footer_inside_fence() -> None:
    text = render_chat_compact(make_envelope())
    lines = text.splitlines()
    assert lines[0].startswith("```")
    assert lines[-1] == "```"
    assert COVERAGE_FOOTER in lines


# ---------------------------------------------------------------------------
# §11.3 surface neutrality
# ---------------------------------------------------------------------------


def test_chat_render_is_fenced_without_ansi_or_pipe_tables() -> None:
    text = render_chat_compact(make_envelope())
    assert text.count("```") >= 2
    assert "\x1b" not in text
    for line in text.splitlines():
        assert not line.lstrip().startswith("|"), f"pipe table row leaked: {line!r}"


def test_chat_render_sections_follow_122_shape() -> None:
    text = render_chat_compact(make_envelope())
    assert "SKILL LENS 0.9.0a0 · pack 2026.08.2" in text
    assert "patient : web-design-guidelines (@vercel-labs/agent-skills · trusted)" in text
    assert "sha256:9f2…f9f" in text or "sha256:" in text
    assert "grade   : B 82/100 · verdict NOTICE" in text
    assert "caps    :" in text
    assert "! WARN LNS-NET-011 posts data externally" in text
    assert "scripts/sync.sh:42 — network.send · UNDECLARED · conf 0.93" in text
    assert "advisor only — lens never blocks installs." in text


def test_clean_bundle_renders_none_and_flag_line_when_needed() -> None:
    clean = make_envelope(
        score={
            "value": 100,
            "grade": "A",
            "verdict": "clean",
            "needs_review": False,
            "ceilings_applied": [],
            "score_math": [],
        },
        findings=[],
    )
    text = render_chat_compact(clean)
    assert "findings: none" in text

    flagged = make_envelope(
        score={
            "value": 40,
            "grade": "D",
            "verdict": "warn",
            "needs_review": True,
            "ceilings_applied": ["suspected-critical"],
            "score_math": [],
        }
    )
    assert "needs_review" in render_chat_compact(flagged)


def test_worst_findings_order_severity_then_law_key() -> None:
    envelope = make_envelope(
        findings=[
            _finding("F-1", "LNS-B-001", "MEDIUM", "m", path="a.sh", line=1),
            _finding("F-2", "LNS-A-001", "CRITICAL", "c", path="z.sh", line=1),
            _finding("F-3", "LNS-C-001", "HIGH", "h", path="b.sh", line=1),
            _finding("F-4", "LNS-D-001", "LOW", "l", path="d.sh", line=1),
        ]
    )
    top = [str(f["rule_id"]) for f in worst_findings(envelope, 4)]
    assert top == ["LNS-A-001", "LNS-C-001", "LNS-B-001", "LNS-D-001"]
    assert [str(f["id"]) for f in worst_findings(envelope, 2)] == ["F-2", "F-3"]


def test_counts_phrase_and_capability_line_shapes() -> None:
    envelope = make_envelope()
    assert counts_phrase(envelope) == "1 warn 1 note"
    assert counts_phrase(make_envelope(findings=[])) == "0 findings"
    caps = capability_line(envelope)
    assert caps.startswith("net.send")
    assert "(declared 1)" in caps


# ---------------------------------------------------------------------------
# Budget ladder + overflow persistence
# ---------------------------------------------------------------------------


def _fat_envelope(count: int = 40) -> dict[str, Any]:
    findings = [
        _finding(f"F-{i}", f"LNS-FAT-{i:03d}", "MEDIUM", "x" * 120, line=i)
        for i in range(1, count + 1)
    ]
    return make_envelope(findings=findings)


def test_over_soft_budget_collapses_to_top3_with_pointer(tmp_path: Path) -> None:
    envelope = _fat_envelope()
    text = render_chat_compact(envelope, plugin_data_dir=tmp_path)
    assert len(text) <= CHAT_SOFT_BUDGET + 200  # collapsed render stays small
    shown = sum(1 for line in text.splitlines() if line.startswith(("!", "○")))
    assert shown == 3  # top-3 only (each finding = head line; detail indented)
    reports = list((tmp_path / "reports").glob("web-design-guidelines-*.txt"))
    assert len(reports) == 1
    assert "full report: " in text
    # Overflow artifact holds the canonical envelope, byte-reloadable.
    stored = json.loads(reports[0].read_text(encoding="utf-8"))
    assert canonical_dumps(stored) == canonical_dumps(envelope)


def test_hard_budget_fallback_is_count_line_only(tmp_path: Path) -> None:
    envelope = _fat_envelope(count=60)
    # Force even the collapsed render over the hard budget via giant messages.
    for finding in envelope["findings"]:
        finding["message"] = "y" * 400
    text = render_chat_compact(envelope, plugin_data_dir=tmp_path)
    assert len(text) <= CHAT_HARD_BUDGET
    assert "full report: " in text


def test_overflow_filename_carries_name_and_hash8(tmp_path: Path) -> None:
    text = render_chat_compact(_fat_envelope(), plugin_data_dir=tmp_path)
    del text
    (path,) = (tmp_path / "reports").glob("*.txt")
    name, shard = path.stem.rsplit("-", 1)
    assert name == "web-design-guidelines"
    assert len(shard) == 8 and int(shard, 16) >= 0


def test_no_dir_degrades_to_inline_notice(tmp_path: Path) -> None:
    unwritable = tmp_path / "missing" / "deep"
    envelope = _fat_envelope()
    text = render_chat_compact(envelope, plugin_data_dir=unwritable / "reports")
    assert "full report:" in text


def test_overflow_filename_sanitizes_hostile_names(tmp_path: Path) -> None:
    """Hostile bundle names must not break the §11.3 pointer contract (D-032)."""
    envelope = _fat_envelope()
    envelope["target"]["name"] = "../evil/" + "x" * 300 + "\n\t.."
    text = render_chat_compact(envelope, plugin_data_dir=tmp_path)
    assert "could not be persisted" not in text  # write succeeded → pointer present
    assert "full report: " in text
    (path,) = (tmp_path / "reports").glob("*.txt")
    assert len(path.name) <= 64 + 1 + 8 + 4  # stem-clip + shard keeps NAME_MAX proof
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    assert set(path.stem) <= safe
    # Artifact still holds the canonical envelope, byte-reloadable.
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert canonical_dumps(stored) == canonical_dumps(envelope)


def test_long_target_name_cannot_break_hard_budget() -> None:
    """A pathological target.name must never push renders past §11.3 hard."""
    envelope = make_envelope()
    envelope["target"]["name"] = "N" * 3000
    text = render_chat_compact(envelope, plugin_data_dir=None)
    assert len(text) <= CHAT_HARD_BUDGET
    assert "N" * 97 not in text  # displayed name clipped (96 chars + ellipsis)
    assert "patient : " + "N" * 95 + "…" in text


# ---------------------------------------------------------------------------
# §11.4 fast-path one-liners
# ---------------------------------------------------------------------------


def test_fast_line_ok_matches_format_a_field_order() -> None:
    line = fast_line_ok(
        name="web-design-guidelines",
        grade="B",
        value=82,
        verdict="notice",
        counts="1 warn 1 note",
        cached_seconds=12,
    )
    assert line == (
        "lens ok web-design-guidelines · B 82/100 · notice "
        "· 1 warn 1 note · cached 12s ago · /lens report"
    )


def test_fast_lines_are_short_ascii_and_pointed() -> None:
    lines = [
        fast_line_ok(
            name="n" * 60, grade="A", value=100, verdict="clean", counts="", cached_seconds=1
        ),
        fast_line_scan_queued(name="new-skill", hash8="9f2ca41e"),
        fast_line_skip(name="s", last_examined="14:02:11"),
        fast_line_fail(name="f", reason="unreadable target: scripts/ (permission denied)"),
    ]
    for line, pointed in zip(
        lines,
        # §11.4 mockups are normative verbatim: ok/scan/fail end with a pull
        # pointer, but format C (skip) is a bare status line without one.
        (True, True, False, True),
        strict=True,
    ):
        assert len(line) <= 160
        # §11.4 mockups are normative: the FIELD SEPARATOR is '·'; all other
        # characters (punctuation inside fields, names, reasons) stay ASCII.
        rest = line.replace("\u00b7", "")
        assert set(rest) <= {chr(c) for c in range(32, 127)}, rest
        assert "\x1b" not in line
        if pointed:
            assert "/lens" in line


def test_fast_line_queued_and_skip_exact_formats() -> None:
    assert fast_line_scan_queued(name="new-skill", hash8="9f2ca41e") == (
        "lens scan queued: new-skill · sha256 9f2ca41e · p95 400ms · "
        "/lens report new-skill when ready"
    )
    assert fast_line_skip(name="web", last_examined="14:02:11") == (
        "lens skip web · unchanged since last exam (14:02:11)"
    )


def test_fast_line_age_never_negative() -> None:
    from skill_lens.cache import CacheEntry

    entry = CacheEntry(
        bundle_hash="sha256:x",
        name="n",
        grade="A",
        value=100,
        verdict="clean",
        counts="",
        cached_at=time.monotonic() + 500,  # clock skew from another writer
    )
    assert entry.age_seconds() == 0


# ---------------------------------------------------------------------------
# Terminal panel is a separate surface (CLI-only, never slash)
# ---------------------------------------------------------------------------


def test_terminal_panel_differs_from_chat_and_stays_plain() -> None:
    envelope = make_envelope()
    panel = render_terminal_panel(envelope)
    chat = render_chat_compact(envelope)
    assert panel != chat
    assert panel.startswith("┌")
    assert "\x1b" not in panel
    assert COVERAGE_FOOTER in panel
