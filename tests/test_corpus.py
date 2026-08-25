"""Corpus harness tests (PLAN §3: golden corpus with expected.toml).

Law of this suite (task spec): every malicious fixture must catch its
expected rules; every benign fixture fires NOTHING from the core pack.
While an expected rule's engine is not implemented yet, that expectation
xfails WITH REASON "engine not implemented" — the only sanctioned xfail
class. When engines land later this phase, the same assertions harden into
real gates without any test edits.

Also enforces the §15 bidirectional fixture contract: every active core rule
declares >=1 positive fixture that expects it, >=1 negative benign fixture,
and all referenced paths exist on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skill_lens.corpus import (
    available_engines,
    claim_stage_rule_ids,
    discover_fixtures,
    evaluate_case,
    find_corpus_root,
    prepare_home,
    run_case,
)
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = REPO_ROOT / "corpus" / "fixtures"


@pytest.fixture(scope="module")
def pack():
    return load_core_pack()


@pytest.fixture(scope="module")
def specs():
    return discover_fixtures(CORPUS_ROOT)


# ---------------------------------------------------------------------------
# Corpus integrity (no engines needed)
# ---------------------------------------------------------------------------


def test_corpus_root_found() -> None:
    assert find_corpus_root(REPO_ROOT) == CORPUS_ROOT


def test_fixture_counts(specs) -> None:
    malicious = [s for s in specs if s.is_malicious]
    benign = [s for s in specs if not s.is_malicious]
    assert len(malicious) >= 12, "core pack v0.1 needs its full TP set"
    assert len(benign) >= 12, "every malicious pattern needs a benign lookalike"


def test_every_fixture_parses_expected_toml(specs) -> None:
    assert specs, "discovery found nothing"
    for spec in specs:
        assert spec.category, f"{spec.klass}/{spec.name}: category missing"
        if spec.is_malicious:
            assert spec.expects, (
                f"{spec.klass}/{spec.name}: malicious fixtures MUST declare expect_rules"
            )
        else:
            assert not spec.expects, f"{spec.klass}/{spec.name}: benign fixtures expect nothing"


def test_expected_rule_ids_exist_in_core_pack(specs, pack) -> None:
    known = {rule.id for rule in pack.rules}
    for spec in specs:
        for expectation in spec.expects:
            assert expectation.rule_id in known, (
                f"{spec.klass}/{spec.name} expects unknown rule {expectation.rule_id}"
            )


def test_bidirectional_rule_fixture_contract(pack) -> None:
    """§15: every active rule ships TP + FP fixtures, wired both ways."""
    by_id = {spec.name: spec for spec in discover_fixtures(CORPUS_ROOT)}
    for rule in pack.rules:
        positives = [name.split("/")[-1] for name in rule.fixtures_positive]
        negatives = [name.split("/")[-1] for name in rule.fixtures_negative]
        assert positives, f"{rule.id} lacks positive fixtures"
        assert negatives, f"{rule.id} lacks negative fixtures (merge blocker)"
        for name in positives:
            spec = by_id.get(name)
            assert spec is not None, f"{rule.id} positive fixture missing: {name}"
            assert spec.is_malicious, f"{rule.id} positive fixture must be malicious"
            expecting = {e.rule_id for e in spec.expects}
            assert rule.id in expecting, (
                f"{name} does not declare expected rule {rule.id} in expected.toml"
            )
        for name in negatives:
            spec = by_id.get(name)
            assert spec is not None, f"{rule.id} negative fixture missing: {name}"
            assert not spec.is_malicious, f"{rule.id} negative fixture must be benign"
            fired = {e.rule_id for e in spec.expects}
            assert rule.id not in fired, f"benign {name} must not expect {rule.id}"


# ---------------------------------------------------------------------------
# Malicious fixtures catch their expected rules (engine-absence => xfail)
# ---------------------------------------------------------------------------


_ENGINE_AVAILABILITY = available_engines()
_CLAIM_STAGE_RULES = claim_stage_rule_ids()


def _require_engine(rule_id: str, pack) -> str | None:
    """Missing-engine reason for *rule_id*, or None when it can fire now.

    Rules hosted by the claims stage (DECISIONS D-020) are live gates even
    while their eventual engine is absent; they xfail never.
    """
    if rule_id in _CLAIM_STAGE_RULES:
        return None
    rule = pack.rule_by_id(rule_id)
    assert rule is not None
    if rule.engine not in _ENGINE_AVAILABILITY:
        return rule.engine
    return None


@pytest.mark.parametrize(
    "spec", [s for s in discover_fixtures(CORPUS_ROOT) if s.is_malicious], ids=lambda s: s.name
)
def test_malicious_fixture_catches_expected_rules(spec, pack, tmp_path) -> None:
    missing_engine = None
    for expectation in spec.expects:
        engine = _require_engine(expectation.rule_id, pack)
        if engine is not None:
            missing_engine = engine
            break
    if missing_engine is not None:
        pytest.xfail(f"engine '{missing_engine}' not implemented yet")

    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    problems = evaluate_case(result)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    "spec", [s for s in discover_fixtures(CORPUS_ROOT) if not s.is_malicious], ids=lambda s: s.name
)
def test_benign_fixture_fires_nothing(spec, pack, tmp_path) -> None:
    """Benign lookalikes stay silent.

    Vacuously true until the bound engines exist; hard gate from the moment
    each engine lands. Ingest diagnostics (unknown fields etc.) do not count
    as findings — evaluate_case only inspects engine findings.
    """
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    problems = evaluate_case(result)
    assert not problems, "\n".join(problems)


# ---------------------------------------------------------------------------
# Determinism + ingest dogfood sanity
# ---------------------------------------------------------------------------


def test_run_case_is_deterministic(pack, tmp_path) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "exfil-env-paste")
    first = run_case(spec, tmp_root=tmp_path / "a", pack=pack)
    second = run_case(spec, tmp_root=tmp_path / "b", pack=pack)
    assert json.dumps([f for f in first.findings], sort_keys=True) == json.dumps(
        [f for f in second.findings], sort_keys=True
    )
    assert first.ir.bundle_hash == second.ir.bundle_hash


def test_prepare_home_dogfoods_categorized_ingest(pack, tmp_path) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "rich-legit-metadata")
    home = prepare_home(spec, tmp_path)
    bundle = home / "skills" / spec.category / spec.name / "SKILL.md"
    companion = home / "skills" / spec.category / "note-helper" / "SKILL.md"
    assert bundle.is_file(), "fixture payload copied into categorized layout"
    assert companion.is_file(), "companion bundles placed for resolution"

    result = run_case(spec, tmp_root=tmp_path / "run", pack=pack)
    assert result.ir.identity.layout == "categorized"
    assert result.ir.frontmatter is not None
    assert result.ir.frontmatter.hermes is not None
    assert result.ir.frontmatter.hermes.category == spec.category


def test_companion_enables_related_skills_resolution(pack, tmp_path) -> None:
    """The rich-metadata benign case declares a RESOLVABLE related_skills ref."""
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "rich-legit-metadata")
    assert "note-helper" in spec.companions
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    assert result.ir.frontmatter is not None, "frontmatter must parse"
    hermes = result.ir.frontmatter.hermes
    assert hermes is not None, "metadata.hermes must resolve"
    assert list(hermes.related_skills) == ["note-helper"]


def test_future_keys_parse_and_are_ignored(pack, tmp_path) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "exfil-env-paste")
    assert spec.future.get("expect_verdict") == "alert"
    assert spec.future.get("expect_grade") == "F"
    # Running with future keys present must not crash or alter behavior.
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    assert isinstance(result.findings, tuple)


def test_missing_expected_toml_fails_closed(pack, tmp_path) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.is_malicious)
    manifest = spec.path / "expected.toml"
    backup = manifest.read_text(encoding="utf-8")
    try:
        manifest.unlink()
        broken = next(
            s
            for s in discover_fixtures(CORPUS_ROOT)
            if s.klass == spec.klass and s.name == spec.name
        )
        result = run_case(broken, tmp_root=tmp_path, pack=pack)
        problems = evaluate_case(result)
        assert any("expected.toml" in p for p in problems), problems
    finally:
        manifest.write_text(backup, encoding="utf-8")


# ---------------------------------------------------------------------------
# Engine-seam simulation: when a real engine lands, tests above harden from
# xfail to gate WITHOUT EDITS. Prove the switch by injecting a fake engine
# module shaped exactly per the D-015 contract.
# ---------------------------------------------------------------------------


def _install_fake_engine(monkeypatch, engine_name, rule_ids):
    """Register ``skill_lens.engines`` exposing REGISTRY + run_all."""
    import sys
    from types import ModuleType

    module = ModuleType("skill_lens.engines")

    def engine_fn(ir, rules, diags):  # noqa: ANN001 - contract-shaped fake
        findings = []
        wanted = set(rule_ids)
        for rule in rules:
            if rule.id not in wanted:
                continue
            findings.append(
                {
                    "rule_id": rule.id,
                    "severity": rule.severity,
                    "location": {"path": "scripts/fake.sh", "start_line": 1},
                }
            )
        return findings

    def run_all(ir, rules_by_engine, diagnostics):  # noqa: ANN001
        produced = []
        for name, fn in sorted(module.REGISTRY.items()):
            produced.extend(fn(ir, rules_by_engine.get(name, ()), diagnostics))
        return produced

    module.REGISTRY = {engine_name: engine_fn}  # type: ignore[attr-defined]
    module.run_all = run_all  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "skill_lens.engines", module)
    return module


def test_fake_engine_flips_malicious_case_green(pack, tmp_path, monkeypatch) -> None:
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "committed-keys")
    _install_fake_engine(monkeypatch, "secretscan", {"LNS-SEC-001"})
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    assert not evaluate_case(result), "engine present => expectation becomes a gate"


def test_benign_firing_is_flagged_as_problem(pack, tmp_path, monkeypatch) -> None:
    """If any engine fires on a benign lookalike, evaluate_case flags it.

    Real benign silence is proven by real detection logic once engines land;
    here we prove the GATE side of the harness with a deliberately dumb
    engine: its finding must surface as a problem, never pass silently.
    """
    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.name == "env-var-documentation")
    _install_fake_engine(monkeypatch, "secretscan", {"LNS-SEC-001"})
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    problems = evaluate_case(result)
    assert any("fired core-pack rules" in p and "LNS-SEC-001" in p for p in problems)


def test_engine_crash_is_isolated_not_fatal(pack, tmp_path, monkeypatch) -> None:
    import sys
    from types import ModuleType

    spec = next(s for s in discover_fixtures(CORPUS_ROOT) if s.is_malicious)
    module = ModuleType("skill_lens.engines")

    def boom(ir, rules, diags):  # noqa: ANN001 - deliberate crash fixture
        raise RuntimeError("deliberate crash")

    module.REGISTRY = {"secretscan": boom}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "skill_lens.engines", module)
    result = run_case(spec, tmp_root=tmp_path, pack=pack)
    codes = {d.code for d in result.diagnostics.snapshot()}
    assert "LNS-CORPUS-ENGINE-FAIL" in codes
    assert isinstance(result.findings, tuple)
