"""``/lens explain-rules`` + CLI registration (Phase 2 deliverable 3).

D-EXPLAIN made mechanical: rule metadata, pinned weight math, and the
provenance chain (pack version → profile → policy layers → severity_override
with reason/expiry). Snapshot stability is asserted byte-for-byte across
invocations; the CLI lane asserts §18 exit-code mapping (malformed policy ⇒ 2).
"""

from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

import pytest

from skill_lens.explain import explain_rules, find_rule
from skill_lens.policy import POLICY_EXIT_CODE, load_policy
from skill_lens.render import CHAT_HARD_BUDGET, COVERAGE_FOOTER
from skill_lens.rules import load_core_pack

REPORT_DATE = date(2026, 8, 25)
FUTURE = date(2099, 1, 1)


def _policy(tmp_path: Path, policy_body: str = ""):
    project = tmp_path / "proj"
    (project / ".lens").mkdir(parents=True, exist_ok=True)
    if policy_body:
        (project / ".lens" / "policy.toml").write_text(policy_body, encoding="utf-8")
    return load_policy(project_dir=project, global_path=tmp_path / "absent-global")


# ---------------------------------------------------------------------------
# Index (no --rule)
# ---------------------------------------------------------------------------


def test_index_carries_pack_provenance_and_footer(tmp_path: Path) -> None:
    pack = load_core_pack()
    text, notice = explain_rules(pack, _policy(tmp_path))
    assert notice == ""
    assert text.startswith("```") and text.rstrip().endswith("```")
    assert f"RULE PACK {pack.name} {pack.version}" in text
    assert "profile street" in text
    assert "sources: built-in" in text
    assert COVERAGE_FOOTER in text
    for rule in pack.rules:
        assert rule.id in text  # the FULL effective set survives collapse
    assert len(text) <= CHAT_HARD_BUDGET


def test_index_is_deterministic(tmp_path: Path) -> None:
    pack = load_core_pack()
    first, _ = explain_rules(pack, _policy(tmp_path))
    second, _ = explain_rules(pack, load_policy())
    # Different tmp projects but identical (empty) layers ⇒ identical bytes.
    assert first == second


def test_index_marks_overrides_and_disabled(tmp_path: Path) -> None:
    body = (
        "[rules]\n"
        'disable = ["LNS-MAN-001"]\n'
        "severity_override = [\n"
        f'  {{ rule_id = "LNS-SHL-001", severity = "LOW", '
        f'reason = "repo convention", expires = "{FUTURE.isoformat()}" }}\n'
        "]\n"
    )
    pack = load_core_pack()
    text, _ = explain_rules(pack, _policy(tmp_path, body), plugin_data_dir=None)
    assert "overrides: 1 active · disabled: 1" in text
    assert "LNS-MAN-001" in text and "DISABLED" in text
    assert "overridden" in text


# ---------------------------------------------------------------------------
# Single-rule card
# ---------------------------------------------------------------------------


def test_card_renders_pinned_weight_math_and_provenance(tmp_path: Path) -> None:
    pack = load_core_pack()
    text, notice = explain_rules(pack, _policy(tmp_path), rule_id="LNS-NET-011")
    assert notice == ""
    assert "RULE LNS-NET-011 v" in text
    assert "capability: network.send" in text
    assert "severity  : CRITICAL · pricing tier CRITICAL" in text
    assert "weight    : −40 first / −25 subsequent · tier cap none" in text
    assert "status    : active" in text
    assert "override: none" in text
    assert COVERAGE_FOOTER in text


def test_card_snapshot_stability_across_invocations(tmp_path: Path) -> None:
    """Same inputs ⇒ byte-identical output (snapshot law; no wall-clock)."""
    pack = load_core_pack()
    first, _ = explain_rules(pack, _policy(tmp_path), rule_id="LNS-SHL-001")
    second, _ = explain_rules(pack, _policy(tmp_path), rule_id="LNS-SHL-001")
    assert first == second
    assert "\x1b" not in first  # surface neutrality holds on detail cards too


def test_card_shows_active_override_with_reason_and_expiry(tmp_path: Path) -> None:
    body = (
        "[rules]\n"
        "severity_override = [\n"
        f'  {{ rule_id = "LNS-SHL-001", severity = "LOW", '
        f'reason = "repo convention: Makefile curl", expires = "{FUTURE.isoformat()}" }}\n'
        "]\n"
    )
    pack = load_core_pack()
    policy = _policy(tmp_path, body)
    text, _ = explain_rules(pack, policy, rule_id="LNS-SHL-001")
    assert "override: HIGH→LOW · expires 2099-01-01 · repo convention: Makefile curl ← " in text
    # The override writer layer names the project file with its line number.
    assert ".lens/policy.toml:L" in text


def test_expired_override_reports_none(tmp_path: Path) -> None:
    body = (
        "[rules]\n"
        "severity_override = [\n"
        '  { rule_id = "LNS-SHL-001", severity = "LOW", '
        'reason = "stale", expires = "2020-01-01" }\n'
        "]\n"
    )
    pack = load_core_pack()
    policy = _policy(tmp_path, body)
    # load_policy pre-filters expired overrides against the report date.
    policy = load_policy(
        project_dir=tmp_path / "proj",
        global_path=tmp_path / "absent",
        report_date=REPORT_DATE,
    )
    text, _ = explain_rules(pack, policy, rule_id="LNS-SHL-001")
    assert "override: none" in text


def test_disabled_rule_card_names_disabling_layer(tmp_path: Path) -> None:
    body = '[rules]\ndisable = ["LNS-NET-011"]\n'
    pack = load_core_pack()
    text, _ = explain_rules(pack, _policy(tmp_path, body), rule_id="LNS-NET-011")
    assert "status    : DISABLED by policy" in text
    assert "disable : DISABLED ← project .lens/policy.toml:L" in text


def test_unknown_rule_gets_sober_notice_not_silence(tmp_path: Path) -> None:
    pack = load_core_pack()
    text, notice = explain_rules(pack, _policy(tmp_path), rule_id="LNS-XXX-999")
    assert text == "" and notice
    assert "unknown rule id 'LNS-XXX-999'" in notice
    assert str(len(pack.rules)) in notice  # points at the real index


def test_find_rule_helper() -> None:
    pack = load_core_pack()
    assert len(find_rule(pack, "LNS-NET-011")) == 1
    assert find_rule(pack, "NOPE") == ()


# ---------------------------------------------------------------------------
# CLI lane: register_cli + §18 exit codes
# ---------------------------------------------------------------------------


class CliCtx:
    """FakePluginContext-shaped double (registration recorder)."""

    def __init__(self, data_root: Path) -> None:
        self.manifest = type("M", (), {"key": "lens", "name": "lens"})()
        self.plugin_id = "lens"
        self.cli_commands: dict[str, dict] = {}
        self.commands: dict[str, dict] = {}
        self.registered_hooks: list[tuple[str, object]] = []
        self._dir = data_root / "pd"
        self._dir.mkdir(parents=True, exist_ok=True)

    def register_hook(self, hook_name, callback):  # pragma: no cover - unused here
        self.registered_hooks.append((hook_name, callback))
        return object()

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = {"handler": handler}
        return object()

    def register_cli_command(self, name, help=None, setup_fn=None, handler_fn=None, description=""):
        self.cli_commands[name] = {
            "help": help,
            "setup_fn": setup_fn,
            "handler_fn": handler_fn,
            "description": description,
        }
        return object()

    @property
    def state(self):
        return type("S", (), {"data_dir": self._dir})()


def test_register_cli_records_on_host_seam(tmp_path: Path) -> None:
    from skill_lens.cache import FastPathCache
    from skill_lens.cli import register_cli
    from skill_lens.context import PluginContextView
    from skill_lens.slash import shared_cache

    ctx = CliCtx(tmp_path)
    view = PluginContextView(ctx)
    assert register_cli(view, cache=FastPathCache()) is True
    entry = ctx.cli_commands["lens"]
    assert callable(entry["setup_fn"]) and callable(entry["handler_fn"])
    assert "advisory" in entry["description"]
    shared_cache().clear()


def test_cli_parser_round_trips_tokens(tmp_path: Path) -> None:
    from skill_lens.cli import setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    namespace = parser.parse_args(
        ["baseline", "my-skill", "--reason", "legacy docs", "--expires", "2027-01-15"]
    )
    # Token reconstruction feeds the SAME slash implementations.
    tokens = _tokens_for_test("baseline", namespace)
    assert tokens[:3] == ["baseline", "my-skill", "--reason"]


def _tokens_for_test(verb: str, namespace: argparse.Namespace) -> list[str]:
    from skill_lens.cli import _tokens_for

    return _tokens_for(verb, namespace)


def test_cli_dispatch_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """help ⇒ 0; unresolvable target ⇒ 2 (§18 total error); usage marker ⇒ 2."""
    from skill_lens.cache import FastPathCache
    from skill_lens.cli import build_cli_handler, setup_parser
    from skill_lens.context import PluginContextView

    parser = argparse.ArgumentParser()
    setup_parser(parser)

    view = PluginContextView(CliCtx(tmp_path))
    dispatch = build_cli_handler(view, FastPathCache())

    code = dispatch(parser.parse_args(["help"]))
    assert code == 0
    assert capsys.readouterr().out.startswith("```")

    code = dispatch(parser.parse_args(["scan", "/nonexistent-target-xyz"]))
    assert code == POLICY_EXIT_CODE
    captured = capsys.readouterr()
    assert "unresolvable target" in captured.out


def test_cli_malformed_policy_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A1 seam coordination: broken config ⇒ exit 2 on the CLI lane."""
    from skill_lens.cache import FastPathCache
    from skill_lens.cli import build_cli_handler, setup_parser
    from skill_lens.context import PluginContextView

    bundle = tmp_path / "skill-under-policy"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        "---\nname: skill-under-policy\ndescription: Supercharges synergy quietly.\n---\nbody\n",
        encoding="utf-8",
    )
    lens_dir = bundle / ".lens"
    lens_dir.mkdir()
    (lens_dir / "policy.toml").write_text("[rules\nbroken = yes\n", encoding="utf-8")

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    view = PluginContextView(CliCtx(tmp_path))
    dispatch = build_cli_handler(view, FastPathCache())

    code = dispatch(parser.parse_args(["scan", str(bundle)]))
    err = capsys.readouterr().err
    assert code == POLICY_EXIT_CODE
    assert err.startswith("lens: policy error")


def test_slash_lane_same_fault_renders_one_line_notice(
    tmp_path: Path,
) -> None:
    """Mirror of the CLI exit-2 case: slash renders ONE line, never raises."""
    from skill_lens.cache import FastPathCache
    from skill_lens.context import PluginContextView
    from skill_lens.slash import make_handler

    bundle = tmp_path / "skill-broken"
    bundle.mkdir()
    lens_dir = bundle / ".lens"
    lens_dir.mkdir()
    (lens_dir / "policy.toml").write_text("[rules\nbroken = yes\n", encoding="utf-8")

    class Ctx(CliCtx):
        pass

    handler = make_handler(PluginContextView(Ctx(tmp_path)), FastPathCache())
    answer = handler(f'scan "{bundle}"')
    assert answer.startswith("lens: policy error")
    assert len(answer.strip().splitlines()) == 1


def test_explain_verb_via_slash_handler(tmp_path: Path) -> None:
    from skill_lens.cache import FastPathCache
    from skill_lens.context import PluginContextView
    from skill_lens.slash import make_handler

    handler = make_handler(PluginContextView(CliCtx(tmp_path)), FastPathCache())
    text = handler("explain-rules --rule LNS-NET-011")
    assert "RULE LNS-NET-011" in text
    index = handler("explain-rules")
    assert "RULE PACK core" in index
    unknown = handler("explain-rules --rule NOPE")
    assert "unknown rule id" in unknown
