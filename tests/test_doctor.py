"""Phase 4 doctor tests — §11.9 nine-check engine + PLAN exit clause proofs.

Structure mirrors SPEC §11.9 exactly: positive coverage pins every check's
pass/warn shape, the two-renderer contract, the events.ndjson mirror, and
the §11.9 exit-code policy (0 even on warnings; **2 on any hard failure**).
The NEGATIVE proofs implement the PLAN Phase 4 exit clause verbatim:

- deliberately broken state (unwritable plugin-data dir, corrupt
  ``jobs.json``, quota breach) must FAIL check 3 LOUDLY;
- a deliberately-blocking wiring (fake ``pre_tool_call`` registration
  injected into our own auditable ledger) must FAIL check 5 LOUDLY;
- a scan_fn that reaches for a socket must FAIL check 6 LOUDLY (proving the
  isolation guard actually enforces, not just decorates).
"""

from __future__ import annotations

import json
import re
import socket as socket_mod
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from skill_lens.context import PluginContextView
from skill_lens.doctor import (
    FAIL,
    FORBIDDEN_HOOK,
    PASS,
    WARN,
    check_network_isolation,
    render_cli_panel,
    render_slash,
    run_doctor,
)
from skill_lens.slash import (
    reset_shared_cache,
    reset_shared_jobs,
)

SKILL_NAME = "web-design-guidelines"
MINIMAL_SKILL_MD = (
    "---\n"
    f"name: {SKILL_NAME}\n"
    "description: Ship accessible interfaces with design-system tokens.\n"
    "---\n"
    "Body text.\n"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Deterministic env: scratch homes, isolated policy layers."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    yield  # type: ignore[misc]


@pytest.fixture(autouse=True)
def _reset_singletons() -> Any:
    """Reset seams around each test (both lanes this module touches)."""
    from skill_lens.triggers import reset_hook_registry, reset_recent_hashes, reset_stats

    reset_shared_jobs()
    reset_shared_cache()
    reset_hook_registry()
    reset_recent_hashes()
    reset_stats()
    yield
    reset_shared_jobs()
    reset_shared_cache()
    reset_hook_registry()
    reset_recent_hashes()
    reset_stats()


@pytest.fixture
def lens_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Scratch HERMES_HOME with a categorized skill bundle + hub state."""
    home = tmp_path / "hermes-home"
    skill_dir = home / "skills" / "tools" / SKILL_NAME
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(MINIMAL_SKILL_MD, encoding="utf-8")
    hub = home / "skills" / ".hub"
    hub.mkdir(parents=True)
    (hub / "lock.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


@pytest.fixture
def view(lens_home: Path, tmp_path: Path) -> PluginContextView:
    """A defensive view over a FakePluginContext with a real data dir."""
    from tests.conftest import FakePluginContext

    return PluginContextView(FakePluginContext(data_root=tmp_path / "state"))


@pytest.fixture
def wired_view(view: PluginContextView) -> PluginContextView:
    """View with the three observer hooks registered (ledger populated)."""
    from skill_lens.triggers import register_triggers

    register_triggers(view)
    return view


# ---------------------------------------------------------------------------
# Positive: the engine, its ordering, and every check's happy shape
# ---------------------------------------------------------------------------


def test_nine_checks_run_in_spec_order(view: PluginContextView) -> None:
    report = run_doctor(view)
    assert [c.number for c in report.checks] == list(range(1, 10))
    keys = [c.key for c in report.checks]
    assert keys == [
        "rule-pack",
        "policy",
        "plugin-data",
        "environment",
        "hook-wiring",
        "network-isolation",
        "lifecycle",
        "parse",
        "render",
    ]
    # No containment-law crashes: every check produced a real verdict row.
    for check in report.checks:
        assert check.status in {PASS, WARN, FAIL}
        assert not any("check crashed" in d for d in check.detail), check.key


def test_scratch_home_has_zero_hard_failures(wired_view: PluginContextView) -> None:
    report = run_doctor(wired_view)
    assert report.failures == []
    assert report.exit_code == 0
    # Phase 5: with the committed ceremony keys present the check is a real
    # signature verification (PASS); in trees without keys/ it degrades to
    # an honest WARN — but NEVER a silent claim of provenance.
    pack = report.checks[0]
    if (Path(__file__).resolve().parents[1] / "keys" / "pack-signing.pub.pem").is_file():
        assert pack.status == PASS
        assert any("verified" in d for d in pack.detail)
    else:
        assert pack.status == WARN
        assert any("unsigned" in d for d in pack.detail)


def test_check1_tampered_signature_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 5 law: a PRESENT-but-invalid signature ⇒ hard FAIL, exit 2."""
    import shutil

    from skill_lens.doctor import check_rule_pack
    from skill_lens.rules import core_pack_path

    if not (Path(__file__).resolve().parents[1] / "keys" / "pack-signing.pub.pem").is_file():
        pytest.skip("ceremony keys not present in this tree")

    root = tmp_path / "plugin"
    (root / "skill_lens" / "rules").mkdir(parents=True)
    shutil.copytree(core_pack_path(), root / "skill_lens" / "rules" / "core")
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "keys", root / "keys"
    )
    # Flip one byte of pack semantics.
    target = root / "skill_lens" / "rules" / "core" / "pack.yaml"
    target.write_text(target.read_text(encoding="utf-8").replace("name: core", "name: corX", 1))

    from skill_lens.rules import load_pack

    result, version, checksum = check_rule_pack(
        root=root, pack=load_pack(root / "skill_lens" / "rules" / "core")
    )
    assert result.status == FAIL
    assert result.hard is True
    joined = "\n".join(result.detail)
    assert "SIGNATURE MISMATCH" in joined or "REJECTED" in joined
    assert version and checksum.startswith("sha256:")


def test_check1_reports_version_and_checksum(view: PluginContextView) -> None:
    from skill_lens.rules import load_core_pack

    pack = load_core_pack()
    report = run_doctor(view)
    check = report.checks[0]
    assert check.number == 1
    assert report.pack_version == pack.version
    assert re.fullmatch(r"\d{4}\.\d{1,2}\.\d+", pack.version)
    assert report.pack_checksum.startswith("sha256:")
    assert report.pack_checksum == pack.content_checksum()


def test_check2_effective_profile_with_all_sources(view: PluginContextView) -> None:
    view.set_config("profile", "lab")
    report = run_doctor(view)
    check = report.checks[1]
    assert check.status == PASS
    joined = "\n".join(check.detail)
    assert "profile lab" in joined
    assert "built-in" in joined  # the always-present source
    assert report.profile == "lab"


def test_check2_malformed_policy_file_fails_hard(
    view: PluginContextView, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    xdg = tmp_path / "xdg"
    (xdg / "lens").mkdir(parents=True)
    (xdg / "lens" / "policy.toml").write_text("[rules\n=broken", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    report = run_doctor(view)
    check = report.checks[1]
    assert check.status == FAIL
    assert check.hard is True
    assert report.exit_code == 2


def test_check3_writability_and_sidecar_notes(view: PluginContextView) -> None:
    data_dir = view.plugin_data_dir()
    (data_dir / "jobs.json").write_text('{"jobs": []}', encoding="utf-8")
    report = run_doctor(view)
    check = report.checks[2]
    assert check.status == PASS
    joined = "\n".join(check.detail)
    assert "job table 0/64" in joined
    assert any("events.ndjson" in d for d in check.detail)  # ledger seen


def test_check4_environment_discovery_and_profiles(
    view: PluginContextView, lens_home: Path
) -> None:
    profiles = lens_home / "profiles" / "coder"
    profiles.mkdir(parents=True)
    (profiles / "config.yaml").write_text("gateway:\n  port: 8679\n", encoding="utf-8")
    report = run_doctor(view)
    check = report.checks[3]
    assert check.status == PASS
    joined = "\n".join(check.detail)
    assert "HERMES_HOME discovered" in joined
    assert "categorized skills tree: 1 bundle(s)" in joined
    assert "hub scan-cache present" in joined or ".hub present" in joined
    assert "profiles tree: 1 profile(s)" in joined
    assert "route table:" in joined


def test_check4_corrupt_hub_lock_is_a_problem(view: PluginContextView, lens_home: Path) -> None:
    lock = lens_home / "skills" / ".hub" / "lock.json"
    lock.write_text("{oops", encoding="utf-8")
    report = run_doctor(view)
    check = report.checks[3]
    assert check.status == FAIL
    assert any(".hub/lock.json unparseable" in d for d in check.detail)


def test_check5_wiring_audit_passes_when_clean(wired_view: PluginContextView) -> None:
    report = run_doctor(wired_view)
    check = next(c for c in report.checks if c.key == "hook-wiring")
    assert check.status == PASS
    joined = "\n".join(check.detail)
    assert FORBIDDEN_HOOK not in joined.replace("pre_tool_call registration(s)", "")
    for hook in ("on_skill_lifecycle", "post_tool_call", "transform_tool_result"):
        assert hook in joined


def test_check7_canary_observed_and_side_effect_free(
    wired_view: PluginContextView,
) -> None:
    from skill_lens.slash import shared_jobs
    from skill_lens.triggers import stats_snapshot

    before = stats_snapshot()["enqueues"]
    report = run_doctor(wired_view)
    check = next(c for c in report.checks if c.key == "lifecycle")
    assert check.status == PASS
    assert any("canary" in d and "observed" in d for d in check.detail)
    # Side-effect-free proof: no cold-scan job was enqueued for the canary.
    assert stats_snapshot()["enqueues"] == before
    assert shared_jobs(wired_view).stats().get("queued", 0) == 0


def test_check8_ast_active_or_honestly_degraded(view: PluginContextView) -> None:
    report = run_doctor(view)
    check = next(c for c in report.checks if c.key == "parse")
    assert check.status in {PASS, WARN}
    assert "AST active" in "\n".join(check.detail) or "AST degraded" in "\n".join(check.detail)


def test_engine_is_deterministic_across_runs(wired_view: PluginContextView) -> None:
    first = [c.status for c in run_doctor(wired_view).checks]
    second = [c.status for c in run_doctor(wired_view).checks]
    assert first == second


# ---------------------------------------------------------------------------
# Renderers + events mirror
# ---------------------------------------------------------------------------


def test_render_slash_fenced_with_final_verdict_line(
    wired_view: PluginContextView,
) -> None:
    out = render_slash(run_doctor(wired_view))
    assert out.startswith("```\n")
    body, _, verdict = out.rpartition("\n")
    assert body.endswith("```") or "```" in body
    assert verdict.startswith("doctor: ")
    assert verdict.endswith(("✓", "✗"))


def test_verdict_line_grammar_matches_spec_example(
    wired_view: PluginContextView,
) -> None:
    verdict = run_doctor(wired_view).verdict_line()
    # e.g. "doctor: OK (2 warnings) · profile street · pack 2026.08.6 ✓"
    assert re.fullmatch(
        r"doctor: (OK|FAIL)( \(\d+( warning| warnings| hard(, \d+ warnings)?)?\))?"
        r"( · profile \w+)?( · pack [\d.]+)? [✓✗]",
        verdict,
    ), verdict


def test_render_cli_panel_box_aligned(wired_view: PluginContextView) -> None:
    panel = render_cli_panel(run_doctor(wired_view))
    lines = panel.splitlines()
    assert lines[0].startswith("┌") and lines[-1].startswith("└")
    widths = {len(line) for line in lines}
    assert len(widths) == 1, f"ragged panel edges: {widths}"
    assert all(line.startswith(("│", "┌", "├", "└")) for line in lines)


def test_render_plain_lane_strips_box_glyphs(wired_view: PluginContextView) -> None:
    from skill_lens.cli import to_ascii_box

    panel = to_ascii_box(render_cli_panel(run_doctor(wired_view)))
    assert not (set(panel) & set("┌┐└┘├┤┬┴┼─│"))
    assert "+" in panel and "|" in panel


def test_results_mirror_to_events_ndjson(wired_view: PluginContextView) -> None:
    data_dir = wired_view.plugin_data_dir()
    run_doctor(wired_view)
    records = [
        json.loads(line)
        for line in (data_dir / "events.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    doctor_records = [r for r in records if r.get("event") == "doctor"]
    assert len(doctor_records) >= 1
    record = doctor_records[-1]
    assert record["schema"] == "lens.events/1"
    assert record["status"] == "ok"
    assert record["exit_code"] == 0
    assert len(record["checks"]) == 9
    assert record["pack"]["version"]
    # Wall-clock ts rides the sidecar only.
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", record["ts"])


# ---------------------------------------------------------------------------
# NEGATIVE PROOFS — the PLAN Phase 4 exit clause, made red
# ---------------------------------------------------------------------------


def test_negative_unwritable_plugin_data_dir_fails_check3_loudly(
    lens_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A data dir that cannot be written ⇒ check 3 fails LOUDLY (hard).

    All three resolution shapes are poisoned: ``ctx.state.data_dir`` and the
    callable seam both point at a regular FILE, and the ``$HERMES_HOME``
    fallback lane hits ``plugin-data`` as a FILE too. The view hands back an
    unusable path by contract; the writability probe then must fail hard.
    """
    from tests.conftest import FakePluginContext

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("i am a file", encoding="utf-8")
    (lens_home / "plugin-data").write_text("blocker", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(lens_home))
    ctx = FakePluginContext(data_root=tmp_path / "state")
    ctx._state = SimpleNamespace(data_dir=blocker)  # type: ignore[misc]
    poisoned = PluginContextView(ctx)

    resolved = poisoned.plugin_data_dir()
    assert not resolved.is_dir()  # unusable by construction
    report = run_doctor(poisoned)
    check = report.checks[2]
    assert check.status == FAIL
    assert check.hard is True
    assert any("not writable" in d or "no usable plugin-data" in d for d in check.detail)
    assert report.exit_code == 2
    assert report.verdict_line().endswith("✗")


def test_negative_corrupt_jobs_json_fails_check3_loudly(
    view: PluginContextView,
) -> None:
    data_dir = view.plugin_data_dir()
    (data_dir / "jobs.json").write_text("{not json at all", encoding="utf-8")
    report = run_doctor(view)
    check = report.checks[2]
    assert check.status == FAIL
    assert check.hard is True
    assert any("jobs.json corrupt/unhealthy" in d for d in check.detail)
    assert report.exit_code == 2


def test_negative_job_quota_breach_fails_check3(view: PluginContextView) -> None:
    from skill_lens.jobs import MAX_PERSISTED_JOBS

    data_dir = view.plugin_data_dir()
    table = {"jobs": [{"job_id": f"j{i}"} for i in range(MAX_PERSISTED_JOBS + 5)]}
    (data_dir / "jobs.json").write_text(json.dumps(table), encoding="utf-8")
    report = run_doctor(view)
    check = report.checks[2]
    assert check.status == FAIL
    assert any("quota breach" in d for d in check.detail)


def test_negative_blocking_wiring_injection_fails_check5_loudly(
    wired_view: PluginContextView,
) -> None:
    """The advisor stance made checkable: inject a blocking registration.

    A hostile/future regression that wires ``pre_tool_call`` must be caught
    by the audit against our own registry record — LOUDLY (hard FAIL, exit 2,
    BLOCKING WIRING FOUND wording), per PLAN Phase 4 exit criteria.
    """
    from skill_lens.triggers import note_hook_registration, registry_snapshot

    def fake_blocking(**_: Any) -> dict[str, str]:  # pragma: no cover — never called
        return {"action": "block"}

    note_hook_registration(FORBIDDEN_HOOK, fake_blocking)
    assert any(name == FORBIDDEN_HOOK for name, _cb in registry_snapshot())

    report = run_doctor(wired_view)
    check = next(c for c in report.checks if c.key == "hook-wiring")
    assert check.status == FAIL
    assert check.hard is True
    assert any("BLOCKING WIRING FOUND" in d for d in check.detail)
    assert any("advisor law violated" in d for d in check.detail)
    assert report.exit_code == 2
    assert not report.ok


def test_negative_unknown_hook_outside_valid_hooks_fails_audit(
    wired_view: PluginContextView,
) -> None:
    from skill_lens.triggers import note_hook_registration

    note_hook_registration("totally_bogus_hook", lambda **_: None)
    report = run_doctor(wired_view)
    check = next(c for c in report.checks if c.key == "hook-wiring")
    assert check.status == FAIL
    assert any("outside host VALID_HOOKS" in d and "totally_bogus_hook" in d for d in check.detail)


def test_negative_isolation_guard_trips_on_socket_use() -> None:
    """A scan_fn that reaches for a socket MUST fail check 6 loudly."""

    def naughty_scan(bundle_dir: Path, data_dir: Path | None) -> dict[str, Any]:
        probe = socket_mod.create_connection(("localhost", 1), timeout=0.01)
        probe.close()  # pragma: no cover — unreachable, guard raises first
        return {"ok": True}

    result = check_network_isolation(scan_fn=naughty_scan)
    assert result.status == FAIL
    assert result.hard is True
    assert any("SOCKET USE DETECTED" in d for d in result.detail)


def test_socket_guard_restores_original_state_after_run() -> None:
    original_socket = socket_mod.socket
    original_getaddrinfo = socket_mod.getaddrinfo
    result = check_network_isolation()  # default canned scan under guard
    assert result.status == PASS
    assert socket_mod.socket is original_socket
    assert socket_mod.getaddrinfo is original_getaddrinfo
    # And the process still works normally post-guard.
    assert socket_mod.socket(socket_mod.AF_INET, socket_mod.SOCK_STREAM)


# ---------------------------------------------------------------------------
# Surface wiring: CLI exit-code policy + slash lane safety
# ---------------------------------------------------------------------------


def _cli_handler(view: PluginContextView) -> Any:
    from skill_lens.cli import build_cli_handler
    from skill_lens.slash import shared_cache

    return build_cli_handler(view, shared_cache())


def test_cli_doctor_exits_zero_with_warnings(wired_view: PluginContextView) -> None:
    handler = _cli_handler(wired_view)
    code = handler(SimpleNamespace(lens_verb="doctor", plain=True))
    assert code == 0  # §11.9 normative: exit 0 even on warnings


def test_cli_doctor_exits_two_on_hard_failure(
    view: PluginContextView,
) -> None:
    handler = _cli_handler(view)
    # Warm the shared JobManager FIRST: it moves corrupt sidecars aside at
    # construction (healing), so the corruption must land after load.
    assert handler(SimpleNamespace(lens_verb="doctor", plain=True)) == 0
    data_dir = view.plugin_data_dir()
    (data_dir / "jobs.json").write_text("{corrupt", encoding="utf-8")
    code = handler(SimpleNamespace(lens_verb="doctor", plain=False))
    assert code == 2  # §11.9: 2 on any hard check failure


def test_slash_lane_renders_doctor_never_raises(wired_view: PluginContextView) -> None:
    from skill_lens.cache import FastPathCache
    from skill_lens.slash import dispatch_verb

    cache = FastPathCache()
    out = dispatch_verb("doctor", view=wired_view, cache=cache)
    assert "doctor: " in out.splitlines()[-1]
    # Unknown args stay usage-safe, never raise.
    assert "usage" in dispatch_verb("doctor --wat", view=wired_view, cache=cache).lower()


def test_doctor_ignores_pull_banner_like_operational_surfaces(
    wired_view: PluginContextView,
) -> None:
    from skill_lens.cache import FastPathCache
    from skill_lens.slash import dispatch_verb

    out = dispatch_verb("doctor", view=wired_view, cache=FastPathCache())
    assert "reports ready" not in out  # operational surface: banner suppressed


def test_setup_parser_accepts_doctor_verb() -> None:
    import argparse

    from skill_lens.cli import setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    ns = parser.parse_args(["doctor"])
    assert ns.lens_verb == "doctor"
    assert ns.plain is False
