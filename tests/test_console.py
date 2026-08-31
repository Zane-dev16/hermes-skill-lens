"""Standalone ``lens`` console script — §18 CLI-verbs surface (v1.0 deliverable b).

Proves the console path shares ONE grammar and ONE exit-code law with the
host lane: argparse over ``skill_lens.cli.setup_parser``, dispatch through
``build_cli_handler`` (slash.dispatch_verb), exit codes 0/1/2 exactly per
§18, ``--sarif-out`` byte-equal to ``render_sarif`` canonical form, and
the one-shot inline arm (``view.inline_scans``) that never enqueues.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from skill_lens.console import main
from skill_lens.slash import reset_shared_cache, reset_shared_jobs

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
BENIGN = REPO_ROOT / "corpus/fixtures/benign/pinned-deps-helper"  # verdict CLEAN
MALICIOUS = REPO_ROOT / "corpus/fixtures/malicious/committed-keys"  # verdict WARN


@pytest.fixture(autouse=True)
def _isolated_singletons():
    """Fresh cache/job singletons per test (the verbs use process-wide state)."""
    import skill_lens.slash as slash_module

    reset_shared_cache()
    reset_shared_jobs()
    yield
    manager = getattr(slash_module, "_shared_jobs", None)  # read-only teardown peek
    if manager is not None:
        manager.shutdown(timeout=2.0)
    reset_shared_cache()
    reset_shared_jobs()


def test_help_exits_zero(capsys) -> None:
    # argparse handles --help itself: SystemExit(0) IS the console-script
    # contract (setuptools' wrapper propagates it as exit code 0).
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "lens" in out
    assert "scan" in out


def test_scan_clean_fixture_exits_zero(capsys) -> None:
    assert main(["scan", str(BENIGN), "--json"]) == 0
    assert "lens" in capsys.readouterr().out


def test_fail_on_breach_exits_one() -> None:
    # §8.4: exit 1 ONLY on an explicit --fail-on breach (committed-keys WARNs).
    assert main(["scan", str(MALICIOUS), "--fail-on", "notice"]) == 1


def test_unknown_fail_on_level_is_total_error() -> None:
    # Malformed flag value = §18 total-error family (exit 2), never a pass.
    assert main(["scan", str(BENIGN), "--fail-on", "bogus"]) == 2


def test_malformed_policy_is_exit_two(tmp_path: pathlib.Path) -> None:
    import shutil

    target = tmp_path / "broken"
    shutil.copytree(BENIGN, target)
    (target / ".lens").mkdir()
    (target / ".lens" / "policy.toml").write_text("profile = [\n", encoding="utf-8")
    # PolicyError is CAUGHT inside build_cli_handler (A1 seam) and mapped to
    # the §18 total-error code — main RETURNS 2, never explodes.
    assert main(["scan", str(target)]) == 2


def test_sarif_out_is_canonical_and_atomic(tmp_path: pathlib.Path) -> None:
    from skill_lens.canonical import canonical_dumps
    from skill_lens.report import render_sarif

    out_file = tmp_path / "results.sarif"
    assert main(["scan", str(MALICIOUS), "--sarif-out", str(out_file)]) == 0
    text = out_file.read_text(encoding="utf-8")
    try:
        sarif = json.loads(text)
    except ValueError as exc:  # a corrupt artifact must fail here, loudly
        raise AssertionError(f"--sarif-out wrote unparsable JSON: {exc}") from exc
    # Byte-equal to render_sarif over the equivalent pipeline envelope.
    from skill_lens.engines import scan_bundle
    from skill_lens.report import build_report

    envelope = build_report(scan_bundle(MALICIOUS))
    assert text == canonical_dumps(render_sarif(envelope))
    assert sarif["version"] == "2.1.0"
    verdict = sarif["runs"][0]["invocations"][0]["properties"]["lens"]["verdict"]
    assert verdict == "warn"


def test_sarif_out_unwritable_path_fails_loud(tmp_path: pathlib.Path) -> None:
    # A requested artifact that cannot be written can never read as clean.
    bad = tmp_path / "no" / "such" / "dir" / "x.sarif"
    assert main(["scan", str(BENIGN), "--sarif-out", str(bad)]) == 2


def test_doctor_degrades_honestly_without_hermes_home(capsys) -> None:
    code = main(["doctor", "--plain"])
    out = capsys.readouterr().out
    # §11.9: 0 even on warnings, 2 only on hard failures.
    assert code == 0 or code == 2
    assert "doctor:" in out


def test_rules_verify_runs_standalone(capsys) -> None:
    assert main(["rules", "verify"]) == 0
    out = capsys.readouterr().out
    assert "lens rules verify" in out


def test_inline_scan_never_enqueues_jobs() -> None:
    """The one-shot arm runs the pipeline inline: no worker, no jobs.json."""
    import skill_lens.slash as slash_module

    assert main(["scan", str(BENIGN)]) == 0
    manager = getattr(slash_module, "_shared_jobs", None)
    if manager is None:  # nothing lazily created a JobManager: queue never used
        return
    records = list(getattr(manager, "_jobs", {}).values())
    assert records == []  # no job was ever enqueued on the standalone lane
