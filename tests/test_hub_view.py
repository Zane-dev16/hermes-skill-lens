"""Phase 4 — async delivered-results UX + hub quarantine view tests.

Covers PLAN Phase 4 bullets 2 & 4 / SPEC §11.5 + §11.7:

1. **events.ndjson mirrors EVERY state transition** — queued → scanning →
   ready appears in ledger order (the ``scan_started`` mirror is new this
   phase; §11.5 "everything lands durably in events.ndjson").
2. **Pull banner counting** — ready-but-unfetched jobs prepend the banner
   until fetched (counting seam pinned in test_jobs.py; here through the
   real slash dispatch).
3. **Hub quarantine view** — fenced chat variant, NO ANSI, budget ladder,
   role labels + the exact advisory wording, per-bundle fast path
   (cached ⇒ format A within beat, cold ⇒ enqueue + pointer), provenance
   annotation from .hub/lock.json (annotation-only), and rmtree-race
   tolerance (vanishing bundle ⇒ skip line, never a raise).
4. **Guard non-coupling (R7)** — zero imports from ``tools.*`` anywhere in
   :mod:`skill_lens`, no INSTALL_POLICY identifier usage, and the host guard
   modules never appear in ``sys.modules`` after a full hub render.
"""

from __future__ import annotations

import ast
import json
import shutil
import time
from pathlib import Path

import pytest

from skill_lens.cache import FastPathCache
from skill_lens.context import PluginContextView
from skill_lens.hubview import (
    ADVISORY_ROLE_LINE,
    CONFIRM_BEAT_BUDGET_SECONDS,
    ROLE_ROWS,
    enumerate_quarantine,
    quarantine_dir,
    render_hub_view,
)
from skill_lens.jobs import STATE_READY, JobManager, ScanContext
from skill_lens.render import CHAT_HARD_BUDGET, CHAT_SOFT_BUDGET
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _staged_bundle(
    home: Path,
    name: str,
    *,
    secret: bool = False,
) -> Path:
    """One staged quarantine dir bundle (optionally finding-bearing)."""
    root = home / "skills" / ".hub" / "quarantine" / name
    root.mkdir(parents=True)
    body = "\nReview me.\n"
    if secret:
        body += 'scripts/a.sh content below\nTOKEN="j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH"\n'
    (root / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Awaits confirmation quietly.\n---\n{body}",
        encoding="utf-8",
    )
    if secret:
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "a.sh").write_text(f'#!/bin/sh\nTOKEN="{secret_token()}"\n', encoding="utf-8")
    return root


def secret_token() -> str:
    """Deterministic high-entropy token shape the secretscan engine flags."""
    return "j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH"


def _lock_entry(home: Path, name: str, *, trust: str = "community") -> None:
    """Append a minimal lock entry so provenance annotation has material."""
    lock_path = home / "skills" / ".hub" / "lock.json"
    data: dict[str, object] = {"version": 1, "installed": {}}
    if lock_path.exists():
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    installed = data.setdefault("installed", {})
    assert isinstance(installed, dict)
    installed[name] = {
        "source": "clawhub",
        "identifier": f"clawhub/{name}",
        "trust_level": trust,
        "content_hash": "sha256:" + "22" * 32,
        "install_path": f".hub/quarantine/{name}",
        "files": ["SKILL.md"],
    }
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(data), encoding="utf-8")


def _manager(tmp_path: Path, cache: FastPathCache) -> JobManager:
    """Real-pipeline worker over the test's cache (mirrors pipeline_runner)."""

    def runner(job: object) -> None:
        context = job.context  # type: ignore[attr-defined]
        from datetime import date

        from skill_lens.ingest import DEFAULT_CEILINGS  # noqa: F401  (parity)
        from skill_lens.slash import run_scan

        outcome = run_scan(
            Path(job.target),  # type: ignore[attr-defined]
            cache=context.cache,
            plugin_data_dir=context.plugin_data_dir or Path(job.target).parent,  # type: ignore[attr-defined]
            baseline_records=context.baseline_records,  # type: ignore[attr-defined]
            key_suffix=context.key_suffix,  # type: ignore[attr-defined]
            report_date=date.today(),
        )
        if not outcome.get("ok"):
            raise RuntimeError(str(outcome.get("error") or "scan failed"))

    return JobManager(
        plugin_data_dir=tmp_path / "plugin-data" / "lens",
        runner=runner,
        register_exit=False,
    )


def _view(tmp_path: Path) -> PluginContextView:
    return PluginContextView(FakePluginContext(data_root=tmp_path / "home"))


# ---------------------------------------------------------------------------
# §11.5 delivered-results UX: ledger mirrors every transition + banner pull
# ---------------------------------------------------------------------------


def test_events_ndjson_mirrors_every_state_transition(tmp_path: Path) -> None:
    """queued → scanning → ready appear IN ORDER in events.ndjson."""
    cache = FastPathCache()
    home = tmp_path / "home"
    bundle = _staged_bundle(home, "ledger-skill")
    manager = _manager(tmp_path, cache)
    decision = manager.enqueue(
        name="ledger-skill",
        target=bundle,
        bundle_hash="sha256:" + "77" * 32,
        context=ScanContext(cache=cache, plugin_data_dir=tmp_path / "plugin-data" / "lens"),
    )
    assert manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=15)

    deadline = time.monotonic() + 5
    kinds: list[str] = []
    while time.monotonic() < deadline:
        raw = manager.events_path.read_text(encoding="utf-8").splitlines()
        kinds = [json.loads(line)["event"] for line in raw if line.strip()]
        if "scan_ready" in kinds:
            break
        time.sleep(0.01)
    assert kinds == ["scan_queued", "scan_started", "scan_ready"]
    manager.shutdown()


def test_banner_prepends_until_pulled_through_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/lens gains the ready banner on any verb until /lens report pulls it."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    cache = FastPathCache()
    home = tmp_path / "home"
    bundle = _staged_bundle(home, "banner-skill")
    manager = _manager(tmp_path, cache)

    decision = manager.enqueue(
        name="banner-skill",
        target=bundle,
        bundle_hash="sha256:" + "66" * 32,
        context=ScanContext(cache=cache, plugin_data_dir=tmp_path / "plugin-data" / "lens"),
    )
    assert manager.wait_for_state(decision.job.job_id, STATE_READY, timeout=15)

    from skill_lens.slash import make_handler

    handler = make_handler(_view(tmp_path), cache, jobs=manager)

    # help is exempt by §11.5 ("every invocation except help and the
    # fetching verb itself"); diff (usage lane) carries the banner.
    assert not handler("help").startswith("1 report ready")
    out = handler("diff")
    assert out is not None
    assert out.splitlines()[0].startswith("1 report ready: banner-skill (scanned ")

    pulled = handler("report banner-skill")
    assert pulled is not None and "banner-skill" in pulled
    after = handler("diff")
    assert after is not None
    assert not after.splitlines()[0].startswith("1 report ready")
    manager.shutdown()


# ---------------------------------------------------------------------------
# §11.7 hub view — cached fast path, cold queue, race, roles, budget
# ---------------------------------------------------------------------------


def _warm_cache(cache: FastPathCache, bundle: Path, tmp_path: Path) -> None:
    from skill_lens.slash import run_scan

    outcome = run_scan(bundle, cache=cache, plugin_data_dir=tmp_path / "plugin-data" / "lens")
    assert outcome["ok"]


def test_hub_render_cached_fenced_no_ansi_within_budget(tmp_path: Path) -> None:
    home = tmp_path / "home"
    bundle = _staged_bundle(home, "cached-one", secret=True)
    _lock_entry(home, "cached-one", trust="community")
    cache = FastPathCache()
    _warm_cache(cache, bundle, tmp_path)

    start = time.perf_counter()
    out = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=None)
    elapsed = time.perf_counter() - start

    assert elapsed < CONFIRM_BEAT_BUDGET_SECONDS * 4  # CI-headroom on the beat
    assert out.startswith("```\n") and out.endswith("\n```\n")
    assert "\x1b[" not in out  # surface-neutral law
    assert len(out) <= CHAT_SOFT_BUDGET
    assert "hub quarantine · 1 bundle awaiting confirmation" in out
    # Role-label block + exact advisory wording (SPEC §11.7 verbatim)
    for row in ROLE_ROWS:
        assert row in out
    assert ADVISORY_ROLE_LINE in out
    assert "gate — decides install policy" in out
    # Cached fast path ⇒ format-A line + undeclared depth fragment
    assert "lens ok cached-one · " in out
    assert "/lens report" in out
    assert "claims-vs-actual: undeclared " in out
    # Provenance annotation-only from .hub/lock.json
    assert "clawhub/cached-one" in out and "trust community" in out
    # Coverage footer rides every report surface (§12.6)
    assert "static analysis only" in out


def test_hub_cold_bundle_queues_and_pointer_then_answers(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _staged_bundle(home, "cold-one")
    cache = FastPathCache()
    manager = _manager(tmp_path, cache)

    out = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=manager)
    assert "lens scan queued: cold-one" in out
    assert "/lens report cold-one when ready" in out
    job = manager.latest_job_for_name("cold-one")
    assert job is not None and manager.wait_for_state(job.job_id, STATE_READY, timeout=20)

    out2 = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=manager)
    assert "lens ok cold-one · " in out2
    assert "scan queued" not in out2
    manager.shutdown()


def test_hub_zip_and_deep_bundles_enumerate_deterministically(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _staged_bundle(home, "aaa-deep").parent.joinpath("nested").mkdir(parents=True, exist_ok=True)
    shutil.move(  # variable-depth staging like the host's quarantine layout
        str(quarantine_dir(home) / "aaa-deep"),
        str(quarantine_dir(home) / "team" / "nested" / "aaa-deep"),
    )
    import zipfile

    qroot = quarantine_dir(home)
    with zipfile.ZipFile(qroot / "packed.zip", "w") as zf:
        zf.writestr(
            "packed/SKILL.md",
            "---\nname: packed\ndescription: Zipped staging target.\n---\n",
        )

    refs = enumerate_quarantine(home)
    names = [ref.name for ref in refs]
    assert names == sorted(names)
    assert "aaa-deep" in names and "packed" in names

    out = render_hub_view(home=home, view=_view(tmp_path), cache=FastPathCache(), jobs=None)
    assert "2 bundles awaiting confirmation" in out


def test_hub_race_vanishing_bundle_degrades_to_skip(tmp_path: Path) -> None:
    """Bundle rmtree'd between enumeration and rendering ⇒ skip, never raise."""
    home = tmp_path / "home"
    doomed = _staged_bundle(home, "victim")
    _staged_bundle(home, "survivor")
    cache = FastPathCache()
    manager = _manager(tmp_path, cache)

    refs = enumerate_quarantine(home)  # captured while both exist…
    shutil.rmtree(doomed)  # …then the host cancels/blocks → rmtree

    out = render_hub_view(
        home=home, view=_view(tmp_path), cache=cache, jobs=manager, refs=refs, lock={}
    )
    assert "lens skip victim" in out
    assert "vanished during view" in out
    assert "survivor" in out
    assert "lens scan queued: survivor" in out or "lens ok survivor" in out
    manager.shutdown()


def test_hub_empty_quarantine_renders_honest_empty_state(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (quarantine_dir(home)).mkdir(parents=True)
    out = render_hub_view(home=home, view=_view(tmp_path), cache=FastPathCache(), jobs=None)
    assert "hub quarantine: empty" in out
    assert "```" in out


def test_hub_budget_ladder_collapses_under_hard_cap(tmp_path: Path) -> None:
    home = tmp_path / "home"
    long_tail = "with-an-unreasonably-long-descriptive-name" * 2
    for seq in range(24):
        _staged_bundle(home, f"{long_tail}-{seq:02d}")
    cache = FastPathCache()

    out = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=None)
    assert len(out) <= CHAT_HARD_BUDGET, "hard budget is a hard cap"
    # Role labels + advisory line survive EVERY ladder rung.
    for row in ROLE_ROWS:
        assert row in out
    assert ADVISORY_ROLE_LINE in out


# ---------------------------------------------------------------------------
# Dispatch wiring through the shared verb table
# ---------------------------------------------------------------------------


def test_slash_and_cli_share_the_hub_verb(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    home = tmp_path / "home"
    _staged_bundle(home, "wired-one")
    cache = FastPathCache()
    manager = _manager(tmp_path, cache)

    from skill_lens.slash import dispatch_verb

    out = dispatch_verb("hub", view=_view(tmp_path), cache=cache, jobs=manager)
    assert "```" in out and "lens scan queued: wired-one" in out

    unknown = dispatch_verb("hub extra-arg", view=_view(tmp_path), cache=cache, jobs=manager)
    assert "usage" in unknown.lower()
    manager.shutdown()


# ---------------------------------------------------------------------------
# R7 non-coupling — static + runtime proofs
# ---------------------------------------------------------------------------


def _iter_skill_lens_sources() -> list[Path]:
    return sorted((REPO_ROOT / "skill_lens").rglob("*.py"))


def test_no_imports_from_host_guard_modules_anywhere() -> None:
    """No ``tools.skills_guard`` / ``tools.skillevaluator_scan`` imports — ever."""
    banned_prefixes = ("tools.", "tools")
    offenders: list[str] = []
    for path in _iter_skill_lens_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tools" or alias.name.startswith("tools."):
                        offenders.append(f"{path.name}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "tools" or module.startswith("tools."):
                    offenders.append(f"{path.name}:{node.lineno} from {module}")
                for alias in node.names:
                    if alias.name in banned_prefixes[0] or alias.name.startswith("tools."):
                        offenders.append(f"{path.name}:{node.lineno} from … import {alias.name}")
    assert offenders == []


def test_no_install_policy_identifier_usage() -> None:
    """INSTALL_POLICY is never READ or WRITTEN as an identifier (annotation law).

    The string may appear ONLY inside display/doc strings (the spec mandates
    the role label); no AST Name/Attribute node may reference it.
    """
    offenders: list[str] = []
    for path in _iter_skill_lens_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and "INSTALL_POLICY" in node.id:
                offenders.append(f"{path.name}:{node.lineno} Name {node.id}")
            elif isinstance(node, ast.Attribute) and "INSTALL_POLICY" in node.attr:
                offenders.append(f"{path.name}:{node.lineno} Attribute {node.attr}")
    assert offenders == []


def test_guard_modules_never_loaded_by_a_full_render(tmp_path: Path) -> None:
    """Runtime proof: hub render + full pipeline never pulls host guard code."""
    import sys

    home = tmp_path / "home"
    _staged_bundle(home, "runtime-one", secret=True)
    cache = FastPathCache()
    manager = _manager(tmp_path, cache)
    render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=manager)
    job = manager.latest_job_for_name("runtime-one")
    assert job is not None and manager.wait_for_state(job.job_id, STATE_READY, timeout=20)
    render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=manager)
    manager.shutdown()

    loaded = [name for name in sys.modules if name.startswith("tools.")]
    assert not any("skills_guard" in name or "skillevaluator" in name for name in loaded)


# ---------------------------------------------------------------------------
# Determinism sanity — same inputs, byte-identical collapsed render
# ---------------------------------------------------------------------------


def test_hub_render_is_byte_stable_across_calls(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _staged_bundle(home, "stable-one", secret=True)
    _lock_entry(home, "stable-one")
    cache = FastPathCache()
    _warm_cache(cache, quarantine_dir(home) / "stable-one", tmp_path)

    first = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=None)
    second = render_hub_view(home=home, view=_view(tmp_path), cache=cache, jobs=None)
    assert first == second


def test_setup_parser_accepts_hub_verb() -> None:
    """CLI lane parity: `hermes lens hub` parses and routes into the shared
    dispatch table like its slash sibling (D-051); zero args by contract."""
    import argparse

    from skill_lens.cli import _tokens_for, setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    ns = parser.parse_args(["hub"])
    assert ns.lens_verb == "hub"
    assert ns.plain is False
    assert _tokens_for("hub", ns) == ["hub"]

    ns = parser.parse_args(["hub", "--plain"])
    assert _tokens_for("hub", ns) == ["hub", "--plain"]
