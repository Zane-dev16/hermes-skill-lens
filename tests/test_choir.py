"""Choir second-opinion adapter — 15-item plan (brief §6).

Covers: off-by-default, downgrade/confirm, upgrade clamp (Cisco), malformed,
trust/misc exceptions, usage, envelope unchanged, import contract, socket-deny,
selection determinism, zero-findings, doctor postures, ledger safety.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from skill_lens.cache import CacheEntry, FastPathCache
from skill_lens.canonical import canonical_dumps
from skill_lens.context import PluginContextView
from skill_lens.slash import dispatch_verb
from tests.conftest import FakePluginContext

REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Helpers: envelope / findings / cache
# ---------------------------------------------------------------------------


def _finding(
    fid: str = "F-1",
    fingerprint: str = "sha256:abc",
    rule_id: str = "LNS-TEST-001",
    effective_severity: str = "HIGH",
    severity: str | None = None,
    confidence: float = 0.9,
    path: str = "SKILL.md",
    start_line: int = 10,
    snippet: str = "evil snippet",
    suppressed: bool = False,
    llm_touched: bool = False,
    capability: str = "execute.code",
) -> dict[str, Any]:
    return {
        "id": fid,
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "effective_severity": effective_severity,
        "severity": severity or effective_severity,
        "confidence": confidence,
        "evidence_kind": "code",
        "static_only": False,
        "capability": capability,
        "tags": ["test"],
        "message": f"finding {fid}",
        "location": {"path": path, "start_line": start_line, "snippet": snippet},
        "suppressed": suppressed,
        "llm_touched": llm_touched,
    }


def _envelope(
    findings: list[dict[str, Any]],
    name: str = "test-skill",
    bundle_hash: str = "sha256:" + "ab" * 32,
) -> dict[str, Any]:
    return {
        "schema": "report/1",
        "tool": {"name": "lens", "version": "0.9.1"},
        "target": {"name": name, "bundle_hash": bundle_hash, "file_count": 1, "total_bytes": 1024},
        "policy": {"profile": "street", "sources": ["built-in"]},
        "rule_pack": {"name": "core", "version": "2026.08.8", "checksum": "abc"},
        "score": {"value": 70, "grade": "C", "verdict": "warn", "needs_review": False},
        "findings": findings,
        "suppressed_count": sum(1 for f in findings if f.get("suppressed")),
        "claims": [],
        "notes": [],
    }


def _put_cache(
    cache: FastPathCache, envelope: dict[str, Any], name: str | None = None
) -> CacheEntry:  # noqa: E501
    text = canonical_dumps(envelope)
    target_name = name or str(envelope.get("target", {}).get("name", "test-skill"))
    entry = CacheEntry(
        bundle_hash=str(envelope.get("target", {}).get("bundle_hash", "sha256:abc")),
        name=target_name,
        grade=str(envelope.get("score", {}).get("grade", "C")),
        value=int(envelope.get("score", {}).get("value", 70)),
        verdict=str(envelope.get("score", {}).get("verdict", "warn")),
        counts="1 warn",
        cached_at=time.monotonic(),
        compact_text="compact",
        envelope_json=text,
    )
    cache.put(entry)
    return entry


# ---------------------------------------------------------------------------
# Fake LLM lane
# ---------------------------------------------------------------------------


class _Usage:
    def __init__(self, input_tokens: int = 0, output_tokens: int = 0, total_tokens: int = 0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.total_tokens = total_tokens or (input_tokens + output_tokens)


class _Result:
    def __init__(
        self,
        parsed: Any = None,
        text: str = "",
        provider: str = "fake-provider",
        model: str = "fake-model",
        usage: Any | None = None,
        content_type: str = "json",
    ):
        self.parsed = parsed
        self.text = text or (json.dumps(parsed) if parsed is not None else "")
        self.provider = provider
        self.model = model
        self.usage = usage or _Usage(120, 64, 184)
        self.content_type = content_type


class FakeLlmLane:
    """Recording lane that scripts results or exceptions."""

    def __init__(
        self,
        result: Any | None = None,
        results: list[Any] | None = None,
        exception: BaseException | None = None,
    ):
        self.calls: list[dict[str, Any]] = []
        self._result = result
        self._results = list(results) if results is not None else None
        self._exception = exception

    def complete_structured(self, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs))
        # Trust-gate hygiene: must not pass override kwargs
        assert kwargs.get("provider") is None, f"provider leak {kwargs.get('provider')}"
        assert kwargs.get("model") is None, f"model leak {kwargs.get('model')}"
        assert kwargs.get("agent_id") is None
        assert kwargs.get("profile") is None
        assert kwargs.get("task") is None
        assert kwargs.get("purpose") == "choir second-opinion"
        assert kwargs.get("max_tokens") == 512
        assert kwargs.get("timeout") == 20.0
        assert kwargs.get("schema_name") == "choir.actions/1"
        # Must provide json_schema
        assert "json_schema" in kwargs and isinstance(kwargs["json_schema"], dict)
        if self._exception is not None:
            raise self._exception
        if self._results is not None:
            if not self._results:
                raise RuntimeError("FakeLlmLane: no more scripted results")
            return self._results.pop(0)
        if self._result is not None:
            return self._result
        # Default: empty actions
        return _Result(parsed={"actions": []}, content_type="json")


# ---------------------------------------------------------------------------
# 1. Off by default
# ---------------------------------------------------------------------------


def test_off_by_default(tmp_path: Path) -> None:
    cache = FastPathCache()
    _view_unused = PluginContextView(FakePluginContext(data_root=tmp_path))  # noqa: F841
    # No choir enabled by default
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    # Attach lane (policy still disabled, so no call should happen)
    ctx = FakePluginContext(data_root=tmp_path)
    ctx.llm = fake  # type: ignore[attr-defined]
    view2 = PluginContextView(ctx)
    finding = _finding()
    envelope = _envelope([finding], name="off-skill")
    _put_cache(cache, envelope, name="off-skill")
    out = dispatch_verb("second-opinion off-skill", view=view2, cache=cache)
    assert "choir is disabled" in out.lower()
    assert fake.calls == [], "LLM must not be called when disabled"
    # No sidecar written
    choir_dir = tmp_path / "plugin-data" / "lens" / "choir"
    if choir_dir.exists():
        assert not list(choir_dir.glob("*.json")), "no sidecar when disabled"


# ---------------------------------------------------------------------------
# 2. Downgrade applied
# ---------------------------------------------------------------------------


def test_downgrade_applied(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    # Enable choir via settings fallback (view.get_config)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(
        fid="F-1", fingerprint="sha256:downgrade-fp", effective_severity="HIGH", confidence=0.9
    )  # noqa: E501
    envelope = _envelope([finding], name="downgrade-skill")
    entry = _put_cache(cache, envelope, name="downgrade-skill")
    before_json = entry.envelope_json
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:downgrade-fp",
                        "new_severity": "LOW",
                        "new_confidence": 0.8,
                        "reason": "benign pattern, over-triggered",
                    }
                ]
            },
            usage=_Usage(120, 64, 184),
            provider="test-provider",
            model="test-model",
        )
    )
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    out = dispatch_verb("second-opinion downgrade-skill", view=view, cache=cache)
    assert "F-1" in out and "HIGH→LOW" in out
    # Sidecar status applied
    from skill_lens.report import report_hash8

    h8 = report_hash8(envelope)
    sidecar = Path(view.plugin_data_dir()) / "choir" / f"{h8}.json"
    assert sidecar.exists(), "sidecar not written"
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["status"] == "applied"
    assert data["actions"][0]["action"] == "downgrade"
    assert data["actions"][0]["to"]["effective_severity"] == "LOW"
    assert data["model"]["provider"] == "test-provider"
    # Envelope byte unchanged
    after = cache.latest_by_name("downgrade-skill")
    assert after is not None and after.envelope_json == before_json


# ---------------------------------------------------------------------------
# 3. Confirm recorded
# ---------------------------------------------------------------------------


def test_confirm_recorded(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(
        fid="F-1", fingerprint="sha256:confirm-fp", effective_severity="MEDIUM", confidence=0.7
    )  # noqa: E501
    envelope = _envelope([finding], name="confirm-skill")
    _put_cache(cache, envelope, name="confirm-skill")
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "confirm",
                        "fingerprint": "sha256:confirm-fp",
                        "new_severity": None,
                        "new_confidence": None,
                        "reason": "evidence supports finding",
                    }
                ]
            }
        )
    )
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    out = dispatch_verb("second-opinion confirm-skill", view=view, cache=cache)
    assert "F-1" in out
    h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
    data = json.loads(
        (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    assert data["actions"][0]["action"] == "confirm"
    assert data["actions"][0]["clamped"] is False


# ---------------------------------------------------------------------------
# 4. Upgrade attempt clamped (Cisco #138)
# ---------------------------------------------------------------------------


def test_upgrade_attempt_clamped(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    # MEDIUM finding, attempt to upgrade to CRITICAL
    finding = _finding(
        fid="F-1", fingerprint="sha256:upgrade-fp", effective_severity="MEDIUM", confidence=0.85
    )  # noqa: E501
    envelope = _envelope([finding], name="upgrade-skill")
    _put_cache(cache, envelope, name="upgrade-skill")
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:upgrade-fp",
                        "new_severity": "CRITICAL",
                        "new_confidence": None,
                        "reason": "attempt upgrade",
                    }
                ]
            }
        )
    )
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    dispatch_verb("second-opinion upgrade-skill", view=view, cache=cache)
    h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
    data = json.loads(
        (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    act = data["actions"][0]
    assert act["action"] == "confirm"
    assert act["clamped"] is True
    assert act["attempted"]["new_severity"] == "CRITICAL"
    assert "upgrade attempt clamped" in act["reason"]

    # Confidence upgrade attempt
    cache2 = FastPathCache()
    ctx2 = FakePluginContext(data_root=tmp_path)
    ctx2._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding2 = _finding(
        fid="F-1", fingerprint="sha256:conf-fp", effective_severity="HIGH", confidence=0.85
    )  # noqa: E501
    envelope2 = _envelope([finding2], name="conf-upgrade")
    _put_cache(cache2, envelope2, name="conf-upgrade")
    fake2 = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:conf-fp",
                        "new_severity": None,
                        "new_confidence": 0.99,
                        "reason": "confidence upgrade",
                    }
                ]
            }
        )
    )
    ctx2.llm = fake2  # type: ignore[attr-defined]
    view2 = PluginContextView(ctx2)
    dispatch_verb("second-opinion conf-upgrade", view=view2, cache=cache2)
    h8b = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope2)
    data2 = json.loads(
        (Path(view2.plugin_data_dir()) / "choir" / f"{h8b}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    act2 = data2["actions"][0]
    assert act2["clamped"] is True

    # Equal-tier no-op must be clamped
    cache3 = FastPathCache()
    ctx3 = FakePluginContext(data_root=tmp_path)
    ctx3._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding3 = _finding(
        fid="F-1", fingerprint="sha256:equal-fp", effective_severity="HIGH", confidence=0.9
    )  # noqa: E501
    envelope3 = _envelope([finding3], name="equal-skill")
    _put_cache(cache3, envelope3, name="equal-skill")
    fake3 = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:equal-fp",
                        "new_severity": "HIGH",
                        "new_confidence": None,
                        "reason": "same tier",
                    }
                ]
            }
        )
    )
    ctx3.llm = fake3  # type: ignore[attr-defined]
    view3 = PluginContextView(ctx3)
    dispatch_verb("second-opinion equal-skill", view=view3, cache=cache3)
    h8c = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope3)
    data3 = json.loads(
        (Path(view3.plugin_data_dir()) / "choir" / f"{h8c}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    assert data3["actions"][0]["clamped"] is True


def test_clamp_pure_function() -> None:
    from skill_lens.choir import clamp_actions

    selection = [
        _finding(fid="F-1", fingerprint="sha256:fp1", effective_severity="HIGH", confidence=0.9),
        _finding(fid="F-2", fingerprint="sha256:fp2", effective_severity="MEDIUM", confidence=0.8),
        _finding(fid="F-3", fingerprint="sha256:fp3", effective_severity="HIGH", confidence=0.9),
        _finding(fid="F-4", fingerprint="sha256:fp4", effective_severity="MEDIUM", confidence=0.8),
        _finding(fid="F-5", fingerprint="sha256:fp5", effective_severity="LOW", confidence=0.7),
    ]
    # Unknown fingerprint void, invalid action void, confirm-with-fields void,
    parsed = {
        "actions": [
            {
                "action": "downgrade",
                "fingerprint": "sha256:unknown",
                "new_severity": "LOW",
                "new_confidence": None,
                "reason": "x",
            },  # noqa: E501
            {
                "action": "bogus",
                "fingerprint": "sha256:fp1",
                "new_severity": None,
                "new_confidence": None,
                "reason": "x",
            },  # noqa: E501
            {
                "action": "confirm",
                "fingerprint": "sha256:fp2",
                "new_severity": "LOW",
                "new_confidence": None,
                "reason": "bad confirm",
            },  # noqa: E501
            {
                "action": "downgrade",
                "fingerprint": "sha256:fp3",
                "new_severity": "HIGH",
                "new_confidence": None,
                "reason": "equal tier",
            },  # noqa: E501
            {
                "action": "downgrade",
                "fingerprint": "sha256:fp4",
                "new_severity": None,
                "new_confidence": True,
                "reason": "bool",
            },  # noqa: E501
            {
                "action": "confirm",
                "fingerprint": "sha256:fp5",
                "new_severity": None,
                "new_confidence": None,
                "reason": "ok",
            },  # noqa: E501
            {
                "action": "confirm",
                "fingerprint": "sha256:fp5",
                "new_severity": None,
                "new_confidence": None,
                "reason": "dup",
            },  # noqa: E501
        ]
    }
    actions, voided = clamp_actions(parsed, selection)
    # Should have clamped confirm for fp3 equal-tier, void for unknown, invalid,
    assert any(v["reason"] == "unknown fingerprint" for v in voided)
    assert any(v["reason"] == "invalid action" for v in voided)
    assert any("confirm must carry" in v["reason"] for v in voided)
    assert any(v["reason"] == "duplicate fingerprint" for v in voided)
    # Clamped actions
    clamped = [a for a in actions if a.get("clamped")]
    assert len(clamped) >= 2  # equal tier + bool
    # First action per fingerprint wins is enforced
    assert len([a for a in actions if a["fingerprint"] == "sha256:fp5"]) == 1


# ---------------------------------------------------------------------------
# 5. Malformed output fail-closed
# ---------------------------------------------------------------------------


def test_malformed_output_fail_closed(tmp_path: Path) -> None:
    for malformed in [
        _Result(parsed=None, text="not json", content_type="text"),
        _Result(parsed={"not_actions": []}, content_type="json"),
        _Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:unknown",
                        "new_severity": "LOW",
                        "new_confidence": None,
                        "reason": "x",
                    }
                ]
            },
            content_type="json",
        ),  # noqa: E501
        _Result(
            parsed={"actions": []}, content_type="text"
        ),  # content_type text with parsed should still be unavailable  # noqa: E501
    ]:
        cache = FastPathCache()
        ctx = FakePluginContext(data_root=tmp_path)
        ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
        finding = _finding(fingerprint="sha256:malformed-fp")
        envelope = _envelope([finding], name="malformed")
        _put_cache(cache, envelope, name="malformed")
        fake = FakeLlmLane(result=malformed)
        ctx.llm = fake  # type: ignore[attr-defined]
        view = PluginContextView(ctx)
        out = dispatch_verb("second-opinion malformed", view=view, cache=cache)
        assert isinstance(out, str)
        # Should not raise, status unavailable or no_actions with errors
        h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
        sidecar = Path(view.plugin_data_dir()) / "choir" / f"{h8}.json"
        assert sidecar.exists()
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        assert data["status"] in ("unavailable", "no_actions")


# ---------------------------------------------------------------------------
# 6. Facade trust error degraded
# ---------------------------------------------------------------------------


def test_facade_trust_error_degraded(tmp_path: Path) -> None:
    try:
        from agent.plugin_llm import PluginLlmTrustError  # type: ignore[import]
    except Exception:
        # Fallback: define dummy
        class PluginLlmTrustError(PermissionError):  # type: ignore[no-redef]
            pass

    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:trust-fp")
    envelope = _envelope([finding], name="trust-skill")
    _put_cache(cache, envelope, name="trust-skill")
    fake = FakeLlmLane(exception=PluginLlmTrustError("trust denied"))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    out = dispatch_verb("second-opinion trust-skill", view=view, cache=cache)
    assert "unavailable" in out.lower() or "trust" in out.lower()
    h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
    data = json.loads(
        (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    assert data["status"] == "unavailable"
    assert any("trust" in e.lower() or "permission" in e.lower() for e in data["errors"])


# ---------------------------------------------------------------------------
# 7. Facade misc exception degraded
# ---------------------------------------------------------------------------


def test_facade_misc_exception_degraded(tmp_path: Path) -> None:
    for exc in [TimeoutError("timed out"), RuntimeError("boom")]:
        cache = FastPathCache()
        ctx = FakePluginContext(data_root=tmp_path)
        ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
        finding = _finding(fingerprint="sha256:misc-fp")
        envelope = _envelope([finding], name="misc-skill")
        _put_cache(cache, envelope, name="misc-skill")
        fake = FakeLlmLane(exception=exc)
        ctx.llm = fake  # type: ignore[attr-defined]
        view = PluginContextView(ctx)
        out = dispatch_verb("second-opinion misc-skill", view=view, cache=cache)
        assert isinstance(out, str)
        h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
        data = json.loads(
            (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
        )  # noqa: E501
        assert data["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 8. Usage recorded
# ---------------------------------------------------------------------------


def test_usage_recorded(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:usage-fp")
    envelope = _envelope([finding], name="usage-skill")
    _put_cache(cache, envelope, name="usage-skill")
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}, usage=_Usage(120, 64, 184)))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    dispatch_verb("second-opinion usage-skill", view=view, cache=cache)
    # Check kwargs purpose and no overrides already asserted in FakeLlmLane
    assert fake.calls[0]["purpose"] == "choir second-opinion"
    h8 = __import__("skill_lens.report", fromlist=["report_hash8"]).report_hash8(envelope)
    data = json.loads(
        (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    assert data["usage"]["input_tokens"] == 120
    assert data["usage"]["output_tokens"] == 64
    assert data["usage"]["total_tokens"] == 184
    # Ledger also records usage
    ledger = Path(view.plugin_data_dir()) / "choir" / "choir-events.ndjson"
    assert ledger.exists()
    rec = json.loads(ledger.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert rec["usage"]["input_tokens"] == 120


# ---------------------------------------------------------------------------
# 9. Envelope byte unchanged (already in 2, pinned separately)
# ---------------------------------------------------------------------------


def test_envelope_byte_unchanged(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:byte-fp")
    envelope = _envelope([finding], name="byte-skill")
    entry = _put_cache(cache, envelope, name="byte-skill")
    before = entry.envelope_json
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "confirm",
                        "fingerprint": "sha256:byte-fp",
                        "new_severity": None,
                        "new_confidence": None,
                        "reason": "ok",
                    }
                ]
            }
        )
    )  # noqa: E501
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    dispatch_verb("second-opinion byte-skill", view=view, cache=cache)
    after = cache.latest_by_name("byte-skill")
    assert after is not None and after.envelope_json == before


# ---------------------------------------------------------------------------
# 11. Socket-deny green with choir enabled but fake lane
# ---------------------------------------------------------------------------


def test_socket_deny_green(tmp_path: Path) -> None:
    # Run verb under socket deny guard — plugin side must not open sockets
    from skill_lens.doctor import socket_deny_guard

    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:socket-fp")
    envelope = _envelope([finding], name="socket-skill")
    _put_cache(cache, envelope, name="socket-skill")
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    with socket_deny_guard() as violations:
        out = dispatch_verb("second-opinion socket-skill", view=view, cache=cache)
        assert violations() == 0
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# 12. Selection determinism
# ---------------------------------------------------------------------------


def test_selection_determinism() -> None:
    from skill_lens.choir import MAX_FINDINGS_PER_CALL, select_findings

    # Create 6 findings with varying severities
    findings = [
        _finding(
            fid=f"F-{i}",
            fingerprint=f"sha256:fp{i}",
            effective_severity=sev,
            confidence=0.9 - i * 0.05,
            path=f"file{i}.py",
            start_line=i,
        )  # noqa: E501
        for i, sev in enumerate(["LOW", "CRITICAL", "HIGH", "MEDIUM", "LOW", "HIGH"])
    ]
    envelope = _envelope(findings)
    sel1 = select_findings(envelope)
    # Shuffle input order — selection must be identical
    import random

    shuffled = list(findings)
    random.seed(0)
    random.shuffle(shuffled)
    sel2 = select_findings(_envelope(shuffled))
    assert [f["fingerprint"] for f in sel1] == [f["fingerprint"] for f in sel2]
    assert len(sel1) == MAX_FINDINGS_PER_CALL
    # Suppressed and llm_touched excluded
    findings2 = [
        _finding(fid="F-1", fingerprint="sha256:suppressed", suppressed=True),
        _finding(fid="F-2", fingerprint="sha256:touched", llm_touched=True),
        _finding(fid="F-3", fingerprint="sha256:ok", effective_severity="HIGH"),
    ]
    sel3 = select_findings(_envelope(findings2))
    assert len(sel3) == 1 and sel3[0]["fingerprint"] == "sha256:ok"
    # Oversized snippet truncated to 600
    big = _finding(snippet="x" * 2000)
    from skill_lens.choir import _finding_card

    card = _finding_card(big)
    assert len(json.dumps(card)) <= 600 or len(card["location"]["snippet"]) <= 600


# ---------------------------------------------------------------------------
# 13. Zero findings — no model call
# ---------------------------------------------------------------------------


def test_zero_findings_no_call(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    envelope = _envelope([], name="clean-skill")
    _put_cache(cache, envelope, name="clean-skill")
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    out = dispatch_verb("second-opinion clean-skill", view=view, cache=cache)
    assert "no findings" in out.lower()
    assert fake.calls == [], "model access must not be spent on clean scans"


# ---------------------------------------------------------------------------
# 14. Doctor postures
# ---------------------------------------------------------------------------


def test_doctor_postures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from skill_lens.doctor import check_choir_posture

    # Disabled default
    ctx = FakePluginContext(data_root=tmp_path)
    view = PluginContextView(ctx)
    res = check_choir_posture(view)
    assert res.number == 10
    assert "disabled (default)" in res.detail[0]

    # Enabled adapter present
    ctx2 = FakePluginContext(data_root=tmp_path)
    ctx2._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    ctx2.llm = fake  # type: ignore[attr-defined]
    view2 = PluginContextView(ctx2)
    res2 = check_choir_posture(view2)
    assert "adapter present" in res2.detail[0]
    assert res2.status == "pass"

    # Enabled but lane absent
    ctx3 = FakePluginContext(data_root=tmp_path)
    ctx3._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    # Do not set llm
    view3 = PluginContextView(ctx3)
    res3 = check_choir_posture(view3)
    assert "host llm lane absent" in res3.detail[0]
    assert res3.status == "warn"

    # Also verify run_doctor has 10 checks
    from skill_lens.doctor import run_doctor

    ctx4 = FakePluginContext(data_root=tmp_path)
    report = run_doctor(PluginContextView(ctx4))
    assert len(report.checks) == 10
    assert any(c.key == "choir" for c in report.checks)


# ---------------------------------------------------------------------------
# 15. Ledger safety — hostile data dir
# ---------------------------------------------------------------------------


def test_ledger_safety_hostile_data_dir(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:hostile-fp")
    envelope = _envelope([finding], name="hostile-skill")
    _put_cache(cache, envelope, name="hostile-skill")
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "confirm",
                        "fingerprint": "sha256:hostile-fp",
                        "new_severity": None,
                        "new_confidence": None,
                        "reason": "ok",
                    }
                ]
            }
        )
    )  # noqa: E501
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    # Make choir dir hostile: create a file where dir should be
    choir_dir = Path(view.plugin_data_dir()) / "choir"
    choir_dir.mkdir(parents=True, exist_ok=True)
    # Remove and replace with file
    import shutil

    shutil.rmtree(choir_dir)
    choir_dir.write_text("not a dir", encoding="utf-8")
    # Verb should still answer without raising
    out = dispatch_verb("second-opinion hostile-skill", view=view, cache=cache)
    assert isinstance(out, str)
    assert "hostile-skill" in out or "unavailable" in out.lower() or "choir" in out.lower()


# ---------------------------------------------------------------------------
# Additional: --json fenced sidecar, CLI parity no --fail-on
# ---------------------------------------------------------------------------


def test_json_fenced_sidecar(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:json-fp")
    envelope = _envelope([finding], name="json-skill")
    _put_cache(cache, envelope, name="json-skill")
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    out = dispatch_verb("second-opinion json-skill --json", view=view, cache=cache)
    assert "```json" in out
    # Extract fenced JSON
    assert "lens.choir/1" in out


def test_cli_no_fail_on(tmp_path: Path) -> None:
    import argparse

    from skill_lens.cli import setup_parser

    parser = argparse.ArgumentParser()
    setup_parser(parser)
    # second-opinion should exist and have no --fail-on
    # Try parsing
    ns = parser.parse_args(["second-opinion", "my-skill", "--json"])
    assert ns.lens_verb == "second-opinion"
    assert hasattr(ns, "json") and ns.json is True
    assert not hasattr(ns, "fail_on") or getattr(ns, "fail_on", None) is None
    # fail-on should be rejected
    try:
        parser.parse_args(["second-opinion", "--fail-on", "warn"])
        pytest.fail("should have rejected --fail-on")
    except SystemExit:
        pass


def test_no_adjusted_score_block(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:score-fp")
    envelope = _envelope([finding], name="score-skill")
    _put_cache(cache, envelope, name="score-skill")
    fake = FakeLlmLane(
        result=_Result(
            parsed={
                "actions": [
                    {
                        "action": "downgrade",
                        "fingerprint": "sha256:score-fp",
                        "new_severity": "LOW",
                        "new_confidence": None,
                        "reason": "x",
                    }
                ]
            }
        )
    )  # noqa: E501
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    dispatch_verb("second-opinion score-skill", view=view, cache=cache)
    from skill_lens.report import report_hash8

    h8 = report_hash8(envelope)
    data = json.loads(
        (Path(view.plugin_data_dir()) / "choir" / f"{h8}.json").read_text(encoding="utf-8")
    )  # noqa: E501
    assert "adjusted_score" not in data
    assert data["schema"] == "lens.choir/1"


def test_sidecar_separate_from_events(tmp_path: Path) -> None:
    cache = FastPathCache()
    ctx = FakePluginContext(data_root=tmp_path)
    ctx._settings["choir"] = {"enabled": True}  # type: ignore[attr-defined]
    finding = _finding(fingerprint="sha256:sep-fp")
    envelope = _envelope([finding], name="sep-skill")
    _put_cache(cache, envelope, name="sep-skill")
    fake = FakeLlmLane(result=_Result(parsed={"actions": []}))
    ctx.llm = fake  # type: ignore[attr-defined]
    view = PluginContextView(ctx)
    dispatch_verb("second-opinion sep-skill", view=view, cache=cache)
    choir_events = Path(view.plugin_data_dir()) / "choir" / "choir-events.ndjson"
    main_events = Path(view.plugin_data_dir()) / "events.ndjson"
    assert choir_events.exists()
    if main_events.exists():
        # Choir events must NOT be in main events file
        text = main_events.read_text(encoding="utf-8")
        assert "choir" not in text.lower() or "lens.choir" not in text
