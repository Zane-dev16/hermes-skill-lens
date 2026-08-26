"""Policy engine tests (SPEC §10) — resolution order, merge semantics,
profiles, severity_override, host lists, the scoring hard boundary, and the
malformed-policy error lane.

Exit criterion under test (PLAN §1 Phase 2): settings-layer precedence is
unit-tested against ``ctx.get_config`` fakes (FakePluginContext), full chains
included; malformed policy raises :class:`PolicyError` for CLI exit-2 mapping
and renders a ONE-LINE notice in-session.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from skill_lens.diagnostics import DiagnosticsCollector
from skill_lens.policy import (
    ANNOTATION_ALLOW_MATCHED,
    ANNOTATION_DENIED_BY_POLICY,
    CODE_POLICY_OVERRIDE_EXPIRED,
    CODE_POLICY_OVERRIDE_INVALID,
    CODE_POLICY_OVERRIDE_NO_REASON,
    CODE_POLICY_SCORE_TAMPER,
    DEFAULT_PROFILE,
    FLAG_ALLOW_MATCHED,
    MARKER_LAB_DECLARED_OFFENSIVE,
    POLICY_EXIT_CODE,
    EffectivePolicy,
    PolicyError,
    declares_offensive_scope,
    is_offensive_tooling_capability,
    lab_declared_offensive,
    load_policy,
    merge_policy_values,
    normalize_endpoint,
    policy_failure_notice,
)
from skill_lens.scoring import score_findings

REPORT_DATE = date(2026, 8, 25)

#: Named expected tuples keep asserts off bare tuple literals (lens rule).
SOURCES_BUILTIN_ONLY = ("built-in",)
DENY_A_B = ("a.example.com", "b.example.com")
ALLOW_BASE_ADDED = ("added.example.com", "base.example.com")
SOURCES_FULL_CHAIN = (
    "built-in",
    "profile lab",
    "plugin settings plugins.entries.lens.settings",
    "project .lens/policy.toml",
)


def write_policy(dir_path: Path, text: str) -> Path:
    lens_dir = dir_path / ".lens"
    lens_dir.mkdir(parents=True, exist_ok=True)
    policy_file = lens_dir / "policy.toml"
    policy_file.write_text(text, encoding="utf-8")
    return policy_file


# ---------------------------------------------------------------------------
# 1. Resolution order (later wins) — every layer, full chains
# ---------------------------------------------------------------------------


class TestResolutionOrder:
    def test_defaults_without_any_layer(self):
        policy = load_policy()
        assert policy.profile == DEFAULT_PROFILE == "street"
        assert policy.sources == SOURCES_BUILTIN_ONLY
        assert policy.disabled_rules == frozenset()
        assert not policy.choir_enabled

    def test_project_file_overrides_builtin(self, tmp_path: Path):
        write_policy(tmp_path, 'profile = "lab"\n[choir]\nenabled = true\n')
        policy = load_policy(project_dir=tmp_path)
        assert policy.profile == "lab"
        assert policy.choir_enabled

    def test_full_chain_settings_file_flags(self, tmp_path: Path, fake_ctx):
        """PLAN exit criterion: precedence chain through a ctx.get_config fake."""
        # settings layer names lab; project file picks a value; flags win last.
        fake_ctx.set_config("profile", "lab")
        write_policy(tmp_path, '[network]\nallow_hosts = ["files.example.com"]\n')
        from_files = load_policy(project_dir=tmp_path, ctx=fake_ctx)
        assert from_files.profile == "lab"  # profile resolved from settings layer

        by_flags = load_policy(project_dir=tmp_path, ctx=fake_ctx, flags={"profile": "street"})
        assert by_flags.profile == "street"  # explicit flag beats every layer

    def test_settings_present_but_file_supplies_values(self, tmp_path: Path, fake_ctx):
        fake_ctx.set_config("voice", "calm")  # settings layer present, different key
        write_policy(tmp_path, '[rules]\ndisable = ["LNS-OBS-002"]\n')
        policy = load_policy(project_dir=tmp_path, ctx=fake_ctx)
        assert policy.is_disabled("LNS-OBS-002")
        assert policy.settings["voice"] == "calm"

    def test_extra_file_sits_between_project_and_flags(self, tmp_path: Path):
        write_policy(tmp_path, '[network]\ndeny_hosts = ["a.example.com"]\n')
        extra = tmp_path / "extra.toml"
        extra.write_text('[network]\ndeny_hosts = ["+b.example.com"]\n', encoding="utf-8")
        policy = load_policy(project_dir=tmp_path, extra_files=[extra])
        assert policy.deny_hosts == DENY_A_B

        overridden = load_policy(
            project_dir=tmp_path, extra_files=[extra], flags={"profile": "lab"}
        )
        assert overridden.profile == "lab"

    def test_global_file_layer(self, tmp_path: Path):
        global_file = tmp_path / "global-policy.toml"
        global_file.write_text("[choir]\nenabled = true\n", encoding="utf-8")
        project = tmp_path / "proj"
        project.mkdir()
        write_policy(project, "[choir]\nenabled = false\n")  # later layer wins
        policy = load_policy(global_path=global_file, project_dir=project)
        assert not policy.choir_enabled
        assert policy.provenance["choir.enabled"] == "project .lens/policy.toml:L2"


# ---------------------------------------------------------------------------
# 2. Merge semantics — scalars override · maps deep-merge · lists replace/+
# ---------------------------------------------------------------------------


class TestMergeSemantics:
    def test_scalar_overrides(self):
        assert merge_policy_values(1, 2) == 2
        assert merge_policy_values("old", "new") == "new"
        assert not merge_policy_values(True, False)  # overlay wins (scalar override)

    def test_maps_deep_merge(self):
        base = {"net": {"allow": ["x"], "deny": []}, "keep": 1}
        over = {"net": {"allow": ["y"]}, "extra": {"deep": {"a": 1}}}
        merged = merge_policy_values(base, over)
        assert merged == {
            "net": {"allow": ["y"], "deny": []},
            "keep": 1,
            "extra": {"deep": {"a": 1}},
        }

    def test_nested_map_deep_merge_three_levels(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        assert merge_policy_values(base, {"a": {"b": {"d": 9}}}) == {"a": {"b": {"c": 1, "d": 9}}}

    def test_lists_replace_by_default(self):
        assert merge_policy_values(["a", "b"], ["c"]) == ["c"]
        assert merge_policy_values([], ["c"]) == ["c"]

    def test_plus_prefix_appends(self):
        assert merge_policy_values(["a"], ["+b"]) == ["a", "b"]
        assert merge_policy_values(["a"], ["+b", "+c"]) == ["a", "b", "c"]

    def test_mixed_plus_list_appends_everything(self):
        assert merge_policy_values(["a"], ["b", "+c"]) == ["a", "b", "c"]

    def test_append_inside_nested_map(self, tmp_path: Path):
        write_policy(
            tmp_path,
            '[network]\nallow_hosts = ["base.example.com"]\n[rules]\ndisable = ["+"]\n'.replace(
                '"+"', '["+"]'
            ),
        )
        extra = tmp_path / "plus.toml"
        extra.write_text('[network]\nallow_hosts = ["+added.example.com"]\n', encoding="utf-8")
        policy = load_policy(project_dir=tmp_path, extra_files=[extra])
        assert policy.allow_hosts == ALLOW_BASE_ADDED

    def test_type_mismatch_replaces(self):
        assert merge_policy_values({"a": 1}, ["not-a-map"]) == ["not-a-map"]
        assert merge_policy_values([1], {"map": True}) == {"map": True}


# ---------------------------------------------------------------------------
# 3. Profiles — street default, lab unlock, selection across layers
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_street_is_default_everywhere(self):
        assert not load_policy().declared_offensive_unlocked

    @pytest.mark.parametrize("layer", ["settings", "file", "flags"])
    def test_lab_selected_from_each_naming_layer(self, tmp_path: Path, fake_ctx, layer):
        if layer == "settings":
            fake_ctx.set_config("profile", "lab")
            policy = load_policy(ctx=fake_ctx)
        elif layer == "file":
            write_policy(tmp_path, 'profile = "lab"\n')
            policy = load_policy(project_dir=tmp_path)
        else:
            policy = load_policy(flags={"profile": "lab"})
        assert policy.profile == "lab"
        assert policy.declared_offensive_unlocked
        assert f"profile {policy.profile}" in policy.sources

    def test_invalid_profile_name_warns_and_keeps_previous(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        policy = load_policy(flags={"profile": "yolo"}, diag=diag)
        assert policy.profile == "street"
        assert any("yolo" in d.message for d in diag)

    def test_later_layer_profile_wins(self, tmp_path: Path, fake_ctx):
        fake_ctx.set_config("profile", "lab")
        write_policy(tmp_path, 'profile = "street"\n')
        policy = load_policy(project_dir=tmp_path, ctx=fake_ctx)
        assert policy.profile == "street"  # project file is later than settings

        flagged = load_policy(project_dir=tmp_path, ctx=fake_ctx, flags={"profile": "lab"})
        assert flagged.profile == "lab"  # flags are last

    def test_declared_offensive_semantics(self):
        assert declares_offensive_scope("A pentest toolkit for labs")
        assert declares_offensive_scope("RED-TEAM exercise tooling")
        assert declares_offensive_scope("use for security testing only")
        assert not declares_offensive_scope("formats your markdown nicely")
        assert not declares_offensive_scope(None)

        assert is_offensive_tooling_capability("execute.shell")
        assert is_offensive_tooling_capability("credentials.read")
        assert is_offensive_tooling_capability("network.scan")
        assert not is_offensive_tooling_capability("persona.write")

        # Lab unlocks the discount ONLY when scope is declared; street never.
        assert lab_declared_offensive("lab", "execute.shell", True)
        assert not lab_declared_offensive("lab", "execute.shell", False)
        assert not lab_declared_offensive("lab", "persona.write", True)
        assert not lab_declared_offensive("street", "execute.shell", True)
        assert MARKER_LAB_DECLARED_OFFENSIVE == "[lab:declared-offensive]"


# ---------------------------------------------------------------------------
# 4. severity_override — reason REQUIRED, expiry deterministic via report_date
# ---------------------------------------------------------------------------


class TestSeverityOverride:
    def _policy_with(self, tmp_path: Path, body: str) -> EffectivePolicy:
        write_policy(tmp_path, f"[rules]\n{body}\n")
        return load_policy(project_dir=tmp_path)

    def test_valid_override_applies_to_effective_severity_only(self, tmp_path: Path):
        policy = self._policy_with(
            tmp_path,
            'severity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW", '
            'reason = "repo convention: Makefile curl", expires = "2026-12-01" }]',
        )
        override = policy.severity_override_for("LNS-SHL-007", REPORT_DATE)
        assert override is not None and override.severity == "LOW"

        findings = [{"rule_id": "LNS-SHL-007", "severity": "HIGH", "effective_severity": "HIGH"}]
        applied, _diags = policy.apply(findings, report_date=REPORT_DATE)
        # display tier follows the override...
        assert applied[0]["effective_severity"] == "LOW"
        # ...but the rule-assigned severity — the pricing key — is untouched.
        assert applied[0]["severity"] == "HIGH"
        assert any("severity-override" in a for a in applied[0]["annotations"])

    def test_weights_out_of_policy_reach_end_to_end(self, tmp_path: Path):
        """Override CRITICAL→LOW: pricing tier keeps rule weight; verdict logic
        sees LOW. Proves severity display moves while weights stay pinned."""
        policy = self._policy_with(
            tmp_path,
            'severity_override = [{ rule_id = "LNS-CRT-001", severity = "LOW", '
            'reason = "accepted risk" }]',
        )
        findings = [
            {
                "rule_id": "LNS-CRT-001",
                "capability": "execute.code",
                "severity": "CRITICAL",
                "effective_severity": "CRITICAL",
                "confidence": 0.9,
                "static_only": False,
                "declared": False,
            }
        ]
        applied, _ = policy.apply(findings, report_date=REPORT_DATE)
        scored = score_findings(applied)
        # CRITICAL first-occurrence weight −40 still prices fully…
        assert scored.value == 60
        # …while ceiling/verdict logic reads the overridden effective severity.
        assert list(scored.ceilings_applied) == []

    def test_missing_reason_diagnosed_never_crash(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        policy = self._policy_with(
            tmp_path,
            'severity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW" }]',
        )
        loaded = load_policy(project_dir=tmp_path, diag=diag)
        assert loaded.severity_override_for("LNS-SHL-007", REPORT_DATE) is None
        assert any(d.code == CODE_POLICY_OVERRIDE_NO_REASON for d in diag)
        assert policy is not None  # loader completed — never an exception

    def test_expired_override_ignored_via_report_date(self, tmp_path: Path):
        # Loader-level: report_date filters expired entries out of the effective
        # set (wall-clock never consulted — the date is a caller parameter).
        diag = DiagnosticsCollector()
        write_policy(
            tmp_path,
            '[rules]\nseverity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW", '
            'reason = "temp", expires = "2026-08-01" }]',
        )
        policy = load_policy(project_dir=tmp_path, report_date=REPORT_DATE, diag=diag)
        assert policy.severity_overrides == {}
        assert any(d.code == CODE_POLICY_OVERRIDE_EXPIRED for d in diag)

        # Apply-level: an unexpired-at-load entry expiring before report_date.
        policy_live = self._policy_with(
            tmp_path,
            'severity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW", '
            'reason = "temp", expires = "2026-12-01" }]',
        )
        findings = [{"rule_id": "LNS-SHL-007", "severity": "HIGH"}]
        applied, diags = policy_live.apply(findings, report_date=date(2027, 1, 1))
        assert "effective_severity" not in applied[0]
        assert any(d.code == CODE_POLICY_OVERRIDE_EXPIRED for d in diags)

    def test_expiry_boundary_is_inclusive(self, tmp_path: Path):
        policy = self._policy_with(
            tmp_path,
            'severity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW", '
            'reason = "r", expires = "2026-08-25" }]',
        )
        # expires ON the report date → still active; strictly past → ignored.
        assert policy.severity_override_for("LNS-SHL-007", date(2026, 8, 25))
        assert not policy.severity_override_for("LNS-SHL-007", date(2026, 8, 26))

    def test_invalid_severity_and_rule_and_shape_diagnosed(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        write_policy(
            tmp_path,
            "[rules]\n"
            "severity_override = [\n"
            '  { rule_id = "NOT-A-RULE", severity = "LOW", reason = "x" },\n'
            '  { rule_id = "LNS-SHL-007", severity = "APOCALYPTIC", reason = "x" },\n'
            '  { rule_id = "LNS-SHL-008", severity = "LOW", reason = "x", expires = "soon-ish" },\n'
            "]\n",
        )
        policy = load_policy(project_dir=tmp_path, diag=diag)
        assert policy.severity_overrides == {}
        codes = {d.code for d in diag}
        assert CODE_POLICY_OVERRIDE_INVALID in codes

    def test_table_shape_normalizes_like_list_shape(self, tmp_path: Path):
        write_policy(
            tmp_path,
            '[rules.severity_override.LNS-SHL-007]\nseverity = "LOW"\nreason = "table shape"\n',
        )
        policy = load_policy(project_dir=tmp_path)
        override = policy.severity_override_for("LNS-SHL-007", REPORT_DATE)
        assert override is not None and override.reason == "table shape"

    def test_later_layer_wins_same_rule_id(self, tmp_path: Path):
        write_policy(
            tmp_path,
            '[rules]\nseverity_override = [{ rule_id = "LNS-SHL-007", '
            'severity = "LOW", reason = "first" }]\n',
        )
        extra = tmp_path / "later.toml"
        extra.write_text(
            '[rules]\nseverity_override = [{ rule_id = "LNS-SHL-007", '
            'severity = "MEDIUM", reason = "second" }]\n',
            encoding="utf-8",
        )
        policy = load_policy(project_dir=tmp_path, extra_files=[extra])
        winner = policy.severity_override_for("LNS-SHL-007")
        assert winner is not None
        assert winner.severity == "MEDIUM"


# ---------------------------------------------------------------------------
# 5. Host lists — allow ⇒ INFO + allow_matched · deny ⇒ annotation only
# ---------------------------------------------------------------------------


class TestHostLists:
    def _policy(self, tmp_path: Path, network_body: str) -> EffectivePolicy:
        write_policy(tmp_path, f"[network]\n{network_body}\n")
        return load_policy(project_dir=tmp_path)

    def test_allow_downgrades_to_info_machine_visible(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'allow_hosts = ["*.github.io"]\n')
        findings = [
            {
                "rule_id": "LNS-NET-011",
                "severity": "CRITICAL",
                "host": "https://foo.github.io/upload",
            }
        ]
        applied, _ = policy.apply(findings, report_date=REPORT_DATE)
        row = applied[0]
        assert row[FLAG_ALLOW_MATCHED]  # machine flag set (literal True at write site)
        assert row["suppressed"]  # rubric-inactive ⇒ INFO-equivalent
        assert row["severity"] == "CRITICAL"  # evidence NOT deleted (§10)
        assert ANNOTATION_ALLOW_MATCHED in row["annotations"][0]

    def test_deny_annotates_only(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'deny_hosts = ["api.github.com"]\n')
        findings = [{"rule_id": "LNS-NET-012", "severity": "HIGH", "host": "api.github.com"}]
        applied, _ = policy.apply(findings, report_date=REPORT_DATE)
        row = applied[0]
        assert row["annotations"] == [ANNOTATION_DENIED_BY_POLICY]
        assert row["severity"] == "HIGH"
        assert not row.get("suppressed")
        assert not row.get(FLAG_ALLOW_MATCHED)

    def test_deny_beats_allow(self, tmp_path: Path):
        policy = self._policy(
            tmp_path,
            'allow_hosts = ["*.github.io"]\ndeny_hosts = ["evil.github.io"]\n',
        )
        findings = [{"rule_id": "X", "host": "evil.github.io", "severity": "LOW"}]
        applied, _ = policy.apply(findings, report_date=REPORT_DATE)
        assert applied[0]["annotations"] == [ANNOTATION_DENIED_BY_POLICY]
        assert not applied[0].get(FLAG_ALLOW_MATCHED)

    def test_glob_spoof_resistance_normative_pairs(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'allow_hosts = ["*.github.io", "api.github.com"]\n')
        assert policy.classify_host("foo.github.io") == "allow"
        assert policy.classify_host("bar.baz.github.io") == "allow"
        # §10 normative: matches foo.github.io, NOT evil.github.io.evil.com
        assert policy.classify_host("evil.github.io.evil.com") is None
        assert policy.classify_host("api.github.com.evil.com") is None
        assert policy.classify_host("phisher-github.io") is None

    def test_ip_lists_match_cidr_and_normalize(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'allow_ips = ["10.0.0.0/8", "192.168.1.1"]\n')
        assert policy.classify_host("http://10.42.0.7:8080/x") == "allow"
        assert policy.classify_host("192.168.1.1") == "allow"
        assert policy.classify_host("11.0.0.1") is None
        assert policy.classify_host("not-an-ip") is None

    def test_endpoint_normalization(self):
        assert normalize_endpoint("HTTPS://Foo.Example.com:8443/a/b?x=1") == "foo.example.com"
        assert normalize_endpoint("[::1]:8443") == "::1"
        assert normalize_endpoint("host.example.") == "host.example"
        assert normalize_endpoint("") is None
        assert normalize_endpoint(None) is None

    def test_findings_without_hosts_untouched(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'allow_hosts = ["*.github.io"]\n')
        finding = {"rule_id": "LNS-MAN-004", "severity": "MEDIUM"}
        applied, _ = policy.apply([finding], report_date=REPORT_DATE)
        assert applied[0] == finding  # pure copy, no host classification possible

    def test_apply_is_pure(self, tmp_path: Path):
        policy = self._policy(tmp_path, 'deny_hosts = ["x.example"]\n')
        original = {"rule_id": "R", "host": "x.example", "severity": "LOW"}
        policy.apply([original], report_date=REPORT_DATE)
        assert "annotations" not in original


# ---------------------------------------------------------------------------
# 6. Hard boundary — weights/caps/ceilings/grades unreachable from policy
# ---------------------------------------------------------------------------


class TestScoreHardBoundary:
    def test_published_defaults_pass_silently(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        write_policy(
            tmp_path,
            "[score]\nsuspected_critical_ceiling = 40\n"
            "money_ceiling = 70\nintegrity_ceiling = 80\n",
        )
        policy = load_policy(project_dir=tmp_path, diag=diag)
        assert not any(d.code == CODE_POLICY_SCORE_TAMPER for d in diag)
        assert policy is not None

    def test_tampered_ceiling_diagnosed_and_ignored(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        write_policy(
            tmp_path,
            "[score]\nmoney_ceiling = 99\nintegrity_ceiling = 10\nunknown_ceiling = 5\n",
        )
        policy = load_policy(project_dir=tmp_path, diag=diag)
        tampers = [d for d in diag if d.code == CODE_POLICY_SCORE_TAMPER]
        assert len(tampers) == 3
        assert all("ignored" in d.message for d in tampers)
        # No score fields exist on the policy object to even carry the tamper.
        tamper_attrs = ["money_ceiling", "score", "ceilings"]
        assert not any(hasattr(policy, attr) for attr in tamper_attrs)

    def test_scoring_math_identical_under_tamper_attempt(self, tmp_path: Path):
        """The proof: identical findings score identically with or without a
        policy that tries to rewrite ceilings."""
        findings = [
            {
                "rule_id": "LNS-NET-013",
                "capability": "money",
                "severity": "HIGH",
                "confidence": 0.95,
                "declared": False,
            }
        ]
        baseline = score_findings(findings)

        write_policy(tmp_path, "[score]\nmoney_ceiling = 1\nintegrity_ceiling = 1\n")
        diag = DiagnosticsCollector()
        policy = load_policy(project_dir=tmp_path, diag=diag)
        applied, _ = policy.apply(findings, report_date=REPORT_DATE)
        tampered_run = score_findings(applied)

        assert tampered_run.to_dict() == baseline.to_dict()
        assert list(baseline.ceilings_applied) == ["undeclared-money"]
        assert any(d.code == CODE_POLICY_SCORE_TAMPER for d in diag)

    def test_weight_tamper_key_is_unknown_and_inert(self, tmp_path: Path):
        diag = DiagnosticsCollector()
        write_policy(tmp_path, "[rules]\ndisable = []\nweight_multiplier = 100\n")
        policy = load_policy(project_dir=tmp_path, diag=diag)
        assert policy.disabled_rules == frozenset()
        # unknown keys warn-and-ignore (never crash, never reach math)
        assert any("weight_multiplier" in d.message for d in diag)


# ---------------------------------------------------------------------------
# 7. Malformed policy — PolicyError lane + one-line notice + provenance
# ---------------------------------------------------------------------------


class TestMalformedPolicyAndProvenance:
    def test_invalid_toml_raises_policy_error(self, tmp_path: Path):
        write_policy(tmp_path, "this is [ not toml ===")
        with pytest.raises(PolicyError) as excinfo:
            load_policy(project_dir=tmp_path)
        notice = policy_failure_notice(excinfo.value)
        assert "\n" not in notice
        assert notice.startswith("lens: policy error")
        assert ".lens/policy.toml" in notice or "policy" in notice

    def test_unreadable_file_raises_policy_error(self, tmp_path: Path, monkeypatch):
        target = tmp_path / "policy.toml"
        target.write_text("[choir]\nenabled = true\n", encoding="utf-8")

        def boom(self, *args, **kwargs):  # noqa: ANN001 — test shim
            raise PermissionError("simulated IO denial")

        monkeypatch.setattr(Path, "read_text", boom)
        with pytest.raises(PolicyError) as excinfo:
            load_policy(global_path=target)
        assert "cannot read" in excinfo.value.message

    def test_missing_files_mean_absent_layers(self, tmp_path: Path):
        policy = load_policy(
            project_dir=tmp_path / "missing-proj", global_path=tmp_path / "missing.toml"
        )
        assert policy.sources == SOURCES_BUILTIN_ONLY

    def test_notice_is_single_line_for_string_errors(self):
        notice = policy_failure_notice("boom\ncollapse\ttabs")
        assert "\n" not in notice and "\t" not in notice

    def test_exit_code_constant_matches_total_error_lane(self):
        assert POLICY_EXIT_CODE == 2

    def test_provenance_covers_every_layer_with_line_numbers(self, tmp_path: Path, fake_ctx):
        fake_ctx.set_config("profile", "lab")  # settings layer names the profile
        write_policy(
            tmp_path,
            '# comment line\n[network]\nallow_hosts = ["a.example"]\n',
        )
        policy = load_policy(project_dir=tmp_path, ctx=fake_ctx)
        prov = policy.provenance
        assert prov["profile"] == "plugin settings plugins.entries.lens.settings.profile"
        assert prov["network.allow_hosts"] == "project .lens/policy.toml:L3"
        assert prov["choir.enabled"] == "built-in"
        assert "plugin settings plugins.entries.lens.settings" in policy.sources

    def test_project_file_provenance_names_profile_when_it_chose_it(self, tmp_path: Path):
        write_policy(tmp_path, 'profile = "lab"\n')
        policy = load_policy(project_dir=tmp_path)
        assert policy.provenance["profile"] == "project .lens/policy.toml:L1"

    def test_baseline_entries_from_policy_merge_earlier_expiry_wins(self, tmp_path: Path):
        write_policy(
            tmp_path,
            '[[baseline]]\nfingerprint = "sha256:aaa1"\nreason = "docs example"\n'
            'expires = "2027-01-15"\n\n'
            '[[baseline]]\nfingerprint = "sha256:aaa1"\nreason = "dup"\n'
            'expires = "2026-09-01"\n',
        )
        policy = load_policy(project_dir=tmp_path)
        entry = policy.baseline_entry_for("sha256:aaa1")
        assert entry is not None
        assert entry.expires == date(2026, 9, 1)  # earlier expiry wins (§10)
        assert len(policy.baseline_entries) == 1

    def test_baseline_entry_missing_fields_diagnosed(self, tmp_path: Path):
        from skill_lens.policy import CODE_POLICY_BASELINE_ENTRY_INVALID

        diag = DiagnosticsCollector()
        write_policy(
            tmp_path,
            '[[baseline]]\nfingerprint = "sha256:bbb"\nreason = "no expires here"\n',
        )
        policy = load_policy(project_dir=tmp_path, diag=diag)
        assert len(policy.baseline_entries) == 0
        assert any(d.code == CODE_POLICY_BASELINE_ENTRY_INVALID for d in diag)

    def test_settings_type_mismatch_warns_never_fails(self, fake_ctx):
        from skill_lens.policy import CODE_POLICY_SETTING_TYPE

        diag = DiagnosticsCollector()
        fake_ctx.set_config("chat_budget_chars", "wide")  # wrong type on purpose
        fake_ctx.set_config("profile", "eminent")  # wrong value domain
        policy = load_policy(ctx=fake_ctx, diag=diag)
        assert policy.settings == {}
        assert policy.profile == "street"
        codes = {d.code for d in diag}
        assert codes >= {CODE_POLICY_SETTING_TYPE}

    def test_hostile_ctx_get_config_raises_degrades(self):
        class HostileCtx:
            def get_config(self, key, default=None):
                raise RuntimeError("host seam explosion")

        diag = DiagnosticsCollector()
        policy = load_policy(ctx=HostileCtx(), diag=diag)
        assert policy.profile == "street"  # advisor law: never raise into host


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_load_identical(self, tmp_path: Path, fake_ctx):
        fake_ctx.set_config("voice", "calm")
        write_policy(
            tmp_path,
            'profile = "lab"\n[rules]\ndisable = ["LNS-OBS-002"]\n'
            'severity_override = [{ rule_id = "LNS-SHL-007", severity = "LOW", reason = "r" }]\n'
            '[network]\nallow_hosts = ["*.github.io"]\n[[baseline]]\n'
            'fingerprint = "sha256:cc"\nreason = "r"\nexpires = "2027-01-01"\n',
        )
        one = load_policy(project_dir=tmp_path, ctx=fake_ctx, report_date=REPORT_DATE)
        two = load_policy(project_dir=tmp_path, ctx=fake_ctx, report_date=REPORT_DATE)
        assert one.profile == two.profile
        assert one.sources == two.sources
        assert one.provenance == two.provenance
        assert one.baseline_entries == two.baseline_entries
        assert one.severity_overrides == two.severity_overrides
        assert one.allow_hosts == two.allow_hosts

    def test_sources_order_stable_and_path_free(self, tmp_path: Path, fake_ctx):
        fake_ctx.set_config("profile", "lab")
        write_policy(tmp_path, '[network]\ndeny_hosts = ["d.example"]\n')
        policy = load_policy(project_dir=tmp_path, ctx=fake_ctx)
        assert policy.sources == SOURCES_FULL_CHAIN
        # absolute paths never enter labels (envelope determinism law)
        assert all(str(tmp_path) not in s for s in policy.sources)
