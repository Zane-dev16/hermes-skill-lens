"""E7 secretscan engine — detection + the redaction guarantee (SPEC §14).

Law under test: evidence snippets NEVER contain the full secret — every
serialized finding is scanned for raw credential substrings. Detection
covers AWS id+secret pairing, PEM blocks, GCP classification, OpenAI and
Slack formats, entropy windows in assignment/bearer contexts, and the
rule-spec example-marker skip.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from skill_lens.engines import scan_bundle
from skill_lens.engines.e7_secretscan import mask_secret, shannon_entropy
from skill_lens.rules import load_core_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pack():
    return load_core_pack()


def _bundle(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    return root


def _rule_findings(result, rule_id):
    return [f for f in result.findings if f["rule_id"] == rule_id]


# ---------------------------------------------------------------------------
# LNS-SEC-001 — known formats
# ---------------------------------------------------------------------------


def test_sec001_aws_pair_fires_and_masks_both_halves(pack, tmp_path) -> None:
    key_id = "AKIAIOSFODNN7EXAMPLE"
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    bundle = _bundle(
        tmp_path / "aws",
        {"references/creds.md": (f"# creds\n\naccess: {key_id}\nsecret: {secret}\n")},
    )
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001")
    assert len(fired) == 1
    assert fired[0]["severity"] == "HIGH"
    assert fired[0]["static_only"] is False  # usable AS-IS by any reader
    assert fired[0]["location"]["redacted"] is True
    dumped = json.dumps([f["location"] for f in fired])
    assert key_id not in dumped and secret not in dumped


def test_sec001_aws_id_without_secret_pair_stays_silent(pack, tmp_path) -> None:
    """Pairing REQUIRED — an id alone proves nothing (the env-var-doc FP)."""
    bundle = _bundle(
        tmp_path / "lone",
        {"references/vars.md": "- `AWS_ACCESS_KEY_ID` looks like AKIAIOSFODNN7EXAMPLE.\n"},
    )
    assert _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001") == []


def test_sec001_short_placeholder_ids_never_match(pack, tmp_path) -> None:
    bundle = _bundle(
        tmp_path / "placeholder",
        {"references/vars.md": "Placeholder ids look like `AKIAEXAMPLE`, not real keys.\n"},
    )
    assert _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001") == []


def test_sec001_pem_block_reports_span(pack, tmp_path) -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKr9\n"
        "Wq2xExampleMaterialForFixtureOnlyNotARealKey00000000\n"
        "-----END PRIVATE KEY-----\n"
    )
    bundle = _bundle(tmp_path / "pem", {"references/k.md": f"key below\n\n{pem}"})
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001")
    assert len(fired) == 1
    loc = fired[0]["location"]
    assert loc["start_line"] == 3
    assert loc["end_line"] == 6  # BEGIN + two body lines + END
    body = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKr9"
    assert body not in json.dumps(loc)


def test_sec001_gcp_shape_classifies_once_not_twice(pack, tmp_path) -> None:
    """private_key_id + PEM => ONE GCP finding, not GCP + plain PEM."""
    payload = (
        '{\n  "client_email": "svc@proj.iam.gserviceaccount.com",\n'
        '  "private_key_id": "abc123def456",\n'
        '  "type": "service_account"\n}\n'
        "-----BEGIN PRIVATE KEY-----\nMIIcHnZ2Vyc2lvbm1hdGVyaWFs\n-----END PRIVATE KEY-----\n"
    )
    bundle = _bundle(tmp_path / "gcp", {"references/sa.json": payload})
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001")
    assert len(fired) == 1
    assert fired[0]["tags"][-1] == "gcp-service-account-json"


@pytest.mark.parametrize(
    ("token", "kind"),
    [
        ("sk-proj-9Xk2mQpVbN4wRt8YcU6aE3sZ0fH1", "openai-token"),
        ("xoxb-2489655019-7943192234-ZxqAw2mQx9VbN", "slack-token"),
    ],
)
def test_sec001_openai_and_slack_formats(pack, tmp_path, token, kind) -> None:
    bundle = _bundle(
        tmp_path / kind, {"scripts/ship.sh": f'TOKEN="{token}"\ncurl -H "A: $TOKEN" https://x\n'}
    )
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-001")
    assert len(fired) == 1
    assert fired[0]["tags"][-1] == kind
    assert token not in json.dumps([f["location"] for f in fired])


# ---------------------------------------------------------------------------
# LNS-SEC-002 — entropy windows
# ---------------------------------------------------------------------------


def test_sec002_high_entropy_assignment_fires(pack, tmp_path) -> None:
    token = "j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH"  # corpus TP token, H=4.86
    bundle = _bundle(tmp_path / "tok", {"scripts/telemetry.sh": f'TELEMETRY_TOKEN="{token}"\n'})
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-002")
    assert len(fired) == 1
    assert fired[0]["severity"] == "MEDIUM"
    assert fired[0]["static_only"] is True
    assert fired[0]["confidence"] == pytest.approx(0.65)
    assert token not in json.dumps([f["location"] for f in fired])


@pytest.mark.parametrize(
    "line",
    [
        "- uuid: 550e8400-e29b-41d4-a716-446655440000",  # hex+dashes, low H
        "- commit: e99a18c428cb38d5f260853678922e03",  # 32-hex, low H
        "TOKEN=" + "aAbB" * 6,  # 24 chars but only 4 symbols
        "see https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaa for docs",  # marker+low H
        "EXAMPLE_TOKEN=Ab12Cd34Ef56Gh78Ij90Kl12Mn34",  # example-marker skip
        "placeholder_value=Ab12Cd34Ef56Gh78Ij90Kl12Mn34Qr",
    ],
)
def test_sec002_benign_shapes_stay_silent(pack, tmp_path, line) -> None:
    bundle = _bundle(tmp_path / "quiet", {"references/notes.md": line + "\n"})
    assert _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-002") == []


def test_sec002_bearer_context_fires_without_assignment(pack, tmp_path) -> None:
    token = "zR3wK8vNpQ6tY2uJ5mL9xC1bH4fD7sG0"
    bundle = _bundle(
        tmp_path / "bearer",
        {"scripts/call.sh": f'curl -H "Authorization: Bearer {token}" https://i\n'},
    )
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-002")
    assert len(fired) == 1
    assert token not in json.dumps([f["location"] for f in fired])


def test_sec002_prose_context_outside_assignment_is_silent(pack, tmp_path) -> None:
    # Long mixed-case run in running prose (no NAME=/":" or bearer prefix).
    prose = "The quick brown fox jumps over j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH lazily."
    bundle = _bundle(tmp_path / "prose", {"references/story.md": prose + "\n"})
    assert _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-002") == []


def test_sec002_json_and_yaml_config_contexts_fire(pack, tmp_path) -> None:
    token = "j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH"
    files = {
        "config/settings.json": f'{{"api_token": "{token}"}}\n',
    }
    bundle = _bundle(tmp_path / "cfg", files)
    fired = _rule_findings(scan_bundle(bundle, pack), "LNS-SEC-002")
    assert len(fired) == 1
    assert fired[0]["location"]["path"] == "config/settings.json"


# ---------------------------------------------------------------------------
# Redaction guarantee (privacy law, task deliverable 3)
# ---------------------------------------------------------------------------


def test_no_full_secret_anywhere_in_serialized_findings(pack, tmp_path) -> None:
    secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sk-proj-9Xk2mQpVbN4wRt8YcU6aE3sZ0fH1",
        "xoxb-2489655019-7943192234-ZxqAw2mQx9VbN",
        "j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH",
    ]
    body = "\n".join(
        [
            f"access: {secrets[0]}",
            f"secret: {secrets[1]}",
            f'token_one="{secrets[2]}"',
            f'token_two="{secrets[3]}"',
            f'token_three="{secrets[4]}"',
            "-----BEGIN PRIVATE KEY-----",
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAm1hdGVyaWFsb25saW5l",
            "-----END PRIVATE KEY-----",
        ]
    )
    bundle = _bundle(tmp_path / "all", {"references/everything.md": body + "\n"})
    result = scan_bundle(bundle, pack)
    dumped = json.dumps(list(result.findings), sort_keys=True)
    for secret in secrets:
        assert secret not in dumped, f"full secret leaked: {mask_secret(secret)}"
    # PEM body material never survives either.
    assert "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAm1hdGVyaWFsb25saW5l" not in dumped
    # But findings DID fire — silence is not how redaction works.
    assert {f["rule_id"] for f in result.findings} >= {"LNS-SEC-001", "LNS-SEC-002"}
    assert all(f["location"]["redacted"] for f in result.findings)


# ---------------------------------------------------------------------------
# Entropy math sanity
# ---------------------------------------------------------------------------


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    # 16 distinct chars of equal frequency = theoretical max 4.0 bits/char.
    alphabet16 = "0123456789abcdef" * 4
    assert shannon_entropy(alphabet16) == pytest.approx(4.0)
    # The corpus benign values sit below the 4.8 threshold; the TP above it.
    assert shannon_entropy("550e8400-e29b-41d4-a716-446655440000") < 4.8
    assert shannon_entropy("j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH") >= 4.8
    assert math.isfinite(shannon_entropy("anything"))


def test_mask_short_values_fully() -> None:
    assert mask_secret("short") == "*****"
    masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert "<20 chars>" in masked
