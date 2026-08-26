"""CLI verb registration — ``hermes lens <verb>`` via ``register_cli_command``.

Phase-2 scope (task law): provide :func:`register_cli` as a helper callable
from ``register()`` and wire BOTH surfaces while it is trivial. The host
seam (hermes_cli/plugins.py::PluginContext.register_cli_command) takes a
``setup_fn`` that fills an argparse subparser plus an optional
``handler_fn`` installed via ``set_defaults(func=…)`` — so the adapter here:

- defines subparsers for scan/report/baseline/explain-rules/diff/help;
- dispatches through THE SAME slash verb implementations by reconstructing
  argv tokens (:func:`shlex.join`) — one behavior source for both lanes;
  the native shared argparse spec of §11.2 lands with the full CLI phase
  (P4/P5) and replaces this adapter;
- maps errors to §18 exit codes: malformed policy/baseline configuration
  raises ``SystemExit(POLICY_EXIT_CODE)`` (=2, the A1 seam contract on the
  CLI lane), unresolvable targets / fail-lines exit 2 (unreadable-target
  family), everything user-facing prints to stdout first.

Registration itself is defensive: any failure logs and degrades — never an
exception into the host.
"""

from __future__ import annotations

import logging
import shlex
import sys
from typing import Any

logger = logging.getLogger("lens")

#: Output prefixes that map to §18 "total error" (exit 2) on the CLI lane.
#: The slash lane renders these same strings as answers; here they decide
#: process exit codes. Interim heuristic until the native argparse spec.
_FAIL_PREFIXES = ("lens fail ", "unknown flag ", "/lens scan requires")

_USAGE_MARKER = "— showing usage"


def build_cli_handler(view: Any, cache: Any) -> Any:
    """Build ``(namespace) -> int`` dispatcher over the shared verb code."""
    from skill_lens.policy import POLICY_EXIT_CODE, PolicyError, policy_failure_notice
    from skill_lens.slash import dispatch_verb

    def dispatch(namespace: Any) -> int:
        verb = str(getattr(namespace, "lens_verb", "") or "help")
        tokens = _tokens_for(verb, namespace)
        try:
            raw = shlex.join(tokens)
        except ValueError:
            raw = " ".join(tokens)
        try:
            text = dispatch_verb(raw, view=view, cache=cache) or ""
        except PolicyError as exc:
            # CLI lane contract (A1 seam): malformed policy/baseline config ⇒
            # exit 2 (§18 total error), SAME wording as the in-session notice
            # so logs stay greppable across surfaces.
            print(policy_failure_notice(exc), file=sys.stderr)
            return POLICY_EXIT_CODE
        print(text)
        if text.startswith(_FAIL_PREFIXES) or _USAGE_MARKER in text.splitlines()[0]:
            return POLICY_EXIT_CODE
        return 0

    return dispatch


def _tokens_for(verb: str, namespace: Any) -> list[str]:
    """Reconstruct argv tokens from parsed namespace (deterministic order)."""
    tokens: list[str] = [verb]
    if verb == "scan":
        target = getattr(namespace, "target", None)
        if target:
            tokens.append(str(target))
        if getattr(namespace, "json", False):
            tokens.append("--json")
        if getattr(namespace, "no_cache", False):
            tokens.append("--no-cache")
    elif verb == "report":
        name = getattr(namespace, "name", None)
        if name:
            tokens.append(str(name))
    elif verb == "baseline":
        name = getattr(namespace, "name", None)
        if name:
            tokens.append(str(name))
        reason = getattr(namespace, "reason", None)
        if reason:
            tokens.extend(["--reason", str(reason)])
        expires = getattr(namespace, "expires", None)
        if expires:
            tokens.extend(["--expires", str(expires)])
    elif verb in ("explain-rules",):
        rule_id = getattr(namespace, "rule_id", None)
        if rule_id:
            tokens.extend(["--rule", str(rule_id)])
    elif verb == "diff":
        left = getattr(namespace, "left", None)
        if left:
            tokens.append(str(left))
        right = getattr(namespace, "right", None)
        if right:
            tokens.append(str(right))
    return tokens


def setup_parser(parser: Any) -> None:
    """Fill the host's ``hermes lens`` argparse subparser (host seam shape)."""
    subparsers = parser.add_subparsers(dest="lens_verb")

    p_scan = subparsers.add_parser("scan", help="scan a skill bundle")
    p_scan.add_argument("target")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--no-cache", dest="no_cache", action="store_true")

    p_report = subparsers.add_parser("report", help="latest cached report")
    p_report.add_argument("name", nargs="?", default=None)

    p_baseline = subparsers.add_parser("baseline", help="baseline current fingerprints")
    p_baseline.add_argument("name")
    p_baseline.add_argument("--reason", required=True)
    p_baseline.add_argument("--expires", default=None)

    p_explain = subparsers.add_parser("explain-rules", help="effective rule set with provenance")
    p_explain.add_argument("--rule", dest="rule_id", default=None)

    p_diff = subparsers.add_parser("diff", help="fingerprint-stable report diff")
    p_diff.add_argument("left")
    p_diff.add_argument("right", nargs="?", default=None)

    subparsers.add_parser("help", help="usage block")


def register_cli(view: Any, *, cache: Any = None) -> bool:
    """Register ``hermes lens`` on the defensive view. Returns True when the
    host accepted the registration; failures log and return False (advisor
    law — never an exception into the host)."""
    if cache is None:
        from skill_lens.slash import shared_cache

        cache = shared_cache()
    try:
        handle = view.register_cli_command(
            "lens",
            help_text="Skill Lens — deterministic security reports for skill bundles",
            setup_fn=setup_parser,
            handler_fn=make_exiting_dispatcher(view, cache),
            description="scan · report · baseline · explain-rules · diff (advisory only)",
        )
    except Exception:  # noqa: BLE001 — registration must never raise into the host
        logger.exception("Skill Lens: hermes-lens CLI registration failed")
        return False
    if handle is None:
        logger.warning("hermes-lens CLI registration degraded: host ctx lacks the seam")
        return False
    return True


def make_exiting_dispatcher(view: Any, cache: Any) -> Any:
    """``(namespace)`` callable that EXITS the process with §18 semantics.

    The host installs ``handler_fn`` via ``set_defaults(func=…)`` and ignores
    return values, so the exit code must ride SystemExit (argparse house
    style). Kept separate from :func:`build_cli_handler` so tests can assert
    on plain integer returns.
    """
    dispatch = build_cli_handler(view, cache)

    def exiting(namespace: Any) -> None:
        raise SystemExit(dispatch(namespace))

    return exiting


__all__ = ["build_cli_handler", "make_exiting_dispatcher", "register_cli", "setup_parser"]
