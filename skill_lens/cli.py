"""CLI verb registration — ``hermes lens <verb>`` via ``register_cli_command``.

Phase-3 scope (task law): the five §11.2 verbs (scan/report/baseline/
explain-rules/diff/help) share ONE routing table with the slash lane
(:func:`skill_lens.slash.dispatch_verb`), plus the §8.4/§18 CI contract:

- ``--fail-on clean|notice|warn|alert`` (scan, report): exit 1 iff the
  envelope verdict is at or beyond the level; default none keeps the advisor
  stance (exit 0 even with findings). With ``--fail-on`` the scan verb runs
  the pipeline INLINE instead of enqueueing — a one-shot CI process has no
  reply path to protect (§11.5's queue-first rule guards interactive
  sessions), and a threshold exit needs a verdict NOW (DECISIONS D-049).
- ``--plain`` (scan, report, diff) strips box drawing to ASCII per §12.1;
  ``NO_COLOR`` forces the same lane. Output prints through a lazy-imported
  Rich Console when available (host house style, §12.1) and degrades to
  plain ``print`` when rich is absent — the plugin never hard-depends on it.

Exit codes map EXACTLY to SPEC §18: 0 completed (default advisor stance);
1 only an explicit ``--fail-on`` breach (projected by the single-source
:func:`skill_lens.scoring.compute_exit_code`); 2 total error (malformed
policy/baseline configuration via ``PolicyError``, unresolvable targets /
fail-lines). Engine crashes are findings, never exit 2 (D-CRASH).

Registration itself is defensive: any failure logs and degrades — never an
exception into the host.
"""

from __future__ import annotations

import logging
import os
import shlex
import sys
from typing import Any

logger = logging.getLogger("lens")

#: Output prefixes that map to §18 "total error" (exit 2) on the CLI lane.
#: The slash lane renders these same strings as answers; here they decide
#: process exit codes. Interim heuristic until the native argparse spec.
_FAIL_PREFIXES = ("lens fail ", "unknown flag ", "/lens scan requires")

_USAGE_MARKER = "— showing usage"

#: §12.1 box-drawing characters the TTY panel may emit. ``--plain`` and
#: ``NO_COLOR`` translate them to ASCII so dumb terminals / CI logs keep
#: the layout without Unicode box glyphs.
_BOX_CHARS = str.maketrans(
    {
        "┌": "+",
        "┐": "+",
        "└": "+",
        "┘": "+",
        "├": "+",
        "┤": "+",
        "┬": "+",
        "┴": "+",
        "┼": "+",
        "─": "-",
        "│": "|",
    }
)


def to_ascii_box(text: str) -> str:
    """Strip §12.1 box-drawing to ASCII headers (--plain / NO_COLOR lane)."""
    return text.translate(_BOX_CHARS)


def _emit(text: str, *, plain: bool) -> None:
    """Print user-facing output; Rich when available, print() otherwise.

    ``--plain`` or a set ``NO_COLOR`` routes through :func:`to_ascii_box`
    (§12.1) and pins ``no_color``; without them the text carries no ANSI of
    its own (slash renders are surface-neutral), so Rich adds nothing but
    safe passthrough — color stays exclusive to hosts that style it.
    """
    strip_box = plain or bool(os.environ.get("NO_COLOR"))
    out = to_ascii_box(text) if strip_box else text
    try:
        from rich.console import Console  # lazy third-party import (dev extra)

        Console(no_color=True if strip_box else None).print(
            out, markup=False, highlight=False, soft_wrap=True
        )
    except Exception:  # noqa: BLE001 — rendering must never crash the verb
        print(out)


def build_cli_handler(view: Any, cache: Any) -> Any:
    """Build ``(namespace) -> int`` dispatcher over the shared verb code."""
    from .policy import POLICY_EXIT_CODE, PolicyError, policy_failure_notice
    from .slash import dispatch_verb

    def dispatch(namespace: Any) -> int:
        verb = str(getattr(namespace, "lens_verb", "") or "help")
        tokens = _tokens_for(verb, namespace)
        try:
            raw = shlex.join(tokens)
        except ValueError:
            raw = " ".join(tokens)
        plain = bool(getattr(namespace, "plain", False))
        sink: dict[str, Any] = {}
        try:
            text = dispatch_verb(raw, view=view, cache=cache, sink=sink) or ""
        except PolicyError as exc:
            # CLI lane contract (A1 seam): malformed policy/baseline config ⇒
            # exit 2 (§18 total error), SAME wording as the in-session notice
            # so logs stay greppable across surfaces.
            print(policy_failure_notice(exc), file=sys.stderr)
            return POLICY_EXIT_CODE
        # Verbs may hand the CLI lane a dedicated §12.1 panel render (map);
        # the slash lane never sees it (D-SURF lane split).
        text = sink.pop("cli_text", None) or text or ""
        _emit(text, plain=plain)
        if verb == "doctor":
            # §11.9 exit policy lives in the report itself: 0 even on
            # warnings, 2 on any hard check failure. The doctor verb stashes
            # it in the sink; text-prefix heuristics and --fail-on don't apply.
            return int(sink.get("doctor_exit", 0))
        if verb == "rules":
            # §18 total-error semantics: a REJECTED rule-pack verification is
            # a checksum/provenance failure (exit 2); pass/warn exits 0.
            return int(sink.get("rules_exit", 0))
        if text.startswith(_FAIL_PREFIXES) or _USAGE_MARKER in text.splitlines()[0]:
            return POLICY_EXIT_CODE
        return _fail_on_exit_code(namespace, sink)

    def _fail_on_exit_code(namespace: Any, sink: dict[str, Any]) -> int:
        """§8.4/§18 projection — exit 1 ONLY on an explicit --fail-on breach."""
        fail_on = getattr(namespace, "fail_on", None)
        if not fail_on:
            return 0
        envelope = sink.get("envelope") or {}
        verdict = str((envelope.get("score") or {}).get("verdict") or "")
        from .scoring import compute_exit_code

        try:
            return compute_exit_code(verdict, fail_on)
        except ValueError as exc:
            # Unprojectable state (missing/corrupt verdict block) is a total
            # error, never a silent pass — CI must not read 0 as "clean".
            print(f"lens fail · {exc}", file=sys.stderr)
            return POLICY_EXIT_CODE

    return dispatch


def _tokens_for(verb: str, namespace: Any) -> list[str]:
    """Reconstruct argv tokens from parsed namespace (deterministic order)."""
    tokens: list[str] = [verb]

    def common_flags() -> None:
        fail_on = getattr(namespace, "fail_on", None)
        if fail_on:
            tokens.extend(["--fail-on", str(fail_on)])
        if getattr(namespace, "plain", False):
            tokens.append("--plain")

    if verb == "scan":
        target = getattr(namespace, "target", None)
        if target:
            tokens.append(str(target))
        if getattr(namespace, "json", False):
            tokens.append("--json")
        if getattr(namespace, "no_cache", False):
            tokens.append("--no-cache")
        if getattr(namespace, "sarif", False):
            tokens.append("--sarif")
        if getattr(namespace, "osv", False):
            tokens.append("--osv")
        common_flags()
    elif verb == "report":
        name = getattr(namespace, "name", None)
        if name:
            tokens.append(str(name))
        if getattr(namespace, "sarif", False):
            tokens.append("--sarif")
        if getattr(namespace, "json", False):
            tokens.append("--json")
        common_flags()
    elif verb == "map":
        target = getattr(namespace, "target", None)
        if target:
            tokens.append(str(target))
        common_flags()
    elif verb == "autopsy":
        name = getattr(namespace, "name", None)
        if name:
            tokens.append(str(name))
        voice = getattr(namespace, "voice", None)
        if voice:
            tokens.extend(["--voice", str(voice)])
        common_flags()
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
        common_flags()
    elif verb == "doctor":
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    elif verb == "hub":
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    elif verb == "watch":
        action = getattr(namespace, "action", None)
        if action:
            tokens.append(str(action))
        secs = getattr(namespace, "secs", None)
        if secs:
            tokens.append(str(secs))
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    elif verb == "rules":
        action = getattr(namespace, "action", None)
        path = getattr(namespace, "path", None)
        sig = getattr(namespace, "sig", None)
        pubkey = getattr(namespace, "pubkey", None)
        # Default action is implicit; emit it only when a path/flag needs an
        # anchor so token reconstruction stays canonical either way.
        if path or sig or pubkey:
            tokens.append(action or "verify")
        if path:
            tokens.append(str(path))
        if sig:
            tokens.extend(["--sig", str(sig)])
        if pubkey:
            tokens.extend(["--pubkey", str(pubkey)])
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    elif verb == "bones":
        target = getattr(namespace, "target", None)
        if target:
            tokens.append(str(target))
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    elif verb == "lens":
        if getattr(namespace, "plain", False):
            tokens.append("--plain")
    return tokens


def setup_parser(parser: Any) -> None:
    """Fill the host's ``hermes lens`` argparse subparser (host seam shape)."""
    subparsers = parser.add_subparsers(dest="lens_verb")

    p_scan = subparsers.add_parser("scan", help="scan a skill bundle")
    p_scan.add_argument("target")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--no-cache", dest="no_cache", action="store_true")
    p_scan.add_argument("--sarif", action="store_true")
    # SPEC §14 G2: OSV.dev enrichment is OPT-IN network — the flag is the
    # only route; the default path stays socket-free (import-contract tested).
    p_scan.add_argument("--osv", action="store_true")
    _add_common_flags(p_scan)

    p_report = subparsers.add_parser("report", help="latest cached report")
    p_report.add_argument("name", nargs="?", default=None)
    p_report.add_argument("--json", action="store_true")
    p_report.add_argument("--sarif", action="store_true")
    _add_common_flags(p_report)

    p_baseline = subparsers.add_parser("baseline", help="baseline current fingerprints")
    p_baseline.add_argument("name")
    p_baseline.add_argument("--reason", required=True)
    p_baseline.add_argument("--expires", default=None)

    p_explain = subparsers.add_parser("explain-rules", help="effective rule set with provenance")
    p_explain.add_argument("--rule", dest="rule_id", default=None)

    p_diff = subparsers.add_parser("diff", help="fingerprint-stable report diff")
    p_diff.add_argument("left")
    p_diff.add_argument("right", nargs="?", default=None)
    # diff carries --plain only: its render has no single verdict envelope,
    # so a threshold gate would be meaningless (§8.4 gates VERDICTS).
    p_diff.add_argument("--plain", action="store_true")

    p_doctor = subparsers.add_parser(
        "doctor", help="§11.9 nine-check self-check (exit 0 on warnings; 2 on hard failures)"
    )
    # doctor carries --plain only: it has no verdict envelope to gate.
    p_doctor.add_argument("--plain", action="store_true")

    p_hub = subparsers.add_parser(
        "hub", help="review bundles staged in skills/.hub/quarantine (advisory lane)"
    )
    # hub carries --plain only: it renders the §11.7 view, no verdict envelope.
    p_hub.add_argument("--plain", action="store_true")

    p_watch = subparsers.add_parser(
        "watch", help="out-of-band drift watcher: status (default) | start [secs] | stop"
    )
    p_watch.add_argument("action", nargs="?", default="status")
    p_watch.add_argument("secs", nargs="?", default=None)
    p_watch.add_argument("--plain", action="store_true")

    p_rules = subparsers.add_parser(
        "rules",
        help="rule-pack governance: verify [path] [--sig F] [--pubkey F] (offline; §15)",
    )
    p_rules.add_argument("action", nargs="?", default="verify")
    p_rules.add_argument("path", nargs="?", default=None)
    p_rules.add_argument("--sig", dest="sig", default=None)
    p_rules.add_argument("--pubkey", dest="pubkey", default=None)
    # rules carries --plain only: its output is a verdict notice, not a
    # score envelope a threshold could gate.
    p_rules.add_argument("--plain", action="store_true")

    p_map = subparsers.add_parser(
        "map", help="SkillIR tree: files, claims vs capabilities, provenance note"
    )
    p_map.add_argument("target")
    _add_common_flags(p_map)

    p_autopsy = subparsers.add_parser(
        "autopsy",
        help="deep narrative walkthrough (voices OPT-IN: clinical default, microscopy;"
        " noir deferred per HQ O4)",
    )
    p_autopsy.add_argument("name")
    p_autopsy.add_argument("--voice", dest="voice", default=None)
    _add_common_flags(p_autopsy)

    # Hidden verbs get a WINK, not real help copy (FUN.md F-6: "never listed
    # in help text beyond a wink"); the host's own help stays uncluttered.
    p_bones = subparsers.add_parser("bones", help="try it and see (wink)")
    p_bones.add_argument("target", nargs="?", default=None)
    p_bones.add_argument("--plain", action="store_true")

    p_self = subparsers.add_parser("lens", help="the instrument, examined by itself")
    p_self.add_argument("--plain", action="store_true")

    subparsers.add_parser("help", help="usage block")


def _add_common_flags(subparser: Any) -> None:
    """Attach the §8.4/§12.1 flags shared by verdict-bearing verbs."""
    subparser.add_argument(
        "--fail-on",
        dest="fail_on",
        default=None,  # levels validated in the shared verb impls (one grammar)
    )
    subparser.add_argument("--plain", action="store_true")


def register_cli(view: Any, *, cache: Any = None) -> bool:
    """Register ``hermes lens`` on the defensive view. Returns True when the
    host accepted the registration; failures log and return False (advisor
    law — never an exception into the host)."""
    if cache is None:
        from .slash import shared_cache

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


__all__ = [
    "build_cli_handler",
    "make_exiting_dispatcher",
    "register_cli",
    "setup_parser",
    "to_ascii_box",
]
