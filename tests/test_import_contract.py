"""Import-contract tests — SPEC §14 G1/G3 enforcement (D-PRIVACY).

Two independent proofs that the DEFAULT Skill Lens pipeline contains zero
network capability, plus one proof that the OSV adapter loads ONLY on the
explicitly flagged codepath:

1. **Default-closure subprocess test** — a pristine interpreter imports
   every shipped ``skill_lens`` module EXCEPT ``skill_lens.enrich.*``, then
   asserts no I/O-capable network module (socket, ssl, urllib.request,
   http, ftplib, smtplib, …) sits in ``sys.modules``. Regression = build
   failure (SPEC §14 G1/G3 enforcement column).
2. **Static source scan** — no module outside ``skill_lens/enrich/`` may
   even TEXTUALLY import a network module; belt-and-suspenders against
   lazy-import tricks sneaking into the default closure.
3. **Lazy-import proof via an importlib meta-path hook** — running the full
   default pipeline (``scan_bundle`` → ``build_report`` → SARIF/compact
   renders) never REQUESTS ``skill_lens.enrich.osv``; calling
   :func:`skill_lens.enrich.osv.enrich_envelope` requests it exactly once.
   This is the "importing enrich.osv happens only inside the flagged
   function" half of the contract.

Honest scope note (R2, SPEC §14): these tests certify zero *direct*
network capability in the shipped default path — not "no network path can
ever exist" (the host's own ctx.llm lane is out of scope by definition).
"""

from __future__ import annotations

import importlib
import importlib.abc
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Modules capable of opening sockets or transferring data. urllib.parse is
#: deliberately ABSENT from this list only because the shipped closure does
#: not import it at all any more (e6_netgraph vendored its own URL parser);
#: if it ever reappears in the default closure, add it here and fix e6.
NETWORK_MODULES: tuple[str, ...] = (
    "socket",
    "ssl",
    "asyncio",
    "urllib",
    "urllib.request",
    "urllib.error",
    "http",
    "http.client",
    "ftplib",
    "smtplib",
    "telnetlib",
    "poplib",
    "imaplib",
    "nntplib",
    "xmlrpc",
    "xmlrpc.client",
)

_SUBPROCESS_PROBE = """
import sys, importlib, pkgutil

sys.path.insert(0, {root!r})
import skill_lens

for module_info in pkgutil.walk_packages(skill_lens.__path__, "skill_lens."):
    if module_info.name.startswith("skill_lens.enrich"):
        continue  # enrichment adapters are the sanctioned lazy boundary
    importlib.import_module(module_info.name)

banned = {banned!r}
loaded = sorted(name for name in banned if name in sys.modules)
print(loaded)
"""


def test_default_closure_imports_no_network_modules() -> None:
    """G1/G3: pristine-interpreter walk of every non-enrich module."""
    probe = _SUBPROCESS_PROBE.format(root=str(REPO_ROOT), banned=list(NETWORK_MODULES))
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    loaded = eval(completed.stdout.strip())  # noqa: S307 — literal list from our own probe
    assert loaded == [], (
        f"default import closure pulled network modules {loaded}; "
        "the deterministic pipeline must stay socket-free (SPEC §14 G1/G3)"
    )


def test_no_static_network_imports_outside_enrich() -> None:
    """Source-level scan: network imports live ONLY under skill_lens/enrich/."""
    pattern = re.compile(
        r"^\s*(?:import\s+(socket|ssl|urllib(?:\.\w+)*)|"
        r"from\s+(socket|ssl|urllib(?:\.\w+)*|http(?:\.\w+)*)\s+import)",
        re.MULTILINE,
    )
    offenders: list[str] = []
    for source in sorted((REPO_ROOT / "skill_lens").rglob("*.py")):
        rel = source.relative_to(REPO_ROOT).as_posix()
        if rel.startswith("skill_lens/enrich/"):
            continue
        match = pattern.search(source.read_text(encoding="utf-8"))
        if match:
            offenders.append(f"{rel}: {match.group(0).strip()!r}")
    assert offenders == [], f"network imports outside skill_lens/enrich/: {offenders}"


class _RecordingFinder(importlib.abc.MetaPathFinder):
    """Meta-path finder that records (never blocks) target-module requests."""

    def __init__(self, targets: set[str]) -> None:
        self._targets = targets
        self.requests: list[str] = []

    def find_spec(self, fullname: str, path: object = None, target: object = None):  # noqa: ANN001, ANN202
        if fullname in self._targets:
            self.requests.append(fullname)
        return None  # never actually satisfies: other finders proceed


def test_enrich_osv_imported_only_on_flagged_codepath(monkeypatch) -> None:  # noqa: ANN001
    """Meta-path hook: default pipeline never requests enrich.osv; the
    opt-in call requests it exactly once (lazy import INSIDE run_scan's
    flagged branch / direct adapter use)."""
    sys.modules.pop("skill_lens.enrich.osv", None)
    finder = _RecordingFinder({"skill_lens.enrich", "skill_lens.enrich.osv"})
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])

    # -- default pipeline: scan a corpus fixture end-to-end, render both ways
    from skill_lens.engines import scan_bundle
    from skill_lens.render import render_chat_compact
    from skill_lens.report import build_report, render_sarif

    fixture = REPO_ROOT / "corpus" / "fixtures" / "benign" / "pinned-deps-helper"
    result = scan_bundle(fixture)
    envelope = build_report(result)
    render_chat_compact(envelope, plugin_data_dir=None)
    render_sarif(envelope)
    assert finder.requests == [], "default pipeline imported the OSV adapter — G1/G3 violation"

    # -- flagged codepath: the adapter function lazily imports its own module
    finder.requests.clear()
    from skill_lens.enrich.osv import enrich_envelope

    enriched = enrich_envelope(envelope, root=fixture, fetch=lambda payload: {"vulns": []})
    assert enriched["enrichment"]["status"] == "ok"
    # Module now cached in sys.modules; the hook fired only until first load.
    assert "skill_lens.enrich.osv" in finder.requests
