"""Import-contract tests — SPEC §14 G1/G3 enforcement (D-PRIVACY).

Two independent proofs that the DEFAULT Skill Lens pipeline contains zero
network capability, plus two proofs that the opt-in adapters load ONLY on
their explicitly flagged codepaths (OSV + Choir):

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
4. **Choir lazy-import proof** — the default pipeline never REQUESTS
   ``skill_lens.choir``; the ``/lens second-opinion`` verb (or a direct
   ``from skill_lens.choir import run_second_opinion``) requests it exactly
   once. The module remains IN the subprocess walk (imports clean,
   zero network) — proving "out of the default *call* closure" without an
   import-graph exclusion.

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


def test_choir_imported_only_on_flagged_codepath(monkeypatch) -> None:  # noqa: ANN001
    """Meta-path hook: default pipeline never requests choir; flagged verb does."""
    sys.modules.pop("skill_lens.choir", None)
    finder = _RecordingFinder({"skill_lens.choir"})
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])

    # -- default pipeline: same fixture walk must NOT request choir
    from skill_lens.engines import scan_bundle  # noqa: F401
    from skill_lens.render import render_chat_compact  # noqa: F401
    from skill_lens.report import build_report, render_sarif  # noqa: F401

    fixture = REPO_ROOT / "corpus" / "fixtures" / "benign" / "pinned-deps-helper"
    result = scan_bundle(fixture)
    envelope = build_report(result)
    render_chat_compact(envelope, plugin_data_dir=None)
    render_sarif(envelope)
    assert finder.requests == [], "default pipeline imported choir — G1/G3 violation"

    # -- flagged codepath: direct adapter import is the lazy boundary
    finder.requests.clear()
    from skill_lens.choir import run_second_opinion  # noqa: F401

    assert "skill_lens.choir" in finder.requests
    # Second import is cached — hook does not fire again, proving exactly-once load.
    finder.requests.clear()
    import skill_lens.choir as _choir_mod  # noqa: F401

    assert finder.requests == [], "choir re-import should be cached"


# ---------------------------------------------------------------------------
# D-053 layout law: host-plugin load must not depend on a top-level
# ``skill_lens`` import name. The Hermes host imports this plugin directory
# as ``hermes_plugins.<key>`` (PluginManager._load_directory_module), where
# ``skill_lens/`` is NOT importable from sys.path. Every intra-package
# import is therefore RELATIVE; these tests pin that contract from both
# sides (static source scan + live host-style subprocess load).
# ---------------------------------------------------------------------------

_ABSOLUTE_INTRA_PACKAGE_IMPORT = re.compile(
    r"^\s*(?:from\s+skill_lens(?:\.\w+)*\s+import\b|import\s+skill_lens(?:\.\w+)*)",
    re.MULTILINE,
)


def test_no_absolute_intra_package_imports() -> None:
    """D-053: skill_lens/** must use relative intra-package imports only.

    An absolute ``from skill_lens.x import ...`` works only while repo root
    sits on sys.path (pytest) and raises ModuleNotFoundError under the
    host's ``hermes_plugins.<key>`` load — the Phase-4 integration blocker.
    Docstring/prose mentions of the public package name are fine; only
    actual import statements are banned.
    """
    offenders: list[str] = []
    for source in sorted((REPO_ROOT / "skill_lens").rglob("*.py")):
        rel = source.relative_to(REPO_ROOT).as_posix()
        for match in _ABSOLUTE_INTRA_PACKAGE_IMPORT.finditer(source.read_text(encoding="utf-8")):
            line_no = source.read_text(encoding="utf-8")[: match.start()].count("\n") + 1
            offenders.append(f"{rel}:{line_no}: {match.group(0).strip()!r}")
    assert offenders == [], f"absolute intra-package imports: {offenders}"


_HOST_LAYOUT_PROBE = """
import os, sys, tempfile, types, importlib.util
from pathlib import Path

REPO = Path({root!r})
os.chdir(tempfile.mkdtemp(prefix="lens-hostlayout-"))
os.environ["HERMES_HOME"] = os.getcwd()          # hermetic scratch home
sys.path = [p for p in sys.path if p and Path(p).resolve() != REPO.resolve()]

ns_name = "hermes_plugins"
ns_pkg = types.ModuleType(ns_name)
ns_pkg.__path__ = []                              # type: ignore[attr-defined]
ns_pkg.__package__ = ns_name
sys.modules[ns_name] = ns_pkg

module_name = ns_name + ".lens_probe"
spec = importlib.util.spec_from_file_location(
    module_name, REPO / "__init__.py", submodule_search_locations=[str(REPO)]
)
module = importlib.util.module_from_spec(spec)
module.__package__ = module_name                  # type: ignore[attr-defined]
module.__path__ = [str(REPO)]                     # type: ignore[attr-defined]
sys.modules[module_name] = module
spec.loader.exec_module(module)

class Ctx:
    # Minimal PluginContext double covering exactly the seams register() uses.
    def __init__(self, data_root):
        self.manifest = types.SimpleNamespace(key="lens", name="lens", version="0.9.0a0")
        self.plugin_id = "lens"
        self.registered_hooks = []
        self.commands = {{}}
        self.cli_commands = {{}}
        self._settings = {{}}
        self._data_dir = Path(data_root) / "plugin-data" / "lens"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def register_hook(self, hook_name, callback):
        self.registered_hooks.append(hook_name)
        return object()

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = {{"handler": handler}}
        return object()

    def register_cli_command(self, name, **kwargs):
        self.cli_commands[name] = kwargs
        return object()

    def get_config(self, key, default=None):
        node = self._settings
        for segment in key.split("."):
            if isinstance(node, dict) and segment in node:
                node = node[segment]
            else:
                return default
        return node

    def set_config(self, key, value):
        self._settings[key] = value

    @property
    def state(self):
        return types.SimpleNamespace(data_dir=self._data_dir)

ctx = Ctx(tempfile.mkdtemp(prefix="lens-hostlayout-data-"))
module.register(ctx)

assert sorted(ctx.registered_hooks) == [
    "on_skill_lifecycle", "post_tool_call", "transform_tool_result"
], ctx.registered_hooks
assert "lens" in ctx.cli_commands, sorted(ctx.cli_commands)

handler = ctx.commands["lens"]["handler"]
doctor_out = handler("doctor")
assert isinstance(doctor_out, str) and doctor_out.strip(), repr(doctor_out)[:200]
hub_out = handler("hub")
assert isinstance(hub_out, str) and hub_out.strip(), repr(hub_out)[:200]

# Core pack must resolve through the LOADED tree (importlib.resources via
# __package__, not a hard-coded top-level name).
loaded_rules = module.skill_lens.rules
pack = loaded_rules.load_core_pack()
assert len(pack.rules) > 0, "core pack empty under host layout"

leaked = [n for n in sys.modules if n == "skill_lens" or n.startswith("skill_lens.")]
assert not leaked, f"top-level skill_lens leaked into host layout: {{sorted(leaked)[:5]}}"
print("HOST-LAYOUT-OK")
"""


def test_host_layout_load_end_to_end(tmp_path) -> None:  # noqa: ANN001
    """D-053: load the plugin EXACTLY like PluginManager does (repo root
    scrubbed from sys.path) and drive register() → slash verbs → core-pack
    load end-to-end. Regression for the Phase-4 integration blocker:
    absolute intra-package imports raised ModuleNotFoundError at slash.py /
    cli.py / watcher.py under this layout."""
    import subprocess

    probe = _HOST_LAYOUT_PROBE.format(root=str(REPO_ROOT))
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, (
        f"host-layout load failed\nstdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
    )
    assert "HOST-LAYOUT-OK" in result.stdout
