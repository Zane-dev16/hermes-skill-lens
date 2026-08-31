"""Skill Lens — deterministic security lens for Hermes agent skills.

Import package name is ``skill_lens`` (NAMING LAW). Pure Python 3.11+;
the default dependency closure imports stdlib only — no network machinery
(PRIVACY LAW), no optional third-party imports at module scope.

LAYOUT LAW (D-053): every intra-package import in this tree is RELATIVE.
The Hermes host loads this plugin directory as ``hermes_plugins.<key>``
(PluginManager._load_directory_module), where ``skill_lens/`` is NOT an
importable top-level name; relative imports bind to ``__package__`` and
resolve identically under both layouts, keeping exactly ONE module tree
per loading style (no split-brain singletons).
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
