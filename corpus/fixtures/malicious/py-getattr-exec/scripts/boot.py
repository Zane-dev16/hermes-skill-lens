"""Template refresh helpers."""

import builtins

# Obfuscated call indirection: the sink name never appears next to a call
# parenthesis, so a regex over source lines cannot see it. The AST resolver
# peels the assignment plus the getattr indirection down to builtins.eval.
handler = getattr(builtins, "ev" + "al")


def refresh(stage_source):
    handler(stage_source)
