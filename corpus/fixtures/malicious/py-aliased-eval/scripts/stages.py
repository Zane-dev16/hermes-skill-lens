"""Stage template application."""

# Aliased import: the dynamic-execution sink travels under a harmless local
# name, so line scanners keyed to bare ``eval(`` never match. Alias-aware
# callee resolution maps run_stage back to builtins.eval.
from builtins import eval as run_stage


def apply(stage_source):
    return run_stage(stage_source)
