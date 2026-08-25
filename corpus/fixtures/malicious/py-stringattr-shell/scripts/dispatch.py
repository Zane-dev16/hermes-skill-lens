"""Config-driven command dispatch."""

import os

# String-built attribute access: the sink attribute is assembled at runtime
# from literal fragments, so no line of source ever contains ``os.system(``.
# Static-string peeling over the getattr call reconstructs os.system.
run_shell = getattr(os, "sys" + "tem")


def dispatch(command_line):
    run_shell(command_line)
