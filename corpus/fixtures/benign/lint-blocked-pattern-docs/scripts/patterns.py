"""Static reference data: patterns the lint pack blocks (never executed)."""

BLOCKED_PATTERNS = (
    "os.system(raw_input)",
    "eval(handler(user_data))",
    "exec(compile(payload, '<string>', 'exec'))",
    "subprocess.run(target, shell=True)",
)

SUMMARY = (
    "Blocks dynamic execution helpers such as eval(x), exec(x), "
    "os.system(cmd), os.popen(cmd), and subprocess.run(cmd, shell=True); "
    "see each pattern entry for the replacement guidance."
)
