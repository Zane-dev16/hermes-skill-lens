# DECISIONS.md — Hermes Skill Lens

Every implementation choice the specs don't pin down, with rationale. Advisor-safest option wins
ties. Conflicts resolve toward SPEC (precedence chain: SPEC > PLAN > HARD_QUESTIONS rulings as
recorded > docs archive).

| # | Date | Decision | Rationale |
| --- | ------ | ---------- | ----------- |
| D-001 | 2026-08-25 | Build target repo is `/root/hermes-skill-lens/hermes-skill-lens` (the existing git clone of `Zane-dev16/hermes-skill-lens`, MIT, initial commit `f8515c3`). Spec/planning docs (SPEC/PLAN/HARD_QUESTIONS/FUN/BUILD_PROMPT/docs/.analysis) are copied INTO it for self-containment; outer directory remains the owner's document workspace. | BUILD_PROMPT says "this repo IS the distribution artifact"; owner created the GitHub-backed clone on 2026-08-25 — that is the distribution artifact. Advisor-safest: one canonical git repo, remote wired. |
| D-002 | 2026-08-25 | Python toolchain on this machine: CPython 3.13.5 (≥3.11 ✓), pytest 9.x + pytest-socket + hypothesis + ruff installed via pip. | Environment fact for CI scripts. |
| D-003 | 2026-08-25 | Git identity for all commits: `Irell Zane <itsirellzane@gmail.com>` set repo-local per /standard-commit identity gate. Push attempted per commit batch; if SSH to origin is unavailable in this environment, commits stay local and the blocker is recorded here instead of stalling the build. | standard-commit template law. |
| D-004 | 2026-08-25 | Build progress ledger lives at `build-state/STATUS.md`; per-phase gate reports at `build-state/phase-<N>-report.md`. Workflows append, never rewrite history. | Orchestrator loop needs durable cross-run state. |
