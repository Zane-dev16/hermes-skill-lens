# FP regression process (standing)

Every closed false positive becomes a **permanent benign fixture**. This is
the FP-as-fixture law (PLAN §1 Phase 3; SPEC §15 corpus semantics): the
corpus is the memory of the rule pack, and a precision fix that is not
pinned by a fixture is a fix that will silently regress.

## The loop

1. **Reproduce as a bundle.** Shape the FP report into a minimal skill
   bundle (`SKILL.md` + payloads) that fires the rule through the real
   pipeline. If it cannot be reproduced through `corpus.run_case`, it is not
   an FP yet — keep investigating.
2. **Triage — exactly one of two verdicts:**
   - **Fixture-side:** the bundle genuinely looks like what the rule
     exists to catch (the report is "this looks scary but is fine" — which
     is still what the rule should say). Fix the FIXTURE's framing or move
     it to `malicious/` if it truly matches detection intent.
   - **Rule-side:** the rule overfires on legitimately-shaped content.
     Fix RULE PRECISION toward fewer FPs: narrower patterns, exemption with
     a documented rationale, allowlist/data extension, or (last) severity /
     confidence re-banding under the D-FP heuristic caps.
3. **Land the fix + the fixture together.** The closed-FP case joins
   `corpus/fixtures/benign/<name>/` with an `expected.toml` and stays in the
   harness forever. A rule-side change logs a DECISIONS entry (mechanism,
   rationale, why no TP was lost). New rules still require ≥1 malicious +
   ≥1 benign lookalike per the §15 bidirectional contract; precision fixes
   add benign fixtures without touching expected bands.
4. **Gates stay green.** `pytest -q` (including `tests/test_benign_floor.py`
   — every benign fixture must grade ≥ B on street) and `ruff check .`;
   golden vectors A–G byte-exact after any shared-code change.

## Deleting a rule

A rule id may only be removed from the core pack if its removal makes its
own malicious fixtures FAIL CI: every malicious fixture declares
`[[expect_rules]]` entries by id, and `test_expected_rule_ids_exist_in_core_pack`
fails closed on any expectation pointing at a missing rule. In practice this
means deletion requires consciously re-authoring those fixtures' manifests
in the same change — never a quiet disappearance.

## Closure ledger

| Closed FP | Rule | Fixture(s) pinning it | Decision |
| --- | --- | --- | --- |
| 2026-08-25 · concrete CJK/Arabic descriptions tokenized to nothing under the Latin-only cue scan → LNS-MAN-004 fired | LNS-MAN-004 | `benign/cjk-notes-helper`, `benign/arabic-task-tracker` | D-047 — multilingual cue tables added inside the rule's own cue semantics; marketing-only copy in any language stays vague |
| 2026-08-25 · `black` scored as distance-2 near-miss of click/flask (dev-toolchain staples missing from the bundled typosquat allowlist) | LNS-DEP-002 | `benign/pinned-pyproject-tool` | D-048 — allowlist extended to top-known staples; membership strictly reduces FPs and only extends squat coverage |
