# QUESTIONS FOR OWNER

Standing arbitration queue. None of these block the v0.9 tag; each records an honest
deviation or a preference the specs left open.

## Q1 · Core pack rule count: 41 vs the "30–40 at v0.9" budget band (BUILD_PROMPT §4.6)

**State:** 41 shipped rules in `skill_lens/rules/core/rules/`, every one corpus-tested both
ways (malicious + benign lookalike fixtures) per SPEC §15.

**The tension:** the 30–40 wording reads as a planning budget, not an invariant like the
scoring law — but it IS written as a range. Options:

1. Keep all 41 (more coverage; band treated as soft target).
2. Merge/deprecate the weakest rule to land inside the band (pack bump required either
   way per §15: removal = deprecation after ≥2 minors OR owner waiver for v0.9).

**Recommendation:** option 1 — dropping detection that passes both-way testing to satisfy a
round-number budget works against the product thesis ("A lens, not a bouncer"). Your call;
no code change until you answer.
