# docs/ — Skill Lens documentation

## Current docs

| Doc | What it covers |
| --- | --- |
| [dev-loop.md](dev-loop.md) | The scratch-`HERMES_HOME` loop: load → enable → iterate → unload without touching your real home. |
| [rule-author-guide.md](rule-author-guide.md) | Adding or changing a detection rule: schema, both-way fixtures, engine wiring, semver governor, signing — with a worked example. |
| [json-schema.md](json-schema.md) | The `--json` envelope (`report/1`): every top-level key, verdict/grade/needs_review semantics, and the byte-stability promise. |
| [threat-model.md](threat-model.md) | What a scan covers and — just as important — what it cannot. Static analysis only; clean != safe. |
| [limitations.md](limitations.md) | Known limitations with host ground truth, and what ships instead. |
| [host-contract.md](host-contract.md) | The consumed hooks, verbatim emit sites, and payload shapes (transcribed from the host tree). |
| [github-action.md](github-action.md) | Using the composite GitHub Action in CI: inputs, SARIF upload, exit-code gating. |
| [key-ceremony.md](key-ceremony.md) | Rule-pack signing: keys, the offline verification path, ceremony steps. |
| [fp-regression.md](fp-regression.md) | The FP-as-fixture law: every closed false positive becomes a permanent benign fixture. |
| [dod-checklist.md](dod-checklist.md) | Definition-of-Done audit with evidence pointers. |
| [corpus-licensing-review.md](corpus-licensing-review.md) | The licensing/provenance gate real-world-derived corpus fixtures must pass, and its record. |

## Historical archive

These are the research-phase documents produced during the **pre-rename era**
(when the project was named "Skill X-Ray", command `xray`, rule prefix `XRY-`).
They are retained verbatim for provenance — the reasoning and evidence still
hold, but every name in them is stale, and where they disagree with the code
or the docs above, the code wins. Treat as read-only history.

| File | Phase |
| --- | --- |
| `threat-taxonomy.md` | Threat classes, detection layers L1/L2/L3, confidence calibration |
| `scoring-policy.md` | Research assessment that fed scoring v2 |
| `architecture.md` | Engine architecture decision record (the "engine-architecture transcript") |
| `arch-review.md` | Adversarial architecture review (the "arch-critique transcript") |
| `policy-and-claims.md` | Claimed-vs-actual extraction + policy design |
| `report-ux.md` | Report format design |
| `hook-and-watch.md` | Trigger/surface design (superseded by Hermes-native triggers) |
| `personality-fun.md` | Early personality ideation (share cards rejected; see `FUN.md` for current voice law) |
| `research/scoring-rubrics.md` | Underlying scoring research |

The design specs themselves are internal working documents and are not part
of this tree's published docs.
