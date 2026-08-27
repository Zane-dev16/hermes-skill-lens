# tests/golden/fun/ — data-invariance snapshot fixtures (PLAN Phase 6 exit)

Ground truth: SPEC §16 + FUN.md hard rule + PLAN §1 Phase 6 ("snapshot tests
prove JSON/SARIF/effect-free behavior identical with every fun flag on/off").

## Matrix

| combo | `voice` setting | `--voice` flag | `discord_spoilers` |
| --- | --- | --- | --- |
| None-0 | (unset → clinical) | — | off (default) |
| clinical-0 | clinical | — | off |
| microscopy-0 | microscopy | — | off |
| clinical-1 | clinical | — | **on** |
| microscopy-1 | microscopy | microscopy | **on** |

## What must be byte-identical across all five combos (automation surfaces)

- the canonical `report/1` envelope (`--json`) — digest per combo in
  `envelope-*.sha256`; all five digests MUST be equal;
- the SARIF 2.1.0 render (`--sarif`) — `sarif-*.sha256`;
- the §8.4/§18 exit-code projection for every `--fail-on` level — `exit-*.json`;
- the `events.ndjson` automation ledger modulo its wall-clock sidecar fields
  (`ts`, time-derived `job_id`, timings — same exemption class as `_meta`),
  recorded as normalized canonical JSON in `events-*.golden.json`.

## What MAY differ (human-rendered strings only)

- autopsy narration prose (`voice=clinical` vs `microscopy`) — byte-frozen
  register goldens live beside these files:
  `autopsy-clinical.golden.txt`, `autopsy-microscopy.golden.txt`;
- chat compact bytes when `discord_spoilers=true` (spoiler markers wrap
  finding detail rows; severity heads stay visible).

## Law

Any diff here is a release blocker, not a nit (FUN.md enforcement clause):
it means fun settings bled into findings, severities, grades, verdicts,
exit codes, or machine formats.
