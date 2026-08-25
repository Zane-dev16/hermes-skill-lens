# 05 · Rename Census (pre-application inventory)

Date: 2026-08-23 · Scope: `SPEC.md`, `PLAN.md`, `HARD_QUESTIONS.md`, `FUN.md` only.
Authority: owner rename decision 2026-08-23 — product is **Hermes Skill Lens** (display "Skill Lens").
`.analysis/` itself is historical evidence and stays untouched (old names preserved there by design).

Method: case-insensitive token census (`grep -io`) for exact occurrence counts, plus line-number
extraction per class. Counts are occurrences (tokens), not matching lines.

---

## 1. Occurrence-count table (per file × pattern)

| Pattern (case-insensitive) | SPEC.md | PLAN.md | HARD_QUESTIONS.md | FUN.md | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `xray` (all cases incl. identifiers) | 89 | 44 | 21 | 41 | 195 |
| `x-ray` / `X-Ray` / `X-RAY` (hyphenated) | 31 | 6 | 14 | 8 | 59 |
| `XRay` (camelCase) | 0 | 0 | 0 | 0 | 0 |
| `XRAY` (upper, unhyphenated) | 0 | 0 | 0 | 0 | 0 |
| `XRY` (rule prefix) | 14 | 4 | 0 | 0 | 18 |
| `sxr` (console-script alias) | 1 | 1 | 1 | 0 | 3 |
| `radiolog*` (radiology ×6/1/6/6 + radiologist ×2 in FUN) | 6 | 1 | 6 | 8 | 21 |
| `radiograph*` (radiograph/radiographic) | 1 | 0 | 4 | 3 | 8 |
| `fluoroscop*` | 1 | 0 | 0 | 3 | 4 |
| `Röntgen` | 0 | 0 | 0 | 2 | 2 |
| `Langevin` | 0 | 0 | 0 | 1 | 1 |
| `Hounsfield` | 0 | 0 | 0 | 1 | 1 |
| `DEVELOPING` | 0 | 0 | 0 | 2 | 2 |
| header-art `X-RAY DEPT.` (true hits) | 0 | 0 | 0 | 1 | 1 |
| **Strict total (task-listed patterns)** | **143** | **55** | **46** | **70** | **314** |

Adjacent vocabulary inventoried (outside the strict pattern list):

| Adjacent pattern | SPEC | PLAN | HQ | FUN | Disposition |
| --- | ---: | ---: | ---: | ---: | --- |
| `.xray/` path namespace | 4 | 3 | 0 | 1 | ⚠ uncovered class U-2 |
| `skill-xray` registry/dist name | 1 | 0 | 3 | 0 | covered (registries → `skill-lens`) |
| `hermes-xray` repo name | 0 | 6 | 0 | 0 | covered |
| `xray_plugin` import name | 2 | 6 | 2 | 0 | covered (`skill_lens`) |
| `--develop` flag | 0 | 0 | 0 | 3 | ⚠ uncovered class U-5 |
| `darkroom` copy | 0 | 0 | 0 | 1 | covered (F-3 focus-pull) |
| `OPACITIES` / `opacity` counts & CSS | 0 | 0 | 0 | 4+2 | KEEP per map (valid optics; verified present FUN:90,134,146,324) |

Census artifact notes:

- Pattern collision: case-insensitive `"X-RAY DEPT"` also matches the phrase **"X-Ray depth"**
  (the depth surface nickname) at SPEC:908 and HQ:67. Those are plain brand substitutions
  ("Lens depth"), NOT header art. The only true header-art `X-RAY DEPT.` is **FUN:122**.
- No camelCase `XRay` and no unhyphenated upper `XRAY` tokens exist anywhere — no identifier-shape risk from case variants.

---

## 2. Covered classes (mechanical substitution, per map)

| Class | Map target | Files/lines |
| --- | --- | --- |
| Display brand `Skill X-Ray` / prose `X-Ray` | Skill Lens / Lens | All files; see §4 line lists |
| Title lines `# Skill X-Ray — …` | `# Hermes Skill Lens — …` | SPEC:9, PLAN:3(?), HQ:5(title), FUN title block |
| CLI verb `xray <verb>` (+ `hermes xray`) | `lens <verb>` | SPEC:42,72,204,486–519,539–553,567,576–580,606,619,623,631,640,672–673,693,797–800,860,865; PLAN many; FUN many; HQ:98,105,117,126,160 |
| Slash `/xray` (incl. `/xray scan`, `/xray report`, `/xray explain --llm`) | `/lens` | All files (see raw lists) |
| Repo `hermes-xray`; install `<owner>/hermes-xray` | `hermes-skill-lens` | PLAN:21,33,61,241,288,292 |
| Import/package `xray_plugin`; `xray/` pkg dir | `skill_lens`; `lens/` | SPEC:8,11; PLAN:21,50–51,61,150,292; HQ:27(—),55,57 |
| Plugin key/manifest `xray`, `plugins.entries.xray.settings`, `register_command("xray")`, `plugins enable xray` | `lens` | SPEC:11,436,493,895; PLAN:23,66,292ff; FUN:75; HQ:35,57 |
| Registry/dist `skill-xray` | `skill-lens` | SPEC:11; HQ:55,57,59 |
| Rule IDs `XRY-*` (NET-011, MAN-004, ENG-000, OBS-002, SHL-007, `community/<pack>/XRY-…`) | `LNS-*` | SPEC:215–216,240,418,451–453,625,662–668,673,689–691,775; PLAN:22,75,284,315 |
| `ctx.llm` purpose `"xray-triage"` | `"lens-triage"` | SPEC:745 |
| Tagline "An X-ray, not a bouncer.…" | "A lens, not a bouncer.…" | SPEC:9(TAGLINE block) |
| Header art `SKILL X-RAY` banners | `SKILL LENS` | SPEC:655(+one-liner banner), FUN mockups |
| Voice key `radiology` → `microscopy` (flags, tables, prose mentions) | mechanical key rename | SPEC:34?,511,789,795,914; PLAN:222; HQ:143,148,151,171; FUN:75,76,88 |
| Fluoroscope Sweep (F-4) → Optical Sweep | same mechanics | FUN:181,188,351; SPEC:799 |
| F-8 codenames Röntgen/Langevin/Hounsfield → Leeuwenhoek/Newton/Fresnel | optics pioneers | FUN:296,300,301 (+heading 296 retitle) |
| F-3 DEVELOPING/darkroom/film-fixing copy → FOCUSING/focus-pull | same ≤2 s skippable mechanics | FUN:155,156,165 |
| Header art `X-RAY DEPT. · RADIOGRAPHIC EXAM` → `LENS LAB · OPTICAL EXAM`; `RADIOLOGIST:` field → `OBSERVER` | keep PATIENT/EXAM | FUN:122, FUN:45(field label) |
| Share-card plates film/blueprint/phosphor/print; OPACITIES count line; grade stamps; PARTIAL EXPOSURE framing; PATIENT/EXAM fields; film-grain typography; cadaver-under-the-lamp principle (FUN:30) | KEEP | verified present, no edits |
| Whitelisted history: v0.3 draft heritage mentions, new Appendix A changelog entry, R6 recorded decision history | DO NOT rename inside history | HQ:55–59 rewritten per instructions (history preserved within rewrite); AWS X-Ray / Xray-core collision rationale stays as R6 history |

---

## 3. UNCOVERED CLASSES (flagged — map does not cover; owner/applier call needed)

- **U-1 · `sxr` console-script alias** (SPEC:740, PLAN:335, HQ:57-inside-R6). Map defines binary,
  slash, import, repo, rule-prefix, registries — but no replacement for the future standalone PyPI
  alias `sxr` (analog of xray→sxr would be lens→? e.g. `skl`, or drop the alias). Needs an explicit call;
  note it appears inside R6's text being rewritten, so the rewrite must either rename or drop it.
- **U-2 · Config/state path namespaces**: `.xray/policy.toml`, `.xray/baseline.toml`, `.xray/rules/`,
  `$XDG_CONFIG_HOME/xray/policy.toml`, `~/.config/xray/rules/`, `<HERMES_HOME>/plugin-data/xray/{reports,jobs.json,watch-state.json,cards}`,
  `plugin_data_dir("xray")`.
  Lines: SPEC:437,442,464–465,529,561,617,761; PLAN:23,25,123,283–284,324; FUN:75,112.
  Implied by plugin-id rename (→ `.lens/…`, `plugin-data/lens/…`) but not enumerated in the map; touches
  on-disk layout so should be stated explicitly (semantics freeze says numbers/vectors unchanged — file
  paths are skin, but baseline/policy filenames are user-visible contract).
- **U-3 · Machine-output schema keys containing xray** (SPEC:223 `{xray_version,…}` `_meta` sidecar;
  SPEC:716 `properties.xray.score/.grade/.verdict`; SPEC:717 `partialFingerprints.xrayPrimaryFingerprint`;
  SARIF `"tool": {"name": "xray"}` SPEC:163). Not in the map; renaming changes the JSON/SARIF output
  contract bytes (tension with semantics freeze / golden tests) — decide rename-to-`lens*` vs keep-as-versioned-compat.
- **U-4 · Prose metaphor word "radiograph/radiographic" + radiology-family phrases outside header art
  and voice key**: SPEC:34 ("radiology-report-style readouts"), SPEC:606 ("full radiograph"),
  SPEC:652 ("Radiology-report language"); HQ:117 ("full radiology panel"), HQ:126/131/134 (flagship
  share-card plate labeled "**Radiograph** (dark film)" — collides with the plates-whitelist which keeps
  film|blueprint|phosphor|print but Q9 names the default face "Radiograph"), HQ:130 ("the radiology identity");
  FUN:43 ("radiology-department visual language"), FUN:111 ("dark-radiograph-vs-sober-print default"),
  FUN:118 ("radiographic negative"), FUN:313 ("Real radiology departments staple…").
  Map gives migration direction (radiology→optics) but no replacement term (photograph? micrograph? optical negative?).
- **U-5 · F-3 demo flag `--develop`** (FUN:153,162,350): coupled to F-3's film-developing→focus-pull
  rename but new flag name unspecified (`--focus` presumed).
- **U-6 · FUN naming-history rows vs live principles**: FUN:43 sentence "**Keep the name `X-Ray`**…" is
  live principles text now contradicting the authoritative decision — needs semantic rewrite (not mechanical);
  brainstorm-table rows "X-Ray Vision" (FUN:55 area) / "Bone Scan" (FUN:56) are naming-rejection history —
  map doesn't say whether they stay as history (recommended: keep rows, mechanically swap embedded
  command refs like `xray bones`→`lens bones`).

---

## 4. METAPHOR-EDIT line list (wording changes beyond plain token substitution)

- **SPEC.md**: 34 (radiology-report-style readouts), 606 (full radiograph), 652 (Radiology-report language),
  799 (fluoroscope sweep → Optical Sweep wording).
- **PLAN.md**: none beyond mechanical (line 222 is the voice-key rename radiology→microscopy).
- **HARD_QUESTIONS.md**: 117 (radiology panel), 126 (plate descriptor "radiograph dark-film" + prose),
  130 (radiology identity), 131 ("Radiograph (dark film)" row), 134 ("Radiograph default" recommendation).
  (R6 55–59 rewrite is directed by the map, not counted here.)
- **FUN.md**: 30 (keep — lamp/cadaver frame stands; listed as reviewed-no-change), 43 (principle rewrite +
  radiology-department language), 45 (RADIOLOGIST→OBSERVER art), 58 (Radiologist character row → Observer),
  76 (voice sample rationale wording), 88–92 (voice block: header key → microscopy; line 90 opacity KEEPS;
  line 92 "follow-up imaging" → "higher magnification"), 111 (plate default wording), 118 (radiographic negative),
  122 (header art LENS LAB · OPTICAL EXAM), 153/155–156/162/165 (F-3 focus-pull copy incl. `--develop`),
  181/188/351 (F-4 Optical Sweep + "as if developing" wording), 247/260 area (`xray xray`→`lens lens` gag copy
  reads fine after substitution), 296–301 (F-8 codenames + heading retitle), 313 (film-jacket provenance wording).

Mechanical-only hotspots (for the applier's convenience): SPEC §11 verb table 508–519, one-liners 544–553,
doctor §11.9 631–640, panels 655–694, exit codes 860–865; PLAN phase/checklist lines; FUN demos 193–281.

Changelog insertion point for the single required entry: SPEC.md **Appendix A at line 869** (add exactly one
owner-rename entry dated 2026-08-23; do not touch existing entries).

Do-not-touch confirmed: everything under `/root/xray-spec/.analysis/`; R6 history content (within its directed
rewrite); vectors A–G, weights, ceilings, exit codes, phase math — none of the metaphor lines above alter any number.
