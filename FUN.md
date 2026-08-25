# FUN.md — Personality & Creativity Module (Skill Lens)

> ## ⚠️ HARD RULE — READ FIRST
>
> **Nothing in this document may change default `lens` scan output.**
> Default findings, severity labels, grades, exit codes, JSON schema, and plain-text reports are
> permanently sober and byte-stable. Every feature below is gated behind an explicit flag, config
> boolean, hidden subcommand, or build-time convention. If a change here would be visible in an
> unaudited `lens ./skills` run, `lens --json`, CI logs, or exit codes — it does not ship.
>
> **Enforcement:** a CI snapshot test renders every finding through every voice preset and asserts
> identical severity, counts, facts, and exit codes. A diff here is a release blocker, not a nit.
>
> **Hermes-native note (reframe amendment):** all features below translate to the plugin context —
> `/lens <verb>` slash commands render with the same rules as CLI output; easter eggs (`bones`,
> self-scan) exist as both slash invocations and CLI verbs; nothing may appear in
> lifecycle/post-tool-call fast-path one-liners except the sober summary line. Slash/chat surfaces
> receive plain strings — no ANSI, no motion: F-3/F-4 are silently inert there; everything else
> renders as Unicode prose inside fenced blocks.

---

## 0. Governing Taste Laws (apply to every feature below)

1. **Opt-in only.** Fun lives behind flags, config, or themed modules. Never in default output.
2. **Data invariance.** Themes change *prose and visuals*, never findings, severity, grades,
   exit codes, or JSON. Automation surfaces are permanently sober.
3. **Deterministic.** No date-triggered pranks, no April-Fools behavior. Same repo → same flavor,
   every run. Nondeterminism kills trust in a diagnostic tool.
4. **Laugh at the codebase-as-patient, never the developer.** The repo is the cadaver under the
   lamp, not the person who wrote it.
5. **Motion & noise gated.** Animation requires interactive TTY **and** explicit opt-in.
   Everything respects `NO_COLOR`, `--plain`, and reduced-motion conventions.
6. **The four-way test** (every feature must pass all four): opt-in ✓ · data-invariant ✓ ·
   deterministic ✓ · laughs at code, not coders ✓.

---

## 1. Naming & Mascot Direction

### Recommendation (pick one — this is it)

**Keep the name `Skill Lens`; adopt an *optics-lab visual language* instead of a mascot.**
The product's personality is delivered by consistent framing — lightbox-style panels, exam-field
headers (`PATIENT:` / `EXAM:` / `OBSERVER:`), monospace "typed report" typography — plus dry
clinical understatement in themed prose. Persona over puppet.

Why: a visual language scales across every surface (terminal, chat renders, docs) without aging,
licensing, or Halloween-season drift, and it reinforces rather than fights the lens metaphor.

### Alternates considered (kept on the shelf, deliberately not chosen)

| Candidate | Verdict | Reason |
| --- | --- | --- |
| **Lens Vision** | Rejected | Toy-store vibe; overpromises ("vision" implies seeing everything). |
| **Bone Scan** (as product name) | Rejected as name, **reused as subcommand** (`lens bones`, §4/F-6). |
| Skeleton mascot | Rejected | Halloween connotation risk; dates poorly. |
| Observer character ("Dr. …") | Rejected | Written lore ages badly and confuses newcomers; implied persona via prose tone works better. |
| Airport-scanner motif | Rejected outright | Surveillance/invasive connotation — dead on arrival for a tool that inspects people's code. |

---

## 2. Feature Mini-Specs

Build order: **F-1 → F-6** first (highest delight-per-cost, trivially gated); **F-3, F-5**
next (more authoring effort); **F-4** once watch mode exists; **F-7–F-8** as garnish.

Effort scale: **S** ≤ half day · **M** = 1–3 days · **L** = 3–5 days.

---

### F-1 · Autopsy Narrative Voice Presets — effort **M**

- **Owning module:** `voices` (rendering layer only)
- **Trigger / flag:** `--voice clinical|microscopy` in v1 (`noir` documented but deferred to v1.x, usage-gated — see HARD_QUESTIONS O4), or the `voice` key in `.lens/policy.toml` / plugin settings (`plugins.entries.lens.settings`).
  Plugin form: `/lens autopsy <name> [--voice clinical|microscopy]` — microscopy reads fine as chat
  prose; noir stays deferred there too.
  Default is `clinical` (current sober rendering — unchanged).
- **What it is:** Narrative presets that re-render the same findings data. Cap at **three**
  forever — more is maintenance debt and diminishing returns.
- **Sample output** (identical finding, three voices):

```
# clinical (default — unchanged today)
[HIGH] src/auth/session.ts:41 — token compared without constant-time equality;
       timing side channel possible.

# microscopy (dry lab dictation — understatement IS the joke)
EXAM: auth module. On examination, error handling demonstrates unremarkable
quality overall. However, a region of increased opacity is noted at
session.ts:41, where token comparison proceeds without constant-time
equality. Recommend higher magnification. Severity: HIGH.

# noir (forensic-pathologist camp)
Time of death: v2.3.1. Cause of death: an unresolved TODO, left bleeding at
session.ts:41. Whoever compared that token without constant-time equality
wanted it to look like an accident. It wasn't. Severity: HIGH.
```

- **Taste guardrails:** Understatement over punchlines — the drier, the funnier, the safer.
  Severity words (`HIGH`/`CRITICAL`) are rendered verbatim in every voice. Never joke about a
  CRITICAL finding's content beyond tone. Noir gets exactly one campy flourish per finding, max.
- **Invariance test:** snapshot test asserts severity/facts/counts identical across all voices.

---

### F-3 · Grade Stamp Reveal — effort **S–M**

- **Owning module:** `report`
- **Trigger / flag:** `--focus` flag (interactive TTY only; silently inert otherwise).
  Default behavior today — instant grade print — is unchanged.
- **What it is:** The run's single emotional peak. On completion, the grade pulls into focus like
  a lens racking onto its subject: characters resolve out of blur over ≤ 2 seconds. Any keypress
  skips immediately. Never delays non-TTY runs; capped at 2 s so the tenth run stays delightful
  instead of embarrassing.
- **Sample output:**

```
$ lens ./skills --focus
Examining… 47 skills · 12 findings

  FOCUSING ░░▒▒▓▓  (any key to skip)            ← ~2 s focus pull

  ┌─────────────────┐
  │     GRADE B     │                            ← static inspection-stamp
  │   FIT FOR       │                              treatment; this frame is
  │    SERVICE      │                              what non-TTY runs get instantly
  └─────────────────┘
```

- **Taste guardrails:** One flourish per run, at the one moment users already care about. Skippable
  always; disabled automatically under `NO_COLOR`, `--plain`, piped output, CI — and equally inert
  on `/lens` surfaces, where a returned string can't animate, so slash runs get the static stamp
  frame only. The drama is in restraint — if anyone proposes sound effects here, the answer is no.

---

### F-4 · Watch Mode Optical Sweep — effort **M** (after `watch` exists)

- **Owning module:** `watch`
- **Trigger / flag:** `--animate` on top of `lens watch`; interactive TTY only. Default watch mode
  shows a static spinner at most. CLI-TTY-only by design: `/lens watch status` and every pull
  surface get static text, never animation.
- **What it is:** While re-examining changed skills, a horizontal beam sweep travels down the file
  list like an optical pass; refreshed entries appear as if coming into focus. Motion lives entirely in
  progress indication — results render identically to a normal run once done.
- **Sample output:**

```
$ lens watch ./skills --animate
 watching · 47 skills · q to quit
 ├─ skills/auth/          ✓ clean
 ├─ skills/hooks/         ⟪ beam ⟫ re-examining…     ← sweep marker moves
 ├─ skills/retrieval/     ◌ queued
 └─ …
 last exam 12 s ago · 0 regressions
```

- **Taste guardrails:** Honors reduced-motion conventions; falls back to the static spinner when
  unavailable. Frame budget ≤ 10 fps. The moment motion costs more than one screen-row of state,
  cut it — gimmick-fatigue sets in fastest here of any feature in this doc.

---

### F-5 · Playground Fiction: A Named Patient — effort **L**

- **Owning module:** `playground`
- **Trigger / flag:** ships as sample data — `lens playground` copies it locally (`/lens playground`
  returns the same copy instructions, as a one-liner on chat); contained entirely outside real
  usage paths.
- **What it is:** A deliberately sick fictional repo that exercises **every** finding type, wrapped
  in a light story that makes learning memorable: *"St. Barlow's General — patient-records system,
  est. 1998, still somehow in production."* Docs walk learners through examining the patient
  finding by finding. The same artifact doubles as the integration-test fixture.
- **Sample excerpt:**

```
$ lens playground && cd st-barlows-general && lens .
EXAM: st-barlows-general
PATIENT HISTORY: patient-records system, est. 1998. Presented with chronic
pain in dependencies. Prior treatments undocumented.

  [CRITICAL] admissions/checkin.py:88 — SQL assembled by string concatenation;
             patient records readable by anyone with a username.
  ...
```

- **Taste guardrails:** The fiction mocks *the codebase*, never the imaginary original authors'
  competence beyond affectionate period detail. All "patient data" is obviously synthetic. Near-
  zero taste risk precisely because it's isolated from real repos — the cost is honest authoring
  labor: convincingly bad code takes longer to write than good code.

---

### F-6 · `lens bones` & Self-Lens Easter Eggs — effort **S**

- **Owning module:** CLI core (hidden subcommands)
- **Trigger / flag:** two hidden commands plus their slash twins; never listed in help text beyond a
  wink (`Try: lens bones`). No flags. `/lens bones` returns the chart inside one fenced block
  (≤1900 chars) — the one format every platform chunker preserves intact; the self-scan twin's
  grade line stays sober-formatted wherever it lands.
- **What they are:**
  - `lens bones` — prints the project's module tree as an annotated anatomical chart.
  - `lens lens` — runs Skill Lens on its own codebase and prints its own grade. Permanent dogfooding
    pressure disguised as a gag.
- **Sample output:**

```
$ lens bones
SKELETON · my-skill-pack
   cranium ──── core/          cognition: engine.py (all decisions originate here)
   spine   ──── modules/       7 vertebrae — one hairline fracture: hooks/ (cyclic import)
   ribs    ──── policies/      cage protecting the vital organs
   femur   ──── scoring/       load-bearing; do not amputate casually
   appendix───  legacy/        vestigial; candidate for removal

$ lens lens
Self-examination complete. GRADE A− — the instrument is fit to inspect others.
(Yes, we ran it on ourselves. That's the point.)
```

- **Taste guardrails:** Read-only, self-contained, deterministic. Joke exit codes forbidden — both
  commands exit 0 on success like anything else. If `lens lens` ever finds a real critical in
  Skill Lens itself, the output prints the finding straight, no joke.

---

### F-7 · Canary Status Line Lore — effort **S** *(post-v0.9 scope — requires the canary tripwire subsystem; lore text reserved now, feature lands with it)*

- **Owning module:** `canary`
- **Trigger / flag:** one config boolean (`canary.personality: true`). Default off.
- **What it is:** Exactly **one status line and one glyph**, ever. When tripwires are quiet, the
  canary is singing; when a tripwire fires, silence. That's the entire lore budget — implied lore
  ages well, written lore confuses newcomers. No backstory docs, no second glyph, no third phrase.
- **Sample output:**

```
$ lens canary status            # personality: true
🐤 canary singing · no tripwire fired since 2026-02-01

# after a tripwire fires:
⚠ canary silent · tripwire tripped: pre-commit hook removed — see canary report
```

- **Taste guardrails:** The line must remain *informative* (it states tripwire state and date) —
  personable-but-useful is why it earns existence at all. With `personality: false` (default) the
  line reads plainly: `tripwires: OK (0 fired)`. It may surface anywhere canary state is legitimately
  reported (status pulls, doctor) precisely because it states facts; lifecycle/post-tool-call
  fast-path one-liners stay exempt regardless of this config — those are permanently sober.

---

### F-8 · Leeuwenhoek Release Codenames — effort **trivial**

- **Owning module:** build/release process (internal metadata only)
- **Trigger / flag:** none — changelog/tag convention, invisible unless you go looking.
- **What it is:** Internal releases named for optics pioneers: v0.9 **Leeuwenhoek** (microscopy),
  v1.0 **Newton** (Opticks), v1.1 **Fresnel** (wave optics). Pure team fun; the cheapest possible personality.
- **Taste guardrails:** Zero runtime surface, zero user-visible effect. Names never appear in
  `lens --version` output (that stays the plain release number, e.g. `lens 0.9.0`).

---

### F-2 · Share-card poster themes — ⛔ CUT (HQ O3, owner 2026-08-23)
### F-9 · Film-jacket index card — ⛔ CUT (HQ O3, owner 2026-08-23)

*(Both removed outright; see §3 rejection record. Numbers retired — not reused.)*

---

## 3. Explicitly Rejected (do not revive without new evidence)

- **Share cards / exportable posters (former F-2 SVG poster themes & F-9 film-jacket index card)**
  — rejected outright by owner arbitration 2026-08-23 (HARD_QUESTIONS O3): an overfeature,
  unnecessary. No SVG posters, no plates or themes, no `/lens card`, no `--card`/`--card-text`
  flag, no `card_theme` setting — in v0.9 or any release. Lens renders stat lines and reports on
  its own surfaces; it does not manufacture shareables. Rejected outright — not deferred, nothing
  to revisit; only the owner editing HARD_QUESTIONS.md revives it.
- **Airport-scanner mascot** — surveillance connotation; hostile framing for an inspection tool.
- **Date-triggered pranks / April Fools modes** — nondeterminism; poisons CI trust.
- **Sound effects** — universally regretted in terminals.
- **Obituary sections for deleted code** — mocks someone's recent decisions; stings, violates Law 4.
- **Product renames** — identity churn, zero payoff. *(naming half superseded by the owner's
  2026-08-23 rename to the optics identity — HARD_QUESTIONS R6; mascot-rejection half stands).*
- **Deep canary backstory documents** — written lore ages badly; implied lore doesn't (see F-7).

## 4. Compliance Checklist (per feature, at review time)

| # | Feature | Opt-in | Data-invariant | Deterministic | Code-not-coder | Est. |
| --- | --- | --- | --- | --- | --- | --- |
| F-1 | Voice presets | ✓ flag/config | ✓ snapshot-tested | ✓ | ✓ | M |
| F-3 | Grade stamp reveal | ✓ `--focus`, TTY | ✓ | ✓ | ✓ | S–M |
| F-4 | Optical sweep | ✓ `--animate`, TTY | ✓ | ✓ | ✓ | M |
| F-5 | Playground patient | ✓ sample data | n/a (fixture) | ✓ | ✓ | L |
| F-6 | `bones` / `lens lens` | ✓ hidden cmds | ✓ read-only | ✓ | ✓ | S |
| F-7 | Canary status line | ✓ config bool | ✓ | ✓ | ✓ | S |
| F-8 | Release codenames | ✓ internal | ✓ | ✓ | ✓ | trivial |

*Plugin-port note:* F-1, F-5, F-6 translate directly to `/lens` verbs; F-3/F-4 remain CLI-TTY-only
and are silently inert on slash surfaces; F-7 never enters fast-path one-liners.
