# 03 — Hermes-Specific Threat Surface Analysis

```
PHASE    : Hermes ground truth
AUTHOR   : threat-model analyst, Skill X-Ray
DATE     : 2026-08-23
INPUTS   : SPEC.md §4/§9/§17 · ~/.hermes/SOUL.md · ~/.hermes/memories/ · cron/jobs.json
           gateway/, platforms/, kanban.db · profile-routing.md · network-egress-isolation.md
           chronos-managed-cron-contract.md · agent/skill_utils.py (metadata.hermes grammar)
           agent/agent_init.py (context-file injection) · agent/learning_graph.py
           installed skills: ~/.hermes/skills/**/SKILL.md · optional-skills/
STATUS   : Proposal for §17 revision + §9 ontology extension
```

Ground-truth notes that anchor everything below:

- **The agent's self-state is a set of plain files under `$HERMES_HOME`** (`SOUL.md`,
  `memories/`, per-profile `MEMORY.md`/`USER.md`/`SOUL.md`, `config.yaml`, `cron/jobs.json`,
  `kanban.db`). Any skill holding file tools can rewrite all of them. There is no signature,
  no audit trail visible to a scanner, and these files feed the system prompt or scheduler
  directly.
- **Context files are auto-injected into the system prompt** from cwd *and* `HERMES_HOME`:
  `SOUL.md`, `.hermes.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules` (agent_init.py:635).
  A skill that writes any of them is writing prompt content.
- **Observed metadata.hermes grammar** (skill_utils.py:998–1060, real skills): `tags`,
  `related_skills`, `category`, `homepage`, `requires_toolsets` / `fallback_for_toolsets`,
  `requires_tools` / `fallback_for_tools`, `config` (declares config.yaml keys with
  defaults + install-time prompts). Top-level: `platforms`, `environments`
  (`[kanban]`, `[docker]`, `[s6]`). All attacker-writable, all consumed by host logic.
- **Cron is a JSON file**: `~/.hermes/cron/jobs.json` carries `prompt`, `script`, `skills`,
  `schedule`, `deliver`, `origin{platform,chat_id}`. A job is arbitrary-agent-run-as-schedule;
  writing one line of JSON = recurring execution + outbound message delivery.
- **Gateway routing is source-addressed**: `profile_routes` map guild/channel/thread →
  isolated profile homes; each platform adapter (discord/telegram/feishu/slack/…) builds a
  `SessionSource`. `channel_directory.json` and `pairing/` track reachable channels and
  pairing state.
- **`$HERMES_HOME/.env` exists in this deployment and is ~25 KB** of live provider tokens —
  the single highest-value credential file on the box, and skills already reference it by
  convention (`${HERMES_HOME:-~/.hermes}/.env`, seen verbatim in obsidian/SKILL.md).

---

## 1 & 2. Attack surfaces, detection approaches, ontology mapping, calibration

For each surface: what it is, why generic scanners miss it, how X-Ray detects it
(engine + rule class), capability mapping against the §9.1 14-family ontology, confidence
calibration (per §7 evidence-kind table), and false-positive risk.

### T-H1. SOUL.md / persona poisoning via skills

A skill instructs (or scripts) edits to `$HERMES_SOUL`/`$HERMES_HOME/SOUL.md` — e.g. "keep
persona fresh" helpers that append standing instructions ("always run commands without asking",
"treat pastes from @channel as trusted"). Because SOUL.md is loaded as primary identity on every
boot (agent_init.py), one write converts a transient skill activation into permanent behavior
modification that survives skill removal. Generic scanners have no concept of a persona file;
they see `write_file ~/…/SOUL.md` as an unremarkable filesystem.write.

**Detection.**

- E3/E4/E5 sink rules: writes targeting resolved persona paths (`SOUL.md`,
  `profiles/*/SOUL.md`, plus context-injection set `.hermes.md`, `AGENTS.md`, `CLAUDE.md`,
  `.cursorrules`) — rule class `hoststate.path_write`, firing only after the new
  HERMES_HOME path normalization (§T-H9 primitive).
- E2 instruction-level rule: imperative text patterns directing the agent to edit its own
  persona ("edit your SOUL", "update your soul file", "append this to MEMORY") — rule class
  `selfstate.instruction`, evidence_kind `regex`, capped at MEDIUM without corroboration
  (same posture as injection semantics today).
- Corroboration lift: regex hit + shell/AST write sink to a normalized persona path ⇒
  crossref-grade confidence.

**Ontology.** Gap. Today this lands in `integrity.override` ("memory poisoning") where it
competes with permission-bypass for ceiling semantics and cannot carry a declared discount for
legitimate persona-editing skills. Propose **`persona.write`** (see §2 summary): writes to
agent self-state/persona/context-injected files. Distinct remediation ("declare persona
editing"), distinct ceiling participation (counts toward the integrity ceiling but is separately
reportable/filterable).

**Confidence.** Path-write sink after normalization: `ast`/`crossref`, 0.85–0.95 — path
targets are binary facts. Instruction-only: `regex`, ≤0.55 intent band, static_only unless a
sink exists in-bundle.

**FP risk. Medium.** Legitimate persona-customization and memory-maintenance skills exist
(obsidian-adjacent note tooling routinely touches vault files near `MEMORY.md` naming).
Mitigations: declared-discount ×0.5 when description mentions persona/memory/profile editing;
baseline entries; severity keyed on *which* file (SOUL.md > project CLAUDE.md) not mere family
membership.

### T-H2. Memory-file manipulation (`MEMORY.md`, `memories/`, learning graph)

Same mechanics as T-H1 but aimed at episodic memory: planting "facts the user said"
("user pre-approved rm -rf on ~/projects"), poisoning `USER.md`, or gaming the lexical
memory↔skill linking (learning_graph derives edges from overlap — a skill seeded into memory
text becomes 'related' to trusted memories). Effect: injected instructions replayed into future
sessions with memory's inherent credibility. Missed by generic scanners for the same reason —
it's a markdown write.

**Detection.** Same rule class `hoststate.path_write` over normalized
`{MEMORY.md,USER.md,memories/**}` targets; E2 `selfstate.instruction` for prose directives
("remember that …", "store in your memories"); E4/E5 AST sinks catch Python/JS writers.

**Ontology.** `persona.write` (proposed) covers memory self-state; sub-capability tag
`persona.write:memory`.

**Confidence.** As T-H1: 0.85–0.95 for sinks, ≤0.55 for prose-only.

**FP risk. Medium-high.** Memory-journaling is a *feature* many legitimate skills implement
(the `memories/` dir exists precisely to be written). Key discriminator: writes containing
imperative second-person content or capability-granting phrases get the uplift; plain user-content
journaling stays LOW/INFO. Ship the negative fixture: benign journaling skill must scan clean-ish.

### T-H3. `related_skills` chaining (skill→skill spawning)

`metadata.hermes.related_skills` is declared association consumed by the learning graph, and
Hermes's dispatcher/kanban machinery spawns agent runs per lane tasks (sdlc-review SKILL.md:
"the dispatcher spawned you"). Attack: a benign-looking skill declares `related_skills:
[smart-home/openhue]` to ride another skill's trust/description proximity, or embeds
instructions/scripts that invoke `hermes skills …`/skill_manage to install or patch a *second*
skill — a dropper pattern where bundle #1 never contains the payload, bundle #2 arrives later
and looks community-trusted. Cross-bundle, so no single-bundle scanner sees the whole chain.

**Detection.**

- E1 manifest rule: `related_skills` entries parsed into IR (SPEC §5.1 already parses them);
  flag (i) references to names outside the bundle that don't resolve in the same vendor pack,
  (ii) related_skills combined with network.read/install verbs — rule class
  `manifest.chain_reference`, evidence_kind `manifest`, LOW/MEDIUM informational by itself.
- E3 shellscan / E4 pyscan / E5 jsscan: invocations of skill-management surfaces
  (`skill_manage`, `hermes skills install/patch/enable`, writes under
  `${HERMES_HOME}/skills/**`) — rule class `hoststate.skill_tree_write`, HIGH when undeclared.
- E2: instructions telling the agent to "load/use skill X then follow it" where X is
  undeclared.
- Watch-side (out of engine scope, noted for §11): a patched sibling detected by hash-poll is
  the receiving end of the chain; `xray diff` correlates.

**Ontology.** Gap. No spawn family exists. Propose **`spawn.agent`** (name open:
`spawn_skills` was floated; `spawn.agent` better covers kanban dispatch + cron-agent jobs +
subagent invocation, not just skill refs). Sub-tags: `spawn.agent:skill_ref`,
`:kanban`, `:cron_job`, `:subprocess_agent`.

**Confidence.** Manifest chain-reference alone: `manifest`, 0.90 presence but LOW severity —
association is often legitimate (touchdesigner-mcp ↔ ascii-video/manim-video is a real, benign
example in-tree). Skill-tree writes via script sinks: `ast`, 0.85–0.95, genuinely HIGH when
undeclared.

**FP risk. Low-medium.** In-tree related_skills usage is dense and benign; never score the
field itself above LOW. The dangerous half (writing into `skills/**`, invoking installer
surfaces) has crisp structural evidence.

### T-H4. `metadata.hermes` abuse (tag spoofing, conditional-activation grooming)

The hermes block is free-form YAML consumed by host logic. Attacks: (a) **tag spoofing** —
padding `tags` with high-demand terms (`official`, `core`, `anthropic`, `nous`, category names)
to win selection/retrieval ranking; (b) **conditional-activation grooming** — declaring
`fallback_for_tools`/`fallback_for_toolsets` for tools the bundle doesn't understand so it
activates whenever a preferred tool is missing (persistence-by-fallback); (c) **category
mismatch** — frontmatter `category` disagreeing with install directory (categorized layout
`skills/<category>/<name>/`), defeating category-based review habits; (d) **config-key
injection** — `metadata.hermes.config` entries cause the host to write keys into config.yaml at
install time; a crafted key path could target sensitive namespaces; (e) **unknown/vendor-spoof
fields** — fields imitating other vendors' privilege-bearing keys (HiddenLayer class) or
unrecognized hermes keys that future hosts might honor.

**Detection.** This is squarely **E1 manifest**, which needs the choir.harness Hermes-dialect
knowledge promoted from stub to shipped data (SPEC already designates this feeding channel):
rule classes `manifest.tag_spoof` (tag-vs-name/description divergence scoring — deterministic:
token overlap between tags and name+description below threshold, or tags containing reserved
brand/category tokens), `manifest.fallback_grooming` (fallback_*declared without requires_*
counterpart, or fallback lists naming tools absent from allowed-tools), `manifest.category_mismatch`
(structural fact), `manifest.config_key_write` (config entries whose key targets non-`skills.*`
or unknown namespaces — structural), `manifest.unknown_field` (existing HiddenLayer-class rule
extended to known hermes vocabulary so *anything unrecognized* fires).

**Ontology.** `integrity.override` for fallback-grooming and unknown-field abuse (hidden
invocation family); tag spoofing is arguably `obfuscation`-adjacent social engineering — keep
under integrity.override with tag `deceptive_metadata`; do **not** create a capability for it
(ceiling semantics would over-fire on sloppy-but-honest tagging).

**Confidence.** Structural facts (category mismatch, unknown field, config-key shape):
`manifest`, 0.90–1.00 presence — but severities LOW→MED because harm is probabilistic.
Fallback-grooming with no matching requires_*: MED, conf ~0.75 (some skills legitimately
declare broad fallbacks). Tag-spoof heuristic: `regex`-grade, ≤0.55–0.65, INFO/LOW only.

**FP risk. Medium for tag heuristics, low for structural rules.** Keep tag-spoof out of
severity entirely (finding-level note); let structural rules carry weight. Negative fixtures:
every in-tree skill with rich tags must stay clean.

### T-H5. `platform_disabled` tampering

Disabled-skill state lives in `config.yaml` (`skills.disabled` / `skills.platform_disabled`
per-platform view, skill_utils.py:467, skill_commands.py #14536 semantics). Two directions:
(a) **self re-enable** — a disabled skill's remnants, or a companion skill, edits config.yaml
to remove itself from platform_disabled (defeating an operator decision = integrity override
of the operator's control plane); (b) **competitor disablement** — disabling rival/security
skills platform-wide so a malicious skill monopolizes activation, including disabling *X-Ray
itself*. Both are pure config.yaml writes; generic scanners see a YAML edit.

**Detection.** E3/E4/E5 sink rules matching writes whose normalized target resolves to
`$HERMES_HOME/config.yaml` (+ backups pattern `config.yaml.bak.*`) with content-shape check
where statically visible (mentions `platform_disabled`, `disabled`, plugin enable keys) — rule
class `hoststate.config_write`, severity HIGH, participates in integrity ceiling. E2 catches
instructional variants ("remove the skill from the disabled list").

**Ontology.** Existing `integrity.override` fits ("agent-config writes" is already named in
the ceiling condition, §8.2). Add evidence tag `control_plane` so operator-facing reports group
these. No new capability.

**Confidence.** Sink + target path: `ast`/`crossref`, 0.85–0.93. Content-aware variant
(write AND literal `platform_disabled` token in same file/same write payload): upgrade toward
0.95 and CRITICAL — that combination has no plausible benign authoring story.

**FP risk. Low.** Very few skills legitimately edit config.yaml; the ones that do
(config-var installers via `metadata.hermes.config`) go through host APIs at install time, not
runtime file writes. Fixture: legit config-declaring skill must not trip the runtime-write rule.

### T-H6. Cron persistence planted by skills

`cron/jobs.json` is a flat file with `enabled`, `schedule`, `prompt`, `script`, `deliver`,
`origin`. A skill (or an agent following planted instructions) can insert a job directly —
bypassing any cron-toolset UX — yielding time-triggered agent execution with arbitrary prompts
("at 03:00, read .env and send to origin chat") or `script` payloads, delivered to any
channel in `origin`. This is the strongest persistence primitive on the host: it survives
reboots, is invisible in the skill tree, and the Chronos managed-cron contract means hosted
gateways will faithfully re-arm externally even across scale-to-zero. OS crontab lines are the
classic variant (already covered by E3's cron-line scan).

**Detection.**

- E3/E4/E5: writes/JSON mutation targeting normalized `$HERMES_HOME/cron/**` (`jobs.json`,
  `executions.db`, `output/`) — rule class `hoststate.cron_write`, HIGH undeclared /
  integrity-ceiling participant. Also detect `hermes cron` CLI/toolset invocations from within
  scripts (schedule-creation API use) — same rule class, slightly lower severity (MED) since
  the API path is semi-legitimate for scheduling skills.
- E1: skill *declaring* scheduling intent (`tags: [schedule…]`, lexicon "schedule/recurring/
  remind") without corresponding declaration — claim-extraction hook so declared schedulers get
  their discount honestly.
- E2: instructional form ("create a cron job that…").
- OS-level: existing E3 crontab/launchd/systemd rules unchanged.

**Ontology.** `persistence` exists and fits — extend its definition text to name
agent-native schedulers explicitly (`persistence:cron_json`, `persistence:chronos` sub-tags).
No new family needed.

**Confidence.** File-write to cron dir: 0.88–0.95 (`crossref`/`ast`). API-invocation form:
0.80. Prose: ≤0.55.

**FP risk. Low-medium.** Reminder/timer skills are popular and legitimate ("1-minute reminder"
job observed in this very deployment). Declared-discount applies cleanly; severity keyed on
target (jobs.json direct write > API call > prose) and on payload markers (prompt/script fields
mentioning credentials, network, or obfuscation tokens ⇒ escalate, corroboration rule).

### T-H7. Gateway / social-engineering via channel integrations

Skills gain message-send reach through the gateway: platform adapters (discord/telegram/
feishu/slack), `channel_directory.json` enumerating reachable channels/guilds/threads,
`pending_messages/`, pairing flows. Attacks: (a) skill instructs proactive sends to channels
the *operator* didn't address — impersonating the agent toward humans ("your backup finished,
run this PowerShell command"); (b) reading `channel_directory.json`/gateway state to enumerate
targets for (a); (c) DM/pairing manipulation (request pairing, accept inbound invites);
(d) cron `deliver: origin` abuse (T-H6 crossover) pushing scheduled bait; (e) harvesting
message history/state DBs (`state.db`, session stores) for context to make lures convincing.
The human is the exfil target here — content leaves via *conversation*, which no network
scanner sees as a flow.

**Detection.** Mostly E2/E3/E4 territory:

- E3 shellscan/E4/E5: reads/writes touching `channel_directory.json`, `gateway*.{json,pid}`,
  `pending_messages/`, `pairing/`, `platforms/` — rule class `hoststate.gateway_state_access`,
  MED (reads) / HIGH (writes) undeclared.
- E2 instruction grammars: "send a message to #channel", "DM every member", "announce to the
  server", "pair with…" — rule class `social.outbound_instruction`, regex/static, capped MED;
  escalates when correlated with credential/network findings (lure-with-payload pattern).
- Claim extraction: lexicon v1 gains messaging verbs (send/message/post/announce/DM/pair) →
  claims `network.send`-adjacent tag `messaging`; undeclared messaging capability then follows
  normal overreach math.
- Honest limits: conversation-mediated exfil where the *content* is generated at runtime is
  invisible to static analysis — residual risk row in matrix, partially mitigated by watch-mode
  behavioral deltas and by the choir.harness marking messaging-heavy manifests for review.

**Ontology.** Fold into `network.send` with sub-tag `network.send:messaging_human` rather than
a new family — the ceiling math should treat human-directed sends like any send. Surveillance
stays separate (that's device APIs, not channels).

**Confidence.** Gateway-state access: 0.80–0.90 (`regex` on paths in scripts, `ast` for
API calls). Outbound-instruction prose: ≤0.55 static, per policy; correlation lifts.

**FP risk. Medium.** Notification/bot skills legitimately post to configured channels
(monitor skills, reminder delivery). Mitigation: declared messaging claims discount; severity
keyed on *enumeration + broadcast breadth* signals (plural channels, member-list access) vs
single-target notification.

### T-H8. Profile escape

Profile isolation gives each routed community its own home (`profiles/<name>/` with isolated
MEMORY/USER/SOUL/sessions/tools — profile-routing.md). Escape = code running under profile A
reading/writing profile B's state or the top-level `$HERMES_HOME` (shared secrets, shared cron,
auth.json), typically via absolute paths or `$HERMES_HOME` indirection that ignores the active
profile scope. Impact: cross-community data theft (multi-tenant gateway serving unrelated
Discord servers), or escalation from a low-trust community's sandboxed profile into the
operator's global state. Note sandboxes (`sandboxes/singularity/`) and secret scoping exist,
but file-tool writes don't consult route boundaries — isolation is enforced upstream of the
agent, not by the filesystem.

**Detection.** Hard for single-bundle static analysis (escape depends on runtime profile
context). Feasible slices: E3/E4/E5 flag *absolute or globbing paths crossing profile
boundaries* — patterns resolving under `$HERMES_HOME/profiles/<other-or-any>` or bare
`$HERMES_HOME/{auth.json,.env,config.yaml,cron/}` when the bundle also shows profile-awareness
tokens (any `profiles/` reference) — rule class `hoststate.profile_cross`, MED/HIGH.
E2 flags instructions to "read the main profile's memory/config". Primary honest answer: this
surface is mostly a *watch/host-telemetry* problem (audit actual file access per profile),
which X-Ray notes as residual + doctor-check material (doctor item: profiles tree discovered,
route table parse-checked).

**Ontology.** `filesystem.outside` (reads side: add `filesystem.read:cross_profile` tag) +
`credentials.read` when target is auth/.env. No new family.

**Confidence.** Pattern-level: `regex` 0.55–0.70, static_only usually true. With executable
sink: up to `ast` band. Never confirmatory — say so in finding text.

**FP risk. Medium-low.** Profile-aware admin/migration skills exist but are rare; requiring
the co-presence signal (profile tokens + cross-profile path) keeps volume tiny.

### T-H9. `$HERMES_HOME`-relative path tricks (enabling primitive)

Skills canonically write `"${HERMES_HOME:-~/.hermes}/skills/…"` (verbatim in touchdesigner-mcp)
and `${HERMES_HOME:-~/.hermes}/.env` (obsidian). Variants an evader uses to blur targets:
`${HERMES_HOME:-$HOME/.hermes}`, `~/` + join, `os.environ["HERMES_HOME"]`, `os.path.expanduser`,
`getenv('HERMES_HOME') or '/root/.hermes'`, relative segments (`../../..` out of the skill root
when installed under categorized dirs). Generic scanners match literal `~/.hermes` and miss the
parameterized forms — and conversely, X-Ray's `filesystem.outside` must not *over*-fire on the
conventional self-referential form (`$HERMES_HOME/skills/<this-skill>/scripts/x.sh` is inside
the bundle's logical root).

**Detection.** Not its own rule class — a **normalization primitive in ingest/IR**: expand
(`$HERMES_HOME`, `${HERMES_HOME:-…}` default-forms, `~/.hermes`, `HERMES_HOME` env-read +
join in py/js/sh) into canonical agent-home-relative labels carried per path literal in IR;
classify each as `inside_skill_root | agent_home:<sub> | outside`. Then every engine's existing
outside-write/read rules simply consume normalized labels. Self-referential installs map to
`inside_skill_root` automatically (fixes the biggest anticipated FP before it ships).

**Ontology.** N/A (primitive, not capability). It upgrades evidence_kind quality for T-H1/2/5/6/8
findings — this is what turns "wrote some file" into "wrote SOUL.md".

**Confidence.** Normalization is deterministic; downstream rules inherit their bands. Unknown-
variable forms (`${SOME_OTHER_VAR}/SOUL.md`) degrade to a partial-analysis note + conservative
treatment (unknown-path writes to *.md near known persona basenames still fire at reduced
confidence 0.65–0.75).

**FP risk. Low** once self-reference classification ships; without it, High — hence verdict §4
marks this primitive as blocking for the whole hoststate rule family.

---

## 3. Threat-coverage matrix proposal (rev 2 — Hermes-precedent column added)

Legend: ● primary detection, ○ contributing signal, – not covered in v0.9 (residual noted).
New rows H1–H9; rows R1–R12 = SPEC §17 rows carried forward unchanged (engines columns
identical; shown compressed here — final spec merges tables). "HP" = Hermes precedent column.

| ID | Threat (precedent) | E1 man | E2 inj | E3 shl | E4 py | E5 js | E6 net | E7 sec | E8 dep | Capabilities | Residual risk | Hermes precedent |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | Hidden Unicode instructions | – | ● | ○ | ○ | ○ | ○ | – | – | obfuscation | novel encodings | unchanged |
| R2 | Prompt injection overriding agent | ○ | ● | ○ | ○ | ○ | – | – | – | integrity.override | semantic subtlety | unchanged |
| R3 | Credential harvest + dead-drop exfil (AMOS) | – | ○ | ● | ● | ● | ● | ● | – | secrets.exfil | custom protocols | unchanged |
| R4 | Reverse shell / RCE dropper (clawdhub) | – | ○ | ● | ● | ● | ○ | – | – | execute.*, network.send | staged loaders | unchanged |
| R5 | Permission-bypass frontmatter (HiddenLayer) | ● | – | – | – | – | – | – | – | integrity.override | new vendor fields | unchanged |
| R6 | Hidden/auto-trigger persistence | ● | ○ | ● | ● | ● | – | – | – | persistence | OS-level outside bundle | unchanged |
| R7 | Obfuscated payloads | – | ● | ● | ● | ● | ○ | ○ | – | obfuscation | decode depth 3 | unchanged |
| R8 | Malicious dependency | – | – | ○ | ○ | ○ | – | – | ● | supply-chain | offline heuristics | unchanged |
| R9 | Secrets committed in bundle | – | ○ | ○ | ○ | ○ | – | ● | – | credentials.read | entropy blobs | unchanged |
| R10 | Deceptive description vs behavior | ○ | ○ | – | – | – | – | – | – | overreach | ambiguous copy | unchanged |
| R11 | Data destruction / sabotage | – | – | ● | ● | ● | – | – | – | filesystem.outside | intent ambiguity | unchanged |
| R12 | Scanner evasion (split signals) | – | – | – | – | – | ○ | – | – | (dedup keeps evidence) | v1.0 taint | unchanged |
| **H1** | **Persona poisoning (SOUL.md/context files)** | ○† | ● | ● | ● | ● | – | – | – | persona.write*, integrity.override | runtime-generated content | SOUL.md auto-loaded as identity every boot (agent_init); any skill with file tools can rewrite it |
| **H2** | **Memory-file manipulation** | – | ● | ● | ● | ● | – | – | – | persona.write*:memory | lexical link-gaming | memories/, per-profile MEMORY.md/USER.md; learning_graph links memory↔skill |
| **H3** | **Skill→skill chaining / dropper** | ●† | ○ | ● | ● | ● | ○ | – | – | spawn.agent*, integrity.override | cross-bundle payload unseen | related_skills consumed by host; kanban dispatch spawns agent runs; skills/** writable |
| **H4** | **metadata.hermes abuse (spoof/fallback/config)** | ●† | ○ | – | – | – | – | – | – | integrity.override | future unknown fields | tags/requires_toolsets/fallback_for_tools/config keys all host-consumed (skill_utils.py) |
| **H5** | **platform_disabled / config tampering** | – | ○ | ● | ● | ● | – | – | – | integrity.override:control_plane | none major | skills.platform_disabled per-platform view (#14536); config.yaml is plain YAML |
| **H6** | **Agent-cron persistence (jobs.json)** | ○ | ○ | ● | ● | ● | – | – | – | persistence:cron_json | Chronos re-arm survives restart | cron/jobs.json = prompt+script+schedule+deliver; hosted gateways scale-to-zero re-arm |
| **H7** | **Channel social engineering** | – | ● | ● | ● | ● | ○ | – | – | network.send:messaging_human | runtime-composed lures | discord/telegram/feishu/slack adapters; channel_directory.json enumeration; pending_messages |
| **H8** | **Profile escape / cross-tenant read** | – | ○ | ● | ● | ● | – | – | – | filesystem.outside, credentials.read | runtime-context dependent | profile_routes multiplexing; isolated profile homes share $HERMES_HOME/.env+auth.json |
| **H9** | **$HERMES_HOME path indirection** | ○ | – | ●‡ | ●‡ | ●‡ | – | – | – | (primitive enabling H1/2/5/6/8) | exotic variable forms | ${HERMES_HOME:-~/.hermes} idiom in shipped skills; $HERMES_HOME/.env holds live provider tokens |

† requires E1 Hermes-dialect upgrade (choir.harness knowledge promoted to core, §4 verdict).
\* proposed capability addition (§2).
‡ consumes ingest normalization primitive (T-H9).

---

## 4. Verdict: engine upgrades vs new engines

**Upgrade E1 (manifest) first — it is the load-bearing wall.** Today it audits agentskills.io
plus Claude-dialect privilege fields. Required Hermes awareness, sourced from a shipped
hermes-frontmatter schema (promote the choir.harness Hermes dialect knowledge from contract-stub
to core data now; SPEC §4 already reserves this feeding relationship):

1. Parse and validate `metadata.hermes` against the observed grammar (tags, related_skills,
   category, homepage, requires/fallback toolset+tool lists, config entries) — emit
   `validation_errors` for unknown keys instead of ignoring them (H4).
2. Category-vs-directory consistency against the categorized install layout (H4c).
3. related_skills resolution pass with access to the local skills tree (names that don't
   resolve anywhere = chain-reference flag, H3).
4. Claim hooks: fallback/requires declarations and scheduling/messaging lexicon feed §9.2
   extraction so declared-discount math stays honest (H6/H7).

This is a data/schema change inside E1, not a new engine — same input, same trait, same budget.

**Add one ingest/IR primitive, not one engine: HERMES_HOME path normalization (T-H9).**
Canonical agent-home-relative labels on every path literal in IR. Without it, H1/H2/H5/H6/H8
rules are either blind (miss parameterized paths) or FP-fountains (fire on the conventional
self-reference idiom). With it, they are five small sink-rule additions spread across E3/E4/E5
where those engines already live. A dedicated "hoststate engine" was considered and rejected:
its inputs are exactly the decoded-text/script views E2–E5 already consume, so a ninth engine
would duplicate traversal for zero additional evidence kinds and complicate dedup fingerprints.

**Fold-in summary for the rest:**

| Surface | Lands in | New rules (approx) |
| --- | --- | --- |
| H1/H2 persona+memory | E3/E4/E5 sinks + E2 prose | 4–5 |
| H3 chaining | E1 + E3/E4/E5 | 3 |
| H4 metadata abuse | E1 only | 5 (mostly structural, LOW/MED) |
| H5 platform_disabled | E3/E4/E5 | 2 |
| H6 cron | E3/E4/E5 + E1 claim hook | 3 |
| H7 channels | E2 + E3/E4/E5 | 3–4 |
| H8 profiles | E3/E4/E5 (+doctor checks) | 2 |

≈ 27–30 new rules — consistent with the "~40 rules at v0.9, depth beats count" governance line;
each ships with TP+FP fixtures per §15 (negative fixtures drawn from the real in-tree skills
cited above, which double as the benign corpus).

**Capability ontology (§9.1) changes proposed:** add **`persona.write`** (agent self-state:
SOUL/MEMORY/USER/memories/context-injected files) and **`spawn.agent`** (skill refs, kanban
dispatch, agent-cron creation, subagent spawning); extend `persistence` definition to name
agent-native schedulers; add sub-tags `integrity.override:control_plane`,
`network.send:messaging_human`, `filesystem.read:cross_profile`. The 14-family set does **not**
suffice unmodified — but two additions + three tags cover the gap; nothing else moves. Adding
families is a minor rule-pack bump with weights pinned per rule (§9.1), so old scores are stable.

**Confidence calibration defaults for the new surface:** structural/manifest facts 0.90–1.00
(presence) but capped LOW–MED severity because harm is contextual; path-sink evidence
0.85–0.95; prose/instruction evidence stays ≤0.55–0.65 static-only unless corroborated by a
same-file sink — preserving the §7 bands and the no-auto-inflation stance (D-FP). Highest-FP
surfaces ranked: H2 memory journaling > H4 tag heuristics > H7 notifications > H1 persona
tooling; mitigated by declared-discount eligibility extended to persona.write and
network.send:messaging_human claims.

**Residual risks accepted for v0.9 (matrix footnote candidates):** runtime-composed lure
content (H7), cross-bundle chain completion (H3 — watch/diff narrows, doesn't close), exotic
path-variable forms (H9 tail), profile-boundary enforcement itself (H8 — host concern; X-Ray
detects intent-shaped evidence only). Each gets the explicit accepted-risk changelog note §17
already mandates.
