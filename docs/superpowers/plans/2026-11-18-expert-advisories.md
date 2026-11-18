# Expert Advisories and Automation Labels Implementation Plan (Project 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Advisories carry structured, expert-written steps. Each step is labelled as automatic, manual or outside support, and each advisory as Auto-fixable, Partly auto-fixable, Guided fix or Needs outside support, so an engineer can decide how to resolve it.

**Architecture:**
- A new nullable `advisories.content` jsonb holds the structured advisory. The old `recommended_action` text keeps being written, so current readers keep working.
- Generation still uses the AI only for wording and expert notes. A deterministic mapper (rules) attaches catalog actions to steps and decides each step's kind.
- The automation label is computed on read from `content` plus the device's agent.

**Tech Stack:** Cloudflare Workers + Hono + Drizzle (neon-http), React 18, `node:test`.

**Spec:** docs/superpowers/specs/2026-11-18-advisory-remediation-design.md (Project 1, plus "Decisions settled after the builder check").

## Global Constraints

- Environment facts are never invented. Keep the existing rules: no unknown CVE ids, no URLs and no shell commands from the model (`parseAiDraft`). Expert knowledge goes only into each step's `expert_note`.
- The model never decides a step's `kind`, `action` key or parameters. Only the mapper does.
- **Catalog action keys:** `pkg.upgrade`, `os.updates.apply`, `service.stop_disable`, `firewall.block_port`, `app.uninstall`, `check.version`, `check.port`, `check.service`.
- **Risk per action:**

  | Action | Risk |
  |---|---|
  | `pkg.upgrade` | low |
  | `os.updates.apply` | medium |
  | `firewall.block_port` | medium |
  | `service.stop_disable` | high |
  | `app.uninstall` | high |
  | `check.*` | low |

- **Step kinds:** `auto` | `manual` | `external`.
- **Labels, verbatim:**
  - `Auto-fixable`: every non-check step is `auto`.
  - `Partly auto-fixable`: at least one `auto` step and at least one `manual` step.
  - `Guided fix`: no `auto` step and no `external` step.
  - `Needs outside support`: any `external` step.
- While automatic fixing is not built (Project 4), every label comes back with `available: false`. When the label is Auto-fixable or Partly auto-fixable, the note reads, verbatim: "Automatic fixing is not switched on yet."
- A device without an EagleEye host agent turns every would-be `auto` step into `external`, with the reason "This device has no EagleEye agent." A network device (asset type `network`) turns them `external` with the reason "Network devices are changed by an engineer or the vendor."
- **Protected lists** (static, one module):
  - **services:** `eagleeye`, `EagleEyeAgent`, `MsMpEng`, `WinDefend`, `mpssvc`, `EventLog`, `wuauserv`, `sshd`, `TermService`, `ufw`, `firewalld`, `auditd`, `rsyslog`, `systemd-journald`, `DNS`, `named`, `dhcpd`, `NTDS`.
  - **ports:** `22`, `3389`, `53`, `67`, `68`, `88`, `389`, `636`, `443`.
  - **apps:** names containing `defender`, `antivirus`, `eagleeye`, `crowdstrike`, `sentinel`, `sophos`, `malwarebytes`.
- No backfill. Advisories without `content` render as today, plus the line, verbatim: "Regenerate to get structured steps and automation labels."
- Staging only. Shared DB: the migration is additive and its number is announced (0040). `.superpowers` is gitignored.

## Review Focus

1. **The model returns old-style string steps, or malformed JSON:** the rule-based fallback is used, and `content` is still written with mapped steps. Pinned by the Task 3 test `content is built for the rule-based fallback`.
2. **The AI step already says "upgrade X to Y":** no duplicate automatic step is added. The matching step gets the action. Pinned by the Task 2 test `attaches the action to the step that names package and version`.
3. **Package names or versions with unsafe characters** (spaces, `;`, backticks): no automatic action is produced, and the step stays manual. Pinned by the Task 2 test `unsafe package name stays manual`.
4. **A protected service or port:** never mapped to `service.stop_disable` or `firewall.block_port`. Pinned by the Task 2 test `protected port is never blocked`.
5. **An old advisory (no `content`) opened in the UI:** no crash, the old text is shown with the regenerate line. Pinned by the Task 5 test `advisoryView falls back to text when content is null`.

---

### Task 1: Migration 0040 and storage of `content`

**Files:**
- Create: `workers/drizzle/0040_advisory_content.sql`, plus its snapshot and journal entry (via `npm run db:generate`, renamed), and `workers/src/lib/migration0040.test.ts`
- Modify: `workers/src/db/schema.ts` (`advisories`), `workers/src/lib/advisoryScope.ts` (`insertAdvisoryIfNoneSql` gains a `content` argument)

**Interfaces:**
- Produces:
  - `advisories.content` (`jsonb`, nullable, Drizzle `content`);
  - `insertAdvisoryIfNoneSql(eventId: string, summary: string, recommendedAction: string, content: unknown | null)`.

- [ ] **Step 1:** In `migration0040.test.ts`, assert that the SQL adds `content jsonb` to `advisories`, nullable, and contains no `DROP`, `UPDATE`, `DELETE` or `TRUNCATE`. Add an `advisoryScope` test that the insert SQL's params include the JSON content.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Keep `db:generate` clean.
- [ ] **Step 4:** Run `npm test`, `npx tsc --noEmit` and `npm run db:generate` (no changes). Expected: PASS.
- [ ] **Step 5:** Commit `feat(db): 0040 adds structured advisory content`.

### Task 2: Remediation catalog, protected lists and the step mapper

**Files:**
- Create: `workers/src/lib/remediationCatalog.ts`, `workers/src/lib/advisoryContent.ts`, and tests for both

**Interfaces:**
- Consumes: `AdvisoryFacts`, `AdvisoryDraft` and `safeToken` from `workers/src/lib/advisoryKit.ts`.
- Produces:
  - **From `remediationCatalog.ts`:**
    - `REMEDIATION_ACTIONS: Record<ActionKey, { label: string; risk: 'low'|'medium'|'high'; rollback: 'auto'|'none'; needsReboot: boolean }>`
    - `type RemediationActionKey`
    - `PROTECTED_SERVICES`, `PROTECTED_PORTS`, `PROTECTED_APP_PATTERNS`
    - `isProtectedService(name)`, `isProtectedPort(port)`, `isProtectedApp(name)`
    - `PACKAGE_MANAGER_FOR: Record<string, 'apt'|'dnf'|'apk'|'pip'|'npm'|'winget'>`, keyed by the SBOM `packageType` values `deb`, `rpm`, `apk`, `python`, `npm`. Windows apps have no reliable mapping in this round.
  - **From `advisoryContent.ts`:**
    - `type AdvisoryStep = { id: string; text: string; kind: 'auto'|'manual'|'external'; action?: { key: RemediationActionKey; params: Record<string,string|number> }; risk: 'low'|'medium'|'high'; needs_reboot?: boolean; expert_note?: string; reason?: string }`
    - `type AdvisoryContent = { summary; why_now; steps: AdvisoryStep[]; verify; rollback; confidence; sources; basis; version: 1 }`
    - `type DeviceInfo = { hasAgent: boolean; isNetworkDevice: boolean; remediationEnabled: boolean; capabilities: string[] }`
    - `mapSteps(facts: AdvisoryFacts, steps: Array<{ text: string; expert_note?: string }>, device: DeviceInfo): AdvisoryStep[]`
    - `automationLabel(steps: AdvisoryStep[], device: DeviceInfo): { label: 'Auto-fixable'|'Partly auto-fixable'|'Guided fix'|'Needs outside support'; available: boolean; reason: string }`
    - `buildContent(draft: AdvisoryDraft & { stepNotes?: string[] }, facts: AdvisoryFacts, basis: string, device: DeviceInfo): AdvisoryContent`

**Mapper rules (deterministic).** The detail keys named below, such as `port`, `protocol`, `service` and `kb`, must be checked against how the alerts are written in `workers/src/services/drift.ts` (port alerts) and `workers/src/services/windowsPatch.ts` (OS patch alerts). Use the real key names.
1. **Package CVE** (`facts.cve` with `pkg`, `group.fixTo` and a supported `packageType`; `safeToken` passes on the package and the version):
   - The action is `pkg.upgrade {manager, package, version: fixTo}`.
   - Attach it to the first step whose text contains both the package name and `fixTo`.
   - Otherwise prepend the step "Upgrade <pkg> to <fixTo>."
2. **`os_patch_missing`** with a KB id in `facts.other.kb`: `os.updates.apply {scope: 'kb', kb}`, attached to the step that names the KB, or prepended.
3. **`port_opened`:**
   - The port comes from `facts.other.port`, and the protocol from `facts.other.protocol`, defaulting to `tcp`.
   - The port must not be protected, and the service from `facts.other.service` must not be protected.
   - The action is `firewall.block_port {port, protocol, direction: 'inbound'}`, attached to the step naming the port together with close, block or firewall, or prepended.
4. **Everything else:** `manual`.
5. **Device rules, applied last to every would-be `auto` step:**
   - `!hasAgent` makes it `external`, with reason "This device has no EagleEye agent."
   - `isNetworkDevice` makes it `external`, with reason "Network devices are changed by an engineer or the vendor."
6. **Risk:** an `auto` step takes `REMEDIATION_ACTIONS[key].risk`. A manual or external step takes `low`, unless its text names a reboot or uninstall, which makes it `medium`.
7. **Ids:** `s1..sN` in order.

**Label rules:** check-only steps are ignored.
- Any `external` step: `Needs outside support`, with the first external reason.
- All `auto`: `Auto-fixable`.
- Mixed `auto` and `manual`: `Partly auto-fixable`.
- Else: `Guided fix`.
- `available = device.remediationEnabled && every auto action is in device.capabilities`. It is false in this round.
- When the label is Auto-fixable or Partly auto-fixable and `available` is false, the reason is "Automatic fixing is not switched on yet."

- [ ] **Step 1: Write failing tests:**
  - `attaches the action to the step that names package and version` (no extra step added);
  - `prepends an upgrade step when no step names it`;
  - `unsafe package name stays manual` (package `"a;rm"`);
  - `no fix version stays manual`;
  - `protected port is never blocked` (port 22, and service `sshd` on port 2222);
  - `port 8080 maps to firewall.block_port`;
  - `device without agent makes auto steps external with the reason`;
  - `network device makes auto steps external`;
  - label cases: all four labels, plus `available` false and the verbatim "not switched on" reason;
  - `risk comes from the catalog`.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(advisories): remediation catalog, protected lists, step mapper and automation label`.

### Task 3: Generation writes expert notes and `content`

**Files:**
- Modify: `workers/src/services/advisory.ts` (`SYSTEM_PROMPT` ~224, `gatherFacts` ~74, `generateAdvisory` ~234), `workers/src/lib/advisoryKit.ts` (`parseAiDraft` ~278)
- Test: `workers/src/lib/advisoryKit.test.ts` (extend), plus pure helpers tested in `advisoryContent.test.ts`

**Interfaces:**
- Consumes: Task 1 `insertAdvisoryIfNoneSql(..., content)`; Task 2 `buildContent`, `DeviceInfo`.
- Produces:
  - `parseAiDraft` accepts `steps` as either `string[]` or `Array<{ text: string; expert_note?: string }>`. It returns `AdvisoryDraft & { stepNotes: string[] }`, where `stepNotes[i]` is a sanitised note of at most 280 characters, or `''`. Notes are subject to the same URL, backtick and unknown-CVE rules as steps.
  - `deviceInfoFor(db, assetId): Promise<DeviceInfo>` in `workers/src/services/advisory.ts`:
    - `hasAgent` = an agent row with `host_asset_id` equal to the asset, `kind` = `host` and `retired_at` null;
    - `isNetworkDevice` = asset `type` = `network`;
    - `remediationEnabled` = false;
    - `capabilities` = [].

Prompt change: add to `SYSTEM_PROMPT`, verbatim:

```
Each step is an object {"text": "...", "expert_note": "..."}. expert_note explains, from general security practice, what the step changes, what it can break, prerequisites and how to undo it (max 280 characters). Never put environment facts in expert_note that are not in the facts given.
```

Keep every existing rule. Facts for non-CVE alerts:
- `cti_match`: add the ATT&CK technique name when the event details carry one (`lib/attack.ts`).
- `os_patch_missing`: add the KB id and title from the event details into `other.kb` / `other.kbTitle`.

`generateAdvisory`:
- Builds `content = buildContent(draft, facts, basis, device)` for both the AI and the rule-based path.
- Writes `content` on both the insert and the update path. `recommended_action` is written exactly as today.

- [ ] **Step 1: Write failing tests:**
  - `parseAiDraft accepts object steps with expert notes`;
  - `expert note with a URL or unknown CVE is dropped`;
  - `string steps still parse`;
  - `content is built for the rule-based fallback` (`buildContent` on a `ruleBasedDraft` gives steps with kinds and a label-ready shape).
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(advisories): expert notes per step and structured content on generate`.

### Task 4: API returns content and the automation label

**Files:**
- Modify: `workers/src/routes/advisories.ts` (`GET /advisories` and `GET /advisories/:id`)
- Test: pure helper `advisoryView(row, device)` in `workers/src/lib/advisoryContent.ts` (+ test)

**Interfaces:**
- Consumes: Task 2 `automationLabel`, `DeviceInfo`; Task 3 `deviceInfoFor`.
- Produces:
  - **Detail response:** both endpoints add `content` (or null) and `automation: { label, available, reason } | null`. It is null when `content` is null.
  - **List response:** each item adds `automation_label` (string or null). The list computes the device info for all listed advisories with one query (agents whose `host_asset_id` is in the listed assets), never per row.
  - `advisoryView(row: { content: AdvisoryContent | null }, device: DeviceInfo)` returns `{ content, automation }`.

- [ ] **Step 1: Write failing tests:**
  - `advisoryView returns null automation for null content`;
  - `advisoryView recomputes the label from current device info` (the same content gives `Needs outside support` without an agent and `Auto-fixable` with one).
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Keep the tenant scoping exactly as is.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(advisories): API returns structured content and automation label`.

### Task 5: Frontend shows structured steps and labels

**Files:**
- Modify: `frontend/src/components/common/AdvisoryBody.jsx`, `frontend/src/pages/AdvisoriesPage.jsx` (list chip + detail ~192), `frontend/src/pages/AlertsPage.jsx` (~955, compact)
- Create: `frontend/src/utils/advisoryView.js` + `advisoryView.test.js`

**Behaviour:**
- **`AdvisoryBody`** takes `content` (preferred) or `text`.
  - With `content`, it shows:
    - numbered steps;
    - a kind badge per step: `Automatic`, `Manual` or `Outside support`;
    - a risk tag;
    - the expert note under a muted "Expert note" label;
    - the reason for external steps;
    - then Why now, Verify, Rollback, Confidence, Sources and Basis, as today.
  - With only `text`, it shows today's parsed view plus the verbatim line "Regenerate to get structured steps and automation labels."
- **Detail page:** a label chip with the reason as its tooltip and subtitle, coloured by label: Auto-fixable green, Partly amber, Guided blue, Needs outside support red. When `available` is false, the "not switched on" reason shows under the chip.
- **List:** a small chip with `automation_label` when present.
- **Pure helpers in `utils/advisoryView.js`:** `labelTone(label)`, `kindBadge(kind)`, `advisoryDisplay(advisory)` (returns `{ mode: 'structured' | 'text', ... }`).

- [ ] **Step 1:** Write failing tests for the helpers, including `advisoryView falls back to text when content is null` and an unknown label getting a neutral tone. Run them with `node --test src/utils/advisoryView.test.js`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): structured advisory steps with automation labels`.

### Task 6: Staging rollout (controller; staging only)

- [ ] **Step 1:** Tell the owner that migration number `0040` is taken (for the teammate). Run `npm run db:status:staging`. Expected: pending exactly `0040_advisory_content`. Then migrate.
- [ ] **Step 2:** Deploy the worker with `npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`, then immediately the frontend (VITE_* unset), then `node scripts/kg/build-system-graph.mjs staging`. Check the bundle.
- [ ] **Step 3:** Smoke test in a temporary tenant (prefix `ADVTEST-`). Create by SQL:
  - an asset with an agent row (`host_asset_id` set) and one without;
  - a package-CVE alert with a fix version;
  - a `port_opened` alert for 8080, and one for 22.

  Then `POST /events/:id/advisory` as a Tenant Superadmin (MFA through the API), wait for the queue, and `GET /advisories/:id`. Expected:
  - `content` is present;
  - the CVE advisory with an agent is labelled Auto-fixable or Partly auto-fixable, with the "not switched on" reason, and the same without an agent is labelled Needs outside support;
  - the port 22 advisory has no automatic step;
  - an older advisory without `content` still loads.

  Cleanup order: audit rows by tenant, then advisories and events (by cascade via the tenant), then the tenant, then users.

  Also check permissions:
  - a Tenant user without `advisory.generate` gets 403 on `POST /events/:id/advisory`;
  - one with `advisory.generate` gets 202 or 200;
  - `GET /advisories/:id` still works with `advisory.view` only;
  - the Platform Superadmin cannot generate. The refusal comes from the existing `decide()` rule; there's no platform test login, so confirm it with the unit test `decide(superadmin, 'advisory.generate')` refusing, or as a browser check.
- [ ] **Step 4:** Run the GET sweep (no 5xx) and the agent check. Record the results. Stop.
