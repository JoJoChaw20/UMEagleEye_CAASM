# Expert Advisories, Safe Assistant and Automated Remediation: Design

Status: draft for owner approval. Date: 2026-11-18.

## Intent

Engineers who pick up an advisory should get advice that reads like a senior security engineer
wrote it, be able to ask follow-up questions until they are confident, and, where it is safe, let
the system carry out the fix on the device and prove it worked. Safety comes first: a fix must
never open a bigger hole, break a service without a way back, or act on a hallucinated
instruction. Where a fix cannot be automated (a physical server, a router with no agent, a vendor
firmware update), the advisory says so clearly and guides the engineer instead.

## What exists today (main)

- **Advisory generation** (`workers/src/services/advisory.ts`, `lib/advisoryKit.ts`,
  `lib/advisoryEnrich.ts`): manual trigger from an alert; facts from the device, the CVE finding
  (KEV, EPSS, CVSS, fix version), NVD and OSV; the model writes at most 5 steps under "use only
  the facts given". Shell commands come from rules, never from the model. Steps are stored as
  labelled plain text in `advisories.recommended_action` and parsed back by the frontend. Non-CVE
  alerts (new port, new device, threat match, downgrade) get mostly template text. The knowledge
  graph is not used for generation.
- **Assistant** (`workers/src/kg/agent.ts`, `kg/guard.ts`): grounded answers only from knowledge
  graph tool results, otherwise "I don't know"; general questions get a separate, unlabelled-to-
  company answer path. "Debug with AI" sends a canned question; the backend does not know which
  advisory is open. Live CVE lookup tools exist (`mcp/intel.ts`) but the chat does not use them.
- **Closing**: an advisory closes when its alert closes; scans, SBOM and inventory close alerts
  when the problem is no longer seen. Chat close refuses while the same problem is still detected
  (`kg/confirm.ts`).
- **Playbooks**: only on the unmerged branch `feature/playbooks` (worktree
  `.claude/worktrees/feature-playbooks`): runs of verification steps (recheck, sbom, inventory,
  active scan), a human approval gate, and close-advisory. No fixing.
- **Agents** (`agent-gui/eagleeye`, Python): run as a privileged service (Administrator / root /
  launchd daemon). Jobs today: active, passive, sbom, inventory, snmp, plus sightings. They only
  collect and upload; there is no remote execution of any kind.

## Goals

1. Expert advisories with structured steps and an automation label per advisory and per step.
2. An advisory-aware assistant that answers technical questions about the steps correctly,
   separates environment facts from expert knowledge, and never confuses the engineer.
3. Playbooks that verify, gate on approval, and close only when the problem is proven gone.
4. Safe automated fixing on devices for a fixed set of pre-written actions.

## Non-goals

- The AI writing or editing commands that run on a device (rejected: approach B below).
- Fixing devices that have no agent (routers, switches, appliances, physical work). Those are
  labelled "Needs outside support".
- Automatic fixing without an engineer's approval. Every run is approved by a person.
- Production rollout in this round (staging only, as with earlier work).
- Email notifications (no email domain; in-app notices only).

## Anti-goals (would be failure even if it "works")

- A fix that disables a security control (firewall, antivirus, EDR, logging, updates) or widens
  exposure (opens ports, weakens auth) to "make an alert go away".
- An advisory closed while the problem is still present.
- The assistant stating something as fact that is not in the environment data, or giving steps
  that contradict the advisory or the action catalog.
- A device left half-changed with no record of what happened.
- The Platform Superadmin able to run changes inside a tenant (it stays view-only).

## Approaches considered (owner picked A)

| | Approach | Safety | Trade-off |
|---|---|---|---|
| **A (chosen)** | **Fixed action catalog.** Agents carry a built-in list of pre-written, tested fix actions with typed parameters. The AI only maps an advisory to catalog actions and parameters; the server validates; the agent validates again; dry run, engineer approval with step-up, run, verify, automatic rollback on failure. | Highest: no AI-written command reaches a device. | Coverage limited to the catalog; everything else is "Guided fix". |
| B | AI-written scripts reviewed by the engineer, executed by the agent. | Low: one wrong or injected line can damage a server; review fatigue. | Fixes almost anything. |
| C | No device changes: ready-to-run script for the engineer plus automated verification. | Safest. | Not automatic. Used as the fallback inside A. |

## The design

Four projects, built and released in this order. Each is usable on its own.

### Project 1: Expert advisories and automation labels

- **Structured advisory content.** New nullable `advisories.content jsonb` with:
  `summary`, `why_now`, `steps[]`, `verify`, `rollback`, `confidence {level, reason}`,
  `sources[]`, `basis`, `automation {label, reason}`. Each step:
  `{ id, text, kind: 'auto' | 'manual' | 'external', action?: { key, params }, risk: 'low'|'medium'|'high', needs_reboot?: boolean, expert_note? }`.
  The existing `recommended_action` text stays written (formatted from `content`) so the current
  UI and older readers keep working; new UI reads `content` when present.
- **Expert reasoning, still grounded.** The generation prompt keeps "never invent versions, CVE
  ids, ports, links" for environment facts, and adds an expert layer: the model may use general
  security expertise for how and why (impact of the change, prerequisites, service restarts,
  common pitfalls), marked per step as `expert_note`. Inputs are extended for non-CVE alerts:
  port service banner and product version, KEV/EPSS when a CVE maps, CWE, ATT&CK technique for
  threat matches, MSRC data for OS patches.
- **Mapping to actions.** After the model drafts steps, a deterministic mapper (rules, not the
  model) decides `kind` and `action` per step from the facts: e.g. an SBOM CVE in a Debian package
  with a published fix maps to `pkg.upgrade {manager: 'apt', package, version}`; a missing Windows
  KB maps to `os.updates.apply {kb}`; an unwanted open port on an agent host maps to
  `firewall.block_port {port, protocol}` (only when the port's service is not in the device's
  "keep" list). Steps the mapper cannot map stay `manual`; steps that need hardware, a device
  without an agent, or a vendor/firmware action are `external`.
- **Advisory label** (shown on the list and the detail page):
  - **Auto-fixable**: every step is `auto` or a read-only check, the device has an agent with
    the remediation role enabled (Project 4) and the agent supports each action.
  - **Partly auto-fixable**: some steps `auto`, some `manual`.
  - **Guided fix**: no `auto` step but the device is reachable by an engineer.
  - **Needs outside support**: any `external` step (with the reason, e.g. "router firmware from
    the vendor", "device has no agent").
  Until Project 4 ships, the label is computed as "would be auto-fixable" with a note that
  automatic fixing is not switched on.
- **Validation.** The existing `parseAiDraft` checks stay (no unknown CVE ids, no URLs, no shell
  commands from the model). The mapper never trusts the model for action keys or parameters.

### Project 2: Advisory-aware assistant that does not hallucinate

- **Advisory context.** A chat can be opened on an advisory: the request carries `advisory_id`;
  the server loads that advisory (tenant-scoped) plus its alert, device, CVE finding and content,
  and puts them in the prompt as cited sources (S1..Sn). The engineer does not need to repeat it.
- **Two kinds of statement, always labelled.**
  - *From your environment*: device, versions, ports, CVE ids, dates, counts. Must appear in the
    cited sources exactly (existing `verifyAnswer` / `citationProblems` rules), otherwise the
    answer is rejected and retried, then "I don't know".
  - *Expert guidance*: how a fix works, what it can break, prerequisites, how to roll back,
    alternatives. Allowed from the model's knowledge, shown under a visible "Expert guidance"
    heading, never stated as a fact about the company.
- **Live security knowledge.** The chat gets the existing read-only tools `lookup_cve` (NVD, OSV,
  KEV, EPSS), `lookup_cwe`, `lookup_attack_technique`, cached in KV as today.
- **Safety review of every answer about a fix.** Before an answer that recommends an action is
  shown, a second, cheaper model call (or the same model with a reviewer prompt) checks it
  against a fixed safety checklist: does it disable or weaken a security control, widen
  exposure, skip a backup/rollback for a risky change, contradict the advisory's steps or the
  action catalog, or claim certainty without a source? A failing answer is rewritten once with
  the reviewer's reasons; if it still fails, the assistant says it cannot recommend that safely
  and suggests escalation. Deterministic checks run first (forbidden phrases: disable firewall /
  antivirus / Defender / SELinux / logging, chmod 777, curl | sh, opening 0.0.0.0/0, etc.).
- **Consistency with the advisory.** If the engineer asks for something the catalog cannot do
  automatically, the assistant says so plainly and labels it manual or external; it never invents
  an automatic path.
- **Uncertainty is explicit.** Each answer ends with a confidence line (High / Medium / Low) and,
  when Low, who to involve (e.g. the vendor, the system owner).
- **Hallucination measurement.** A fixed evaluation set of advisory questions (real staging
  advisories plus crafted traps: wrong versions, unsafe requests, out-of-scope asks) runs in CI
  as a script against recorded tool results and scores: fact accuracy, labelled expert guidance,
  safety refusals, and "I don't know" when appropriate. The existing kg QA scripts are the base.
- The general (non-company) path keeps its "General security guidance, not specific to your
  environment" label.

### Project 3: Playbooks for verification and approval

- Bring the `feature/playbooks` Stage 1 work onto the current main (rebase or port; it predates
  the action-based access and MFA work): runs and steps tables, a dedicated queue, single-winner
  step claims, step kinds `recheck`, `sbom`, `inventory`, `active`, `approval`, `close_advisory`.
- A playbook run is created from an advisory: one verification playbook per advisory type
  (e.g. CVE in a package: SBOM -> recheck -> close; open port: active scan of that port ->
  recheck -> close). `close_advisory` reuses the "still detected" check from `kg/confirm.ts`.
- Approval gates use step-up (password + MFA code, staging exemption rules apply) and the
  action-based permissions: new actions `playbook.run` (start a verification run) and
  `playbook.approve`. Audit every start, approval, cancel and close.
- UI: an advisory shows its playbook timeline (step, status, result, who approved, when).

### Project 4: Safe automated fixing (fixed action catalog)

- **Action catalog** (the only things a device will ever do on request), shared definition in the
  backend and the agent:
  - `pkg.upgrade {manager: apt|dnf|yum|zypper|apk|winget|brew|pip|npm, package, version}`:
    upgrade exactly that package to exactly that version (or the nearest version that fixes the
    CVE when the advisory says so); never `upgrade all`.
  - `os.updates.apply {scope: security|kb, kb?}`: Windows Update for a named KB or security
    updates; Linux security updates only (`unattended-upgrade`-style), with reboot handling as a
    separate, explicit step.
  - `service.stop_disable {name}`: only for services not on a protected list (security agents,
    the EagleEye agent itself, SSH/RDP when they are the only remote access, DNS/DHCP on servers).
  - `firewall.block_port {port, protocol, direction: inbound}`: add a host firewall rule; never
    removes existing rules, never touches outbound or management ports on the protected list.
  - `app.uninstall {name, version?}`: only software flagged as unwanted by the advisory, never
    security tools or the agent.
  - Read-only helpers: `check.version {package}`, `check.port {port}`, `check.service {name}`.
  Each action has: typed parameter schema with strict patterns, pre-checks (e.g. package
  installed, version older than target, enough disk), a dry-run mode that reports exactly what
  would change, the execution using the platform tool with argument arrays (no shell string),
  post-checks, and a defined rollback (e.g. reinstall previous version, remove the added rule,
  re-enable the service) where possible. Actions without a reliable rollback are marked
  `rollback: none` and need an explicit second confirmation.
- **Device side.** A new agent role `remediator`, OFF by default for every agent. Only the Tenant
  Superadmin can enable it per agent (new high-impact action `agent.remediation.enable`). The
  agent refuses any action not in its local catalog, re-validates every parameter, refuses
  protected targets, runs one action at a time, enforces a timeout, and reports stdout/stderr
  (truncated, redacted) and exit code. Remediation jobs are signed by the server (HMAC with the
  agent's key) and expire quickly; the agent rejects unsigned, expired or replayed jobs.
- **Server side.** A fix run is a playbook run with fix steps: `dry_run` -> `approval` (step-up)
  -> `fix` -> `verify` (the matching scan/SBOM/inventory) -> `close_advisory`, and `rollback` on a
  failed fix or failed verification. New actions `advisory.automation.run` (high impact, not in
  any preset) and `advisory.automation.approve`. Limits: one fix run per device at a time, a
  tenant-wide kill switch, optional maintenance window per device, and refusal when the device's
  agent is offline or out of date.
- **Who can do what.** Engineers with `advisory.automation.run` can prepare a fix run and see the
  dry run; approval needs `advisory.automation.approve` and step-up; the Platform Superadmin can
  view runs across tenants but can never start or approve one.
- **Everything recorded.** Each step's input, dry-run output, approval, execution output,
  verification result and rollback is stored on the run and audited.

## Constraints

- Cloudflare Workers backend (Hono, Drizzle on Neon via neon-http batches), React frontend,
  Python agent; free-plan subrequest budget in chat (45 per request) must be respected when
  adding lookup tools and the reviewer call.
- Models: DeepSeek (`deepseek-chat`) or OpenRouter (`OPENROUTER_MODEL`); keep temperature low.
- Action-based access control: every new capability is a grantable action with a clear label
  and impact level; Tenant Superadmin-only items stay reserved.
- MFA and step-up rules from the MFA work apply to every approval.
- Shared staging database with the teammate: additive migrations, announced migration numbers.
- No email; in-app notices.

## Decisions settled after the builder check

- **Executor rule (from the Project 1 review).** Stored content may keep a validated `action` on a
  step that is external only because of the device (`device_blocked: true`), so the label can
  recompute when an agent is installed. Project 4's executor and any "Apply" UI must run a step
  only when its kind — re-derived on the server from the current device at run time — is `auto`,
  never because an `action` is present, and must re-validate the action against the catalog.
- **Who runs the workflow (owner).** The person who can generate an advisory can carry the whole
  workflow for it. `advisory.generate` (with `chatbot.use` for the assistant) is the permission
  for: viewing structured steps and labels, the advisory-scoped assistant ("Debug with AI" — today
  gated on `advisory.close_via_chat`, moves to `advisory.generate`), starting verification
  playbooks, and preparing and approving fix runs as the advisory's assignee with step-up. No
  separate playbook or automation actions are added; the per-agent remediation switch (Tenant
  Superadmin only) and step-up remain the safety gates. (This replaces `playbook.run`,
  `playbook.approve`, `advisory.automation.run` and `advisory.automation.approve` named above.)
- **Platform Superadmin (owner).** Can use the assistant only for cross-tenant overview statistics
  and general security questions. It can never generate an advisory (already refused: write
  action), never open an advisory-scoped chat, never get "fix"/debug answers about a specific
  advisory, alert or device, and never start or approve a playbook or fix run. It may still view
  advisories read-only (`advisory.view`). Project 2 enforces the assistant part server-side (a
  superadmin question classified as a fix/debug question, or carrying `advisory_id`, is refused
  with: "The Platform Superadmin can view overall statistics and ask general security questions,
  but cannot debug advisories.").

- **Approval (owner).** One engineer owns an incident and is fully in charge of it, so a fix run
  is approved by that one engineer (the advisory's assignee, holding `advisory.automation.approve`)
  with password + MFA code. There is no second approver. Risky steps — no reliable rollback, a
  reboot, stopping a service, or uninstalling software — add an explicit extra confirmation in the
  same approval (the engineer ticks "I understand this step cannot be rolled back automatically"
  or the matching risk), and the dry run must have been viewed in that session before Approve is
  enabled. The run records who approved and which risks were acknowledged.

- **Plan boundary.** All four projects are in scope, each with its own plan, built in order
  1 -> 2 -> 3 -> 4; the first plan written is Project 1. Project 1 already defines the action keys
  and the label so Project 4 needs no change to the advisory format.
- **Playbooks baseline (Project 3).** `feature/playbooks` (owner's branch, 2026-11-12) has Stage 1
  complete and reviewed (run engine, Verify-fix and close, staging smoke 14/14). Its tables
  `playbook_runs` and `playbook_run_steps` ALREADY EXIST on the shared staging database (applied
  from that branch's migration `0033_stiff_ironclad`, which collides with main's `0033`). Project 3
  ports the code onto main with a new migration number that adopts the existing tables
  (`CREATE TABLE IF NOT EXISTS`, compare columns first; never drop) and adds what changed since
  (action-based permissions, step-up approvals).
- **Job signing (my call).** The server stores only a SHA-256 hash of each agent's API key, so it
  cannot HMAC with that key. Remediation jobs are signed with a server Ed25519 key instead: the
  private key is a Worker secret, the public key is pinned by the agent at enrolment (and
  delivered with heartbeats for agents enrolled earlier, accepted only over the existing
  authenticated channel). Jobs reach the agent by the existing polling (pending jobs / heartbeat).
  Each job carries a job id, the agent id, an expiry (10 minutes) and the action; the agent keeps
  the ids it has executed and refuses repeats and expired or foreign jobs.
- **Capabilities (my call).** Agents report their version (already in heartbeats) plus a new
  `capabilities` list (catalog action keys and catalog version). "Out of date" = the agent lacks
  the action or the catalog version is older than the server's minimum for that action. The label
  reads these from the agent row.
- **Protected and keep lists (my call).** Protected services/ports/apps are a static built-in list
  shipped with the catalog (security agents, the EagleEye agent, remote-access services when they
  are the only access path, DNS/DHCP/AD on servers, management ports). No per-device keep list in
  this round: `firewall.block_port` is only mapped for a port reported by drift as newly opened,
  whose service is not protected; the engineer sees the exact rule in the dry run.
- **Rollback failure (my call).** If an automatic rollback fails (e.g. the old package version is
  no longer in the repository), the run ends in state `needs_attention`, the advisory stays open,
  the engineer and the Tenant Superadmin get a notice, and the run record shows exactly what was
  changed and what could not be undone.
- **Assistant budget (my call).** Deterministic safety checks run first; lookups run only when the
  advisory context lacks the fact; if the 45-subrequest budget runs short, lookups are skipped
  before the safety review — the review is never skipped for an answer that recommends an action.
  Extra latency for fix-related answers is acceptable.
- **Old advisories (my call).** No backfill. Advisories without `content` show their text as today
  with "Regenerate to get structured steps and automation labels"; regenerating fills `content`.
  The label is computed on read from `content` + the device's agent capabilities.
- **Evaluation (my call).** There is no CI for the app (only an MSRC workflow). The evaluation set
  runs as a script (`workers/scripts/kg/`) against staging with recorded fixtures; it is a
  required step in each project's staging rollout, not a merge gate.
- **Kill switch and maintenance window (my call).** The kill switch is a Tenant Superadmin action
  (audited). Turning it on stops new runs and pauses runs before their next step; a fix step
  already executing on the device finishes, then its verification runs, and a failed verification
  rolls back as usual (never left half-changed). Outside a maintenance window a run waits at the
  approval step; it does not start fixing.

## Left to the builder

- Exact JSON schema field names beyond those named above, migration numbers, file layout.
- Which reviewer model to use for the safety review (cheapest model that passes the evaluation
  set), and the exact deterministic forbidden-pattern list (start from the anti-goals).
- How to port the playbooks branch (rebase vs re-implement), provided the behaviour above holds.
- Per-platform implementation of each catalog action in the agent, and which actions ship first
  (recommendation: `pkg.upgrade` for apt and winget, `firewall.block_port`, then the rest).
- The evaluation set's size and pass thresholds (start with 40 questions, 100% on safety refusals
  and 0 unlabelled invented facts).
