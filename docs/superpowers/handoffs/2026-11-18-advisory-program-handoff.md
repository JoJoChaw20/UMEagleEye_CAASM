# Handoff: advisory remediation program (Projects 1-3)

Date: 2026-11-18. Repo: `c:\FYP\UMEagleEye_CAASM-1` (Windows, Git Bash and PowerShell). Read this whole file before acting.

## 1. Read first

- Spec (the authority): `docs/superpowers/specs/2026-11-18-advisory-remediation-design.md`. Its "Decisions settled" section records the owner's rulings.
- Project 1 plan (done): `docs/superpowers/plans/2026-11-18-expert-advisories.md`
- Project 2 plan (code done, verifying): `docs/superpowers/plans/2026-11-18-advisory-assistant.md`
- Project 2 ledger (rulings 1-10, task results): `.superpowers/sdd/2026-11-18-advisory-assistant/progress.md` (gitignored, local only)

## 2. Owner rules (non-negotiable)

- **Staging only.** Never touch production. Production is behind main and still needs migrations 0035-0040, applied in order, before any production deploy. Migration numbers up to 0040 are taken.
- **The Neon database is shared with a teammate** who is running scanning work.
  - Never break scanning, agents, the agent APIs, or the five agent builds (Windows, Linux, macOS in `agent/` and `agent-gui/`; iOS and Android in `mobile-agent/`).
  - After every deploy, confirm agent heartbeats still advance and scans and SBOMs still arrive.
- **Safety first.** No change may create a bigger vulnerability. Check step by step. Keep all existing features working.
- **Approvals:**
  - **Already approved:** deploy, push and merge Project 2, but only once all tests pass.
  - **Needs owner approval first:** the Project 3 plan, before any Project 3 code.
- **Who does what:**
  - Whoever holds `advisory.generate` runs the advisory workflow.
  - The Platform Superadmin only sees cross-tenant statistics and asks general security questions. It never generates or debugs advisories. Its refusal text is fixed: "The Platform Superadmin can view overall statistics and ask general security questions, but cannot debug advisories."
- **Replies must be accurate and never cut off.**
- **Model and subagents:**
  - Sonnet subagents are blocked by the weekly limit until Nov 23, 12pm.
  - Until then, build in-session with tests and an inline review per task.
  - After the reset, return to the subagent-driven workflow (`superpowers:subagent-driven-development`).

## 3. Environment and commands

- Branch: `feat/advisory-assistant` (16 commits ahead of `main`). `main` = `e35ce0a` (Project 1 merged).
- Worker deploy: `cd workers && npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`. Use the noperf config: the PERF binding breaks deploys with error 10089.
- Frontend deploy: `cd frontend && env $(env | grep -oE '^VITE_[A-Z_]+' | sed 's/^/-u /') npm run deploy:staging`.
  - `frontend/.env` must exist.
  - Afterwards, check that the bundle in `dist/assets/*.js` contains `umeagleeye-api-staging` and not `localhost`.
- System graph rebuild after a deploy: `cd workers && node scripts/kg/build-system-graph.mjs staging`.
- Tests:
  - Worker: `cd workers && npm test` (766 pass) and `npx tsc --noEmit` (clean).
  - Frontend: `cd frontend && node --test src/utils/*.test.js` (71 pass) and `npx vite build`.
- Migrations: `npm --prefix workers run db:status:staging` / `db:migrate:staging`. Project 2 needed none.
- Staging API: `https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1`. Frontend: `https://staging.umeagleeye.pages.dev`.
- Logs: `npx wrangler tail -c wrangler.prod-noperf.toml --env staging --format json`.
  - The output is pretty-printed, multi-line JSON.
  - Parse it with a string-aware brace scanner (the two helper scripts below do this).
  - Events carry `cpuTime`, `outcome` and `logs`.
  - Save the tail to a file, then summarise it: `node scripts/smoke/parsetail.mjs <file> [regex]` (log lines, exceptions, failed outcomes) and `node scripts/smoke/cputail.mjs <file>` (CPU p50, p95 and max per route, failed outcomes).
- Smoke and helper scripts: `workers/scripts/smoke/`. Run each from `workers/`, e.g. `node scripts/smoke/mfa-smoke.mjs`.

## 4. Project 1: expert advisories and automation labels (DONE, merged `e35ce0a`)

- **Content:** `advisories.content jsonb` (migration 0040) holds steps `{id, text, kind auto|manual|external, action?, risk, expert_note?, reason?, device_blocked?}`.
- **Labels:** Auto-fixable / Partly auto-fixable / Guided fix / Needs outside support. They show `available: false` ("Automatic fixing is not switched on yet.") until Project 4.
- **Key files:**
  - `workers/src/lib/remediationCatalog.ts`
  - `workers/src/lib/advisoryContent.ts` (the mapper, plus `advisoryView`, which re-derives kinds from the device)
  - `workers/src/services/advisory.ts` (generation)
  - `workers/src/lib/advisoryKit.ts`
  - `frontend/src/components/.../AdvisoryBody.jsx`
  - `frontend/src/utils/advisoryView.js`
- **Executor rule for Project 4:** run only steps whose kind is re-derived as `auto` on the server at run time, never just because an `action` is present.

## 5. Project 2: advisory-aware assistant (CODE DONE; staging verification in progress)

### What was built (commits, oldest first)

- `e45d4c9` **T1 advisory context.**
  - `POST /chatbot` takes `advisory_id`.
  - `workers/src/kg/advisoryContext.ts` loads the advisory, alert, device, CVEs and steps as S# sources.
  - The caller needs `advisory.generate` and the same tenant; otherwise 404 before any model call. The Superadmin gets the fixed refusal at the route.
- `cbf3884` **T2 Superadmin limits.**
  - A fix-kind question or an advisory gets the refusal.
  - Record tools read shared and platform knowledge only.
  - `count_nodes` returns totals and groups only, filtered by `STATISTIC_FIELDS`.
- `e407705` **T3 knowledge base.**
  - `workers/src/data/securityKb.json` holds 80 entries; all sources are allowed and verified. Search is local (`workers/src/kg/knowledge.ts`).
  - Tools: `search_knowledge` (K#) plus live `lookup_cve`, `lookup_cwe`, `lookup_attack_technique` (L#, via `workers/src/kg/intelRunner.ts`).
  - Answers use "## From your environment" (S#) and "## Expert guidance" (every paragraph cites K# or L#), then a `Confidence:` line. Low confidence also needs a "Check with:" line.
- `c8e0903` **T4 safety (`workers/src/kg/safety.ts`).**
  - The fixed check `unsafeMatches`/`unsafeRecommendations` runs on every answer.
  - `reviewAnswer` runs for fix answers: JSON only, any fail wins.
  - On failure: one rewrite. If that fails too, the fixed `SAFE_REFUSAL` text.
- `dbdbbfa` **T5 continuation (`workers/src/kg/continuation.ts`).** Up to 3 continuations and 12 000 tokens; otherwise the answer ends on a full sentence plus `LONG_NOTE`.
- `ca6d244` **T6 UI.**
  - `frontend/src/utils/chatAnswer.js`, `ChatWidget.jsx`, `AdvisoriesPage.jsx`.
  - Citation chips with https-only links; confidence chip; warning style for refusals.
  - "Debug with AI" requires `advisory.generate` + `chatbot.use` and is hidden for the Superadmin.
- `70098b1` **T7 eval script:** `workers/scripts/kg/advisory-eval.mjs` (section 6).
- **Fixes after staging runs:**
  - `7f54808`: Red Hat KB URLs (the owner confirmed them in a browser).
  - `721949b`: tolerant review parser; advisory facts carry graph keys (this fixed the red cross on "Reading a record"); rejection categories are logged.
  - `1857072` **Overview feature** (owner request): `workers/src/kg/overview.ts` plus the `get_overview` tool.
    - "How are we doing / what's going on / summarise / what should we fix first" questions are routed by `isOverviewQuestion` in `guard.ts` to a system answer.
    - The answer covers posture, assets, agents, scans, alerts by severity and advisories, then the P0/P1/P2 tiers using the dashboard's rules, then the top items with their advisory IDs.
    - The Superadmin and roles limited to status and score get counts only.
  - `1a21958`: reviewer token room; knowledge-base entries preloaded for fix answers and advisory chats.
  - `8637edb`: never claim an automatic fix (spec: consistency with the advisory); eval extended.
  - `7d0a31c`: **model calls are no longer streamed** (CPU, see below); the exposure check skips descriptions.
  - `9f2665e`: 100 s model timeout; exposure check judges from the nearest verb; auto-step wording.
  - `ea9be00`: an empty reply is asked again with 8192 tokens; overview `period_days: 7`; the reviewer gets the whole advisory with 5000 tokens; value-shape logging.

### Deployed state

- **Worker:** staging version `9e1e7516` (= `ea9be00`).
- **Frontend:** staging deploy `efa27817` (= `ca6d244`). There have been no frontend changes since.

### Important finding: CPU and scanning

- The account is on the Workers Free plan, where the CPU limit is enforced against a burst allowance.
- Parsing the reasoning model's streamed reply cost about 100 ms of CPU per question. Chat requests hit "exceeded CPU", and **one agent heartbeat was killed**.
- After switching to non-streamed replies (`readModelReply` in `agent.ts`), chat CPU dropped: p50 105 to 27 ms, max 1067 to 122 ms. In eval v4, 0 of 81 heartbeats failed.
- **Do not reintroduce streaming from the model.** Re-check heartbeat outcomes after any chat change.

### Model facts

- Staging uses DeepSeek (`DEEPSEEK_API_KEY`, `deepseek-chat`), which behaves like a reasoning model: it thinks first.
- Every model call needs generous `max_tokens`. Examples: classify 1024, review 5000, answers 4096 with an 8192 re-ask when empty.

### Eval history (46 questions; thresholds: (c), (d), (e) and (g) 100%; (a), (b) ≥95%; (f) ≥80%)

| Run | Result | Main problem found |
|---|---|---|
| v1 | 14 false safe refusals, 18 IDK | review parser failed |
| v2 | stopped early | old build |
| v3 | facts 89%, safety 92%, 5 errors | CPU limit (streaming), exposure false positives |
| v4 | facts 95.7%, citations 95.7%, safety 100%, cross-tenant 100% | (d) failed on 2 timeouts; useful answers 59%; overview 0/4 (the "7 days" value) |
| v5 | **stopped at 19/46 for the handoff; must be re-run in full.** Partial: 13/14 non-trap questions answered (only Q11 IDK), 5/5 unsafe requests refused or IDK, all cross-tenant checks pass. Staging cleaned (0 rows left). | none yet |

## 6. What to do next (in order)

1. **Get the eval v5 result.**
   - v5 was stopped at 19/46 for the handoff: re-run it in full.
   - If that run is gone or incomplete, re-run: `cd workers && node scripts/kg/advisory-eval.mjs staging`. It takes 25-30 minutes, creates temporary tenants `ADVEVAL-a` and `ADVEVAL-b`, and cleans up after itself.
   - If a run is interrupted, clean up with `node scripts/smoke/eval-clean.mjs`: audit rows first, then users, then tenants.
   - Pass means every check passes (section 5 thresholds). If it fails, read the `[kg-safety]` and `[kg-agent]` lines in the tail. They log categories, value shapes and matched phrases only. Fix, add tests, deploy, re-run.
2. **Smoke suites on staging** (`workers/scripts/smoke/`, run from `workers/`), each must show 0 fail and cleanup 0:
   - `mfa-smoke.mjs` (23 checks)
   - `final-check.mjs` (26)
   - `handover-smoke.mjs` (63)
   - `adv-smoke.mjs` (19; includes the real-agent heartbeat and scan/SBOM continuity check)
   - `api-sweep-mfa.mjs` (70 routes, no 5xx)

   They create temporary tenants and users with test prefixes and remove them at the end; run them one at a time, never while an eval is running.
3. **Merge.** Deploy the worker (and the frontend, if it changed), push, and merge `feat/advisory-assistant` into `main`.
   - End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
   - Confirm tests on the merged result.
   - Then report: production is untouched and still needs 0035-0040.
4. **Project 3 plan.** Write it with `superpowers:writing-plans`, save it to `docs/superpowers/plans/`, and get owner approval before any code.

## 7. Project 3: playbooks for verification and approval (NOT STARTED)

### From the spec

- **Base:** bring the `feature/playbooks` Stage 1 work onto current main by rebase or port. That work predates action-based access and MFA, so it needs updating, not a plain merge.
  - **Tables:** runs and steps.
  - **Execution:** a dedicated queue, with single-winner step claims.
  - **Step kinds:** `recheck`, `sbom`, `inventory`, `active`, `approval`, `close_advisory`.
- **One verification playbook per advisory type:**
  - CVE in a package: SBOM, then recheck, then close.
  - Open port: active scan of that port, then recheck, then close.
  - `close_advisory` reuses the "still detected" check from `workers/src/kg/confirm.ts`. An advisory closes only when the problem is proven gone.
- **Approval gates:**
  - **Step-up:** password plus MFA code; the staging exemption rules apply.
  - **New actions:** `playbook.run` and `playbook.approve`.
  - **Audit:** every start, approval, cancel and close.
- **UI:** an advisory shows its playbook timeline: step, status, result, who approved, when.

### Known state

- Staging already has `playbook_runs` / `playbook_run_steps` tables from earlier work. Adopt them; don't recreate them. Inspect their columns first.
- New migrations start at 0041.

### Risks to plan for

- Playbook steps queue scans on the teammate's agents. Respect rate limits and the existing job flow (`services/pendingJobs.ts`), and don't flood the agents.
- Never close an advisory while the problem is still detected.
- Reuse the existing step-up/MFA code from the MFA project.

## 8. Project 4 (after Project 3; summary only)

- **Fixed action catalog:** `pkg.upgrade`, `os.updates.apply`, `service.stop_disable`, `firewall.block_port`, `app.uninstall`, and read-only `check.*`.
- **Agent side:** a `remediator` role, off by default, signed and expiring jobs.
- **Run flow:** dry run, approval with step-up (one engineer), fix, verify, close or roll back.
- **Permissions:** `advisory.automation.run` and `advisory.automation.approve`. The Superadmin can never start or approve a run.

## 9. Gotchas seen in this work

- **Shell escaping:**
  - Bash heredocs and `sed` with backslashes or quotes mangle TypeScript regexes and strings on this machine.
  - For multi-line or escaped code changes, use the Edit/Write tools, or a Python script written with the Write tool.
- **Permission classifier:** it blocks fetching bot-protected sites and Wayback lookups. Don't work around it; ask the owner instead.
- **Log noise:** after an eval's cleanup, `[kg] refresh ... kg_nodes_tenant_id_fkey` errors appear for deleted temporary tenants. Harmless.
- **Line endings:** `LF will be replaced by CRLF` warnings on commit are expected.
- **Unanswered owner items:** usage settings (`CLAUDE_CODE_SUBAGENT_MODEL` etc.); nothing has been applied.
