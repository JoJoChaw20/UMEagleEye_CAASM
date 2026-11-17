# Two-Step Role Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let old-role code and the new action-based code run against the same database, by
replacing migration 0035 with an additive "expand" step now and a "contract" step later.

**Architecture:**
- The database keeps the old role values `tenant_admin` and `business_owner` until the contract
  step, and gains `tenant_user` plus a nullable `actions` column.
- New code turns every stored user row into the new model through one function,
  `normalizeAccount`, before using its role or actions.
- Legacy role names appear only in TypeScript, never in SQL. So the code from Part A keeps
  working after the contract migration removes those enum values.

**Tech Stack:** Cloudflare Workers + Hono, Drizzle ORM on Neon Postgres, `node:test` via `npm test`, wrangler.

**Spec:** docs/superpowers/specs/2026-11-17-action-based-access-control-design.md, section 8 and 8.1.
This plan replaces Task 11 of docs/superpowers/plans/2026-11-17-action-based-permissions.md.

## Global Constraints

- Migration 0035 has never been applied to any database. Rewrite it in place, keeping its tag `0035_action_based_access` and its journal `when` (1794912409156).
- Part A must not change any existing row and must not remove anything from the database.
- Converted action sets are `MIGRATION_ACTIONS.tenant_admin` (53) and `MIGRATION_ACTIONS.business_owner` (13) in `workers/src/lib/actions.ts`. Do not copy them anywhere else in TypeScript.
- When a Tenant Superadmin edits the actions of a legacy-role user, write `actions` and keep the stored role unchanged.
- The string literals `'tenant_admin'` and `'business_owner'` may appear in non-test `workers/src/**/*.ts` only in `lib/actions.ts` and `db/schema.ts`.
- Worker deploys: `npx wrangler deploy -c wrangler.prod-noperf.toml [--env staging]`. Never run a plain `wrangler deploy`.
- Frontend deploys: unset the shell's VITE_* variables first: `env $(env | grep -oE '^VITE_[A-Z_]+' | sed 's/^/-u /') npm run deploy:staging`. Afterwards, check that the bundle contains the API host and 0 occurrences of `localhost:8000`.
- Every database or deploy step needs the project owner's go-ahead in the session. Part B also needs the teammate's agreement.
- The teammate's scanning must keep working without a break:
  - Agent-authenticated endpoints (agent polls, job pickup, scan, SBOM and sightings uploads, enrolment by token) must behave exactly as on `main`.
  - Every Tenant Superadmin must keep every scan action.

## Review Focus

1. **Legacy user opens the grant screen:** a Tenant Superadmin opens a `tenant_admin` user created before the migration. The screen shows the 53 actions, not zero. Pinned by the Task 3 test `tenant user list shows legacy users' converted actions`.
2. **Legacy user in the assignee list:** a `tenant_admin` with no stored actions is assigned an alert. They appear in the assignee list, and the assignment is accepted. Pinned by the Task 3 test `assignable list includes legacy tenant_admin`.
3. **Legacy role in SQL:** after migration 0036 removes the legacy enum values, a query with a legacy role literal fails with "invalid input value for enum". Pinned by the Task 3 test `no legacy role literal outside actions.ts and schema.ts`.
4. **Old worker meets a new user:** an old worker reads a user with role `tenant_user`. Old code never fails for `tenant_user`: role-gated routes return 403, open read routes return its own tenant's data. Never a 500, never another tenant's data. Checked in the Task 4 rollback rehearsal.
5. **Edited actions survive the contract step:** actions a Tenant Superadmin saved for a legacy user before the contract step are kept by it. Pinned by the Task 5 SQL test `0036 keeps edited actions (COALESCE)`.

---

## Part A: Expand (now)

### Task 1: `normalizeAccount`

**Files:**
- Modify: `workers/src/lib/actions.ts`
- Test: `workers/src/lib/actions.test.ts`

**Interfaces:**
- Produces:
  - `export type Role = 'superadmin' | 'tenant_superadmin' | 'tenant_user'`
  - `export type LegacyRole = 'tenant_admin' | 'business_owner'`
  - `export function normalizeAccount(role: string, actions: readonly string[] | null | undefined): { role: Role; actions: ActionKey[] }`

- [ ] **Step 1: Write failing tests** in `actions.test.ts`:

```ts
test('normalizeAccount: legacy roles become tenant_user with converted actions when none stored', () => {
  assert.deepEqual(normalizeAccount('tenant_admin', null), { role: 'tenant_user', actions: [...MIGRATION_ACTIONS.tenant_admin] })
  assert.deepEqual(normalizeAccount('business_owner', undefined), { role: 'tenant_user', actions: [...MIGRATION_ACTIONS.business_owner] })
})
test('normalizeAccount: stored actions win for legacy roles, including an empty list', () => {
  assert.deepEqual(normalizeAccount('tenant_admin', ['asset.view']), { role: 'tenant_user', actions: ['asset.view'] })
  assert.deepEqual(normalizeAccount('business_owner', []), { role: 'tenant_user', actions: [] })
})
test('normalizeAccount: new roles keep their role; null actions become []', () => {
  assert.deepEqual(normalizeAccount('superadmin', null), { role: 'superadmin', actions: [] })
  assert.deepEqual(normalizeAccount('tenant_superadmin', null), { role: 'tenant_superadmin', actions: [] })
  assert.deepEqual(normalizeAccount('tenant_user', ['scan.view']), { role: 'tenant_user', actions: ['scan.view'] })
})
test('normalizeAccount: unknown action keys are dropped; unknown role fails closed', () => {
  assert.deepEqual(normalizeAccount('tenant_user', ['scan.view', 'feeds.refresh']), { role: 'tenant_user', actions: ['scan.view'] })
  assert.deepEqual(normalizeAccount('owner', ['scan.view']), { role: 'tenant_user', actions: [] })
})
```

- [ ] **Step 2:** Run `cd workers && npm test`. Expected: FAIL, because `normalizeAccount` is not exported.
- [ ] **Step 3:** Implement the types and `normalizeAccount` in `actions.ts`, beside `MIGRATION_ACTIONS`. Filter with `isActionKey`.
- [ ] **Step 4:** Run `npm test`. Expected: all pass.
- [ ] **Step 5:** Commit `feat(rbac): normalizeAccount reads legacy roles as tenant users`.

### Task 2: Expand migration and schema

**Files:**
- Modify: `workers/drizzle/0035_action_based_access.sql` (replace the whole body)
- Modify: `workers/src/db/schema.ts:52-54, 95-97, 110`
- Modify: `workers/drizzle/meta/0035_snapshot.json`
- Modify: `workers/src/lib/migration0035.test.ts` (replace the tests)

**Interfaces:**
- Produces:
  - DB enum `user_role` = `('superadmin','tenant_superadmin','tenant_admin','business_owner','tenant_user')`.
  - `users.actions` is `text[]`, nullable, with no default.
  - The Drizzle type of `users.actions` becomes `string[] | null`.

- [ ] **Step 1: Write the new tests** in `migration0035.test.ts`:

```ts
test('0035 is additive: adds tenant_user and a nullable actions column', () => {
  assert.match(sqlText, /ALTER TYPE "public"\."user_role" ADD VALUE IF NOT EXISTS 'tenant_user';/)
  const col = sqlText.split('\n').find((l) => /ADD COLUMN IF NOT EXISTS actions text\[\]/.test(l))
  assert.ok(col, 'actions column line')
  assert.doesNotMatch(col!, /NOT NULL|DEFAULT/)
})
test('0035 changes no rows and removes nothing', () => {
  const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')
  assert.doesNotMatch(code, /\bUPDATE\b|\bDELETE\b|DROP TYPE|DROP DEFAULT|ALTER COLUMN role|CREATE UNIQUE INDEX/i)
})
```

- [ ] **Step 2:** Run `npm test`. Expected: both new tests FAIL against the current SQL.
- [ ] **Step 3:** Replace the SQL body with:
  - a header comment naming this the expand step and pointing to spec 8.1;
  - exactly two statements joined by `--> statement-breakpoint`: the `ALTER TYPE ... ADD VALUE IF NOT EXISTS 'tenant_user'` line and `ALTER TABLE users ADD COLUMN IF NOT EXISTS actions text[];`.
- [ ] **Step 4:** Update `schema.ts`:
  - `userRoleEnum` gets the 5 values, in the database order above.
  - `role` keeps its existing default `'business_owner'`. Old code inserts rows without a role, and new code always sets one.
  - `actions` becomes `text('actions').array()`, nullable with no default. Update its comment.
  - Remove the `uq_users_one_tenant_superadmin` index. Leave a one-line comment that it returns in 0036.
- [ ] **Step 5:** Edit `0035_snapshot.json` to match the schema: same enum values, `actions` not null `false` with no default, no index. Run `npm run db:generate`. Expected: drizzle-kit reports no schema changes. If it writes a new migration file, delete that file and fix the snapshot.
- [ ] **Step 6:** Run `npx tsc --noEmit` and `npm test`. The type errors from `actions` becoming nullable and the role type widening are the site list for Task 3. Record them in the report and do not fix them here, except in `schema.ts` itself. Commit `feat(db): 0035 becomes the additive expand step`.

### Task 3: Read every user row through `normalizeAccount`

**Files:**
- Modify: `workers/src/middleware/auth.ts:28-44`
- Modify: `workers/src/routes/auth.ts`: the password login response (around line 80), the MFA verify response (around 183), the Google sign-in response (around 274-282), and `/me` (around 355-390)
- Modify: `workers/src/routes/tenants.ts`: the user list (around 298-320) and PUT actions (around 500-506)
- Modify: `workers/src/routes/events.ts`: the assignable list (around 402-412) and the two assignee checks (around 623 and 682)
- Create: `workers/src/lib/legacyRoles.test.ts`
- Test: route tests next to the touched routes. Use the existing `*.test.ts` pattern for routes. If a route has no test harness, extract the row-mapping into a pure exported function and test that.

**Interfaces:**
- Consumes: `normalizeAccount`, `Role` (Task 1); `users.actions: string[] | null` (Task 2).

Rule: wherever a `users` row's `role` or `actions` is compared, passed to `decide`, put in an
`AuthUser`, or returned in JSON, it goes through `normalizeAccount` first. Audit
`previousState`/`newState` keep the raw stored values. A role filter in SQL must name only
`superadmin` / `tenant_superadmin` / `tenant_user`. Express "any tenant member" as
`ne(users.role, 'superadmin')`, so the query is valid both before and after 0036.

- [ ] **Step 1: Write failing tests:**
  - `legacyRoles.test.ts` → `no legacy role literal outside actions.ts and schema.ts`. Read every non-test `.ts` under `src/`. Assert that only `src/lib/actions.ts` and `src/db/schema.ts` contain `'tenant_admin'` or `'business_owner'`.
  - `tenant user list shows legacy users' converted actions`: a stored row `{role:'tenant_admin', actions:null}` is listed as `role:'tenant_user'` with the 53 actions.
  - `assignable list includes legacy tenant_admin`: a row `{role:'tenant_admin', actions:null}` passes the `alert.manage` filter, and a `business_owner` with null actions does not.
  - `PUT actions accepts a legacy user and keeps its stored role`: the update writes only `actions`.
- [ ] **Step 2:** Run `npm test`. Expected: the new tests FAIL.
- [ ] **Step 3:** Apply `normalizeAccount` at every site in **Files**. Then grep `from(users)` across `src/` and check each remaining hit against the rule. Put a table of every hit and its verdict in the report.
- [ ] **Step 4:** Run `npx tsc --noEmit` and `npm test`. Expected: 0 type errors, and all tests pass. Then run `cd ../frontend && npm test && npx vite build`. Expected: pass, because the API now returns only the three new role values.
- [ ] **Step 5: Agent endpoint check.** List every route that authenticates an agent, not a user, starting from the mounts in `src/index.ts`. Run `git diff main..HEAD` over those handlers and over the services they call (job pickup, result ingest). Put a table of route → "unchanged" or the changed lines in the report. Any behaviour change on an agent route is a blocker. Report it and do not adjust it.
- [ ] **Step 6:** Commit `fix(rbac): read legacy-role users as tenant users everywhere`.

### Task 4: Staging rollout with rollback rehearsal (needs owner go-ahead; the controller runs this, not a subagent)

Run the steps in this order. Stop at the first failure and report it.

- [ ] **Step 1:** Tell the teammate the deploy time, and pick a time when she is not mid-scan. Their local code keeps working on the staging DB. Tell her to scan from her Tenant Superadmin account: the Platform Superadmin (`admin`) becomes view-only and can no longer start scans. Also agree these rules for the whole coexistence window (until Part B is done):
  - (a) no worker or frontend deploy from `main`. A deploy from `main` silently replaces ours, and a worker-only deploy leaves the new frontend talking to an old worker without `/auth/actions` or actions in `/auth/me`;
  - (b) no `drizzle-kit push` against the shared database. `main`'s schema lacks `users.actions`, so push would offer to drop it;
  - (c) she tells us before she generates or applies any migration. Hers would also take index 0035 with a later `when` (ours is 1794912409156), and if hers is applied first the migrator silently skips ours;
  - (d) user management (invites, role or action changes) only on the new worker.
- [ ] **Step 2:** `cd workers && npm run db:status:staging`. Expected: pending is exactly `0035_action_based_access`. If it is not listed (a migration with a later `when` already ran), stop: the migrator would skip it. Regenerate our migration with the next index and a `when` later than the last applied `created_at`, then run the status check again before migrating.
- [ ] **Step 3:** `npx wrangler deployments list -c wrangler.prod-noperf.toml --env staging`. Record the current version id as the rollback target. Record the current Pages `staging` deployment from the Cloudflare dashboard.
- [ ] **Step 4:** On the old staging site, sign in as one `tenant_admin`, one `business_owner` and one `tenant_superadmin` account. Note what each can open. This is the baseline.
- [ ] **Step 5:** `npm run db:migrate:staging`, then `npm run db:status:staging`. Expected: no pending migrations.
- [ ] **Step 6:** Repeat Step 4 against the old worker, which is still live. Expected: identical. This shows old code survives the expand step.
- [ ] **Step 7:** Deploy the worker (`npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`), then run `node scripts/kg/build-system-graph.mjs staging` (staging only; `npm run deploy:staging` runs it after the deploy, raw wrangler does not). Deploy the frontend (with VITE_* unset) straight after the worker, and check the bundle. Between the two deploys the old frontend shows legacy users the role `tenant_user` with a reduced menu. The window is brief.
- [ ] **Step 8:** Run the smoke tests from Plan 1 Task 11 (a-i), plus:
  - the `tenant_admin` account has 53 actions on the grant screen and can start a scan;
  - the `business_owner` account has 13 actions and no Discovery page;
  - the Tenant Superadmin removes one action from the legacy user. It takes effect on that user's next click. A read-only SELECT shows the stored role unchanged;
  - an alert can be assigned to the legacy `tenant_admin`;
  - a newly invited user is stored as `tenant_user`;
  - **scanning continuity:** compare agents' online status and last-seen before and after Step 5 (migrate), not only after the deploy. For the hour after the deploy, read-only queries show `scan_results` rows still arriving from the same agents. Compare passive, SBOM and SNMP counts per hour with the hour before. Agents keep reporting as online;
  - **scanning by a Tenant Superadmin:** an active scan started from Discovery is picked up by an agent and completes. Its hosts show in the results, and an SBOM scan request completes too.
- [ ] **Step 9:** Rollback rehearsal:
  - Run `npx wrangler rollback <version id from Step 3> -c wrangler.prod-noperf.toml --env staging`, and roll Pages `staging` back in the dashboard.
  - Roll the frontend back straight after the worker; for a short while the old frontend shows legacy users a reduced menu. Expected: the Step 4 accounts work as in the baseline. Check the `tenant_user` from Step 8 on one role-gated route (expect 403) and one open read route (expect 200, its own tenant's data only, no 500).
  - Then redeploy the new worker and frontend as in Step 7, and re-check one smoke test.
- [ ] **Step 10:** Record the results in the ledger. Stop. Production waits for the owner's go-ahead, and then runs Steps 1-9 with `prod` commands (`db:status:prod`, `db:migrate:prod`, no `--env`). Worker: `npx wrangler deploy -c wrangler.prod-noperf.toml`. Frontend: `npm run deploy` in `frontend/` with VITE_* unset. Before the production run, merge Part A into `main`, so her next deploy carries it. Skip the rollback rehearsal in production.

---

## Part B: Contract (later, gated)

**Gate:** start Part B only when all three hold:
- the teammate confirms every copy of their code that uses these databases includes Part A;
- the owner gives the go-ahead;
- Part A has run on both environments.

Do Part B on a new branch from main, after Part A is merged.

### Task 5: Contract migration and code cleanup

**Files:**
- Create: `workers/drizzle/0036_drop_legacy_roles.sql`, plus its snapshot and journal entry. Change the schema first (Step 4), then run `npm run db:generate`. Rename the generated file and its journal `tag` to `0036_drop_legacy_roles`, and replace the generated body with the Step 3 SQL.
- Create: `workers/src/lib/migration0036.test.ts`
- Rename: `workers/scripts/db/check-0035.mjs` → `check-0036.mjs`
- Modify: `workers/src/db/schema.ts`, `workers/src/lib/actions.ts`, `workers/src/lib/actions.test.ts`, `workers/src/lib/legacyRoles.test.ts`

**Interfaces:**
- Produces:
  - DB enum `('superadmin','tenant_superadmin','tenant_user')` with default `'tenant_user'`.
  - `actions text[] NOT NULL DEFAULT '{}'`.
  - The unique index `uq_users_one_tenant_superadmin`.
  - `normalizeAccount` keeps its signature and loses the legacy branch.

- [ ] **Step 1: Write failing tests** in `migration0036.test.ts`:
  - **Arrays match the catalog:** port the array check from commit e9fc6f7's `migration0035.test.ts`. The tenant_admin and business_owner arrays must match `MIGRATION_ACTIONS`, and the `rn > 1` array must match `ACTION_KEYS`.
  - `0036 keeps edited actions (COALESCE)`: the tenant_admin and business_owner updates both use `COALESCE(actions, ARRAY[`.
  - The three-value enum and the unique index are present.
  - `actions` is filled from NULL to `'{}'` before `SET NOT NULL`.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Write the 0036 SQL. Start from the body of `0035_action_based_access.sql` at commit e9fc6f7 (`git show e9fc6f7:workers/drizzle/0035_action_based_access.sql`), and make these changes:
  - drop its `ADD COLUMN` line;
  - wrap the tenant_admin and business_owner arrays as `COALESCE(actions, ARRAY[...]::text[])`;
  - before the enum swap, add `UPDATE users SET actions='{}' WHERE actions IS NULL;`, `ALTER TABLE users ALTER COLUMN actions SET DEFAULT '{}';` and `ALTER TABLE users ALTER COLUMN actions SET NOT NULL;`.
  - Keep the order: role becomes text → dedupe owners → orphan owners → convert legacy roles → actions not null → enum swap → default → unique index.
- [ ] **Step 4:** Update the schema: 3-value enum, default `'tenant_user'`, `actions` not null with default `'{}'`, and the unique index restored. Remove the legacy branch and `LegacyRole` from `normalizeAccount`, and drop the legacy-role cases from its tests. In `legacyRoles.test.ts`, remove `schema.ts` and `actions.ts` from the allowed list, so no legacy literal remains in `src/`. Update `check-0036.mjs` so it also prints the number of legacy-role rows with NULL actions.
- [ ] **Step 5:** Run `npx tsc --noEmit`, `npm test` and `npm run db:generate`. Expected: 0 errors, all tests pass, and no schema changes. Commit `feat(db): 0036 contracts roles to the action-based model`.

### Task 6: Contract rollout (needs owner and teammate go-ahead; the controller runs this)

- [ ] **Step 1:** In the Neon console, create a branch from the current state of the target database, named `pre-0036-<staging|production>`. This is the restore point.
- [ ] **Step 2:** Run `node scripts/db/check-0036.mjs <env>`. Resolve every tenant it flags with more than one Tenant Superadmin or an inactive kept owner, with the owner, before going on.
- [ ] **Step 3:** Run `npm run db:status:<env>`. Expected: pending is exactly `0036_drop_legacy_roles`. Then run `npm run db:migrate:<env>`. Part A code is still live and keeps working, because it uses no legacy literal in SQL. Between applying 0036 and deploying the Task 5 worker (Step 4), make no Tenant Superadmin invites: the Part A worker writes NULL actions for that role, and 0036's NOT NULL refuses them.
- [ ] **Step 4:** Deploy the Task 5 worker. The frontend does not change.
- [ ] **Step 5:** Smoke tests: former legacy users keep their actions, including any edited in Part A. A second Tenant Superadmin cannot be created (409).
- [ ] **Step 6:** Rollback, only if needed: restore the database from `pre-0036-<env>` and redeploy the Part A worker.
