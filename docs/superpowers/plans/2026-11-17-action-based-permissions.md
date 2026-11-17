# Action-Based Permissions Implementation Plan (Plan 1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the four fixed roles with two roles (Platform Superadmin, Tenant Superadmin) plus per-user grantable actions, enforced on every API route and reflected in every screen.

**Architecture:** One catalog file (`workers/src/lib/actions.ts`) defines the 58 actions, their requirements, presets and the migration map. The API serves it to the frontend, so the catalog exists once. `authMiddleware` reloads the user's role, tenant, active flag and actions from the database on every request, so a grant or removal takes effect on the user's next request. `requireAction(...)` replaces `requireRoles(...)`. A static guard test fails if any authenticated route has no permission check.

**Tech Stack:** Cloudflare Workers, Hono, Drizzle ORM on Neon Postgres, Node test runner (`npm test`), React 18 and Vite.

**Spec:** `docs/superpowers/specs/2026-11-17-action-based-access-control-design.md`

**Out of scope (later plans):**
- **Plan 2, MFA:** mandatory MFA, recovery codes, Tenant Superadmin MFA reset, break-glass, and Cloudflare Email sending. This plan's "converted users" email is sent there.
- **Plan 3, ownership:** handover Paths A, B and C, Provision tenant as an invitation flow, and tenant deactivation and deletion with 90-day retention. Also the Tenant Superadmin's audit-log viewer (reserved action "View the tenant audit log"), which has no endpoint today.

## Global Constraints

- Roles after migration: `superadmin`, `tenant_superadmin`, `tenant_user`. The UI labels are "Platform Superadmin", "Tenant Superadmin" and "Tenant user".
- There are exactly 58 grantable actions, with labels and descriptions copied verbatim from spec section 2. "Refresh threat feeds" does not exist.
- A tenant has at most one `tenant_superadmin`, enforced by a unique partial index.
- The Tenant Superadmin holds every action in their own tenant implicitly. Their `actions` column stays empty.
- The Platform Superadmin passes only actions whose `readOnly` is true, across all tenants. Every other action is refused with: `The Platform Superadmin can view tenants but cannot make changes inside them.`
- The refusal for a missing action is: `You do not have the "<label>" action. Ask your Tenant Superadmin to grant it.` It is returned with HTTP 403 and the body `{ detail, missing_action: <key> }`.
- A deactivated or deleted account gets HTTP 401 with: `Your account is deactivated. Contact your Tenant Superadmin.`
- Granting stores the transitive closure of requirements (spec rule 2). Removing an action never removes others silently: the frontend asks for confirmation and sends the reduced set.
- Every change to a user's actions writes an audit entry `user.actions` with `previousState`, `newState`, `added` and `removed`.
- The database is shared with a teammate. Apply migrations to staging first, and to production only after the user says so (memory: shared-neon-db).
- Worker deploys use `-c wrangler.prod-noperf.toml` (the Analytics Engine binding breaks a plain deploy). Frontend deploys unset the shell's `VITE_*` variables first (memory: frontend-deploy-env).

## Review Focus

1. **A body-dependent action:** `POST /scans/active` with `scan_type: 'passive'` needs `scan.passive.run`, not `scan.active.run`. `PATCH /agents/:id/policy` that changes `sightings` needs `agent.sightings.enable`, and one that changes role settings needs `agent.roles.assign`. Task 4 and Task 7 tests pin the pure helpers that decide this.
2. **A stale session after a removal:** a user whose action was removed, or who was deactivated, still holds a valid JWT. The next request must be refused. This is pinned by Task 3's `decide` tests plus the staging smoke check in Task 11, step 4.
3. **A grant naming an unknown or misspelled key**, such as `asset.veiw`: 400 that lists the bad keys, with nothing stored. Pinned in Task 7's `parseActionList` test.
4. **A route with no permission check:** a new or missed route silently open to every signed-in user. Pinned by Task 3's guard test, which scans every route file.
5. **Migration drift:** the SQL arrays in `0035` differ from `MIGRATION_ACTIONS` in the catalog. Pinned by Task 2's test that parses the SQL file.

---

## File Structure

| File | Responsibility |
|---|---|
| `workers/src/lib/actions.ts` (create) | Catalog: groups, 58 actions, requirements, presets, migration map, `decide`, refusal copy |
| `workers/src/lib/actions.test.ts` (create) | Catalog invariants and `decide` |
| `workers/src/lib/routeGuard.test.ts` (create) | Static check that every authenticated route carries a permission middleware |
| `workers/drizzle/0035_action_based_access.sql` (create) | Role enum change, `actions` column, user conversion, one-Tenant-Superadmin index |
| `workers/src/lib/migration0035.test.ts` (create) | SQL arrays equal `MIGRATION_ACTIONS` and `ACTION_KEYS` |
| `workers/scripts/db/check-0035.mjs` (create) | Read-only pre-check: tenants with more than one Tenant Superadmin |
| `workers/src/middleware/auth.ts` (modify) | Fresh user load, `requireAction`, `requireTenantSuperadmin`, `requirePlatformSuperadmin`, `hasAction` |
| `workers/src/lib/policyChange.ts` (create) | `policyChangeActions(body)`: which actions an agent-policy PATCH needs |
| `workers/src/lib/userAdmin.ts` (modify) | Add-user rules without roles, `parseActionList` |
| `workers/src/routes/*.ts`, `workers/src/kg/*.ts`, `workers/src/mcp/tools.ts` (modify) | Guards switched to actions |
| `workers/src/lib/permissions.ts` (delete) | Replaced by `actions.ts` |
| `frontend/src/utils/actions.js` (create) | Client helpers: `withRequirements`, `dependentsOf`, `matchPreset`, `roleLabel` |
| `frontend/src/utils/actions.test.js` (create) | `node --test` for those helpers |
| `frontend/src/context/AuthContext.jsx` (modify) | Loads `/auth/me` and `/auth/actions`, exposes `can(key)` and `catalog` |
| `frontend/src/components/users/ActionPicker.jsx` (create) | The grant screen: presets, groups, impact badges, dependency notices |
| `frontend/src/pages/*`, `frontend/src/components/*` (modify) | Role checks replaced by `can()` |

---

### Task 1: Action catalog

**Files:**
- Create: `workers/src/lib/actions.ts`
- Test: `workers/src/lib/actions.test.ts`

**Interfaces:**
- Produces:
  - `ACTION_KEYS: readonly ActionKey[]` (58, in catalog order)
  - `type ActionKey`
  - `type GroupKey`
  - `GROUPS: readonly { key: GroupKey; label: string }[]`
  - `ACTIONS: readonly ActionDef[]`, where `ActionDef = { key: ActionKey; group: GroupKey; label: string; description: string; impact: 'low' | 'medium' | 'high'; requires: readonly ActionKey[]; readOnly: boolean }`
  - `ACTION_BY_KEY: Record<ActionKey, ActionDef>`
  - `isActionKey(s: string): s is ActionKey`
  - `withRequirements(keys: readonly string[]): ActionKey[]`: transitive closure, unknown keys dropped, returned in catalog order
  - `dependentsOf(key: ActionKey): ActionKey[]`: every action whose closure contains `key`, excluding `key`
  - `PRESETS: readonly { key: 'viewer' | 'analyst' | 'operator'; label: string; description: string; actions: readonly ActionKey[] }[]` (full cumulative lists)
  - `matchPreset(keys: readonly string[]): 'viewer' | 'analyst' | 'operator' | null`
  - `MIGRATION_ACTIONS: { tenant_admin: readonly ActionKey[]; business_owner: readonly ActionKey[] }`
  - `type Decision = { ok: true } | { ok: false; reason: 'superadmin_read_only' | 'missing_action' | 'not_tenant_member' }`
  - `decide(user: { role: string; tenantId?: string | null; actions: readonly string[] }, key: ActionKey): Decision`
  - `refusalMessage(reason: Exclude<Decision, { ok: true }>['reason'], key: ActionKey): string`

**Keys, groups and requirements.** Copy each label, description and impact verbatim from the matching spec section 2 row, in this order:

| Group (label) | Key, followed by its requires list |
|---|---|
| `dashboard` (Dashboard) | `dashboard.view` [] |
| `assets` (Asset inventory) | `asset.view` []; `asset.create`, `asset.import`, `asset.edit`, `asset.delete`, `asset.merge`, `asset.duplicate.dismiss`, `asset.rescore`, `asset.inventory.collect`, `asset.inventory.clear`, each [asset.view] |
| `scans` (Discovery and scanning) | `scan.view` []; `scan.active.run`, `scan.passive.run`, `scan.cancel`, `scan.route.view`, each [scan.view]; `scan.drift.run` [scan.view, alert.view] |
| `sbom` (SBOM) | `sbom.view` []; `sbom.download` [sbom.view]; `sbom.scan` [sbom.view, asset.view]; `sbom.delete` [sbom.view] |
| `alerts` (Alerts) | `alert.view` []; `alert.manage` [alert.view]; `alert.bulk_update` [alert.manage] |
| `advisories` (Advisories) | `advisory.view` []; `advisory.generate` [advisory.view, alert.view]; `advisory.update` [advisory.view]; `advisory.close_via_chat` [advisory.update, chatbot.use] |
| `threat_intel` (Threat intelligence) | `cti.view` []; `ti_event.view` [cti.view]; `ti_event.create`, `ti_event.edit`, `ti_event.publish`, `ti_event.delete`, each [ti_event.view] |
| `network` (Network map and relationships) | `network.view` []; `network.map.run` [network.view]; `topology.edit` [network.view]; `relationship.view` [asset.view]; `relationship.manage`, `relationship.delete`, each [relationship.view] |
| `reports` (Reports) | `report.view` []; `report.download`, `report.generate`, `report.delete`, `report.snapshot`, each [report.view] |
| `agents` (Agents) | `agent.view` []; `agent.installer.download`, `agent.enrol`, `agent.rename`, `agent.configure`, `agent.key.rotate`, `agent.remove`, each [agent.view]; `agent.roles.assign`, `agent.sightings.enable`, each [agent.configure] |
| `settings` (Tenant settings) | `settings.view` []; `settings.scan_policy.edit`, `settings.agent_defaults.edit`, each [settings.view] |
| `assistant` (AI assistant) | `chatbot.use` [] |

`readOnly: true` applies exactly to these actions:
- every key ending in `.view`
- `sbom.download`
- `report.download`
- `agent.installer.download`
- `chatbot.use`

**Presets** (cumulative; labels "Viewer", "Analyst", "Operator"; descriptions "Sees everything, changes nothing.", "Investigates and responds.", "Runs scans and manages assets and agents."):

- **viewer (15 actions):**
  - `dashboard.view`
  - `asset.view`
  - `scan.view`
  - `sbom.view`
  - `sbom.download`
  - `alert.view`
  - `advisory.view`
  - `cti.view`
  - `ti_event.view`
  - `network.view`
  - `relationship.view`
  - `report.view`
  - `report.download`
  - `agent.view`
  - `chatbot.use`
- **analyst:** viewer plus these 12 actions:
  - `asset.duplicate.dismiss`
  - `scan.route.view`
  - `alert.manage`
  - `alert.bulk_update`
  - `advisory.generate`
  - `advisory.update`
  - `advisory.close_via_chat`
  - `ti_event.create`
  - `ti_event.edit`
  - `ti_event.publish`
  - `relationship.manage`
  - `report.generate`
- **operator:** analyst plus these 17 actions:
  - `asset.create`
  - `asset.import`
  - `asset.edit`
  - `asset.rescore`
  - `asset.inventory.collect`
  - `scan.active.run`
  - `scan.passive.run`
  - `scan.cancel`
  - `scan.drift.run`
  - `sbom.scan`
  - `network.map.run`
  - `topology.edit`
  - `agent.installer.download`
  - `agent.rename`
  - `agent.configure`
  - `agent.roles.assign`
  - `settings.view`

**Migration map:**
- `tenant_admin`: operator plus these 9 actions:
  - `asset.inventory.clear`
  - `sbom.delete`
  - `ti_event.delete`
  - `relationship.delete`
  - `report.delete`
  - `agent.enrol`
  - `agent.sightings.enable`
  - `agent.key.rotate`
  - `agent.remove`
- `business_owner`: viewer minus `scan.view` and `relationship.view`.

**`decide` rules, in order:**
1. If `role === 'superadmin'`: return ok when `readOnly` is true, otherwise `superadmin_read_only`.
2. If there is no `tenantId`: return `not_tenant_member`.
3. If `role === 'tenant_superadmin'`: return ok.
4. Otherwise: return ok if `key` is in `actions`, else `missing_action`.

**Refusal copy:**
- `superadmin_read_only`: "The Platform Superadmin can view tenants but cannot make changes inside them."
- `missing_action`: `You do not have the "${label}" action. Ask your Tenant Superadmin to grant it.`
- `not_tenant_member`: "Your account is not part of an organisation yet. Ask your administrator to add you."

- [ ] **Step 1: Write the failing tests** in `actions.test.ts` using `node:test` and `node:assert/strict`, as in `agentPolicy.test.ts`:

```ts
test('58 unique actions, every group used, every requirement exists', () => {
  assert.equal(ACTIONS.length, 58)
  assert.equal(new Set(ACTION_KEYS).size, 58)
  for (const a of ACTIONS) for (const r of a.requires) assert.ok(isActionKey(r), `${a.key} -> ${r}`)
  assert.deepEqual(new Set(ACTIONS.map(a => a.group)).size, GROUPS.length)
  assert.ok(!isActionKey('cti.ingest'))
})
test('requirements are acyclic and closure is transitive', () => {
  assert.deepEqual(withRequirements(['alert.bulk_update']), ['alert.view', 'alert.manage', 'alert.bulk_update'])
  assert.deepEqual(withRequirements(['advisory.close_via_chat']).sort(),
    ['advisory.close_via_chat', 'advisory.update', 'advisory.view', 'chatbot.use'].sort())
  assert.deepEqual(withRequirements(['nope', 'asset.edit']), ['asset.view', 'asset.edit'])
})
test('dependentsOf lists what removing a view action would take away', () => {
  assert.deepEqual(dependentsOf('alert.view').sort(),
    ['advisory.generate', 'alert.bulk_update', 'alert.manage', 'scan.drift.run'].sort())
})
test('presets: sizes, cumulative, closed under requirements, never high impact', () => {
  const [v, a, o] = PRESETS
  assert.deepEqual([v.actions.length, a.actions.length, o.actions.length], [15, 27, 44])
  assert.ok(v.actions.every(k => a.actions.includes(k)) && a.actions.every(k => o.actions.includes(k)))
  for (const p of PRESETS) {
    assert.equal(withRequirements(p.actions).length, p.actions.length, p.key)
    assert.ok(p.actions.every(k => ACTION_BY_KEY[k].impact !== 'high'), p.key)
  }
  assert.equal(matchPreset([...a.actions].reverse()), 'analyst')
  assert.equal(matchPreset([...a.actions, 'asset.delete']), null)
})
test('migration map: tenant_admin 53, business_owner 13, both closed', () => {
  assert.equal(MIGRATION_ACTIONS.tenant_admin.length, 53)
  assert.equal(MIGRATION_ACTIONS.business_owner.length, 13)
  for (const list of Object.values(MIGRATION_ACTIONS)) assert.equal(withRequirements(list).length, list.length)
  for (const k of ['asset.delete', 'asset.merge', 'report.snapshot', 'settings.scan_policy.edit', 'settings.agent_defaults.edit'])
    assert.ok(!MIGRATION_ACTIONS.tenant_admin.includes(k as ActionKey), k)
})
test('decide', () => {
  const t = 'tenant-1'
  assert.deepEqual(decide({ role: 'superadmin', actions: [] }, 'asset.view'), { ok: true })
  assert.deepEqual(decide({ role: 'superadmin', actions: [] }, 'asset.edit'), { ok: false, reason: 'superadmin_read_only' })
  assert.deepEqual(decide({ role: 'tenant_superadmin', tenantId: t, actions: [] }, 'agent.remove'), { ok: true })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: t, actions: ['asset.view'] }, 'asset.view'), { ok: true })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: t, actions: ['asset.view'] }, 'asset.edit'), { ok: false, reason: 'missing_action' })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: null, actions: ['asset.view'] }, 'asset.view'), { ok: false, reason: 'not_tenant_member' })
  assert.equal(refusalMessage('missing_action', 'scan.active.run'), 'You do not have the "Run active scans" action. Ask your Tenant Superadmin to grant it.')
})
```

- [ ] **Step 2: Run** `cd workers && npm test`. Expected: FAIL, because `actions.ts` cannot be resolved.
- [ ] **Step 3: Implement `workers/src/lib/actions.ts`** per the Interfaces block and the tables above. Declare `ACTION_KEYS` `as const`, so `ActionKey` is a literal union.
- [ ] **Step 4: Run** `npm test`. Expected: all tests PASS, existing ones included.
- [ ] **Step 5: Commit**

```bash
git add workers/src/lib/actions.ts workers/src/lib/actions.test.ts
git commit -m "feat(rbac): action catalog with requirements, presets and migration map"
```

---

### Task 2: Database migration 0035

**Files:**
- Modify: `workers/src/db/schema.ts:52` (enum), `:90-107` (users)
- Create: `workers/drizzle/0035_action_based_access.sql` (plus the snapshot and journal entry that drizzle-kit writes)
- Create: `workers/scripts/db/check-0035.mjs`
- Test: `workers/src/lib/migration0035.test.ts`

**Interfaces:**
- Consumes: `MIGRATION_ACTIONS` and `ACTION_KEYS` (Task 1).
- Produces:
  - `userRoleEnum` = `['superadmin', 'tenant_superadmin', 'tenant_user']`
  - `users.role` defaults to `'tenant_user'`
  - `users.actions` = `text('actions').array().notNull().default(sql\`'{}'::text[]\`)`
  - unique index `uq_users_one_tenant_superadmin` on `(tenant_id)` where `role = 'tenant_superadmin'`

**SQL, in this order, inside one transaction:**
1. `ALTER TABLE users ADD COLUMN IF NOT EXISTS actions text[] NOT NULL DEFAULT '{}'`
2. `ALTER TABLE users ALTER COLUMN role DROP DEFAULT`, then `ALTER TABLE users ALTER COLUMN role TYPE text`.
3. Extra Tenant Superadmins. Rank by `ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY is_active DESC, created_at ASC)` among `role='tenant_superadmin' AND tenant_id IS NOT NULL`. Rows with rank greater than 1 get `role='tenant_user'` and `actions` = all 58 keys.
4. `UPDATE users SET role='tenant_user', actions='{}' WHERE role='tenant_superadmin' AND tenant_id IS NULL`.
5. `UPDATE users SET role='tenant_user', actions=ARRAY[...53] WHERE role='tenant_admin'`.
6. `UPDATE users SET role='tenant_user', actions=ARRAY[...13] WHERE role='business_owner'`.
7. Recreate the enum, as in `migrations/rbac_4role_migration.sql`, but use `CREATE TYPE user_role AS ENUM ('superadmin','tenant_superadmin','tenant_user')`. Then cast the column back and set the default to `'tenant_user'`.
8. `CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_tenant_superadmin ON users (tenant_id) WHERE role = 'tenant_superadmin'`.

Write each array literal as one line, `ARRAY['a','b',...]::text[]`, so the test can parse it.

- [ ] **Step 1: Write the failing test** `migration0035.test.ts`. It reads `join(process.cwd(), 'drizzle/0035_action_based_access.sql')` with `node:fs` and extracts the `ARRAY[...]` literal on the lines containing `'tenant_admin'`, `'business_owner'` and `rn > 1` respectively.

```ts
test('0035 arrays match the catalog', () => {
  assert.deepEqual(arrayOn("role='tenant_admin'").sort(), [...MIGRATION_ACTIONS.tenant_admin].sort())
  assert.deepEqual(arrayOn("role='business_owner'").sort(), [...MIGRATION_ACTIONS.business_owner].sort())
  assert.deepEqual(arrayOn('rn > 1').sort(), [...ACTION_KEYS].sort())
})
test('0035 creates the one-tenant-superadmin index and the three-value enum', () => {
  assert.match(sqlText, /CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_tenant_superadmin/)
  assert.match(sqlText, /ENUM \('superadmin','tenant_superadmin','tenant_user'\)/)
})
```

- [ ] **Step 2: Run** `npm test`. Expected: FAIL, because the file is missing.
- [ ] **Step 3: Update `schema.ts`.** Run `npm run db:generate` to produce the snapshot and journal entry, then replace the generated SQL body with the hand-written SQL above. If drizzle-kit asks an interactive rename question about the enum, answer "create" for `tenant_user`. The SQL body is replaced anyway.
- [ ] **Step 4: Write `scripts/db/check-0035.mjs <staging|production>`.** It loads credentials with `loadEnvFile` from `scripts/db/lib.mjs`, as `db.mjs` does. It is read-only: it prints counts per role, and lists each tenant with more than one Tenant Superadmin, showing usernames, `created_at` and which account the migration keeps.
- [ ] **Step 5: Run** `npm test`. Expected: PASS. Then run `node scripts/db/check-0035.mjs staging`. Expected: a report, and no writes.
- [ ] **Step 6: Commit**

```bash
git add workers/src/db/schema.ts workers/drizzle workers/src/lib/migration0035.test.ts workers/scripts/db/check-0035.mjs
git commit -m "feat(rbac): migration 0035 - tenant_user role, actions column, one tenant superadmin per tenant"
```

---

### Task 3: Auth middleware, permission guards, catalog endpoint, route guard test

**Files:**
- Modify: `workers/src/middleware/auth.ts`
- Modify: `workers/src/types.ts` (`AuthUser`)
- Modify: `workers/src/routes/auth.ts` (`GET /me` adds `actions`; new `GET /actions`; delete `POST /register`)
- Create: `workers/src/lib/routeGuard.test.ts`

**Interfaces:**
- Consumes: `decide`, `refusalMessage`, `ACTIONS`, `GROUPS`, `PRESETS`, `ActionKey` (Task 1).
- Produces:
  - `AuthUser` gains `actions: string[]`.
  - `requireAction(...anyOf: ActionKey[])`: passes when `decide` is ok for at least one key. Otherwise it returns 403 `{ detail: refusalMessage(reason, anyOf[0]), missing_action: anyOf[0] }`.
  - `hasAction(user: AuthUser, key: ActionKey): boolean`
  - `requireTenantSuperadmin`: role is `tenant_superadmin` and `user.tenantId === c.req.param('tenantId')`. If the route has no `:tenantId`, it checks the role only. Refusal: "Only the Tenant Superadmin can do this."
  - `requirePlatformSuperadmin`: role is `superadmin`. Refusal: "Only the Platform Superadmin can do this."
  - `GET /api/v1/auth/actions` (authenticated, any user) returns `{ groups, actions, presets }`, where each action is `{ key, group, label, description, impact, requires, read_only }`.
  - `GET /auth/me` adds `actions: string[]`.

**Middleware change.** After `verifyToken`, `authMiddleware` reads `role, tenantId, isActive, actions` from `users` by `payload.sub`, in one query. If the row is missing or `!isActive`, it returns 401 "Your account is deactivated. Contact your Tenant Superadmin." It then sets `user` from that row, not from the JWT claims, keeping `username` from the JWT. The existing no-tenant guard stays and uses the fresh values. `requireRoles` and `requireTenantAccess` stay exported until Task 7 deletes them.

- [ ] **Step 1: Write the failing guard test** `routeGuard.test.ts`. For each file in `join(process.cwd(), 'src/routes')`, match every route registration `/\.(get|post|put|patch|delete|all)\(\s*'([^']*)'([\s\S]*?)(?:async )?\(c\) =>/g`. The `async` is optional because some handlers, such as cti `/attack`, are plain `(c) =>`. When the captured middle contains `authMiddleware`, assert it also contains `requireAction(`, `requireTenantSuperadmin` or `requirePlatformSuperadmin`, unless `file:path` is in this allowlist:

```ts
const SELF_SERVICE = new Set([
  'auth.ts:/mfa/setup', 'auth.ts:/mfa/enable', 'auth.ts:/change-password', 'auth.ts:/set-password',
  'auth.ts:/me', 'auth.ts:/actions', 'auth.ts:/mfa/reset', 'mcp.ts:/',
])
test('every authenticated route checks a permission', () => { /* collect offenders, assert.deepEqual(offenders, []) */ })
test('no route still uses role lists', () => { /* assert no file in src/routes contains 'requireRoles(' or 'requireTenantAccess(' */ })
```

`auth.ts:/mfa/reset` stays allowlisted until Plan 2 moves it. `mcp.ts:/` is checked inside the MCP tools (Task 5). Also add these tenants routes, which use `superadminOnly` or `tenantAdminAccess` spread variables that the regex cannot see: `tenants.ts:/` and `tenants.ts:/:tenantId`. Task 7 replaces those spreads, then removes them from the allowlist.

- [ ] **Step 2: Run** `npm test`. Expected: FAIL, listing every unguarded route. The second test also fails. That list is the work queue for Tasks 4 to 7.
- [ ] **Step 3: Implement the middleware changes, the `AuthUser` field, the `/actions` endpoint and the `/me` change.** Delete `POST /register` and its schema. Mark the guard tests `{ todo: 'Tasks 4-7' }` so `npm test` stays green while routes are converted. Task 7 removes the `todo`.
- [ ] **Step 4: Run** `npm test` (PASS, with 2 todo) and `npx tsc --noEmit -p workers` (no errors).
- [ ] **Step 5: Commit**

```bash
git add workers/src/middleware/auth.ts workers/src/types.ts workers/src/routes/auth.ts workers/src/lib/routeGuard.test.ts
git commit -m "feat(rbac): fresh per-request user load, requireAction guards, /auth/actions catalog"
```

---

### Task 4: Convert asset, SBOM and scan routes

**Files:**
- Modify: `workers/src/routes/assets.ts`, `workers/src/routes/sbom.ts`, `workers/src/routes/scans.ts`

**Interfaces:**
- Consumes: `requireAction`, `hasAction` (Task 3).
- Produces: `scanActionFor(scanType: 'active' | 'passive'): ActionKey`, exported from `scans.ts`.

Remove the file-level `*_ROLES` constants. Replace each `requireRoles(...X)` with the action below, and add `requireAction` where a route had none. Endpoints that use agent API keys (no `authMiddleware`) are untouched.

| Endpoint | Action |
|---|---|
| assets `GET /`, `/duplicates`, `/:assetId`, `/:assetId/software`, `/:assetId/addresses`, `/:assetId/score`, `/:assetId/baseline`, `/:assetId/inventory-job-status` | `asset.view` |
| assets `GET /:assetId/sbom-scan-status` | `sbom.view` |
| assets `POST /` | `asset.create` |
| assets `POST /import` | `asset.import` |
| assets `PATCH /:assetId`, `POST /:assetId/baseline` | `asset.edit` |
| assets `DELETE /:assetId` | `asset.delete` |
| assets `POST /merge`, `POST /duplicates/merge-safe` | `asset.merge` |
| assets `POST /duplicates/dismiss`, `DELETE /duplicates/dismissals/:dismissalId` | `asset.duplicate.dismiss` |
| assets `POST /rescore`, `POST /:assetId/rescore` | `asset.rescore` |
| assets `POST /:assetId/collect-inventory` | `asset.inventory.collect` |
| assets `DELETE /:assetId/inventory` | `asset.inventory.clear` |
| assets `POST /:assetId/scan-sbom` | `sbom.scan` |
| sbom: every authenticated `GET` except download | `sbom.view` |
| sbom `GET /:sbomId/download` | `sbom.download` |
| sbom `DELETE /by-asset/:assetId` | `sbom.delete` |
| scans `GET /`, `/networks`, `/:scanId/hosts`, `/compare`, `/status/:scanId` | `scan.view` |
| scans `GET /route` | `scan.route.view` |
| scans `POST /:scanId/cancel` | `scan.cancel` |
| scans `POST /drift-audit` | `scan.drift.run` |
| scans `POST /active` | `requireAction('scan.active.run', 'scan.passive.run')`. In the handler, after validation, refuse with 403 `refusalMessage` when `!hasAction(user, scanActionFor(body.scan_type))`. |

- [ ] **Step 1: Write a failing test** in `workers/src/lib/actions.test.ts`:

```ts
test('scan type picks its action', () => {
  assert.equal(scanActionFor('active'), 'scan.active.run')
  assert.equal(scanActionFor('passive'), 'scan.passive.run')
})
```

Import it from `../routes/scans`. If bundling the route pulls in Worker-only modules and fails, move `scanActionFor` into `actions.ts` and import it from there.

- [ ] **Step 2: Run** `npm test`. Expected: FAIL.
- [ ] **Step 3: Apply the table.**
- [ ] **Step 4: Run** `npm test` and `npx tsc --noEmit -p workers`. Expected: PASS. Then run the guard test without `todo`, locally: no offenders in `assets.ts`, `sbom.ts` or `scans.ts`.
- [ ] **Step 5: Commit:** `git commit -am "feat(rbac): asset, SBOM and scan routes guarded by actions"`

---

### Task 5: Convert alert, advisory, assistant routes and the knowledge-graph chatbot

**Files:**
- Modify: `workers/src/routes/events.ts`, `workers/src/routes/advisories.ts`, `workers/src/routes/chatbot.ts`
- Modify: `workers/src/kg/access.ts:15-19`, `workers/src/kg/agent.ts:61-62,163,290,657,666`, `workers/src/kg/confirm.ts:77`, `workers/src/mcp/tools.ts:53-59`
- Test: `workers/src/kg/confirm.test.ts` (update)

**Interfaces:**
- Consumes: `decide`, `requireAction` (Tasks 1 and 3).
- Produces:
  - `analystAccess(user: { role: string; tenantId?: string | null; actions: readonly string[] }): boolean`, in `kg/access.ts`. It is true when `decide` is ok for all of `asset.view`, `alert.view` and `advisory.view`.
  - `ConfirmUser` gains `actions: readonly string[]`.

| Endpoint | Action |
|---|---|
| events `GET /`, `/stats/summary`, `/:eventId`, `/:eventId/windows-cves`, `/:eventId/cves` | `alert.view` |
| events `GET /assignees` | `requireAction('alert.manage', 'advisory.update')` |
| events `PATCH /:eventId`, `POST /:eventId/acknowledge` | `alert.manage` |
| events `POST /bulk` | `alert.bulk_update` |
| events `POST /:eventId/advisory` | `advisory.generate` |
| advisories `GET /`, `GET /:advisoryId` | `advisory.view` |
| advisories `PATCH /:advisoryId/status` | `advisory.update` |
| chatbot `POST /`, `POST /categorize` | `chatbot.use` |
| chatbot `POST /confirm` | `advisory.close_via_chat` |

In the chatbot code:
- **kg/access.ts:** replace `analyst: user.role !== 'business_owner'` with `analyst: analystAccess(user)`.
- **kg/agent.ts:**
  - Delete `ADVISORY_STATUS_ROLES`. Every `includes(user.role)` check becomes `decide(user, 'advisory.close_via_chat').ok`.
  - Lines 163 and 666 test `role === 'business_owner'`. Change them to `!analystAccess(user)`.
- **kg/confirm.ts:77:** use `decide(user, 'advisory.close_via_chat').ok`.
- **mcp/tools.ts:** tools that propose an action need `advisory.close_via_chat`. Other tools need `analystAccess(user)`. Delete both role lists.
- **routes/chatbot.ts:** pass `actions` through wherever it builds the `user` objects for these modules.

- [ ] **Step 1: Update `kg/confirm.test.ts`.** The fixture becomes `{ userId: 'u1', role: 'tenant_user', tenantId: T, actions: ['advisory.view', 'advisory.update', 'chatbot.use', 'advisory.close_via_chat'] }`. The "refused" case loops over:
  - `{ role: 'tenant_user', actions: ['advisory.view'] }`
  - `{ role: 'superadmin', actions: [] }`

  Add one test: `analystAccess` is true for the viewer preset, and false for `MIGRATION_ACTIONS.business_owner`.
- [ ] **Step 2: Run** `npm test`. Expected: FAIL on the changed fixtures.
- [ ] **Step 3: Apply the table and the chatbot changes.**
- [ ] **Step 4: Run** `npm test` and `npx tsc --noEmit -p workers`. Expected: PASS. Then run `grep -rn "business_owner\|tenant_admin\|ADVISORY_STATUS_ROLES\|ANALYST_ROLES" workers/src/kg workers/src/mcp`. Expected: no output.
- [ ] **Step 5: Commit:** `git commit -am "feat(rbac): alerts, advisories and assistant guarded by actions"`

---

### Task 6: Convert threat-intel, network, report and dashboard routes

**Files:**
- Modify: `workers/src/routes/cti.ts`, `tiEvents.ts`, `network.ts`, `topology.ts`, `relationships.ts`, `reports.ts`, `dashboard.ts`, `posture.ts`, `notifications.ts`
- Modify: `frontend/src/pages/ThreatIntelPage.jsx:130` (remove the Refresh feeds button and its handler)

| Endpoint | Action |
|---|---|
| cti `GET /indicators`, `/stats`, `/attack`, `/matrix`, `/lookup` | `cti.view` |
| cti `GET /debug` | `requirePlatformSuperadmin` |
| cti `POST /ingest` | **Delete the route.** The cron queues `cti_ingest` directly (`cron/triggers.ts:75`). |
| tiEvents `GET /`, `GET /:id` | `ti_event.view` |
| tiEvents `POST /` | `ti_event.create` |
| tiEvents `PATCH /:id`, `POST /:id/attributes`, `PATCH /:id/attributes/:attrId`, `DELETE /:id/attributes/:attrId` | `ti_event.edit` |
| tiEvents `POST /:id/publish`, `POST /:id/unpublish` | `ti_event.publish` |
| tiEvents `DELETE /:id` | `ti_event.delete` |
| network `GET /links`, `GET /map`; topology `GET /` | `network.view` |
| network `POST /run/:agentId` | `network.map.run` |
| topology `POST /nodes`, `DELETE /nodes/:nodeId`, `POST /infer` | `topology.edit` |
| relationships `GET /graph/:assetId`, `GET /blast-radius/:assetId` | `relationship.view` |
| relationships `POST /infer`, `POST /` | `relationship.manage` |
| relationships `DELETE /:relationshipId` | `relationship.delete` |
| reports `GET /data`, `GET /list` | `report.view` |
| reports `GET /download/:filename` | `report.download` |
| reports `POST /generate`, `POST /upload` | `report.generate` |
| reports `DELETE /delete/:filename` | `report.delete` |
| reports `POST /snapshot` | `report.snapshot` |
| dashboard `GET /summary`; posture `GET /current`, `GET /history`; notifications `GET /`, `GET /count` | `dashboard.view` |

In `tiEvents.ts`, branches that let the superadmin write platform-wide events (no `tenant_id`) become unreachable, because `decide` refuses the write. Remove them. Reading platform-wide events stays as it is.

- [ ] **Step 1: Apply the table.**
- [ ] **Step 2: Run** `npm test` and `npx tsc --noEmit -p workers`. Expected: PASS, with no guard offenders in these nine files. Then run `cd frontend && npx vite build`. Expected: build succeeds.
- [ ] **Step 3: Commit:** `git commit -am "feat(rbac): threat intel, network, reports and dashboard guarded by actions; feed refresh is schedule-only"`

---

### Task 7: Convert agent, enrolment and tenant routes, and the user-access API

**Files:**
- Create: `workers/src/lib/policyChange.ts`; test in `workers/src/lib/policyChange.test.ts`
- Modify: `workers/src/routes/agents.ts`, `enrolment.ts`, `tenants.ts`
- Modify: `workers/src/lib/userAdmin.ts` and its test
- Delete: `workers/src/lib/permissions.ts`; `requireRoles` and `requireTenantAccess` in `middleware/auth.ts`
- Modify: `workers/src/lib/routeGuard.test.ts` (remove `todo` and the two tenants allowlist entries)

**Interfaces:**
- Consumes: `ROLE_KEYS` from `lib/agentPolicy.ts`; `withRequirements`, `isActionKey` (Task 1); the guards (Task 3).
- Produces:
  - `policyChangeActions(body: { settings?: Record<string, unknown>; roles?: Record<string, boolean> }): ActionKey[]`. It always includes `agent.configure`. It adds `agent.roles.assign` when `roles` is non-empty, or when `settings` touches any key in `Object.values(ROLE_KEYS).flat()`. It adds `agent.sightings.enable` when `settings` has `sightings`.
  - `parseActionList(input: unknown): { ok: true; actions: ActionKey[] } | { ok: false; unknown: string[] }`. The input must be an array of strings. The result is the closure via `withRequirements`. Unknown keys are reported, not dropped.
  - `addRefusal(caller: Account, target: Account, tenantId: string): Refusal | null`. The `role` parameter and the `'role'` refusal are removed. A tenant superadmin may add only accounts with no tenant (or already in theirs), never a superadmin and never another tenant superadmin.
  - `PUT /api/v1/tenants/:tenantId/users/:userId/actions`, body `{ actions: string[] }`, guarded by `requireTenantSuperadmin`. The target must be a `tenant_user` in this tenant, otherwise 404. Unknown keys return 400 `Unknown actions: a, b`. The closure is stored. Audit `user.actions` with `{ previousState, newState, added, removed }`. Response: `{ actions, added_requirements }`, where `added_requirements` is the closure minus the request.

| Endpoint | Guard |
|---|---|
| agents `GET /`, `GET /:agentId`, `GET /:agentId/policy` | `agent.view`. The policy response's `canEdit` becomes `hasAction(user, 'agent.configure') && !retired`. |
| agents `GET /installer`, `GET /installer/download` | `agent.installer.download` |
| agents `POST /`; enrolment `GET /tokens`, `POST /tokens`, `DELETE /tokens/:id` | `agent.enrol` |
| agents `PATCH /:agentId` | `agent.rename` |
| agents `PATCH /:agentId/policy` | `agent.configure`, plus an in-handler check that the user holds every key in `policyChangeActions(body)`. Otherwise 403 with the first missing key's `refusalMessage`. |
| agents `POST /:agentId/rotate-key` | `agent.key.rotate` |
| agents `DELETE /:agentId` | `agent.remove` |
| tenants `GET /`, `POST /`, `DELETE /:tenantId` | `requirePlatformSuperadmin` (until Plan 3) |
| tenants `GET /:tenantId` | `settings.view`. A tenant user may read only their own tenant. |
| tenants `PATCH /:tenantId` | Platform Superadmin: `is_active` only (until Plan 3). Tenant Superadmin of that tenant: `name`. `auto_investigate_new_devices` and `allow_local_scans` need `settings.scan_policy.edit` in the handler. Any other caller or field: 403. |
| tenants `GET /:tenantId/agent-policy` | `requireAction('settings.view', 'agent.view')` |
| tenants `PATCH /:tenantId/agent-policy` | `settings.agent_defaults.edit` |
| tenants `GET /:tenantId/users` | `requireAction('settings.view')` for the Platform Superadmin (read-only). Otherwise `requireTenantSuperadmin`. Each row includes `role` and `actions`. |
| tenants `POST /:tenantId/users` (assign existing) | `requireTenantSuperadmin`. The account becomes `tenant_user` with `actions = '{}'`. |
| tenants `POST /:tenantId/users/invite` | Tenant Superadmin: body `{ email, username?, actions?: string[] }`, creating a `tenant_user` with the parsed actions. **Interim, until Plan 3:** the Platform Superadmin may call it only with `as_tenant_superadmin: true`, and only when the tenant has no Tenant Superadmin. Otherwise 409 "This tenant already has a Tenant Superadmin." |
| tenants `PATCH /:tenantId/users/:userId/role` | **Delete.** |
| tenants `PATCH /:tenantId/users/:userId/deactivate` | `requireTenantSuperadmin`. Refuse when the target is the caller, or a `tenant_superadmin`: "The Tenant Superadmin can only change through an ownership transfer." |

- [ ] **Step 1: Write the failing tests.**

```ts
// policyChange.test.ts
test('plain setting needs configure only', () =>
  assert.deepEqual(policyChangeActions({ settings: { inventory_interval: 3600 } }), ['agent.configure']))
test('role toggle or role setting needs roles.assign', () => {
  assert.ok(policyChangeActions({ roles: { scanner: false } }).includes('agent.roles.assign'))
  assert.ok(policyChangeActions({ settings: { passive: true } }).includes('agent.roles.assign'))
})
test('sightings needs sightings.enable', () =>
  assert.ok(policyChangeActions({ settings: { sightings: true } }).includes('agent.sightings.enable')))
// userAdmin.test.ts (replace the role cases)
test('parseActionList closes requirements and reports unknown keys', () => {
  assert.deepEqual(parseActionList(['alert.manage']), { ok: true, actions: ['alert.view', 'alert.manage'] })
  assert.deepEqual(parseActionList(['asset.veiw', 'x']), { ok: false, unknown: ['asset.veiw', 'x'] })
  assert.deepEqual(parseActionList('asset.view'), { ok: false, unknown: ['asset.view'] })
})
```

- [ ] **Step 2: Run** `npm test`. Expected: FAIL.
- [ ] **Step 3: Implement the helpers and apply the table.** Then delete `permissions.ts`, `requireRoles`, `requireTenantAccess`, the `superadminOnly`, `tenantAdminAccess` and `tenantViewAccess` spreads, and `mayGrantRole`. Remove `todo` and the two tenants entries from `routeGuard.test.ts`.
- [ ] **Step 4: Run** `npm test` (all PASS, guard test included, with zero offenders) and `npx tsc --noEmit -p workers` (no errors). Then run `grep -rn "business_owner\|tenant_admin\|requireRoles\|_ROLES\b" workers/src --include=*.ts | grep -v "actions.ts\|\.test\.ts"`. Expected: no output.
- [ ] **Step 5: Commit:** `git commit -am "feat(rbac): agents, enrolment, tenant settings and user access API on actions; role lists removed"`

---

### Task 8: Frontend foundation

**Files:**
- Create: `frontend/src/utils/actions.js`, `frontend/src/utils/actions.test.js`
- Modify: `frontend/src/context/AuthContext.jsx`, `frontend/src/components/common/ProtectedRoute.jsx`, `frontend/src/App.jsx:23-27,57-87`, `frontend/src/components/layout/navConfig.js`, `CommandPalette.jsx:37,67`, `Sidebar.jsx:66-67`, `Header.jsx:313`

**Interfaces:**
- Consumes: `GET /auth/me` (`role`, `actions`) and `GET /auth/actions` (Task 3).
- Produces:
  - `useAuth()` adds `can(key: string): boolean`, `catalog: { groups, actions, presets } | null`, and `refreshUser(): Promise<void>`.
  - `can` mirrors `decide`:
    - superadmin: true only when the catalog marks the action `read_only`
    - tenant_superadmin: true
    - otherwise: `user.actions.includes(key)`
  - `<ProtectedRoute action="asset.view">`: the `allowedRoles` prop is removed. The refusal text is "You do not have access to this page. Ask your Tenant Superadmin for access."
  - `buildNavSections(can, role)` in `navConfig.js`.
  - In `utils/actions.js`: `withRequirements(keys, catalog)`, `dependentsOf(key, catalog)`, `matchPreset(keys, catalog)` (same semantics as Task 1) and `roleLabel(role)`. `roleLabel` maps `superadmin` to "Platform Superadmin", `tenant_superadmin` to "Tenant Superadmin" and `tenant_user` to "Tenant user".

**Routes and navigation:**

| Page route or nav item | Action |
|---|---|
| `/` dashboard | `dashboard.view` |
| `inventory`, `inventory/:assetId` | `asset.view` |
| `discovery` | `scan.view` |
| `network-map` | `network.view` |
| `alerts` | `alert.view` |
| `advisories` | `advisory.view` |
| `threat-intel` | `cti.view` |
| `sbom` | `sbom.view` |
| `reports` | `report.view` |
| `agents` | `agent.view` |
| `settings` | Every signed-in user. Profile, password and MFA live there. Tenant sections inside check `settings.view`. |
| `users` | `role === 'tenant_superadmin'` |
| `tenants` | `role === 'superadmin'` |

A nav item is hidden when its action fails `can()`. Tenant users with no view actions see only Settings. Their dashboard route shows: "You have no access yet. Ask your Tenant Superadmin to grant you actions."

- [ ] **Step 1: Write the failing test** `frontend/src/utils/actions.test.js` (`node:test`). Use a small inline catalog fixture: `a.view`, `a.edit` requiring `a.view`, `a.bulk` requiring `a.edit`, and one preset `p` = [`a.view`].

```js
test('withRequirements', () => assert.deepEqual(withRequirements(['a.bulk'], cat), ['a.view', 'a.edit', 'a.bulk']))
test('dependentsOf', () => assert.deepEqual(dependentsOf('a.view', cat).sort(), ['a.bulk', 'a.edit']))
test('matchPreset', () => { assert.equal(matchPreset(['a.view'], cat), 'p'); assert.equal(matchPreset(['a.view', 'a.edit'], cat), null) })
test('roleLabel', () => assert.equal(roleLabel('tenant_user'), 'Tenant user'))
```

- [ ] **Step 2: Run** `cd frontend && node --test src/utils/actions.test.js`. Expected: FAIL.
- [ ] **Step 3: Implement** the helpers, `AuthContext` (fetch `/auth/actions` once after sign-in; `refreshUser` re-reads `/auth/me`), `ProtectedRoute`, `App.jsx`, `navConfig`, `CommandPalette`, and the role labels in `Sidebar` and `Header`.
- [ ] **Step 4: Run** `node --test src/utils/actions.test.js` (PASS) and `npx vite build` (succeeds).
- [ ] **Step 5: Commit:** `git commit -am "feat(rbac): frontend can(), action-based routes and navigation"`

---

### Task 9: Frontend controls follow actions

**Files (modify):** `pages/AdvisoriesPage.jsx:23-24`, `AgentsPage.jsx:282-283,484`, `AlertsPage.jsx:73-74`, `AssetDetailPage.jsx:68-71,657`, `DiscoveryPage.jsx:239-240,470`, `InventoryPage.jsx:101`, `components/threatintel/TiEventsPanel.jsx:36,523`, `components/chat/ChatWidget.jsx:355-360,505-506,707`, `components/agents/AgentPanel.jsx`, plus any control found by step 1 in `ReportsPage`, `SBOMPage`, `NetworkMapPage` and `DashboardPage`.

**Rule:** each button, menu item or form calls one endpoint. It renders only when `can(<that endpoint's action from Tasks 4-7>)`. Use the exact action, never a coarser stand-in. Specifics the rule alone does not settle:
- **Discovery:** the scan-type choice in `NewScanModal` offers only the types the user can run.
- **AgentPanel:**
  - Role switches are disabled without `agent.roles.assign`.
  - The sightings switch is disabled without `agent.sightings.enable`.
  - Each disabled control has the tooltip "Requires the "<label>" action."
- **ScanPolicyCard:** `canEdit` becomes `can('settings.scan_policy.edit')`.
- **ChatWidget:**
  - `QUICK` entries take `action` instead of `roles`: Assets uses `asset.view`, Alerts uses `alert.view`, Advisories uses `advisory.view`, and the others use `null`.
  - `canDebugAI` becomes `can('alert.manage')`.
- **TiEventsPanel:** `canWrite` splits into the four `ti_event.*` checks. `isMine` stays.

- [ ] **Step 1: List the role checks:** `cd frontend && grep -rnE "user\?\.role|\.role ===|_ROLES|isBusinessOwner|canManage|canScan|canWrite|canDelete" src`. Every hit outside `TenantSelector.jsx` (which scopes the superadmin's tenant picker), `AuthContext.jsx`, `utils/actions.js` and `ProtectedRoute` is converted.
- [ ] **Step 2: Convert the hits**, following the rule and the specifics above.
- [ ] **Step 3: Run** the step 1 grep again. Expected: only the four allowed files. Then run `npx vite build`. Expected: build succeeds.
- [ ] **Step 4: Commit:** `git commit -am "feat(rbac): every control shows only with its action"`

---

### Task 10: The grant screen (Users page)

**Files:**
- Create: `frontend/src/components/users/ActionPicker.jsx`
- Modify: `frontend/src/pages/TenantSettingsPage.jsx` (role dropdown at :224 removed), `frontend/src/pages/TenantsPage.jsx:348` (role dropdown removed; users list read-only; interim invite)

**Interfaces:**
- Consumes: `catalog`, `withRequirements`, `dependentsOf`, `matchPreset`, `roleLabel` (Task 8); `PUT /tenants/:id/users/:userId/actions`, `POST /tenants/:id/users/invite` (Task 7).
- Produces: `<ActionPicker value={string[]} onChange={(next: string[]) => void} catalog={catalog} />`, a controlled component with no API calls of its own.

**ActionPicker behaviour (copy is fixed):**
- **Preset row:** three buttons, "Viewer", "Analyst" and "Operator", each with its description underneath. Clicking one replaces the selection with that preset's actions.
- **Summary line:** "Matches: Analyst · 27 actions" or "Custom · 31 actions". An empty selection shows "No access".
- **Groups:**
  - One collapsible section per catalog group, showing "<n> of <m>".
  - Each action row shows a checkbox, the label, the description and an impact badge: Low (neutral), Medium (amber), High (red).
  - High rows also show "Not in any preset. Review before granting."
- **Ticking an action:**
  - Add its closure.
  - When this adds actions, show an inline note under the row for 6 seconds: "Also added: View alerts, Manage alerts".
- **Unticking an action that others depend on:**
  - Open a confirm dialog: "Removing "View alerts" also removes: Manage alerts, Bulk-update alerts, Run drift check. Remove all 4?"
  - Buttons: "Remove all" and "Cancel".

**TenantSettingsPage (Tenant Superadmin only):**
- **User table columns:** Name, Email, Access, Status, Actions menu.
  - Access shows "Tenant Superadmin · all actions" (not editable), "Matches: Viewer", "Custom · 12 actions" or "No access".
- **Edit access:** opens a side panel with `ActionPicker`, then Save and Cancel.
  - Save sends PUT. On success it shows the toast "Access updated for <name>."
  - If the response's `added_requirements` is non-empty, the toast adds "Also granted: …".
  - On 400 it shows the server's `detail`.
- **Invite form:** email, optional username, and an `ActionPicker` that starts empty. Helper text: "New users start with no access until you grant actions."
- **Deactivate:** unchanged, but hidden on the Tenant Superadmin row.

**TenantsPage (Platform Superadmin):**
- The users list is read-only: Access column, no edit controls.
- If the tenant has no Tenant Superadmin, show "Invite Tenant Superadmin" (email). This calls invite with `as_tenant_superadmin: true`.

- [ ] **Step 1: Build `ActionPicker`** against the fixed copy and behaviour above.
- [ ] **Step 2: Wire `TenantSettingsPage` and `TenantsPage`.** Delete their `/role` calls and the role dropdowns.
- [ ] **Step 3: Run** `npx vite build` (succeeds). Then run `grep -rn "/role'" src` and `grep -rn "users/\${[^}]*}/role" src`. Expected: no output.
- [ ] **Step 4: Commit:** `git commit -am "feat(rbac): grant screen with presets, impact levels and dependency confirmation"`

---

### Task 11: Staging rollout and smoke check

**Files:** none (operations). Results are recorded in the PR description.

- [ ] **Step 1: Check the data.** Run `cd workers && node scripts/db/check-0035.mjs staging`. Expected: a report. Show it to the user if any tenant has more than one Tenant Superadmin.
- [ ] **Step 2: Migrate staging.** Run `npm run db:migrate:staging`. Expected: `0035_action_based_access` applied. Then re-run the check. Expected: role counts show only `superadmin`, `tenant_superadmin` and `tenant_user`.
- [ ] **Step 3: Deploy staging.**
  - Worker: `npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`
  - Frontend: `cd ../frontend && env $(env | grep -oE '^VITE_[A-Z_]+' | sed 's/^/-u /') npm run deploy:staging`
  - Then check the live `assets/index-*.js`: it must contain the staging API host, and `localhost:8000` must appear 0 times.
- [ ] **Step 4: Smoke-test against the staging API** with `curl` and one token per account kind.

  | # | Caller | Request | Expected |
  |---|---|---|---|
  | a | Tenant user with the Viewer preset | `GET /assets` | 200 |
  | b | same | `POST /assets` | 403 with `missing_action: "asset.create"` |
  | c | same, after the Tenant Superadmin grants `asset.create` | `POST /assets`, no new sign-in | 201 |
  | d | Platform Superadmin | `GET /assets?tenant_id=…` | 200 |
  | e | Platform Superadmin | `PATCH /assets/:id` | 403 with the read-only message |
  | f | Tenant Superadmin | `PUT …/actions` with `["asset.veiw"]` | 400 `Unknown actions: asset.veiw` |
  | g | Tenant user deactivated while signed in | next request | 401 with the deactivated message |
  | h | Former business_owner | the user's actions | exactly the 13 migrated actions |
  | i | Former tenant_admin | the user's actions | exactly 53 |

- [ ] **Step 5: Check the browser** as each account kind. The menu shows only permitted pages. Controls without their action are hidden or disabled with the tooltip. The grant screen's presets, dependency notice and removal confirmation behave as in Task 10.
- [ ] **Step 6: Stop and ask the user** before touching production. The database is shared with a teammate: their running code still expects the old roles, and 0035 changes the enum under it.
