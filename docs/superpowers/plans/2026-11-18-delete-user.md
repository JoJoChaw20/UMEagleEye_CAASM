# Delete User Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Tenant Superadmin can permanently delete a Tenant user of their own tenant, and the deleted user's audit history is kept.

**Architecture:**
- Today `audit_logs.user_id` cascades on delete, which would erase a user's history. Migration 0038 changes it to `ON DELETE SET NULL` (added `NOT VALID`, then validated) and adds the nullable `audit_logs.actor_username varchar(100)`.
- The audit row already stores what happened. The delete itself writes an audit row that records the deleted username and email.
- The route reuses the step-up confirmation from the MFA plan (`stepUp` in `workers/src/services/mfaStepUp.ts`) and the target rule of the MFA reset (`resetTarget` in `workers/src/lib/mfaFlow.ts`).
- Deactivate and reactivate already exist (`PATCH /tenants/:tenantId/users/:userId/deactivate`) and stay as they are.

**Tech Stack:** Hono, Drizzle (Neon Postgres), React 18, `node:test`.

**Spec:** docs/superpowers/specs/2026-11-17-action-based-access-control-design.md, section 4.1.
**Order:**
- Run after the MFA plan's Task 8, because it needs `stepUp`. The MFA plan's staging rollout (its Task 9) then also applies 0038 and smoke-tests delete.
- The ownership-handover plan's migration becomes 0039.

## Global Constraints

- Only a Tenant Superadmin, only in their own tenant, and only a `tenant_user` target. Never the caller, the Tenant Superadmin, or the Platform Superadmin. Refusals give 404 `User not found in this tenant`, the same as the MFA reset.
- Confirmation: the caller's password and MFA code (code only for an account without a password), plus the body field `confirm_username`, which must equal the target's username exactly. Otherwise 400 `Type the username exactly to confirm.`
- Effects: the users row is deleted.
  - Assigned alerts and advisories become unassigned through the existing `ON DELETE SET NULL`.
  - Recovery codes and break-glass rows go through the existing cascade.
  - Audit rows keep their content and get `user_id = NULL`. In the same `db.batch` (one transaction), before the delete, they get `actor_username` = the target's username (column added by 0038), so history shows "<username> (deleted)" (spec 4.1), not "system".
- Audit entry `user.delete`, with `previousState: { user_id, username, email, actions }`, written **after** a successful delete, by the caller (a refused delete writes `user.delete_refused`; Ruling 1).
- If a foreign key refuses the delete (Postgres 23503, for example the ownership-history tables added later with `restrict`), answer 409 `This account is part of the tenant's ownership history and cannot be deleted. Deactivate it instead.`
- UI dialog text, verbatim: "Delete [username]? This removes the account permanently and cannot be undone. Their past actions stay in the audit log. To keep the account, deactivate it instead."
- Staging only.

## Review Focus

1. **Another tenant's user:** deleting a user of another tenant, the caller, or the owner is refused. Pinned by the Task 1 test `deleteTarget refuses self, owner, superadmin, other tenant`.
2. **Audit history survives:** after a delete, the audit history of that user stays. Pinned by the Task 1 migration test, which checks that the FK is `ON DELETE SET NULL`.
3. **Wrong-case username:** a typed username in the wrong case is refused. Pinned by the Task 1 test `confirm_username must match exactly`.

---

### Task 1: Migration 0038 and the delete route

**Files:**
- Create: `workers/drizzle/0038_audit_keeps_deleted_users.sql`, plus its snapshot and journal (via `npm run db:generate`, renamed), and `workers/src/lib/migration0038.test.ts`
- Modify: `workers/src/db/schema.ts` (`auditLogs.userId` → `onDelete: 'set null'`), `workers/src/routes/tenants.ts`, `workers/src/lib/mfaFlow.ts` (+ test)

**Interfaces:**
- **`DELETE /tenants/:tenantId/users/:userId`:**
  - Guard: `requireTenantSuperadmin`.
  - JSON body `{ password?, code, confirm_username }`.
  - Order: uuid check → load target in tenant → `deleteTarget` → `confirm_username` → `stepUp` on the caller → audit → delete.
  - Returns `{ ok: true }`.
- `deleteTarget(caller, target, tenantId)` is the same rule as `resetTarget`. Reuse it; if the rule is literally identical, export one function under a shared name and use it in both places.
- `confirmMatches(typed: unknown, username: string): boolean` is exact and case-sensitive.

- [ ] **Step 1: Write failing tests:**
  - `migration0038.test.ts`: the SQL drops the old FK and adds `audit_logs_user_id_users_user_id_fk` (or the generated name) with `ON DELETE set null`, and contains no `DELETE`, `UPDATE` or `TRUNCATE`;
  - `confirm_username must match exactly`;
  - `deleteTarget refuses self, owner, superadmin, other tenant`.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Map a Postgres 23503 error on the delete to the 409. Check that the route guard test passes.
- [ ] **Step 4:** Run `npm test`, `npx tsc --noEmit` and `npm run db:generate` (no changes). Expected: PASS.
- [ ] **Step 5:** Commit `feat(users): Tenant Superadmin deletes a user; audit history survives the delete`.

### Task 2: Users page "Delete user"

**Files:**
- Modify: `frontend/src/pages/TenantSettingsPage.jsx` (row menu ~line 439, next to Deactivate)
- Test: `frontend/src/utils/users.js` + `users.test.js`

**Behaviour:**
- The Tenant Superadmin sees "Delete user" (danger) in a Tenant user's row menu.
- The dialog shows the verbatim text, a "Type the username to confirm" field, and password (hidden for accounts without a password) and MFA code fields, reusing the step-up fields from the MFA plan's Task 8.
- The Delete button is disabled until the typed username matches exactly and a 6-digit code is entered. The dialog blocks a second click while a request is in flight.
- On success: the toast "[username] was deleted." and the row is removed.
- Errors show the server's message, including the ownership-history 409.

- [ ] **Step 1:** Write failing tests for `canConfirmDelete({ typed, username, code, needsPassword, password })`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): Tenant Superadmin can delete a user from the Users page`.
