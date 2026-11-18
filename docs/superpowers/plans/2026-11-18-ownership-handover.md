# Tenant Ownership Handover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ownership of a tenant can move without database access when a Tenant Superadmin resigns or is terminated, by three paths:
- **Path A:** a planned transfer;
- **Path B:** emergency recovery by a successor and 2 approvers;
- **Path C:** a platform-verified restore.

Every path keeps exactly one owner.

**Architecture:**
- **Pure logic.** State machines and validation live in `workers/src/lib/ownership.ts`.
- **One swap function.** Every ownership change goes through `swapOwner()`. It runs in one transaction and demotes the old owner before promoting the new one, so the unique index `uq_users_one_tenant_superadmin` never sees two owners.
- **Time-based steps settle lazily.** Expiry and the 72-hour hold have no staging cron. `settleOwnership()` runs whenever the tenant's ownership state is read or acted on, and at sign-in.
- **Notices.** In-app notices live in a new `tenant_notices` table.

**Tech Stack:** Hono, Drizzle (Neon Postgres), React 18, `node:test`, wrangler.

**Spec:** docs/superpowers/specs/2026-11-17-action-based-access-control-design.md, section 6 (and 4, 5).
**Depends on:** docs/superpowers/plans/2026-11-18-mandatory-mfa.md:
- step-up confirmation (`stepUpOk` and the password-plus-code check);
- `sendMail`;
- `users.sessions_valid_after`;
- `sessionGate`.

Run this plan after that one.

## Global Constraints

- Exactly one Tenant Superadmin per tenant at every moment. Never none and never two.
- Every step needs the actor's password and MFA code (step-up as in the MFA plan), and is written to the tenant audit log.
- **Path A, planned transfer:**
  - Started by the current owner. The recipient is an active user of the tenant.
  - The owner chooses what happens to their own account afterwards:
    - `stay`, with chosen actions;
    - `deactivate_on`, with a date and actions kept until then;
    - `deactivate_now`.
  - The recipient has 72 hours to accept or decline. The owner can cancel before acceptance.
  - One pending transfer per tenant.
- **Recipient message, verbatim with placeholders:** "[Name] wants to make you the Tenant Superadmin of [Tenant]. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. [Name] will become a Tenant user [or: will be deactivated on date]."
- **Path B, emergency recovery:**
  - The owner sets in advance a successor and two recovery approvers: three distinct active users of the tenant, none of them the owner.
  - **Banner** to the owner until all three are set, verbatim: "No recovery plan. If you lose access, your tenant cannot recover without platform verification."
  - **Reasons:** `terminated`, `compromised`, `resigned`, `unreachable`. UI labels: "Terminated", "Account compromised", "Resigned without handover", "Unreachable".
  - **Approvals:** both approvers must approve within 72 hours, or the request expires.
  - **Terminated or compromised:** the change takes effect at once. The former owner is suspended: deactivated, signed out everywhere, and blocked.
  - **Resigned or unreachable:** a 72-hour hold begins. The former owner is emailed and can cancel with step-up, which marks the request `disputed` (the case then goes to Path C). If nobody cancels, ownership moves when the hold ends.
- **Path C, platform restore:**
  - Run by the Platform Superadmin only: "Restore tenant ownership".
  - It suspends the former owner and invites the named person as the Tenant Superadmin, using the existing invite.
  - The Platform Superadmin gains no tenant access.
  - Every tenant user sees for 30 days, verbatim: "Ownership of this tenant was restored by platform verification on [date]."
- **All paths:**
  - All tenant users get the in-app notice, verbatim: "Tenant ownership changed from [A] to [B] on [date]."
  - The former owner, the new owner and the approvers are emailed at each step through `sendMail`. Email may be unconfigured; the in-app notice still appears.
- **Done automatically after Path B or C:**
  - sign the former owner out (`sessions_valid_after = now()`);
  - revoke all unused agent enrolment tokens of the tenant.
- **After every swap:** the former and the new owner are removed from the successor and approver positions.
- **New owner's first sign-in:** a security checklist with these items:
  - "Review every user's actions";
  - "Choose a new successor and recovery approvers";
  - "Reassign alerts and advisories assigned to the former owner";
  - after Path B or C only: "Consider replacing agent keys".
- The former owner's account is never deleted.
- Staging only. Never touch production.

## Review Focus

1. **Two accept clicks at once:** two concurrent accepts, or an accept racing a cancel, give exactly one owner, never two or none. Pinned by the Task 2 test `swap runs demote before promote in one transaction`, and Task 3's guarded `UPDATE ... WHERE status='pending'` state check.
2. **Acting on an expired request:** a transfer or recovery past 72 hours cannot be accepted or approved, and shows as expired. Pinned by the Task 2 test `expired transitions are refused`.
3. **Approving your own recovery:** the successor cannot also count as an approver, and the same approver cannot approve twice. Pinned by the Task 2 test `approvals need two distinct approvers, not the successor`.
4. **A deactivation date in the past:** a `deactivate_on` date already past at transfer time is refused. After it passes, sign-in and API both refuse the account. Pinned by the Task 2 test `deactivate_on must be in the future` and the Task 5 sessionGate test.
5. **A plan holding a departed user:** a recovery plan naming a user who was later deactivated can no longer be used to start a recovery. Pinned by the Task 2 test `inactive successor or approver cannot act`.

---

### Task 1: Migration 0039 (additive) and schema

**Files:**
- Create: `workers/drizzle/0039_ownership.sql`, plus its snapshot and journal (via `npm run db:generate`, renamed)
- Modify: `workers/src/db/schema.ts`
- Test: `workers/src/lib/migration0039.test.ts`

**Interfaces:**
- Produces:
  - `users.scheduled_deactivation_at timestamptz NULL`
  - **`ownership_transfers`**:
    - `transfer_id uuid pk`
    - `tenant_id fk cascade`
    - `from_user_id fk`
    - `to_user_id fk`
    - `after_mode varchar(16) not null`
    - `after_actions text[] not null default '{}'`
    - `deactivate_on timestamptz null`
    - `status varchar(16) not null default 'pending'`
    - `created_at`
    - `expires_at not null`
    - `decided_at null`
    - Partial unique index on `(tenant_id) WHERE status='pending'`.
  - **`tenant_recovery_plans`**:
    - `tenant_id uuid pk fk cascade`
    - `successor_id fk null`
    - `approver1_id fk null`
    - `approver2_id fk null`
    - `updated_at`
  - **`ownership_recoveries`**:
    - `recovery_id uuid pk`
    - `tenant_id fk cascade`
    - `successor_id fk`
    - `former_owner_id fk`
    - `reason varchar(16)`
    - `status varchar(20) not null default 'awaiting_approval'`
    - `approver1_at timestamptz null`
    - `approver2_at timestamptz null`
    - `created_at`
    - `expires_at not null`
    - `hold_until null`
    - `completed_at null`
    - Partial unique index on `(tenant_id) WHERE status IN ('awaiting_approval','on_hold')`.
  - **`tenant_notices`**:
    - `notice_id uuid pk`
    - `tenant_id fk cascade`
    - `user_id fk null` (null = every user of the tenant)
    - `kind varchar(32)`
    - `body text`
    - `created_at`
    - `expires_at null`
    - `dismissed_at null`
  - User foreign keys use `on delete set null` where nullable, otherwise `restrict`. Users are never deleted.

- [ ] **Step 1:** Test that the SQL creates these tables, the column and both partial unique indexes, and has no `DROP`, `TRUNCATE`, `UPDATE` or `DELETE`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test`, `npx tsc --noEmit` and `npm run db:generate` (no changes). Expected: PASS.
- [ ] **Step 5:** Commit `feat(db): 0039 adds ownership transfers, recovery plans and recoveries, tenant notices`.

### Task 2: Ownership core logic (`lib/ownership.ts`)

**Files:**
- Create: `workers/src/lib/ownership.ts`, `workers/src/lib/ownership.test.ts`

**Interfaces:**
- Produces:
  - `validateTransfer({ ownerId, toUser: { userId, tenantId, isActive, role }, tenantId, after: { mode, actions?, deactivateOn? }, now }): string | null`. Returns an error message or null. Rules:
    - the recipient is an active `tenant_user` of the tenant and is not the owner;
    - the mode is one of the three;
    - `deactivate_on` is in the future;
    - actions pass `parseActionList`.
  - `validateRecoveryPlan({ ownerId, successor, approvers: [a, b], tenantId }): string | null`. Three distinct active tenant users, none the owner.
  - `transferNext(status, action: 'accept' | 'decline' | 'cancel' | 'expire', now, expiresAt): status | null`. Only `pending` moves, and `accept`/`decline` are refused after `expiresAt`.
  - `recoveryNext(r: { status, reason, approver1At, approver2At, expiresAt, holdUntil }, action: 'approve1' | 'approve2' | 'cancel_by_owner' | 'settle', now)`. Returns the new fields, or null.
    - When both approvals are in: `terminated`/`compromised` → `complete_now`; `resigned`/`unreachable` → `on_hold` with `holdUntil = now + 72h`.
    - `settle` completes an `on_hold` request past `holdUntil` and expires `awaiting_approval` past `expiresAt`.
  - `approverSlot(plan, userId, successorId): 'approver1' | 'approver2' | null`. Null for the successor or non-approvers.
  - `swapStatements(tenantId, fromId, toId, after)`: the ordered list of the two updates for `swapOwner`. First demote: `role='tenant_user'`, `actions` = after actions, `is_active = mode !== 'deactivate_now'`, `scheduled_deactivation_at`. Then promote: `role='tenant_superadmin'`, `actions='{}'`.
  - `ownershipChangedNotice(a, b, date)` and `restoredNotice(date)` render the verbatim texts.

- [ ] **Step 1: Write failing tests:**
  - `deactivate_on must be in the future`;
  - recipient rules (owner, inactive, other tenant, superadmin);
  - `approvals need two distinct approvers, not the successor`;
  - `expired transitions are refused` (transfer accept after 72 h; recovery approve after 72 h);
  - `swap runs demote before promote in one transaction` (statement order);
  - recovery paths for all 4 reasons;
  - `settle completes on_hold after 72h only`;
  - `inactive successor or approver cannot act`;
  - notice texts verbatim.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ownership): transfer and recovery rules, owner swap order, notice texts`.

### Task 3: Path A routes (planned transfer)

**Files:**
- Create: `workers/src/routes/ownership.ts` (mounted at `/api/v1/tenants` in `src/index.ts`, or merged into tenants.ts if mounting order makes that cleaner), `workers/src/services/ownership.ts` (DB side: `swapOwner`, `postNotice`, `settleOwnership`)
- Modify: `workers/src/index.ts`, `workers/src/lib/routeGuard.test.ts`

**Interfaces:**
- **`GET /tenants/:tenantId/ownership`** (any member of the tenant):
  - Calls `settleOwnership` first.
  - Returns `{ owner: {user_id, username}, pending_transfer?: {...}, recovery_plan?: {...} | null, recovery?: {...} | null, plan_complete: boolean }`.
  - Only the owner sees the plan's members. Others see only what concerns them (as recipient, successor, approver or former owner).
- **`POST /tenants/:tenantId/ownership/transfer`** (owner, step-up):
  - Body `{ to_user_id, after: { mode, actions?, deactivate_on? }, password?, code }`.
  - 409 if one is pending. Otherwise create it with `expires_at = now + 72h`.
  - Post a notice to the recipient with the verbatim message, and email them. Audit `ownership.transfer_requested`.
- **`DELETE /tenants/:tenantId/ownership/transfer`** (owner): cancel. Audit.
- **`POST /tenants/:tenantId/ownership/transfer/accept`** (recipient, step-up):
  - Guarded `UPDATE ownership_transfers SET status='accepted' ... WHERE transfer_id=$id AND status='pending' AND expires_at > now() RETURNING`. No row → 409 `This request is no longer open.`
  - Then `swapOwner` in the same transaction.
  - Remove both users from recovery positions, post the all-users notice and the new-owner checklist notice (`kind: 'owner_checklist'`), and email all parties. Audit `ownership.transferred`.
- **`POST /tenants/:tenantId/ownership/transfer/decline`** (recipient): decline. Audit.

- [ ] **Step 1:** Write failing tests for any extra pure mapping, e.g. `ownershipView(row, viewerId)` shows the plan only to the owner.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Use one DB transaction for accept plus swap (drizzle `db.transaction`, or the neon `sql.transaction` the code base already uses — check `getDb`).
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ownership): planned transfer with accept, decline, cancel`.

### Task 4: Path B routes (emergency recovery)

**Files:**
- Modify: `workers/src/routes/ownership.ts`, `workers/src/services/ownership.ts`

**Interfaces:**
- **`PUT /tenants/:tenantId/ownership/recovery-plan`** (owner, step-up): body `{ successor_id, approver_ids: [a, b], password?, code }`, checked with `validateRecoveryPlan`. Audit.
- **`POST /tenants/:tenantId/ownership/recovery`** (successor, step-up):
  - Body `{ reason, password?, code }`.
  - The plan must be complete, with all three members active. 409 if one is open.
  - Email and notify both approvers.
- **`POST /tenants/:tenantId/ownership/recovery/approve`** (approver, step-up):
  - Records the slot via `recoveryNext`.
  - When both approvals are in: complete at once, or set the 72-hour hold and email the former owner.
- **`POST /tenants/:tenantId/ownership/recovery/cancel`** (former owner during the hold, step-up): status `disputed`. Notify the successor and approvers: "Recovery was disputed. Contact platform support for verification."
- **Completion** (immediate, or by `settleOwnership` after the hold):
  - `swapOwner` with after `{ mode: 'deactivate_now' }`, so the former owner is suspended;
  - `sessions_valid_after = now()` for the former owner;
  - delete unused rows from `enrolment_tokens` for the tenant (check the table name in schema.ts);
  - remove both users from recovery positions;
  - post the notices, with the checklist including "Consider replacing agent keys".
  - Audit `ownership.recovered`.
- `settleOwnership(db, tenantId)` also runs at sign-in (Task 4 of the MFA plan: after MFA succeeds, for users with a tenant).

- [ ] **Step 1:** Write failing tests for the service's pure decisions not already covered, e.g. `completionEffects(reason)` returns `checklistHasAgentKeys: true`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ownership): emergency recovery with successor, two approvers and 72h hold`.

### Task 5: Path C, notices API, scheduled deactivation

**Files:**
- Modify: `workers/src/routes/ownership.ts`, `workers/src/routes/tenants.ts` (reuse the invite logic), `workers/src/middleware/auth.ts` / `sessionGate`, `workers/src/routes/auth.ts` (sign-in refuses past `scheduled_deactivation_at`)
- Create: `workers/src/routes/notices.ts` (mounted at `/api/v1/notices`)

**Interfaces:**
- **`POST /tenants/:tenantId/ownership/restore`** (`requirePlatformSuperadmin`, step-up):
  - Body `{ email, username?, password?, code }`.
  - In one transaction: demote and suspend the current owner, if any, and sign them out. Then invite the named person as Tenant Superadmin through the same code path as the interim invite (`as_tenant_superadmin`).
  - Revoke unused enrolment tokens. Post the 30-day `restoredNotice` to all users and the checklist to the new owner.
  - Audit `ownership.restored` with the tenant id. Return 201.
- **`GET /notices`** (authMiddleware, self-service): the caller's unexpired, undismissed notices, which are the tenant-wide ones plus their own.
- **`POST /notices/:id/dismiss`**: only for the caller's own notices (`user_id` = caller). Tenant-wide notices expire and are not dismissed.
- `sessionGate` gains a rule: `scheduled_deactivation_at <= now()` gives the deactivated 401. Sign-in refuses such accounts the same way. Extend the `sessionGate` test.

- [ ] **Step 1: Write failing tests:**
  - sessionGate scheduled-deactivation case;
  - `noticeVisible(notice, viewer, now)`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Register the routes in the route guard test.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ownership): platform restore, tenant notices, scheduled deactivation`.

### Task 6: Frontend ownership section

**Files:**
- Create: `frontend/src/components/ownership/OwnershipSection.jsx` (with sub-views), `frontend/src/utils/ownership.js` + `ownership.test.js`
- Modify: `frontend/src/pages/TenantSettingsPage.jsx` (adds the "Tenant ownership" section)

**Behaviour**, driven by `GET /ownership`:
- **Owner:**
  - "Transfer ownership" form:
    - recipient picker (active tenant users);
    - after-mode radio, with an action picker for `stay`/`deactivate_on` (reuse `ActionPicker`) and a date field;
    - password and code fields.
  - The pending transfer, with a Cancel button.
  - The recovery plan form: successor and two approvers.
  - The "No recovery plan" banner when the plan is incomplete.
- **Recipient:** the verbatim message, with Accept and Decline. Accept asks for password and code.
- **Successor:** "Start emergency recovery", with the reason choice and step-up.
- **Approver:** the open recovery, with "Approve" and step-up.
- **Former owner during the hold:** "Cancel this recovery", with step-up.
- **Everyone:** the current owner's name.

- [ ] **Step 1:** Write failing tests for `utils/ownership.js`: `viewFor(ownershipResponse, me)` returns which sub-view to show, and `afterModeLabel`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): tenant ownership: transfer, recovery plan, emergency recovery`.

### Task 7: Frontend notices, checklist, platform restore

**Files:**
- Create: `frontend/src/components/layout/NoticeBar.jsx`, `frontend/src/components/ownership/OwnerChecklist.jsx`
- Modify: `frontend/src/components/layout/MainLayout.jsx`, `frontend/src/pages/TenantsPage.jsx` (platform "Restore tenant ownership" dialog)

**Behaviour:**
- **NoticeBar:** shows `GET /notices` (tenant-wide and own). Own notices can be dismissed.
- **OwnerChecklist:** shows the checklist items for a `kind: 'owner_checklist'` notice, with links to:
  - the Users page;
  - the ownership section;
  - Alerts filtered by the former owner;
  - Agents.
  - "Done" dismisses it.
- **TenantsPage (Platform Superadmin):**
  - "Restore tenant ownership" opens a dialog explaining the verification rule, verbatim: "Verify the request by calling back the organisation contact on record. Do not use contact details given in the request itself."
  - Fields: email, username, password and code.

- [ ] **Step 1:** Write failing tests for any pure helper, e.g. `checklistItems(notice)`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): ownership notices, new-owner checklist, platform restore`.

### Task 8: Staging rollout (controller; needs owner go-ahead)

- [ ] **Step 0:** Tell the teammate before migrating: `0039` is taken, and her journal must include it before any `db:generate` or `db:push`.
- [ ] **Step 1:** `npm run db:status:staging`. Expected: pending exactly `0039_ownership`. Then migrate.
- [ ] **Step 2:** Deploy the worker, the system graph and the frontend (VITE_* unset). Check the bundle.
- [ ] **Step 3:** API smoke test in a temporary test tenant with 5 users (owner, recipient, successor, 2 approvers; all with MFA set up through the API):
  - **Path A:** transfer, accept → exactly one owner, and the former owner is `tenant_user` with the chosen actions. A second accept → 409. An expired request cannot be accepted (set `expires_at` in the past with SQL on the test row).
  - **Path B, terminated:** plan, start, approve ×2 → the former owner is suspended and their old token gets 401.
  - **Path B, resigned:** hold → the former owner cancels → `disputed`.
  - **Path C:** restore by the platform. Only if the owner provides a test platform login; otherwise mark it for a browser check.
  - **Notices:** they appear and are dismissable.
  - **Concurrency:** two parallel accepts of one transfer, and an accept racing a cancel. Exactly one call returns 200 and the tenant has exactly one owner. This also proves the `FOR UPDATE` lock statement runs on staging.
  - **Path B, resigned, completion:** set `hold_until` in the past by SQL on the test row, then call `GET /ownership`. Check the swap, a 401 for the former owner's old token, and that the test tenant's unused enrolment tokens are gone.
  - **Recovery expiry:** set `expires_at` in the past on an open recovery; `GET /ownership` marks it `expired` and its notices end.
  - **Scheduled deactivation:** set `scheduled_deactivation_at` in the past for a test user. Their token gets 401, sign-in is refused, and `is_active` flips.
  - **Non-owner UI (browser):** sign in as the recipient, then as an approver. Each reaches `/ownership` from the nav and from the notice link, and sees Accept, Decline or Approve.
  - Run every smoke step only in the temporary tenant. Restore and Path B revoke only that tenant's unused enrolment tokens, so existing agents are unaffected.
  - **Cleanup order:** delete the test tenant's audit rows first (`audit_logs.tenant_id` has no cascade), then the test tenant (it cascades the ownership tables and notices; the users' `tenant_id` becomes null), then audit rows of the test users, then the test users.
- [ ] **Rollback:** the previous worker is compatible with `0039` but ignores `scheduled_deactivation_at`. Roll the frontend back together with the worker.
- [ ] **Step 4:** Agents still online, the GET sweep shows no 5xx, and the user counts are unchanged. Record in the ledger. Stop.
