# Mandatory MFA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make MFA required for every account at sign-in. Code checks must be reliable: they tolerate a small clock drift, refuse a reused code, and tie the code to the password step. Users get recovery codes. The Tenant Superadmin can reset a user's MFA. The Platform Superadmin gets a break-glass reset.

**Architecture:**
- **Sign-in.** A password or Google sign-in no longer returns an access token on its own. It returns a short-lived signed `mfa_token`. Either the user exchanges it for an access token with a valid code (`verify`), or they first set up MFA with it (`enrol`).
- **Middleware.** It refuses `mfa_token`s as access tokens. It signs users out everywhere through `users.sessions_valid_after`, and it refuses every non-`/auth` route to an account without MFA.
- **Pure logic.** TOTP, recovery codes and step-up live in `workers/src/lib/mfa.ts`, so they can be unit tested.
- **Email.** It goes through one mailer that skips quietly when email is not configured.

**Tech Stack:** Hono, Drizzle (Neon Postgres), jose (JWT), otplib (`authenticator`), React 18, `node:test`, wrangler.

**Spec:** docs/superpowers/specs/2026-11-17-action-based-access-control-design.md, section 7 (and section 1 general rules).

## Global Constraints

- Every account, the Platform Superadmin included, must have MFA. A new or existing account without MFA sets it up at sign-in before it can see anything. There is no grace period. Google sign-in also asks for the MFA code.
- TOTP: 6 digits, 30-second step, accept the current step ±1 (`window: 1`). A step that was already used for this account is refused.
- `mfa_token`: JWT signed with `JWT_SECRET_KEY`, claim `purpose: 'mfa'`, claim `stage: 'verify' | 'enrol'`. Lifetime: 5 minutes for `verify`, 15 minutes for `enrol`, so a user has time to install an authenticator app. `authMiddleware` must refuse any token that carries a `purpose` claim.
- Set-up is permanent, as in Microsoft or Google Authenticator. Once set-up finishes, the account entry in the app keeps working with no expiry. Only an MFA reset (by the Tenant Superadmin, or break-glass) replaces the secret. Nothing else may overwrite `totp_secret` of an enabled account: no timer, no new sign-in, no Settings action. Each sign-in asks for the 6-digit code the app shows at that moment.
- Set-up must not break on a retry, a slow user or a new sign-in:
  - `enrol/start` reuses the existing `mfa_pending_secret` when there is one, so the QR the phone already scanned stays valid. It makes a new secret only when the body says `{ new_secret: true }`, behind the UI button "Show a new QR code".
  - The pending secret is kept until set-up finishes or an MFA reset clears it.
- Clear messages instead of a bare "invalid code":
  - **Phone clock off:** when a code is not accepted but matches within ±10 steps, the answer is 401 `Your phone's clock is about N minutes off. Turn on automatic date and time on your phone, then try again.` It is still refused.
  - **Locked out:** the answer is 429 `Too many wrong codes. Try again in N minutes.`, with the real remaining time.
- Recovery codes: 10 per account, shown once, format `XXXXX-XXXXX` from the alphabet `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` (50 bits each). Store only their SHA-256 hex. Each works once. Input is case-insensitive and ignores spaces and dashes.
- "Sign out everywhere" = set `users.sessions_valid_after = now()`. A token whose `iat` (seconds) is earlier is refused with 401 `Your session has ended. Sign in again.`
- MFA failure limit: the existing KV limiter (`workers/src/lib/loginLimit.ts`, `mfa_account`, 5 per 15 minutes) applies to code and recovery-code attempts, keyed by user id. A success clears it.
- Step-up confirmation (MFA reset, regenerating recovery codes) needs the caller's password and current MFA code. For an account with no password (Google-only, `NO_PASSWORD_HASH`), the MFA code alone.
- Reset guidance text, verbatim: "Confirm this request in person or by phone. Do not reset MFA based only on an email or chat message, because these are common ways attackers take over accounts."
- Email to a reset user, verbatim: "Your MFA was reset by [Name] on [date]. If you did not ask for this, contact them immediately."
- Email is sent only through `sendMail` in `workers/src/services/mailer.ts`. Without the `EMAIL` binding and the `MAIL_FROM` var it logs and returns `{ sent: false }`, and it never throws into a request.
- Break-glass reset: one-time secret `PLATFORM_MFA_RESET` (wrangler secret), 24-hour hold after the email link is opened, cancel link in the same email. Only for role `superadmin`. It refuses with 503 when email is not configured. A secret value that was used once is refused afterwards.
- Every MFA event is audited through `audit()` in `workers/src/services/audit.ts`.
- Staging only. Never touch production. Worker deploy: `npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`. Frontend: unset VITE_* first.

## Review Focus

1. **A replayed code is refused:** a code used once is refused when sent again within its 30 seconds. Pinned by the Task 2 test `replay of the same step is refused`.
2. **A tampered token is refused:** an `mfa_token` with a changed signature or a wrong `purpose` cannot be exchanged, and an `mfa_token` is refused as an access token by every protected route. Pinned by the Task 3 test `mfa purpose token is not an access token`.
3. **An old session ends after an MFA reset:** a session that was open before the reset gets 401 on its next request. Pinned by the Task 3 test `token issued before sessions_valid_after is refused`.
4. **A recovery code works once:** using the same code a second time fails. Pinned by the Task 2 test `recovery code consumed once`.
5. **An existing user without MFA is forced to set it up:** they cannot reach data with an old token. Their next request gets 403 `mfa_setup_required`, and they set up MFA. Pinned by the Task 3 test `account without MFA is refused outside /auth`.

---

### Task 1: Migration 0037 (additive) and schema

**Files:**
- Create: `workers/drizzle/0037_mfa.sql`, plus its snapshot and journal entry (generate with `npm run db:generate`, rename to `0037_mfa`, replace the body)
- Modify: `workers/src/db/schema.ts`
- Test: `workers/src/lib/migration0037.test.ts`

**Interfaces:**
- Produces:
  - `users.mfa_pending_secret varchar(64) NULL`, `users.totp_last_step bigint NULL`, `users.sessions_valid_after timestamptz NULL`.
  - Table `mfa_recovery_codes(code_id uuid pk, user_id uuid fk users on delete cascade, code_hash char(64) not null, used_at timestamptz null, created_at timestamptz not null default now())`, with unique `(user_id, code_hash)`.
  - Table `platform_mfa_resets(reset_id uuid pk, user_id uuid fk users on delete cascade, secret_hash char(64) not null, confirm_hash char(64) not null, cancel_hash char(64) not null, status varchar(16) not null default 'requested', requested_at timestamptz not null default now(), confirmed_at timestamptz null, effective_at timestamptz null, completed_at timestamptz null)`, with index on `secret_hash`.
  - Drizzle names: `mfaPendingSecret`, `totpLastStep`, `sessionsValidAfter`, `mfaRecoveryCodes`, `platformMfaResets`.

- [ ] **Step 1:** Write `migration0037.test.ts`:
  - the SQL creates both tables and adds the three columns, all nullable;
  - it has no `DROP`, `TRUNCATE`, `UPDATE` or `DELETE` (comment lines ignored).
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Update the schema, generate, and write the SQL.
- [ ] **Step 4:** Run `npm test`, `npx tsc --noEmit` and `npm run db:generate`. Expected: tests pass, 0 type errors, and generate reports no schema changes.
- [ ] **Step 5:** Commit `feat(db): 0037 adds MFA recovery codes, replay guard, session cut-off, break-glass resets`.

### Task 2: MFA core logic (`lib/mfa.ts`)

**Files:**
- Create: `workers/src/lib/mfa.ts`, `workers/src/lib/mfa.test.ts`
- Modify: `workers/src/lib/auth.ts`. Keep `generateTotpSecret` and `buildOtpauthUrl`. Replace `verifyTotp` with a re-export from mfa.ts or remove it once Task 4 no longer uses it.

**Interfaces:**
- Produces, all exported from `lib/mfa.ts`:
  - `matchTotpStep(secret: string, code: string, nowMs?: number): number | null` returns the absolute 30-second step that matched with `window: 1`, or null. It uses otplib `authenticator.checkDelta`, so the step is `Math.floor(nowMs/30000) + delta`.
  - `acceptStep(lastStep: number | null, step: number): boolean`. True only when `lastStep === null || step > lastStep`.
  - `generateRecoveryCodes(): string[]` returns 10 codes as `XXXXX-XXXXX`, using `crypto.getRandomValues`.
  - `normalizeRecoveryCode(input: string): string` uppercases and strips spaces and dashes.
  - `hashRecoveryCode(code: string): Promise<string>` returns the SHA-256 hex of the normalized code, via WebCrypto.
  - `createMfaToken(userId: string, stage: 'verify' | 'enrol', secret: string): Promise<string>` and `verifyMfaToken(token: string, secret: string): Promise<{ sub: string; stage: 'verify' | 'enrol' } | null>`. The token has `purpose: 'mfa'`, with a 5-minute expiry for `verify` and 15 minutes for `enrol`. Verifying refuses a missing or wrong purpose.
  - `clockSkewMinutes(secret: string, code: string, nowMs?: number): number | null`. When the code matches at a step between 2 and 10 steps away, it returns the signed offset rounded to whole minutes, with at least 1 in magnitude. Otherwise it returns null. It is for the message only and never accepts a code.
  - `sha256Hex(s: string): Promise<string>` and `timingSafeEqualStr(a: string, b: string): boolean`.

- [ ] **Step 1: Write the failing tests** in `mfa.test.ts`:
  - `matchTotpStep accepts the current, previous and next step and refuses two steps away`. Generate codes with `authenticator.generate` at fixed times, using otplib's `epoch` option or a stubbed `Date.now`.
  - `replay of the same step is refused`: `acceptStep(s, s) === false`, `acceptStep(s, s+1) === true`, `acceptStep(null, s) === true`.
  - `recovery codes: 10, unique, format /^[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}$/`.
  - `normalize ignores case, spaces and dashes`: `normalizeRecoveryCode(' abcde-fghjk ') === 'ABCDEFGHJK'`.
  - `recovery code consumed once` is pinned in Task 4's mapper test. Here, test that the hash is stable and 64 hex chars.
  - `mfa token round-trip; wrong secret, expired, or missing purpose are refused`.
  - `enrol token lives 15 minutes, verify token 5`: decode `exp - iat`.
  - `a secret keeps working months later`: a code generated at set-up time + 180 days with the same secret is matched at that time.
  - `clockSkewMinutes reports a phone 3 minutes behind and stays null for a random wrong code`.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(auth): MFA core: drift window, replay guard, recovery codes, signed MFA token`.

### Task 3: Middleware: purpose tokens, session cut-off, MFA required

**Files:**
- Modify: `workers/src/middleware/auth.ts`, `workers/src/lib/accountRows.ts` (where `toAuthUser` lives)
- Test: `workers/src/lib/accountRows.test.ts` (or a new `sessionGate.test.ts`)

**Interfaces:**
- Consumes: Task 1 columns.
- Produces: a pure `sessionGate(payload: { iat?: number; purpose?: unknown }, row: { isActive: boolean; mfaEnabled: boolean; sessionsValidAfter: Date | null }, path: string): null | { status: 401 | 403; body: { detail: string; mfa_setup_required?: true } }`. authMiddleware calls it after loading the row (select `mfaEnabled` and `sessionsValidAfter` too).

Rules, in this order:
1. `purpose` present → 401 `Token expired or invalid`.
2. Not active → the existing 401 deactivation message.
3. `sessionsValidAfter` set and `iat < floor(sessionsValidAfter/1000)` → 401 `Your session has ended. Sign in again.`
4. `!mfaEnabled` and the path does not start with `/api/v1/auth/` → 403 `{ detail: 'Set up MFA to continue.', mfa_setup_required: true }`.

- [ ] **Step 1: Write failing tests:**
  - `mfa purpose token is not an access token`;
  - `token issued before sessions_valid_after is refused`, plus one issued after passes;
  - `account without MFA is refused outside /auth`, plus `/api/v1/auth/me` still passes;
  - a deactivated account still gets the deactivation message.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement `sessionGate` and wire it into authMiddleware.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(auth): middleware refuses MFA tokens, ended sessions, and accounts without MFA`.

### Task 4: Auth routes: sign-in, verify, enrol, recovery codes

**Files:**
- Modify: `workers/src/routes/auth.ts`, `workers/src/lib/routeGuard.test.ts` (SELF_SERVICE list), `workers/src/lib/accountRows.ts`
- Test: pure helpers in `workers/src/lib/mfaFlow.ts` + `mfaFlow.test.ts`. Extract the decision logic, because the routes have no DB harness.

**Interfaces:**
- Consumes: Task 2 functions, Task 3 columns.
- Produces the HTTP contract the frontend (Task 7, Task 8) relies on:
  - **`POST /auth/login` and `POST /auth/google`:**
    - On success: `{ mfa_token, stage: 'verify' | 'enrol' }`. There is no `access_token` here any more. `stage = mfaEnabled ? 'verify' : 'enrol'`.
    - Do not update `lastLogin` here.
    - Before deciding, apply a completed break-glass reset, if any (Task 6 provides `applyDueBreakGlass(db, userId)`; until then call nothing).
  - **`POST /auth/mfa/verify`:**
    - Body: `{ mfa_token, code?: string, recovery_code?: string }`, exactly one of the two.
    - Requires a stage `verify` token.
    - Code path: `matchTotpStep`, then the atomic replay guard `UPDATE users SET totp_last_step = $step WHERE user_id = $id AND (totp_last_step IS NULL OR totp_last_step < $step) RETURNING user_id`. No row → 401 `This code was already used. Wait for the next one.`
    - Recovery path: `UPDATE mfa_recovery_codes SET used_at = now() WHERE user_id = $id AND code_hash = $h AND used_at IS NULL RETURNING code_id`. No row → 401 `That recovery code is not valid.` On success, audit `auth.mfa_recovery_code_used` and email the user (Task 5 mailer; until Task 5, skip). Return `recovery_codes_left`.
    - On success: update `lastLogin`, clear the failure limit, and return `{ access_token, role, user_id, recovery_codes_left? }`.
  - **Wrong code** (verify and enrol finish): when `clockSkewMinutes` is not null, use the clock message from Global Constraints. When the limiter blocks, answer 429 with the remaining minutes.
  - **`POST /auth/mfa/enrol/start`:**
    - Body `{ mfa_token, new_secret?: boolean }`, stage `enrol`.
    - Reuses an existing `mfa_pending_secret`. It writes a new one only when none exists or `new_secret` is true. Never touches `totp_secret` of an enabled account; refuse with 409 if already enabled.
    - Returns `{ totp_secret, qr_code_base64, otpauth_url, two_devices: boolean }`. `two_devices` is true for role `superadmin` (spec Layer 1).
  - **`POST /auth/mfa/enrol/finish`:**
    - Body `{ mfa_token, code }`, stage `enrol`.
    - The code must match the pending secret, and the same replay guard applies.
    - In one transaction:
      - set `totp_secret` = pending and clear pending;
      - set `mfa_enabled = true` and `totp_last_step = step`;
      - replace recovery codes with 10 new ones.
    - Audit `auth.mfa_enabled`, update `lastLogin`, and return `{ access_token, role, user_id, recovery_codes: string[] }`.
  - **`GET /auth/mfa/status`** (authMiddleware): `{ mfa_enabled, recovery_codes_left }`.
  - **`POST /auth/mfa/recovery-codes`** (authMiddleware):
    - Body `{ password?, code }`, step-up per Global Constraints.
    - Replaces all codes and returns `{ recovery_codes }`. Audit `auth.mfa_recovery_codes_regenerated`.
  - **Remove** `POST /auth/mfa/setup`, `POST /auth/mfa/enable` and `POST /auth/mfa/reset`. The platform reset-by-email is gone (spec: the Platform Superadmin grants nothing).

- [ ] **Step 1: Write failing tests** in `mfaFlow.test.ts` for the extracted helpers:
  - `signInOutcome(mfaEnabled)` → stage;
  - `parseVerifyBody` → exactly one of code or recovery_code, refuses both or neither;
  - `stepUpOk({ hasPassword, passwordOk, codeOk })`, including the Google-only case;
  - `recovery code consumed once`, simulated with an in-memory store that implements the same `used_at IS NULL` rule as the SQL.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement the routes. Update SELF_SERVICE in `routeGuard.test.ts` for the new authMiddleware routes, and remove the deleted ones.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(auth): sign-in always ends with MFA; enrol, verify, recovery codes`.

### Task 5: Mailer and the Tenant Superadmin MFA reset

**Files:**
- Create: `workers/src/services/mailer.ts`, `workers/src/services/mailer.test.ts`
- Modify: `workers/src/types.ts` (Env: `EMAIL?: { send(msg: unknown): Promise<unknown> }`, `MAIL_FROM?: string`, `PLATFORM_MFA_RESET?: string`), `workers/src/routes/tenants.ts`, `workers/src/routes/auth.ts` (recovery-code email)

**Interfaces:**
- Produces:
  - `sendMail(env: Env, msg: { to: string; subject: string; text: string }): Promise<{ sent: boolean }>`. It uses `env.EMAIL.send({ to, from: { email: env.MAIL_FROM, name: 'UMEagleEye' }, subject, text })`.
  - **`POST /tenants/:tenantId/users/:userId/mfa-reset`:**
    - Guards: `requireTenantSuperadmin`, own tenant.
    - Body `{ password?, code }`, step-up.
    - Target must be a `tenant_user` of this tenant, not the caller. Otherwise 404 `User not found in this tenant`.
    - Effects:
      - `mfa_enabled = false`;
      - `totp_secret`, `mfa_pending_secret` and `totp_last_step` set to null;
      - recovery codes deleted;
      - `sessions_valid_after = now()`.
    - Audit `user.mfa_reset`. Email the target with the spec text.
    - Return `{ ok: true }`.

- [ ] **Step 1: Write failing tests:**
  - `sendMail without binding returns sent:false and does not throw`;
  - `sendMail with a fake binding passes to/from/subject/text`;
  - `binding that throws → sent:false`;
  - `resetTarget` mapper: tenant_user in tenant → ok; self, tenant_superadmin, superadmin or another tenant → refused.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Add the route to the route guard test if needed.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(auth): Tenant Superadmin resets a user's MFA; mailer with quiet fallback`.

### Task 6: Platform break-glass reset

**Files:**
- Modify: `workers/src/routes/auth.ts`, `workers/src/lib/mfa.ts` (or a new `lib/breakGlass.ts`), `workers/src/lib/routeGuard.test.ts`
- Test: `workers/src/lib/breakGlass.test.ts`

**Interfaces:**
- Consumes: Task 5 `sendMail`; Task 1 `platform_mfa_resets`.
- Produces:
  - **`POST /auth/mfa/break-glass/request`** (public; rate-limited by IP and account with the existing limiter):
    - Body `{ email, password, reset_secret }`.
    - Always answers 202 `{ detail: 'If the details are right, a confirmation email is on its way.' }`, except 503 `{ detail: 'Email is not set up, so this reset cannot run.' }` when `sendMail` would skip.
    - It acts only when all of these hold:
      - the user is `superadmin` and active;
      - the password is right;
      - `env.PLATFORM_MFA_RESET` is set and `timingSafeEqualStr` with `reset_secret`;
      - `sha256Hex(reset_secret)` is in no earlier row.
    - Then it creates a row with random confirm and cancel tokens (store their hashes) and emails both links: `${FRONTEND_URL}/mfa-recovery?confirm=…` and `…?cancel=…`.
  - **`POST /auth/mfa/break-glass/confirm`** `{ token }`: a `requested` row → `confirmed`, `confirmed_at = now()`, `effective_at = now() + 24h`.
  - **`POST /auth/mfa/break-glass/cancel`** `{ token }`: a `requested` or `confirmed` row → `cancelled`.
  - **`applyDueBreakGlass(db, userId): Promise<boolean>`:**
    - For a `confirmed` row with `effective_at <= now()`:
      - clear MFA as in the Task 5 reset, and set `sessions_valid_after`;
      - set the row to `done` with `completed_at`.
    - Returns true. Task 4's login calls it.
  - Every step is audited with `tenantId: null`.

- [ ] **Step 1: Write failing tests** for pure helpers:
  - `breakGlassEligible({ role, active, passwordOk, secretSet, secretMatches, secretUsedBefore })`;
  - `nextState(status, action, now, effectiveAt)`, covering:
    - confirm only from requested;
    - cancel from requested or confirmed;
    - apply only when confirmed and due;
    - a done or cancelled row cannot move.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement. Wire `applyDueBreakGlass` into Task 4's login and google paths.
- [ ] **Step 4:** Run `npm test` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(auth): platform break-glass MFA reset with 24h hold and email cancel`.

### Task 7: Frontend sign-in, enrolment, recovery codes, lost-MFA page

**Files:**
- Modify: `frontend/src/pages/LoginPage.jsx`, `frontend/src/context/AuthContext.jsx`, `frontend/src/api/client.js`, `frontend/src/App.jsx`
- Create: `frontend/src/components/auth/MfaEnrol.jsx`, `frontend/src/components/auth/RecoveryCodes.jsx`, `frontend/src/pages/MfaRecoveryPage.jsx`
- Test: `frontend/src/utils/mfa.test.js`, with pure helpers in `frontend/src/utils/mfa.js` (`formatRecoveryCodes`, `isMfaSetupRequired(response)`)

**Interfaces:**
- Consumes: the Task 4 and Task 6 HTTP contract.

Behaviour:
- **Login:**
  - It holds `mfa_token` and `stage` in memory. Drop the sessionStorage `mfa_user_id`.
  - Stage `verify`: a 6-digit code field, plus a "Use a recovery code" link that switches to a recovery-code field.
  - Stage `enrol`: `MfaEnrol` shows:
    - the QR, with the secret as text and a copy button;
    - when `two_devices`, the note "Scan this code on two devices: your phone and a backup device kept somewhere safe.";
    - a code field.
  - After finish: `RecoveryCodes` shows the 10 codes once, with "Copy" and "Download .txt", and a required checkbox "I have saved these codes". Only then does it start the session.
  - When the `mfa_token` expires (401 with the token error), go back to the password form with "The sign-in took too long. Sign in again.". After signing in again, set-up shows the same QR, so the code already scanned still works. A small "Show a new QR code" button sends `new_secret: true`.
  - Show the server's message for a wrong code as it is: the clock-off and lockout texts tell the user what to do.
- **Lost MFA:** a link "Lost your authenticator?" opens a short explanation:
  - "Use a recovery code. If you have none, ask your Tenant Superadmin to reset your MFA."
  - For the Tenant Superadmin: "use a recovery code or emergency recovery".
  - For the Platform Superadmin: a "Lost all MFA methods" form with email, password and reset secret, which posts to break-glass request.
- **`/mfa-recovery?confirm=` or `?cancel=`:** `MfaRecoveryPage` posts the token and shows the result. It is a public route.
- **client.js:**
  - Add `/auth/mfa/` to the 401 redirect exemptions.
  - On 403 with `mfa_setup_required`, clear the session and go to login with "Set up MFA to continue.".

- [ ] **Step 1: Write failing tests** for `utils/mfa.js` helpers, run with `node --test src/utils/mfa.test.js`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement the components and pages.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): sign-in with MFA enrolment, recovery codes and lost-MFA help`.

### Task 8: Frontend Settings MFA section and the Users-page reset

**Files:**
- Modify: `frontend/src/pages/SettingsPage.jsx` (MFA section ~255-340), `frontend/src/pages/TenantSettingsPage.jsx` (users table row menu), `frontend/src/utils/mfa.js` (+ test)

Behaviour:
- **Settings:**
  - It shows MFA status from `GET /auth/mfa/status`: "MFA is on", with "N recovery codes left".
  - A "Get new recovery codes" button opens a dialog with password (hidden for accounts without a password) and code fields. It shows the new codes once, using `RecoveryCodes`.
  - Remove the old "Setup TOTP MFA" flow.
- **Users page:** for a Tenant user row, the Tenant Superadmin sees "Reset MFA" in the row menu. A ConfirmDialog shows:
  - the verbatim guidance text;
  - the target's name;
  - password and code fields.
  - On success: the toast "MFA reset. [Name] must set it up at their next sign-in.".

- [ ] **Step 1: Write failing tests** for any new pure helper, e.g. `needsPasswordForStepUp(user)`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `node --test src/utils/*.test.js` and `npx vite build`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(ui): MFA status, new recovery codes, and Tenant Superadmin MFA reset`.

### Task 9: Staging rollout (controller; needs owner go-ahead)

- [ ] **Step 0: Read-only pre-checks** on staging (no writes):
  - `SELECT username, role, mfa_enabled, totp_secret IS NOT NULL FROM users WHERE is_active`. Today none has `mfa_enabled = true`, so every account enrols fresh and gets 10 recovery codes.
  - `SELECT conname FROM pg_constraint WHERE conrelid = 'audit_logs'::regclass AND conname = 'audit_logs_user_id_users_user_id_fk'`. Expected: one row (0038 drops and recreates it by this name).
  - Record the current worker version id (`npx wrangler deployments list -c wrangler.prod-noperf.toml --env staging`) and the current Pages staging deployment, for rollback.
- [ ] **Step 1:** Tell the owner and the teammate:
  - after this deploy, every staging account without MFA must set it up at its next sign-in, and every open session without MFA is refused at once;
  - reload any open tab after the deploy (the old page cannot sign in against the new worker);
  - agents are not affected, because they authenticate with agent keys;
  - the Platform Superadmin and every Tenant Superadmin must save their 10 recovery codes at enrolment. The Platform Superadmin also scans the same QR on a backup device (spec section 7, Layer 1).
  - Known temporary exception to spec section 7: until email (break-glass) and the handover plan's Path B exist, a Tenant Superadmin or the Platform Superadmin who loses the phone AND the recovery codes needs a manual database reset.
- [ ] **Step 2:** `npm run db:status:staging`. Expected: pending exactly `0037_mfa` and `0038_audit_keeps_deleted_users` (delete-user plan). Then `npm run db:migrate:staging`.
  - 0038 adds the FK `NOT VALID`, then validates it. drizzle-kit runs all pending migrations in one transaction, so `audit_logs` stays locked during the scan; the table is small.
- [ ] **Step 3: Deploy, worker and frontend back to back.** The old frontend cannot sign in against the new worker (it stores an undefined access token), so the gap must be short.
  - `npx wrangler deploy -c wrangler.prod-noperf.toml --env staging`;
  - IMMEDIATELY deploy the frontend (`frontend/.env` present, shell `VITE_*` unset): `npm run deploy:staging` in `frontend/`, and check the bundle points at the staging API;
  - then `node scripts/kg/build-system-graph.mjs staging`.
- [ ] **Step 4:** API smoke test with a temporary test tenant (otplib generates the codes):
  - password sign-in returns stage `enrol`;
  - enrol finish returns 10 codes and a token;
  - a reused code gets 401;
  - a code from the previous 30 s is accepted;
  - a recovery code works once;
  - an `mfa_token` sent as a Bearer token gets 401;
  - after the owner's MFA reset, the target's old token gets 401;
  - break-glass request gets 503 when no email is configured.
  - Permanence: start enrolment, sign in again, and `enrol/start` returns the SAME secret. After enrolment, a fresh sign-in minutes later with a code from the same secret succeeds.
  - Step-up: getting new recovery codes works; a wrong step-up password gets 401 and the session still works.
  - Delete: a wrong-case username gets 400; the correct delete gets 200; the target's old token gets 401; the target's audit rows still exist with `user_id` NULL and `actor_username` set.
  - Remove the test data afterwards. Delete the test tenant's audit rows first (`audit_logs.tenant_id` has no cascade).
- [ ] **Step 5:** Check that agents are still online and that scan results keep arriving. Run the GET sweep: no 5xx.
- [ ] **Step 6: kg QA prep.** Before running the kg QA or stress scripts, give the QA users MFA: `node scripts/kg/seed-test.mjs --add-mfa` for users seeded earlier, or re-seed (`--remove`, then seed). Their TOTP secrets stay in the OS-temp creds file.
- [ ] **Step 7:** Record the results in the ledger. Stop.

**Rollback** (if the rollout must be undone):
- Roll back the worker AND the frontend together. The new and old frontends cannot read each other's sign-in answers.
  - Worker: `npx wrangler rollback <id recorded in Step 0> -c wrangler.prod-noperf.toml --env staging`.
  - Frontend: roll back to the Pages deployment recorded in Step 0 (Pages dashboard, Rollback), or rebuild the previous commit and `npm run deploy:staging`.
- No database change is needed: 0037 and 0038 only add columns and tables and relax a foreign key, and the old worker ignores them.
- Optional: rotate `JWT_SECRET_KEY` (`npx wrangler secret put JWT_SECRET_KEY -c wrangler.prod-noperf.toml --env staging`) to drop tokens issued during the rollout. The old worker's middleware would accept an `mfa_token` as an access token. Everyone then signs in again.

### Task 10: Email sending (gated: needs a domain on the Cloudflare account)

- [ ] **Step 1:** The owner gives:
  - a domain on the Cloudflare account for sending;
  - a wrangler login or API token with Email Sending permission.
- [ ] **Step 2:** `npx wrangler email sending enable <domain>`. Add the `send_email` binding `EMAIL` and the var `MAIL_FROM = "no-reply@<domain>"` under `[env.staging]` in `wrangler.prod-noperf.toml` and `wrangler.toml`.
- [ ] **Step 3:** Deploy staging. Send one test (reset a test user's MFA to a real address the owner controls). Then check the break-glass request flow end to end with a test secret (`wrangler secret put PLATFORM_MFA_RESET --env staging`).
