import { Hono, type Context } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, isNull, lt, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import { users, tenants, mfaRecoveryCodes } from '../db/schema'
import {
  hashPassword,
  verifyPassword,
  createToken,
  generateTotpSecret,
  generateTotpQR,
  NO_PASSWORD_HASH,
} from '../lib/auth'
import { authenticator } from 'otplib'
import { TOO_MANY, clearFailures, minutesLeftInWindow, overLimit, recordFailure } from '../lib/loginLimit'
import { audit, callerIp } from '../services/audit'
import { ACTIONS, GROUPS, PRESETS } from '../lib/actions'
import { enrolsTwoDevices, signIn, withAccount } from '../lib/accountRows'
import {
  acceptStep, createMfaToken, generateRecoveryCodes, hashRecoveryCode, matchTotpStep, verifyMfaToken, type MfaStage,
} from '../lib/mfa'
import {
  CODE_REPLAYED, RECOVERY_CODE_INVALID, parseVerifyBody, pendingSecretPlan, signInOutcome, stepUpOk,
  tooManyCodesDetail, useRecoveryCode, wrongCodeDetail, type RecoveryCodeStore,
} from '../lib/mfaFlow'

const app = new Hono<{ Bindings: Env }>()

type Ctx = Context<{ Bindings: Env }>
type UserRow = typeof users.$inferSelect

const passwordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/[a-z]/, 'Password must contain a lowercase letter')
  .regex(/[A-Z]/, 'Password must contain an uppercase letter')
  .regex(/[0-9]/, 'Password must contain a number')
  .regex(/[^A-Za-z0-9\s]/, 'Password must contain a special character')
  .refine((password) => !/\s/.test(password), 'Password must not contain spaces')

// A password hash to check against when the username does not exist, so a wrong username takes
// as long as a wrong password and cannot be told apart by timing.
let decoyHash: Promise<string> | null = null
const decoy = () => (decoyHash ??= hashPassword('decoy-password-never-matches'))

// ── MFA sign-in helpers ──────────────────────────────────────────
// A password or Google sign-in never returns an access token on its own: it returns a short-lived
// mfa_token (lib/mfa.ts), exchanged at /mfa/verify (a code) or /mfa/enrol/finish (first set-up).
const SIGN_IN_AGAIN = 'Your sign-in has expired. Sign in again.'
const DEACTIVATED = 'Your account is deactivated. Contact your Tenant Superadmin.'
const ALREADY_SET_UP = 'MFA is already set up for this account. Sign in again and enter the code from your authenticator app.'
const ENTER_SIX_DIGITS = 'Enter the 6-digit code from your authenticator app.'

/** The answer to a correct password or Google sign-in: the MFA step, no access token. */
async function mfaStep(c: Ctx, row: UserRow) {
  // Task 6: apply a completed break-glass reset of this account here, before the stage is decided.
  const stage = signInOutcome(row.mfaEnabled)
  return c.json({ mfa_token: await createMfaToken(row.userId, stage, c.env.JWT_SECRET_KEY), stage })
}

/** The access token, issued only after the MFA step. Claims keep the stored role (lib/accountRows.ts). */
async function accessFor(c: Ctx, row: UserRow) {
  const session = signIn(row)
  const access_token = await createToken(session.claims, c.env.JWT_SECRET_KEY, parseInt(c.env.JWT_EXPIRE_MINUTES))
  return { access_token, role: session.role, user_id: row.userId }
}

/** The active account an mfa_token of this stage names, or the refusal to send. */
async function mfaAccount(
  c: Ctx, db: DB, token: string, stage: MfaStage,
): Promise<{ row: UserRow; refused?: undefined } | { refused: Response }> {
  const claims = await verifyMfaToken(token, c.env.JWT_SECRET_KEY)
  if (!claims || claims.stage !== stage) return { refused: c.json({ detail: SIGN_IN_AGAIN }, 401) }
  const [row] = await db.select().from(users).where(eq(users.userId, claims.sub)).limit(1)
  if (!row) return { refused: c.json({ detail: SIGN_IN_AGAIN }, 401) }
  if (!row.isActive) return { refused: c.json({ detail: DEACTIVATED }, 401) }
  return { row }
}

/** 429 with the real remaining minutes while the account's MFA failure limit blocks it. */
async function codeLimited(c: Ctx, userId: string) {
  if (!await overLimit(c.env.KV_CACHE, 'mfa_account', userId)) return null
  return c.json({ detail: tooManyCodesDetail(minutesLeftInWindow()) }, 429)
}

/** A refused code, recovery code or step-up: counted against the limit, audited, 401. */
async function codeFailed(c: Ctx, db: DB, row: UserRow, detail: string, method: string, reason: string) {
  await recordFailure(c.env.KV_CACHE, 'mfa_account', row.userId)
  await audit(db, c, {
    userId: row.userId, tenantId: row.tenantId, actionType: 'auth.mfa_failed', targetEntity: row.userId,
    newState: { method, reason },
  })
  return c.json({ detail }, 401)
}

/**
 * Replay guard: records the step only if it is later than the last one used, in one statement, so
 * two requests with the same code cannot both pass. `extra` columns are written with it. The
 * account must still have MFA on with the secret the code was checked against, so an MFA reset
 * landing between the read and this write cannot let a code of the old secret through.
 */
async function claimStep(
  db: DB, userId: string, secret: string, step: number, extra: Partial<typeof users.$inferInsert> = {},
) {
  const rows = await db.update(users).set({ ...extra, totpLastStep: step })
    .where(and(
      eq(users.userId, userId), eq(users.mfaEnabled, true), eq(users.totpSecret, secret),
      or(isNull(users.totpLastStep), lt(users.totpLastStep, step)),
    ))
    .returning({ userId: users.userId })
  return rows.length > 0
}

/** used_at IS NULL in the WHERE: a code is consumed by exactly one request (mfaFlow.test.ts). */
const recoveryStore = (db: DB): RecoveryCodeStore => ({
  async markUsed(userId, codeHash) {
    const rows = await db.update(mfaRecoveryCodes).set({ usedAt: sql`now()` })
      .where(and(eq(mfaRecoveryCodes.userId, userId), eq(mfaRecoveryCodes.codeHash, codeHash), isNull(mfaRecoveryCodes.usedAt)))
      .returning({ codeId: mfaRecoveryCodes.codeId })
    return rows.length > 0
  },
})

async function recoveryCodesLeft(db: DB, userId: string): Promise<number> {
  const [row] = await db.select({ n: sql<number>`count(*)::int` }).from(mfaRecoveryCodes)
    .where(and(eq(mfaRecoveryCodes.userId, userId), isNull(mfaRecoveryCodes.usedAt)))
  return Number(row?.n ?? 0)
}

/**
 * The end of MFA set-up, in one statement (atomic on its own; the neon-http driver has no
 * interactive transaction, and a db.batch could not make the code replacement depend on the
 * update): the pending secret becomes totp_secret, MFA is on, the step is recorded, and the
 * recovery codes are replaced. Nothing is written unless the account is still without MFA, still
 * has the pending secret the code was checked against, and the step is later than the last one.
 */
async function finishEnrolment(db: DB, userId: string, pending: string, step: number, codeHashes: string[]) {
  const values = sql.join(codeHashes.map((h) => sql`(${h})`), sql`, `)
  const res = await db.execute(sql`
    WITH done AS (
      UPDATE users
      SET totp_secret = mfa_pending_secret, mfa_pending_secret = NULL, mfa_enabled = true,
          totp_last_step = ${step}::bigint, last_login = now()
      WHERE user_id = ${userId}::uuid AND mfa_enabled = false AND mfa_pending_secret = ${pending}
        AND (totp_last_step IS NULL OR totp_last_step < ${step}::bigint)
      RETURNING user_id
    ), cleared AS (
      DELETE FROM mfa_recovery_codes WHERE user_id IN (SELECT user_id FROM done)
    ), added AS (
      INSERT INTO mfa_recovery_codes (user_id, code_hash)
      SELECT done.user_id, v.code_hash FROM done CROSS JOIN (VALUES ${values}) AS v(code_hash)
    )
    SELECT user_id FROM done
  `)
  return res.rows.length > 0
}

/** Ten new recovery codes: the codes to show once, and the hashes to store. */
async function newRecoveryCodes() {
  const codes = generateRecoveryCodes()
  return { codes, hashes: await Promise.all(codes.map(hashRecoveryCode)) }
}

// ── POST /login ──────────────────────────────────────────────────
const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
})

app.post('/login', zValidator('json', loginSchema), async (c) => {
  try {
    const { username, password } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)
    const kv = c.env.KV_CACHE
    const ip = callerIp(c) ?? 'unknown'

    // Brute force (lib/loginLimit.ts): refused while over the limit, even with the right password.
    if (await overLimit(kv, 'password_account', username) || await overLimit(kv, 'password_address', ip)) {
      return c.json({ detail: TOO_MANY }, 429)
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.username, username))
      .limit(1)

    const valid = await verifyPassword(password, user?.passwordHash ?? await decoy())
    if (!user || !user.isActive || !valid) {
      await Promise.all([recordFailure(kv, 'password_account', username), recordFailure(kv, 'password_address', ip)])
      if (user) {
        await audit(db, c, { userId: user.userId, tenantId: user.tenantId, actionType: 'auth.login_failed', targetEntity: user.userId })
      }
      return c.json({ detail: 'Invalid credentials' }, 401)
    }
    await clearFailures(kv, 'password_account', username)

    // Every account goes through MFA: verify a code, or set it up first. last_login is written when
    // the MFA step succeeds, not here.
    return await mfaStep(c, user)
  } catch (err) {
    console.error('login error:', err)
    return c.json({ detail: 'Login failed' }, 500)
  }
})

// ── POST /mfa/verify ─────────────────────────────────────────────
// Body: the mfa_token of a verify-stage sign-in and exactly one of a 6-digit code or a recovery code.
const mfaVerifySchema = z.object({
  mfa_token: z.string(),
  code: z.string().optional(),
  recovery_code: z.string().optional(),
})

app.post('/mfa/verify', zValidator('json', mfaVerifySchema), async (c) => {
  try {
    const body = c.req.valid('json')
    const parsed = parseVerifyBody(body)
    if (!parsed.ok) return c.json({ detail: parsed.detail }, 400)
    const db = getDb(c.env.DATABASE_URL)

    const account = await mfaAccount(c, db, body.mfa_token, 'verify')
    if (account.refused) return account.refused
    const user = account.row
    // MFA was reset after this sign-in started: the account must sign in again and set it up.
    if (!user.mfaEnabled || !user.totpSecret) return c.json({ detail: SIGN_IN_AGAIN }, 401)

    const limited = await codeLimited(c, user.userId)
    if (limited) return limited

    let recovery_codes_left: number | undefined
    if (parsed.input.kind === 'code') {
      const step = matchTotpStep(user.totpSecret, parsed.input.code)
      if (step === null) {
        return await codeFailed(c, db, user, wrongCodeDetail(user.totpSecret, parsed.input.code), 'totp', 'wrong_code')
      }
      if (!await claimStep(db, user.userId, user.totpSecret, step, { lastLogin: new Date() })) {
        return await codeFailed(c, db, user, CODE_REPLAYED, 'totp', 'replayed')
      }
    } else {
      if (!await useRecoveryCode(recoveryStore(db), user.userId, parsed.input.recoveryCode)) {
        return await codeFailed(c, db, user, RECOVERY_CODE_INVALID, 'recovery_code', 'invalid')
      }
      await db.update(users).set({ lastLogin: new Date() }).where(eq(users.userId, user.userId))
      recovery_codes_left = await recoveryCodesLeft(db, user.userId)
      await audit(db, c, {
        userId: user.userId, tenantId: user.tenantId, actionType: 'auth.mfa_recovery_code_used', targetEntity: user.userId,
        newState: { recovery_codes_left },
      })
      // Task 5: email the user that a recovery code was used.
    }

    await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
    const access = await accessFor(c, user)
    return c.json(recovery_codes_left === undefined ? access : { ...access, recovery_codes_left })
  } catch (err) {
    console.error('mfa/verify error:', err)
    return c.json({ detail: 'MFA verification failed' }, 500)
  }
})

// ── POST /mfa/enrol/start ────────────────────────────────────────
// First MFA set-up, with the mfa_token of an enrol-stage sign-in. The pending secret is kept across
// retries and new sign-ins, so a QR already scanned stays valid; { new_secret: true } replaces it.
// totp_secret is never touched here, and an account that has MFA is refused.
const enrolStartSchema = z.object({
  mfa_token: z.string(),
  new_secret: z.boolean().optional(),
})

app.post('/mfa/enrol/start', zValidator('json', enrolStartSchema), async (c) => {
  try {
    const { mfa_token, new_secret } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const account = await mfaAccount(c, db, mfa_token, 'enrol')
    if (account.refused) return account.refused
    const user = account.row
    if (user.mfaEnabled) return c.json({ detail: ALREADY_SET_UP }, 409)

    let secret = user.mfaPendingSecret
    let created = false
    if (pendingSecretPlan(secret, new_secret) === 'create') {
      const fresh = generateTotpSecret()
      // Only on an account still without MFA; without new_secret, only where no pending secret was
      // stored in the meantime, so two tabs end up showing the same QR.
      const [written] = await db.update(users).set({ mfaPendingSecret: fresh })
        .where(and(
          eq(users.userId, user.userId), eq(users.mfaEnabled, false),
          new_secret ? undefined : isNull(users.mfaPendingSecret),
        ))
        .returning({ userId: users.userId })
      if (written) {
        secret = fresh
        created = true
      } else {
        const [now] = await db.select({ mfaEnabled: users.mfaEnabled, mfaPendingSecret: users.mfaPendingSecret })
          .from(users).where(eq(users.userId, user.userId)).limit(1)
        if (!now?.mfaPendingSecret || now.mfaEnabled) return c.json({ detail: ALREADY_SET_UP }, 409)
        secret = now.mfaPendingSecret
      }
    }
    if (!secret) return c.json({ detail: 'MFA set-up failed' }, 500)
    // Started with a new secret, or resumed with the pending one the phone may already have scanned.
    await audit(db, c, {
      userId: user.userId, tenantId: user.tenantId, targetEntity: user.userId,
      actionType: created ? 'auth.mfa_enrol_started' : 'auth.mfa_enrol_resumed',
      newState: created ? { new_secret: new_secret === true } : undefined,
    })

    const qr_code_base64 = await generateTotpQR(secret, user.username)
    const otpauth_url = authenticator.keyuri(user.username, 'UMEagleEye', secret)
    return c.json({ totp_secret: secret, qr_code_base64, otpauth_url, two_devices: enrolsTwoDevices(user) })
  } catch (err) {
    console.error('mfa/enrol/start error:', err)
    return c.json({ detail: 'MFA set-up failed' }, 500)
  }
})

// ── POST /mfa/enrol/finish ───────────────────────────────────────
// The first code from the authenticator app: turns MFA on, signs in, and shows the recovery codes once.
const enrolFinishSchema = z.object({
  mfa_token: z.string(),
  code: z.string(),
})

app.post('/mfa/enrol/finish', zValidator('json', enrolFinishSchema), async (c) => {
  try {
    const body = c.req.valid('json')
    const code = body.code.replace(/\s/g, '')
    if (!/^\d{6}$/.test(code)) return c.json({ detail: ENTER_SIX_DIGITS }, 400)
    const db = getDb(c.env.DATABASE_URL)

    const account = await mfaAccount(c, db, body.mfa_token, 'enrol')
    if (account.refused) return account.refused
    const user = account.row
    if (user.mfaEnabled) return c.json({ detail: ALREADY_SET_UP }, 409)
    const pending = user.mfaPendingSecret
    if (!pending) return c.json({ detail: 'Start MFA set-up first: scan the QR code, then enter its code.' }, 400)

    const limited = await codeLimited(c, user.userId)
    if (limited) return limited

    const step = matchTotpStep(pending, code)
    if (step === null) return await codeFailed(c, db, user, wrongCodeDetail(pending, code), 'totp', 'wrong_code')
    if (!acceptStep(user.totpLastStep, step)) return await codeFailed(c, db, user, CODE_REPLAYED, 'totp', 'replayed')

    const { codes, hashes } = await newRecoveryCodes()
    if (!await finishEnrolment(db, user.userId, pending, step, hashes)) {
      // Another request finished set-up, replaced the QR, or used this step first.
      const [now] = await db.select({ mfaEnabled: users.mfaEnabled }).from(users).where(eq(users.userId, user.userId)).limit(1)
      if (now?.mfaEnabled) return c.json({ detail: ALREADY_SET_UP }, 409)
      return await codeFailed(c, db, user, CODE_REPLAYED, 'totp', 'replayed')
    }

    await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
    await audit(db, c, { userId: user.userId, tenantId: user.tenantId, actionType: 'auth.mfa_enabled', targetEntity: user.userId })
    return c.json({ ...(await accessFor(c, user)), recovery_codes: codes })
  } catch (err) {
    console.error('mfa/enrol/finish error:', err)
    return c.json({ detail: 'MFA set-up failed' }, 500)
  }
})

// ── POST /google ─────────────────────────────────────────────────
// Sign in with Google to an account an administrator created (Users page). An email with no
// account is refused: access is granted by an admin, never by signing in (until 2026-11-09 it
// created a tenantless account with the old business owner role). An existing account is matched by its linked Google
// ID, or by email only when Google has verified that email.
const googleSchema = z.object({ access_token: z.string() })

app.post('/google', zValidator('json', googleSchema), async (c) => {
  try {
    const { access_token: googleToken } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    // The token must have been issued to EagleEye's own Google client: userinfo alone accepts a
    // token from ANY site the user signed in to with Google, which could then sign in here as them.
    // tokeninfo names the client (aud/azp); the token goes in the body, not the URL, so it is not logged.
    if (!c.env.GOOGLE_CLIENT_ID) return c.json({ detail: 'Google sign-in is not set up on this server' }, 503)
    const infoRes = await fetch('https://oauth2.googleapis.com/tokeninfo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ access_token: googleToken }),
    })
    const info = infoRes.ok ? await infoRes.json() as { aud?: string; azp?: string } : null
    if (!info || (info.aud !== c.env.GOOGLE_CLIENT_ID && info.azp !== c.env.GOOGLE_CLIENT_ID)) {
      return c.json({ detail: 'Invalid Google access token' }, 401)
    }

    // The account's details from Google's userinfo endpoint (the token in a header, not the URL)
    const userinfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${googleToken}` },
    })
    if (!userinfoRes.ok) {
      return c.json({ detail: 'Invalid Google access token' }, 401)
    }
    const googlePayload = await userinfoRes.json() as { sub: string; email: string; name?: string; email_verified?: boolean }
    if (!googlePayload.sub || !googlePayload.email) {
      return c.json({ detail: 'Invalid Google user info' }, 401)
    }

    // The account this Google login belongs to: the one it is linked to, else the one with its
    // email, but only an email Google has verified (otherwise anyone could add an admin's address
    // to a Google account and sign in as that admin).
    const [byGoogleId] = await db.select().from(users).where(eq(users.googleId, googlePayload.sub)).limit(1)
    let resolvedUser: UserRow | undefined = byGoogleId
    if (!resolvedUser) {
      const [byEmail] = await db.select().from(users).where(eq(users.email, googlePayload.email)).limit(1)
      if (byEmail && googlePayload.email_verified !== true) {
        return c.json({ detail: 'Google has not verified this email address, so it cannot be used to sign in.' }, 403)
      }
      if (byEmail && byEmail.googleId && byEmail.googleId !== googlePayload.sub) {
        return c.json({ detail: 'This account is linked to a different Google account.' }, 403)
      }
      resolvedUser = byEmail
    }

    if (!resolvedUser) {
      console.warn(`google sign-in refused: no account for an address at ${googlePayload.email.split('@')[1] ?? '?'}`)
      return c.json({
        detail: 'There is no EagleEye account for this Google address. Ask your administrator to create one for you.',
      }, 403)
    }
    if (!resolvedUser.googleId) {
      // First Google sign-in to an account made with this email: link the two
      await db.update(users).set({ googleId: googlePayload.sub }).where(eq(users.userId, resolvedUser.userId))
    }

    if (!resolvedUser.isActive) {
      return c.json({ detail: 'Account is disabled' }, 403)
    }

    // Google sign-in also goes through MFA. last_login is written when the MFA step succeeds.
    return await mfaStep(c, resolvedUser)
  } catch (err) {
    console.error('google auth error:', err)
    return c.json({ detail: 'Google authentication failed' }, 500)
  }
})

// ── POST /change-password ────────────────────────────────────────
const changePasswordSchema = z.object({
  current_password: z.string(),
  new_password: passwordSchema,
})

app.post('/change-password', authMiddleware, zValidator('json', changePasswordSchema), async (c) => {
  try {
    const { current_password, new_password } = c.req.valid('json')
    const authUser = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const [user] = await db.select().from(users).where(eq(users.userId, authUser.userId)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)

    const valid = await verifyPassword(current_password, user.passwordHash)
    if (!valid) return c.json({ detail: 'Current password is incorrect' }, 400)

    const newHash = await hashPassword(new_password)
    await db.update(users).set({ passwordHash: newHash }).where(eq(users.userId, authUser.userId))
    await audit(db, c, { userId: authUser.userId, tenantId: authUser.tenantId ?? null, actionType: 'auth.password_changed', targetEntity: authUser.userId })

    return c.json({ detail: 'Password changed successfully' })
  } catch (err) {
    console.error('change-password error:', err)
    return c.json({ detail: 'Failed to change password' }, 500)
  }
})

// ── POST /set-password ──────────────────────────────────────────
// Google-only accounts have already authenticated with Google, so they can establish a
// password from an authenticated session without supplying a password that does not exist.
const setPasswordSchema = z.object({
  new_password: passwordSchema,
})

app.post('/set-password', authMiddleware, zValidator('json', setPasswordSchema), async (c) => {
  try {
    const { new_password } = c.req.valid('json')
    const authUser = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const [user] = await db.select({ passwordHash: users.passwordHash }).from(users)
      .where(eq(users.userId, authUser.userId)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)
    if (user.passwordHash !== NO_PASSWORD_HASH) {
      return c.json({ detail: 'A password is already set. Use change password instead.' }, 409)
    }

    const newHash = await hashPassword(new_password)
    await db.update(users).set({ passwordHash: newHash }).where(eq(users.userId, authUser.userId))
    await audit(db, c, { userId: authUser.userId, tenantId: authUser.tenantId ?? null, actionType: 'auth.password_set', targetEntity: authUser.userId })

    return c.json({ detail: 'Password set successfully' })
  } catch (err) {
    console.error('set-password error:', err)
    return c.json({ detail: 'Failed to set password' }, 500)
  }
})

// ── GET /me ──────────────────────────────────────────────────────
app.get('/me', authMiddleware, async (c) => {
  try {
    const authUser = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const [row] = await db
      .select({
        userId:         users.userId,
        username:       users.username,
        email:          users.email,
        role:           users.role,
        tenantId:       users.tenantId,
        tenantName:     tenants.name,
        mfaEnabled:     users.mfaEnabled,
        isActive:       users.isActive,
        createdAt:      users.createdAt,
        lastLogin:      users.lastLogin,
        telegramChatId: users.telegramChatId,
        passwordHash:   users.passwordHash,
        actions:        users.actions,
      })
      .from(users)
      .leftJoin(tenants, eq(users.tenantId, tenants.tenantId))
      .where(eq(users.userId, authUser.userId))
      .limit(1)

    if (!row) {
      return c.json({ detail: 'User not found' }, 404)
    }

    // Role and actions as normalized (a legacy role reads as a tenant user): lib/accountRows.ts
    const { passwordHash, ...profile } = withAccount(row)
    return c.json({ ...profile, hasPassword: passwordHash !== NO_PASSWORD_HASH })
  } catch (err) {
    console.error('me error:', err)
    return c.json({ detail: 'Failed to fetch user profile' }, 500)
  }
})

// ── GET /actions ─────────────────────────────────────────────────
// The catalog the Users page builds its checkboxes from.
app.get('/actions', authMiddleware, (c) => {
  return c.json({
    groups: GROUPS,
    actions: ACTIONS.map(({ key, group, label, description, impact, requires, readOnly }) => ({
      key, group, label, description, impact, requires, read_only: readOnly,
    })),
    presets: PRESETS,
  })
})

// ── GET /mfa/status ──────────────────────────────────────────────
app.get('/mfa/status', authMiddleware, async (c) => {
  try {
    const authUser = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const [row] = await db.select({ mfaEnabled: users.mfaEnabled }).from(users).where(eq(users.userId, authUser.userId)).limit(1)
    return c.json({ mfa_enabled: row?.mfaEnabled === true, recovery_codes_left: await recoveryCodesLeft(db, authUser.userId) })
  } catch (err) {
    console.error('mfa/status error:', err)
    return c.json({ detail: 'Failed to read MFA status' }, 500)
  }
})

// ── POST /mfa/recovery-codes ─────────────────────────────────────
// New recovery codes (the old ones stop working). Step-up: the password and the current code; an
// account with no password (Google-only) gives the code alone.
const recoveryCodesSchema = z.object({
  password: z.string().optional(),
  code: z.string(),
})

app.post('/mfa/recovery-codes', authMiddleware, zValidator('json', recoveryCodesSchema), async (c) => {
  try {
    const authUser = c.get('user')
    const { password, code } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const [user] = await db.select().from(users).where(eq(users.userId, authUser.userId)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)
    if (!user.mfaEnabled || !user.totpSecret) return c.json({ detail: 'Set up MFA first.' }, 409)

    const limited = await codeLimited(c, user.userId)
    if (limited) return limited

    const hasPassword = user.passwordHash !== NO_PASSWORD_HASH
    const passwordOk = hasPassword && !!password && await verifyPassword(password, user.passwordHash)
    const digits = code.replace(/\s/g, '')
    const step = /^\d{6}$/.test(digits) ? matchTotpStep(user.totpSecret, digits) : null
    if (!stepUpOk({ hasPassword, passwordOk, codeOk: step !== null })) {
      if (hasPassword && !passwordOk) {
        return await codeFailed(c, db, user, 'Your password is not correct.', 'step_up', 'wrong_password')
      }
      return await codeFailed(c, db, user, wrongCodeDetail(user.totpSecret, digits), 'step_up', 'wrong_code')
    }
    if (!await claimStep(db, user.userId, user.totpSecret, step!)) return await codeFailed(c, db, user, CODE_REPLAYED, 'step_up', 'replayed')

    // Old codes out, new ones in, in one Neon HTTP transaction (db.batch).
    const { codes, hashes } = await newRecoveryCodes()
    await db.batch([
      db.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, user.userId)),
      db.insert(mfaRecoveryCodes).values(hashes.map((codeHash) => ({ userId: user.userId, codeHash }))),
    ])

    await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
    await audit(db, c, {
      userId: user.userId, tenantId: user.tenantId, actionType: 'auth.mfa_recovery_codes_regenerated', targetEntity: user.userId,
    })
    return c.json({ recovery_codes: codes })
  } catch (err) {
    console.error('mfa/recovery-codes error:', err)
    return c.json({ detail: 'Failed to make new recovery codes' }, 500)
  }
})

export default app
