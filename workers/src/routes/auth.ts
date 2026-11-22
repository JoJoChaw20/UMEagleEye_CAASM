import { Hono, type Context } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, isNull, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import { users, tenants, mfaRecoveryCodes, platformMfaResets } from '../db/schema'
import {
  hashPassword,
  verifyPassword,
  createToken,
  generateTotpSecret,
  generateTotpQR,
  NO_PASSWORD_HASH,
} from '../lib/auth'
import { authenticator } from 'otplib'
import { TOO_MANY, clearFailures, overLimit, recordFailure } from '../lib/loginLimit'
import { audit, callerIp } from '../services/audit'
import { claimStep, codeFailed, codeLimited, stepUp } from '../services/mfaStepUp'
import { mailConfigured, sendMail } from '../services/mailer'
import { applyDueBreakGlass } from '../services/breakGlass'
import { settleOwnership } from '../services/ownership'
import { isDeactivated } from '../lib/sessionGate'
import { flipIfDue } from '../services/deactivation'
import { connectRefusal } from '../lib/googleConnect'
import { passwordSchema } from '../lib/passwordRules'
import { isUniqueViolation } from '../lib/fkViolation'
import { HOLD_HOURS, breakGlassEligible, nextState } from '../lib/breakGlass'
import { ACTIONS, GROUPS, PRESETS } from '../lib/actions'
import { enrolsTwoDevices, signIn, withAccount } from '../lib/accountRows'
import {
  acceptStep, createMfaToken, generateRecoveryCodes, hashRecoveryCode, matchTotpStep, sha256Hex, timingSafeEqualStr, verifyMfaToken, type MfaStage,
} from '../lib/mfa'
import {
  CODE_REPLAYED, RECOVERY_CODE_INVALID, isMfaExempt, parseVerifyBody, pendingSecretPlan, signInOutcome,
  useRecoveryCode, wrongCodeDetail, type RecoveryCodeStore,
} from '../lib/mfaFlow'

const app = new Hono<{ Bindings: Env }>()

type Ctx = Context<{ Bindings: Env }>
type UserRow = typeof users.$inferSelect


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
  // A break-glass reset whose hold is over is applied first: the account then sets MFA up again.
  // The stage comes from the account as it is after that, never from the row read before it.
  const db = getDb(c.env.DATABASE_URL)
  // Staging only: an exempt account with MFA off signs in with the password alone (lib/mfaFlow.ts isMfaExempt);
  // one that set MFA up signs in with its code like everyone else.
  if (!row.mfaEnabled && isMfaExempt(c.env, row.username, row.role)) {
    const settled = await settledAccount(c, db, row)
    if (settled.refused) return settled.refused
    await db.update(users).set({ lastLogin: new Date() }).where(eq(users.userId, row.userId))
    await clearFailures(c.env.KV_CACHE, 'mfa_account', row.userId)
    await audit(db, c, { userId: row.userId, tenantId: row.tenantId, actionType: 'auth.login_mfa_exempt', targetEntity: row.userId })
    return c.json(await accessFor(c, settled.row))
  }
  await applyDueBreakGlass(db, row.userId)
  const [fresh] = await db.select({ mfaEnabled: users.mfaEnabled }).from(users).where(eq(users.userId, row.userId)).limit(1)
  const stage = signInOutcome(fresh?.mfaEnabled ?? row.mfaEnabled)
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
  if (isDeactivated(row)) {
    await flipIfDue(db, row.userId)
    return { refused: c.json({ detail: DEACTIVATED }, 401) }
  }
  return { row }
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
    if (user && isDeactivated(user)) await flipIfDue(db, user.userId)
    if (!user || isDeactivated(user) || !valid) {
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

// ── Platform break-glass MFA reset ───────────────────────────────
// For a Platform Superadmin who lost the authenticator and the recovery codes. Needs the password
// and the one-time secret PLATFORM_MFA_RESET (a value used once is refused afterwards), and email.
// The request emails a confirm link and a cancel link. Confirming starts a 24-hour hold; if nobody
// cancels, the next sign-in clears MFA (services/breakGlass.ts). All steps are audited, tenantId null.
const BREAK_GLASS_ACCEPTED = 'If the details are right, a confirmation email is on its way.'
const BREAK_GLASS_NO_EMAIL = 'Email is not set up, so this reset cannot run.'
const LINK_NOT_VALID = 'This link is not valid, or it was already used.'
const newLinkToken = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

app.post(
  '/mfa/break-glass/request',
  zValidator('json', z.object({ email: z.string(), password: z.string(), reset_secret: z.string() })),
  async (c) => {
    try {
      if (!mailConfigured(c.env)) return c.json({ detail: BREAK_GLASS_NO_EMAIL }, 503)
      const { email, password, reset_secret } = c.req.valid('json')
      const db = getDb(c.env.DATABASE_URL)
      const kv = c.env.KV_CACHE
      const ip = callerIp(c) ?? 'unknown'
      if (await overLimit(kv, 'password_account', email) || await overLimit(kv, 'password_address', ip)) {
        return c.json({ detail: TOO_MANY }, 429)
      }

      const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1)
      const passwordOk = await verifyPassword(password, user?.passwordHash ?? await decoy())
      const secretHash = await sha256Hex(reset_secret)
      const [earlier] = await db.select({ resetId: platformMfaResets.resetId }).from(platformMfaResets)
        .where(eq(platformMfaResets.secretHash, secretHash)).limit(1)
      const expected = c.env.PLATFORM_MFA_RESET
      const eligible = !!user && breakGlassEligible({
        role: user.role, active: user.isActive, passwordOk, secretSet: !!expected,
        secretMatches: !!expected && timingSafeEqualStr(reset_secret, expected),
        secretUsedBefore: !!earlier,
      })
      if (!user || !eligible) {
        await Promise.all([recordFailure(kv, 'password_account', email), recordFailure(kv, 'password_address', ip)])
        if (user) {
          await audit(db, c, {
            userId: user.userId, tenantId: null, actionType: 'auth.break_glass_refused', targetEntity: user.userId,
          })
        }
        return c.json({ detail: BREAK_GLASS_ACCEPTED }, 202)
      }

      const confirm = newLinkToken()
      const cancel = newLinkToken()
      // The unique index on secret_hash makes "used once" strict: a concurrent second request with
      // the same secret inserts nothing and takes the refused path.
      const inserted = await db.insert(platformMfaResets).values({
        userId: user.userId, secretHash, confirmHash: await sha256Hex(confirm), cancelHash: await sha256Hex(cancel),
      }).onConflictDoNothing().returning({ resetId: platformMfaResets.resetId })
      if (inserted.length === 0) return c.json({ detail: BREAK_GLASS_ACCEPTED }, 202)
      await audit(db, c, { userId: user.userId, tenantId: null, actionType: 'auth.break_glass_requested', targetEntity: user.userId })
      const base = `${c.env.FRONTEND_URL}/mfa-recovery`
      await sendMail(c.env, {
        to: user.email, subject: 'Confirm your MFA reset',
        text: `Someone asked to reset the MFA of your platform account.\n\n`
          + `To go ahead, open: ${base}?confirm=${confirm}\n`
          + `MFA is then cleared ${HOLD_HOURS} hours later, at your next sign-in.\n\n`
          + `If this was not you, or you changed your mind, cancel with: ${base}?cancel=${cancel}`,
      })
      return c.json({ detail: BREAK_GLASS_ACCEPTED }, 202)
    } catch (err) {
      console.error('break-glass request error:', err)
      return c.json({ detail: 'Failed to process the request' }, 500)
    }
  }
)

/** Moves the reset row that a link token names (its hash must match the confirm or cancel column). */
async function moveBreakGlass(c: Ctx, token: string, action: 'confirm' | 'cancel') {
  const db = getDb(c.env.DATABASE_URL)
  const hash = await sha256Hex(token)
  const [row] = await db.select().from(platformMfaResets)
    .where(eq(action === 'confirm' ? platformMfaResets.confirmHash : platformMfaResets.cancelHash, hash)).limit(1)
  const now = new Date()
  const to = row ? nextState(row.status, action, now, row.effectiveAt) : null
  if (!row || !to) return c.json({ detail: LINK_NOT_VALID }, 400)
  const effectiveAt = to === 'confirmed' ? new Date(now.getTime() + HOLD_HOURS * 3_600_000) : null
  // Only from the status just read, so two clicks cannot both move it.
  const moved = await db.update(platformMfaResets)
    .set(effectiveAt ? { status: to, confirmedAt: now, effectiveAt } : { status: to })
    .where(and(eq(platformMfaResets.resetId, row.resetId), eq(platformMfaResets.status, row.status)))
    .returning({ resetId: platformMfaResets.resetId })
  if (moved.length === 0) return c.json({ detail: LINK_NOT_VALID }, 400)
  await audit(db, c, {
    userId: row.userId, tenantId: null, actionType: `auth.break_glass_${to}`, targetEntity: row.userId,
    previousState: { status: row.status }, newState: { status: to, effective_at: effectiveAt },
  })
  return c.json(effectiveAt
    ? { detail: `Confirmed. MFA will be cleared in ${HOLD_HOURS} hours. Use the cancel link in the email to stop it.`, effective_at: effectiveAt }
    : { detail: 'Cancelled. Nothing was changed.' })
}

const linkTokenSchema = z.object({ token: z.string().min(1) })

app.post('/mfa/break-glass/confirm', zValidator('json', linkTokenSchema), async (c) => {
  try {
    return await moveBreakGlass(c, c.req.valid('json').token, 'confirm')
  } catch (err) {
    console.error('break-glass confirm error:', err)
    return c.json({ detail: 'Failed to confirm' }, 500)
  }
})

app.post('/mfa/break-glass/cancel', zValidator('json', linkTokenSchema), async (c) => {
  try {
    return await moveBreakGlass(c, c.req.valid('json').token, 'cancel')
  } catch (err) {
    console.error('break-glass cancel error:', err)
    return c.json({ detail: 'Failed to cancel' }, 500)
  }
})

// ── POST /mfa/verify ─────────────────────────────────────────────
// Body: the mfa_token of a verify-stage sign-in and exactly one of a 6-digit code or a recovery code.
const mfaVerifySchema = z.object({
  mfa_token: z.string(),
  code: z.string().optional(),
  recovery_code: z.string().optional(),
})

// Settles what time decides for the user's tenant (an expired transfer or recovery, an ended hold). Cheap; a
// failure is logged and never fails the sign-in.
async function settleAfterSignIn(c: Ctx, db: DB, user: UserRow) {
  if (!user.tenantId) return
  try {
    await settleOwnership(db, user.tenantId, c.env)
  } catch (err) {
    console.error('settleOwnership after sign-in failed:', err)
  }
}

/**
 * Settles, then re-reads the account: a just-suspended former owner is refused and a just-promoted successor gets
 * the settled role, never the row read before the settle.
 */
async function settledAccount(c: Ctx, db: DB, user: UserRow): Promise<{ row: UserRow; refused?: undefined } | { refused: Response }> {
  await settleAfterSignIn(c, db, user)
  const [fresh] = await db.select().from(users).where(eq(users.userId, user.userId)).limit(1)
  if (!fresh) return { refused: c.json({ detail: SIGN_IN_AGAIN }, 401) }
  if (isDeactivated(fresh)) return { refused: c.json({ detail: DEACTIVATED }, 401) }
  return { row: fresh }
}

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
      await audit(db, c, { userId: user.userId, tenantId: user.tenantId, actionType: 'auth.mfa_verified', targetEntity: user.userId })
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
      await sendMail(c.env, {
        to: user.email, subject: 'A recovery code was used',
        text: `A recovery code was used to sign in to your UMEagleEye account on ${new Date().toISOString().slice(0, 10)}. You have ${recovery_codes_left} recovery code${recovery_codes_left === 1 ? '' : 's'} left. If this was not you, change your password and contact your Tenant Superadmin.`,
      })
    }

    await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
    const settled = await settledAccount(c, db, user)
    if (settled.refused) return settled.refused
    const access = await accessFor(c, settled.row)
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
    const settled = await settledAccount(c, db, user)
    if (settled.refused) return settled.refused
    return c.json({ ...(await accessFor(c, settled.row)), recovery_codes: codes })
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

type GoogleIdentity = { sub: string; email: string; name?: string; email_verified?: boolean }

/** The Google account behind an access token issued to EagleEye's own client, or the refusal to send. */
async function googleIdentity(c: Ctx, googleToken: string): Promise<{ id: GoogleIdentity; refused?: undefined } | { refused: Response }> {
  // The token must have been issued to EagleEye's own Google client: userinfo alone accepts a
  // token from ANY site the user signed in to with Google, which could then sign in here as them.
  // tokeninfo names the client (aud/azp); the token goes in the body, not the URL, so it is not logged.
  if (!c.env.GOOGLE_CLIENT_ID) return { refused: c.json({ detail: 'Google sign-in is not set up on this server' }, 503) }
  const infoRes = await fetch('https://oauth2.googleapis.com/tokeninfo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ access_token: googleToken }),
  })
  const info = infoRes.ok ? await infoRes.json() as { aud?: string; azp?: string } : null
  if (!info || (info.aud !== c.env.GOOGLE_CLIENT_ID && info.azp !== c.env.GOOGLE_CLIENT_ID)) {
    return { refused: c.json({ detail: 'Invalid Google access token' }, 401) }
  }

  // The account's details from Google's userinfo endpoint (the token in a header, not the URL)
  const userinfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${googleToken}` },
  })
  if (!userinfoRes.ok) return { refused: c.json({ detail: 'Invalid Google access token' }, 401) }
  const id = await userinfoRes.json() as GoogleIdentity
  if (!id.sub || !id.email) return { refused: c.json({ detail: 'Invalid Google user info' }, 401) }
  return { id }
}

app.post('/google', zValidator('json', googleSchema), async (c) => {
  try {
    const { access_token: googleToken } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const google = await googleIdentity(c, googleToken)
    if (google.refused) return google.refused
    const googlePayload = google.id

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

    if (isDeactivated(resolvedUser)) {
      await flipIfDue(db, resolvedUser.userId)
      return c.json({ detail: 'Account is disabled' }, 403)
    }

    // Google sign-in also goes through MFA. last_login is written when the MFA step succeeds.
    return await mfaStep(c, resolvedUser)
  } catch (err) {
    console.error('google auth error:', err)
    return c.json({ detail: 'Google authentication failed' }, 500)
  }
})

// ── POST /google/connect ─────────────────────────────────────────
// The signed-in owner of an account (often one created with a username and starting password, so
// with no email) connects their Google account: Google's verified address becomes the account's
// email and Google sign-in works from then on. Confirmed with step-up (password and MFA code), so a
// stolen session cannot add its own way in. Rules: lib/googleConnect.ts.
const googleConnectSchema = z.object({
  access_token: z.string(),
  password: z.string().optional(),
  code: z.string().optional(),
})

app.post('/google/connect', authMiddleware, zValidator('json', googleConnectSchema), async (c) => {
  try {
    const { access_token: googleToken, password, code } = c.req.valid('json')
    const authUser = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const [user] = await db.select().from(users).where(eq(users.userId, authUser.userId)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)
    if (user.googleId) return c.json({ detail: 'A Google account is already connected to this account.' }, 409)

    // Google first: it changes nothing, while step-up uses up the MFA code.
    const google = await googleIdentity(c, googleToken)
    if (google.refused) return google.refused
    const id = google.id

    const refused = await stepUp(c, db, user, { password, code })
    if (refused) return refused

    const [byGoogleId] = await db.select({ userId: users.userId }).from(users).where(eq(users.googleId, id.sub)).limit(1)
    const [byEmail] = await db.select({ userId: users.userId }).from(users).where(eq(users.email, id.email)).limit(1)
    const refusal = connectRefusal(user, id, byGoogleId, byEmail)
    if (refusal) return c.json({ detail: refusal.detail }, refusal.status)

    try {
      // google_id IS NULL in the WHERE: two connects at once cannot both win.
      const done = await db.update(users).set({ googleId: id.sub, email: id.email })
        .where(and(eq(users.userId, user.userId), isNull(users.googleId)))
        .returning({ userId: users.userId })
      if (done.length === 0) return c.json({ detail: 'A Google account is already connected to this account.' }, 409)
    } catch (err) {
      // Another account took the Google ID or the address between the check and the write.
      if (isUniqueViolation(err)) return c.json({ detail: 'That Google account or email address belongs to another EagleEye account.' }, 409)
      throw err
    }
    await audit(db, c, {
      userId: user.userId, tenantId: user.tenantId, actionType: 'auth.google_connected', targetEntity: user.userId,
      previousState: { email: user.email }, newState: { email: id.email },
    })
    return c.json({ detail: 'Google account connected. You can now also sign in with Google.', email: id.email })
  } catch (err) {
    console.error('google connect error:', err)
    return c.json({ detail: 'Could not connect the Google account' }, 500)
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
    // A starting password set by an administrator must really be replaced.
    if (user.passwordChangeRequired && new_password === current_password) {
      return c.json({ detail: 'Choose a password different from the one you were given.' }, 400)
    }

    const newHash = await hashPassword(new_password)
    await db.update(users).set({ passwordHash: newHash, passwordChangeRequired: false }).where(eq(users.userId, authUser.userId))
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
        googleId:       users.googleId,
        passwordChangeRequired: users.passwordChangeRequired,
      })
      .from(users)
      .leftJoin(tenants, eq(users.tenantId, tenants.tenantId))
      .where(eq(users.userId, authUser.userId))
      .limit(1)

    if (!row) {
      return c.json({ detail: 'User not found' }, 404)
    }

    // Role and actions as normalized (a legacy role reads as a tenant user): lib/accountRows.ts
    // The Google ID itself is never sent, only whether one is connected.
    const { passwordHash, googleId, passwordChangeRequired, ...profile } = withAccount(row)
    return c.json({
      ...profile, hasPassword: passwordHash !== NO_PASSWORD_HASH, mfa_exempt: isMfaExempt(c.env, row.username, row.role),
      google_connected: !!googleId, password_change_required: passwordChangeRequired,
    })
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
    const [row] = await db.select({ mfaEnabled: users.mfaEnabled, username: users.username, role: users.role }).from(users).where(eq(users.userId, authUser.userId)).limit(1)
    return c.json({ mfa_enabled: row?.mfaEnabled === true, mfa_exempt: isMfaExempt(c.env, row?.username ?? '', row?.role),recovery_codes_left: await recoveryCodesLeft(db, authUser.userId) })
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
  code: z.string().optional(),
})

app.post('/mfa/recovery-codes', authMiddleware, zValidator('json', recoveryCodesSchema), async (c) => {
  try {
    const authUser = c.get('user')
    const { password, code } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const [user] = await db.select().from(users).where(eq(users.userId, authUser.userId)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)
    const refused = await stepUp(c, db, user, { password, code })
    if (refused) return refused

    // Old codes out, new ones in, in one Neon HTTP transaction (db.batch).
    const { codes, hashes } = await newRecoveryCodes()
    await db.batch([
      db.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, user.userId)),
      db.insert(mfaRecoveryCodes).values(hashes.map((codeHash) => ({ userId: user.userId, codeHash }))),
    ])

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
