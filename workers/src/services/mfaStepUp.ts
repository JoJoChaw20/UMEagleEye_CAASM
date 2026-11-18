// MFA failure counting and step-up confirmation, shared by the routes that need them
// (routes/auth.ts: sign-in, recovery codes; routes/tenants.ts: MFA reset).
import type { Context } from 'hono'
import { and, eq, isNull, lt, or, sql, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import type { DB } from '../db/client'
import { mfaRecoveryCodes, users } from '../db/schema'
import { NO_PASSWORD_HASH, verifyPassword } from '../lib/auth'
import { clearFailures, minutesLeftInWindow, overLimit, recordFailure } from '../lib/loginLimit'
import { matchTotpStep } from '../lib/mfa'
import { CODE_REPLAYED, isMfaExempt, stepUpOk, tooManyCodesDetail, wrongCodeDetail } from '../lib/mfaFlow'
import { audit } from './audit'

type Ctx = Context<{ Bindings: Env }>
export type UserRow = typeof users.$inferSelect

/** 429 with the real remaining minutes while the account's MFA failure limit blocks it. */
export async function codeLimited(c: Ctx, userId: string) {
  if (!await overLimit(c.env.KV_CACHE, 'mfa_account', userId)) return null
  return c.json({ detail: tooManyCodesDetail(minutesLeftInWindow()) }, 429)
}

/** A refused code, recovery code or step-up: counted against the limit, audited, 401. */
export async function codeFailed(c: Ctx, db: DB, row: UserRow, detail: string, method: string, reason: string) {
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
export async function claimStep(
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

/**
 * Step-up confirmation of the signed-in account `user`: the password and the current MFA code
 * (the code alone for an account with no password). Returns the refusal response to send, or null
 * when confirmed (the step is then claimed and the failure count cleared).
 */
export async function stepUp(
  c: Ctx, db: DB, user: UserRow, input: { password?: string; code?: string },
): Promise<Response | null> {
  const passwordOnly = !user.mfaEnabled && isMfaExempt(c.env, user.username)
  if (!passwordOnly && (!user.mfaEnabled || !user.totpSecret)) return c.json({ detail: 'Set up MFA first.' }, 409)
  const limited = await codeLimited(c, user.userId)
  if (limited) return limited

  const hasPassword = user.passwordHash !== NO_PASSWORD_HASH
  const passwordOk = hasPassword && !!input.password && await verifyPassword(input.password, user.passwordHash)
  if (passwordOnly) {
    if (!stepUpOk({ hasPassword, passwordOk, codeOk: false, passwordOnly })) {
      return await codeFailed(c, db, user, 'Your password is not correct.', 'step_up', 'wrong_password')
    }
    await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
    return null
  }
  const secret = user.totpSecret!
  const digits = (input.code ?? '').replace(/\s/g, '')
  const step = /^\d{6}$/.test(digits) ? matchTotpStep(secret, digits) : null
  if (!stepUpOk({ hasPassword, passwordOk, codeOk: step !== null })) {
    if (hasPassword && !passwordOk) {
      return await codeFailed(c, db, user, 'Your password is not correct.', 'step_up', 'wrong_password')
    }
    return await codeFailed(c, db, user, wrongCodeDetail(secret, digits), 'step_up', 'wrong_code')
  }
  if (!await claimStep(db, user.userId, secret, step!)) {
    return await codeFailed(c, db, user, CODE_REPLAYED, 'step_up', 'replayed')
  }
  await clearFailures(c.env.KV_CACHE, 'mfa_account', user.userId)
  return null
}

/**
 * The statements that reset an account's MFA, for db.batch (one transaction): MFA off, the secret
 * and any pending one gone, recovery codes deleted, open sessions ended. Used by the Tenant
 * Superadmin's reset and the break-glass reset. `guard`, when given, must also hold for both
 * statements to change anything (break-glass: only if this transaction won the status flip).
 */
export function mfaClearStatements(db: DB, userId: string, guard?: SQL) {
  return [
    db.update(users).set({
      mfaEnabled: false, totpSecret: null, mfaPendingSecret: null, totpLastStep: null,
      sessionsValidAfter: sql`now()`,
    }).where(guard ? and(eq(users.userId, userId), guard) : eq(users.userId, userId)),
    db.delete(mfaRecoveryCodes).where(guard ? and(eq(mfaRecoveryCodes.userId, userId), guard) : eq(mfaRecoveryCodes.userId, userId)),
  ] as const
}
