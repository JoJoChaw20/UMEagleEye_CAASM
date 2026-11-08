import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, or } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { users, tenants } from '../db/schema'
import {
  hashPassword,
  verifyPassword,
  createToken,
  generateTotpSecret,
  verifyTotp,
  generateTotpQR,
} from '../lib/auth'
import { authenticator } from 'otplib'
import { TOO_MANY, clearFailures, overLimit, recordFailure } from '../lib/loginLimit'
import { audit, callerIp } from '../services/audit'

const app = new Hono<{ Bindings: Env }>()

// A password hash to check against when the username does not exist, so a wrong username takes
// as long as a wrong password and cannot be told apart by timing.
let decoyHash: Promise<string> | null = null
const decoy = () => (decoyHash ??= hashPassword('decoy-password-never-matches'))

// ── POST /register ───────────────────────────────────────────────
const registerSchema = z.object({
  username: z.string().min(3).max(100),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']).optional(),
})

// Platform superadmin only: it can create an account with any role, superadmin included.
// (It was open to anyone; tenant users are created from the Users and Tenants pages.)
app.post('/register', authMiddleware, requireRoles('superadmin'), zValidator('json', registerSchema), async (c) => {
  try {
    const { username, email, password, role } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const existing = await db
      .select({ userId: users.userId })
      .from(users)
      .where(or(eq(users.username, username), eq(users.email, email)))
      .limit(1)

    if ((existing[0]?.userId) != null) {
      return c.json({ detail: 'Username or email already registered' }, 409)
    }

    const passwordHash = await hashPassword(password)
    const inserted = await db
      .insert(users)
      .values({ username, email, passwordHash, role: role ?? 'business_owner' })
      .returning({
        userId: users.userId,
        username: users.username,
        email: users.email,
        role: users.role,
      })

    const newUser = inserted[0]
    if (!newUser) {
      return c.json({ detail: 'Registration failed' }, 500)
    }

    return c.json({ user_id: newUser.userId, username: newUser.username, email: newUser.email, role: newUser.role }, 201)
  } catch (err) {
    console.error('register error:', err)
    return c.json({ detail: 'Registration failed' }, 500)
  }
})

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

    // Update last login
    await db.update(users).set({ lastLogin: new Date() }).where(eq(users.userId, user.userId))

    if (user.mfaEnabled) {
      return c.json({ mfa_required: true, user_id: user.userId })
    }

    const access_token = await createToken(
      { sub: user.userId, role: user.role, username: user.username, tenant_id: user.tenantId ?? undefined },
      c.env.JWT_SECRET_KEY,
      parseInt(c.env.JWT_EXPIRE_MINUTES),
    )

    return c.json({ access_token, role: user.role, user_id: user.userId, mfa_required: false })
  } catch (err) {
    console.error('login error:', err)
    return c.json({ detail: 'Login failed' }, 500)
  }
})

// ── POST /mfa/setup ──────────────────────────────────────────────
app.post('/mfa/setup', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    // Turning MFA on again would replace the authenticator without proving the current one: someone
    // holding a stolen session could make the account theirs. Resetting it is an administrator's job.
    const [current] = await db.select({ mfaEnabled: users.mfaEnabled }).from(users).where(eq(users.userId, user.userId)).limit(1)
    if (current?.mfaEnabled) {
      return c.json({ detail: 'MFA is already on for this account. To use a new authenticator, ask an administrator to reset your MFA.' }, 409)
    }

    const secret = generateTotpSecret()
    const qr_code_base64 = await generateTotpQR(secret, user.username)
    const otpauth_url = authenticator.keyuri(user.username, 'UMEagleEye', secret)

    await db.update(users).set({ totpSecret: secret }).where(eq(users.userId, user.userId))

    return c.json({ totp_secret: secret, qr_code_base64, otpauth_url })
  } catch (err) {
    console.error('mfa/setup error:', err)
    return c.json({ detail: 'MFA setup failed' }, 500)
  }
})

// ── POST /mfa/enable ─────────────────────────────────────────────
const mfaEnableSchema = z.object({ code: z.string().length(6) })

app.post('/mfa/enable', authMiddleware, zValidator('json', mfaEnableSchema), async (c) => {
  try {
    const user = c.get('user')
    const { code } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)

    const [dbUser] = await db
      .select({ totpSecret: users.totpSecret })
      .from(users)
      .where(eq(users.userId, user.userId))
      .limit(1)

    if (!dbUser?.totpSecret) {
      return c.json({ detail: 'MFA setup not initiated. Call /mfa/setup first.' }, 400)
    }

    const valid = verifyTotp(dbUser.totpSecret, code)
    if (!valid) {
      return c.json({ detail: 'Invalid TOTP code' }, 401)
    }

    await db.update(users).set({ mfaEnabled: true }).where(eq(users.userId, user.userId))
    await audit(db, c, { userId: user.userId, tenantId: user.tenantId ?? null, actionType: 'auth.mfa_enabled', targetEntity: user.userId })

    return c.json({ message: 'MFA enabled successfully' })
  } catch (err) {
    console.error('mfa/enable error:', err)
    return c.json({ detail: 'MFA enable failed' }, 500)
  }
})

// ── POST /mfa/verify ─────────────────────────────────────────────
const mfaVerifySchema = z.object({
  user_id: z.string().uuid(),
  code: z.string().length(6),
})

app.post('/mfa/verify', zValidator('json', mfaVerifySchema), async (c) => {
  try {
    const { user_id, code } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)
    const kv = c.env.KV_CACHE
    if (await overLimit(kv, 'mfa_account', user_id)) return c.json({ detail: TOO_MANY }, 429)

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.userId, user_id))
      .limit(1)

    if (!user || !user.isActive || !user.mfaEnabled || !user.totpSecret) {
      return c.json({ detail: 'MFA verification failed' }, 401)
    }

    const valid = verifyTotp(user.totpSecret, code)
    if (!valid) {
      await recordFailure(kv, 'mfa_account', user_id)
      await audit(db, c, { userId: user.userId, tenantId: user.tenantId, actionType: 'auth.mfa_failed', targetEntity: user.userId })
      return c.json({ detail: 'Invalid TOTP code' }, 401)
    }

    const access_token = await createToken(
      { sub: user.userId, role: user.role, username: user.username, tenant_id: user.tenantId ?? undefined },
      c.env.JWT_SECRET_KEY,
      parseInt(c.env.JWT_EXPIRE_MINUTES),
    )

    return c.json({ access_token, role: user.role, user_id: user.userId })
  } catch (err) {
    console.error('mfa/verify error:', err)
    return c.json({ detail: 'MFA verification failed' }, 500)
  }
})

// ── POST /google ─────────────────────────────────────────────────
// Sign in with Google to an account an administrator created (Users page). An email with no
// account is refused: access is granted by an admin, never by signing in (until 2026-11-09 it
// created a tenantless business_owner). An existing account is matched by its linked Google
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
    type UserRow = typeof users.$inferSelect
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

    await db.update(users).set({ lastLogin: new Date() }).where(eq(users.userId, resolvedUser.userId))

    if (resolvedUser.mfaEnabled) {
      return c.json({ mfa_required: true, user_id: resolvedUser.userId })
    }

    const access_token = await createToken(
      {
        sub: resolvedUser.userId,
        role: resolvedUser.role,
        username: resolvedUser.username,
        tenant_id: resolvedUser.tenantId ?? undefined,
      },
      c.env.JWT_SECRET_KEY,
      parseInt(c.env.JWT_EXPIRE_MINUTES),
    )

    return c.json({ access_token, role: resolvedUser.role, user_id: resolvedUser.userId })
  } catch (err) {
    console.error('google auth error:', err)
    return c.json({ detail: 'Google authentication failed' }, 500)
  }
})

// ── POST /change-password ────────────────────────────────────────
const changePasswordSchema = z.object({
  current_password: z.string(),
  new_password: z.string().min(8),
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
      })
      .from(users)
      .leftJoin(tenants, eq(users.tenantId, tenants.tenantId))
      .where(eq(users.userId, authUser.userId))
      .limit(1)

    if (!row) {
      return c.json({ detail: 'User not found' }, 404)
    }

    return c.json(row)
  } catch (err) {
    console.error('me error:', err)
    return c.json({ detail: 'Failed to fetch user profile' }, 500)
  }
})

// ── POST /mfa/reset ──────────────────────────────────────────────
const mfaResetSchema = z.object({ email: z.string().email() })

app.post('/mfa/reset', authMiddleware, zValidator('json', mfaResetSchema), async (c) => {
  try {
    const caller = c.get('user')
    if (caller.role !== 'superadmin') {
      return c.json({ detail: 'Forbidden' }, 403)
    }
    const { email } = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)
    const result = await db.update(users).set({ mfaEnabled: false, totpSecret: null }).where(eq(users.email, email)).returning({ userId: users.userId, email: users.email })
    if (result.length === 0) return c.json({ detail: 'User not found' }, 404)
    await audit(db, c, { userId: caller.userId, tenantId: null, actionType: 'auth.mfa_reset', targetEntity: result[0]!.userId })
    return c.json({ message: 'MFA reset successfully', user: result[0] })
  } catch (err) {
    console.error('mfa/reset error:', err)
    return c.json({ detail: 'MFA reset failed' }, 500)
  }
})

export default app
