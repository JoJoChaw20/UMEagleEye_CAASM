// Install codes: one code for many computers (Intune, GPO, a script, a container). Each
// computer exchanges it once for an agent of its own, so no two computers share an agent the
// way they would with one agent's connection code.
//
//   GET    /enrolment/tokens       the tenant's install codes (never the code itself)
//   POST   /enrolment/tokens       a new code: the token is returned once; only its SHA-256 is kept
//   DELETE /enrolment/tokens/:id   withdraw a code (agents it made keep working)
//   POST   /enrolment/enrol        the agent: {token, name, kind} -> {agent_id, api_key}

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, desc, eq, isNull, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { AGENT_MANAGE_ROLES } from '../lib/permissions'
import { getDb } from '../db/client'
import { agents, auditLogs, enrolmentTokens } from '../db/schema'
import { generateApiKey } from '../lib/auth'
import { REFUSAL, agentName, tokenState } from '../lib/enrolment'

const app = new Hono<{ Bindings: Env }>()

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function tokenOut(t: typeof enrolmentTokens.$inferSelect) {
  return {
    token_id: t.tokenId, name: t.name, kind: t.kind, max_uses: t.maxUses, uses: t.uses,
    expires_at: t.expiresAt, revoked_at: t.revokedAt, last_used_at: t.lastUsedAt, created_at: t.createdAt,
    state: tokenState(t),
  }
}

app.get('/tokens', authMiddleware, requireRoles(...AGENT_MANAGE_ROLES), async (c) => {
  const user = c.get('user')
  if (!user.tenantId) return c.json({ tokens: [] })
  const db = getDb(c.env.DATABASE_URL)
  const rows = await db.select().from(enrolmentTokens)
    .where(eq(enrolmentTokens.tenantId, user.tenantId)).orderBy(desc(enrolmentTokens.createdAt)).limit(100)
  return c.json({ tokens: rows.map(tokenOut) })
})

app.post('/tokens', authMiddleware, requireRoles(...AGENT_MANAGE_ROLES), zValidator('json', z.object({
  name: z.string().trim().min(1).max(100),
  kind: z.enum(['host', 'network', 'mobile']).default('host'),
  days: z.number().int().min(1).max(90).default(14),
  max_uses: z.number().int().min(1).max(100000).nullable().default(null),
}), (result, c) => {
  if (!result.success) return c.json({ detail: result.error.issues[0]?.message ?? 'Invalid request' }, 400)
}), async (c) => {
  const user = c.get('user')
  if (!user.tenantId) return c.json({ detail: 'User has no tenant assigned' }, 400)
  const body = c.req.valid('json')
  const db = getDb(c.env.DATABASE_URL)
  const token = generateApiKey()
  const [row] = await db.insert(enrolmentTokens).values({
    tenantId: user.tenantId, name: body.name, kind: body.kind, tokenHash: await sha256Hex(token),
    maxUses: body.max_uses, expiresAt: new Date(Date.now() + body.days * 86400_000), createdBy: user.userId,
  }).returning()
  if (!row) return c.json({ detail: 'Failed to create the install code' }, 500)
  await db.insert(auditLogs).values({
    userId: user.userId, tenantId: user.tenantId, actionType: 'agent.install_code_created', targetEntity: row.tokenId,
    previousState: null, newState: { name: row.name, kind: row.kind, max_uses: row.maxUses, expires_at: row.expiresAt },
  }).catch((err) => console.error('install code audit failed:', err))
  // The token is shown once; the dashboard wraps it with the API URL into the install code.
  return c.json({ ...tokenOut(row), token }, 201)
})

app.delete('/tokens/:id', authMiddleware, requireRoles(...AGENT_MANAGE_ROLES), async (c) => {
  const user = c.get('user')
  const id = c.req.param('id')
  if (!user.tenantId || !z.string().uuid().safeParse(id).success) return c.json({ detail: 'Install code not found' }, 404)
  const db = getDb(c.env.DATABASE_URL)
  const [row] = await db.update(enrolmentTokens).set({ revokedAt: new Date() })
    .where(and(eq(enrolmentTokens.tokenId, id), eq(enrolmentTokens.tenantId, user.tenantId), isNull(enrolmentTokens.revokedAt)))
    .returning()
  if (!row) return c.json({ detail: 'Install code not found' }, 404)
  await db.insert(auditLogs).values({
    userId: user.userId, tenantId: user.tenantId, actionType: 'agent.install_code_revoked', targetEntity: id,
    previousState: { name: row.name, uses: row.uses }, newState: { revoked_at: row.revokedAt },
  }).catch((err) => console.error('install code audit failed:', err))
  return c.json(tokenOut(row))
})

// ── POST /enrol ── a computer exchanges the install code for an agent of its own ──
// No user login: the token is the credential (256 random bits; only its hash is stored).
app.post('/enrol', zValidator('json', z.object({
  token: z.string().regex(/^[0-9a-f]{64}$/),
  name: z.string().max(255).optional(),
  kind: z.enum(['host', 'network', 'mobile']).optional(),
}), (result, c) => {
  if (!result.success) return c.json({ detail: 'This is not a valid install code' }, 400)
}), async (c) => {
  try {
    const body = c.req.valid('json')
    const db = getDb(c.env.DATABASE_URL)
    const hash = await sha256Hex(body.token)
    const [token] = await db.select().from(enrolmentTokens).where(eq(enrolmentTokens.tokenHash, hash)).limit(1)
    if (!token) return c.json({ detail: 'This install code is not known. Check that it was copied whole.' }, 403)
    const state = tokenState(token)
    if (state !== 'active') return c.json({ detail: REFUSAL[state] }, 403)
    if (body.kind && body.kind !== token.kind) {
      return c.json({ detail: `This install code is for ${token.kind === 'network' ? 'network agents' : token.kind === 'mobile' ? 'phones' : "computers' agents"}` }, 403)
    }
    // Count the use first, atomically, so a limited code never makes more agents than allowed.
    const [counted] = await db.update(enrolmentTokens)
      .set({ uses: sql`${enrolmentTokens.uses} + 1`, lastUsedAt: new Date() })
      .where(and(eq(enrolmentTokens.tokenId, token.tokenId), isNull(enrolmentTokens.revokedAt),
        sql`${enrolmentTokens.expiresAt} > now()`,
        or(isNull(enrolmentTokens.maxUses), sql`${enrolmentTokens.uses} < ${enrolmentTokens.maxUses}`)))
      .returning({ uses: enrolmentTokens.uses })
    if (!counted) return c.json({ detail: REFUSAL.used_up }, 403)

    const apiKey = generateApiKey()
    const [agent] = await db.insert(agents).values({
      tenantId: token.tenantId, name: agentName(body.name), apiKeyHash: await sha256Hex(apiKey), kind: token.kind,
      config: { enrolled_with: token.tokenId },
    }).returning()
    if (!agent) return c.json({ detail: 'Failed to register the agent' }, 500)
    await db.insert(auditLogs).values({
      userId: null, tenantId: token.tenantId, actionType: 'agent.enrolled', targetEntity: agent.agentId,
      previousState: null, newState: { name: agent.name, kind: agent.kind, install_code: token.name, uses: counted.uses },
    }).catch((err) => console.error('enrol audit failed:', err))
    return c.json({ agent_id: agent.agentId, api_key: apiKey, name: agent.name, kind: agent.kind }, 201)
  } catch (err) {
    console.error('enrolment POST /enrol error:', err)
    return c.json({ detail: 'Failed to register the agent' }, 500)
  }
})

export default app
