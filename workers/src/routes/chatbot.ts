import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { desc, eq, and, or, sql, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { isOpenEvent } from '../lib/eventStatus'
import { assets, events, advisories, auditLogs, postureMetrics, ctiIndicators } from '../db/schema'
import { ACTIVE_ADVISORY_STATUSES, advisoryIdPrefix, advisoryIdStartsWith, advisoryInTenant } from '../lib/advisoryScope'
import { agentReply, agentStream } from '../mcp/agent'

// Who may change an advisory's status (routes/advisories.ts STATUS_ROLES).
const ADVISORY_STATUS_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

const app = new Hono<{ Bindings: Env }>()

// ── Intent detection ──────────────────────────────────────────────
function detectIntent(raw: string): { intent: string; query: string } {
  const m = raw.toLowerCase().trim()

  if (/^\/?(help)$/.test(m)) return { intent: 'help', query: '' }
  if (/^\/?mcp$/.test(m)) return { intent: 'mcp', query: '' }
  if (/^\/?status$/.test(m) || /\b(status|health|how are|overview)\b/.test(m))
    return { intent: 'status', query: '' }
  if (/^\/?(assets?)$/.test(m) || /\bassets?\b/.test(m) || /\b(device|server|host|workstation)\b/.test(m))
    return { intent: 'assets', query: '' }
  if (/^\/?alerts?$/.test(m) || /\balerts?\b/.test(m) || /\b(threat|critical event|attack|incident)\b/.test(m))
    return { intent: 'alerts', query: '' }
  if (/^\/?advisori/.test(m) || /\badvisori/.test(m) || /\b(remediat|action item|pending fix)\b/.test(m))
    return { intent: 'advisories', query: '' }
  if (/^\/?posture$/.test(m) || /\b(posture|score|risk level|security score)\b/.test(m))
    return { intent: 'posture', query: '' }
  if (/^\/ask\s+/.test(m))
    return { intent: 'ai', query: raw.slice(4).trim() }
  if (/^debug\s+\S+/i.test(m))
    return { intent: 'debug', query: raw.replace(/^debug\s+/i, '').trim() }
  if (/^fix\s+\S+/i.test(m))
    return { intent: 'fix', query: raw.replace(/^fix\s+/i, '').trim() }
  if (/^fix$/i.test(m))
    return { intent: 'fix', query: '' }
  if (/\b(how (to|do|can|should)|what is|explain|why|prevent|mitigat|harden|block|stop)\b/.test(m))
    return { intent: 'ai', query: raw }

  // Default: AI
  return { intent: 'ai', query: raw }
}

function helpText(role: string): string {
  const lines = [
    '**Available commands:**',
    '',
    '`status` — System health overview',
    '`posture` — Security posture score',
  ]
  if (role !== 'business_owner') {
    lines.push(
      '`assets` — Top assets by criticality',
      '`alerts` — Recent critical & high alerts',
      '`advisories` — Open advisories',
      '`ask <question>` — AI security assistant',
      '`fix <advisory_id>` — Mark advisory as resolved',
      '`mcp` — Connect Claude Code, Claude Desktop or another MCP client to this data',
    )
  }
  lines.push('', 'You can also type naturally — I\'ll understand!')
  return lines.join('\n')
}

// ── DB helpers ────────────────────────────────────────────────────
async function queryStatus(db: ReturnType<typeof getDb>, tenantId?: string) {
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined

  const [totalAssetCnt, myAssetCnt, advisoryCnt, ctiCnt] = await Promise.all([
    db.select({ count: sql<number>`count(*)::int` }).from(assets).where(af),
    db.select({ count: sql<number>`count(*)::int` }).from(assets)
      .where(af ? and(af, eq(assets.inMyAssets, true)) : eq(assets.inMyAssets, true)),
    db.select({ count: sql<number>`count(*)::int` }).from(advisories)
      .where(and(inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), tenantId ? advisoryInTenant(db, tenantId) : undefined)),
    db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(sql`${ctiIndicators.tiEventId} IS NULL`),  // global feeds
  ])

  // Critical events scoped by asset tenant
  let critCount = 0
  if (!tenantId) {
    const [r] = await db.select({ count: sql<number>`count(*)::int` }).from(events)
      .where(and(isOpenEvent(), eq(events.severity, 'critical')))
    critCount = r?.count ?? 0
  } else {
    const assetIds = (await db.select({ assetId: assets.assetId }).from(assets).where(af))
      .map(a => a.assetId)
    if (assetIds.length > 0) {
      const [r] = await db.select({ count: sql<number>`count(*)::int` }).from(events)
        .where(and(inArray(events.assetId, assetIds), isOpenEvent(), eq(events.severity, 'critical')))
      critCount = r?.count ?? 0
    }
  }

  return [
    { label: 'Total Assets',    value: totalAssetCnt[0]?.count ?? 0 },
    { label: 'My Assets',       value: myAssetCnt[0]?.count ?? 0 },
    { label: 'Critical Events', value: critCount },
    { label: 'Open Advisories', value: advisoryCnt[0]?.count ?? 0 },
    { label: 'CTI Indicators',  value: ctiCnt[0]?.count ?? 0 },
    { label: 'Updated',         value: new Date().toLocaleTimeString('en-MY', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Kuala_Lumpur' }) },
  ]
}

async function queryAssets(db: ReturnType<typeof getDb>, tenantId?: string) {
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined
  return db.select({
    hostname:        assets.hostname,
    ipAddress:       assets.ipAddress,
    deviceType:      assets.deviceType,
    criticalityScore: assets.criticalityScore,
  })
    .from(assets)
    .where(af)
    .orderBy(desc(assets.criticalityScore))
    .limit(10)
}

async function queryAlerts(db: ReturnType<typeof getDb>, tenantId?: string) {
  let assetIds: string[] | undefined
  if (tenantId) {
    assetIds = (await db.select({ assetId: assets.assetId }).from(assets)
      .where(eq(assets.tenantId, tenantId))).map(a => a.assetId)
    if (assetIds.length === 0) return []
  }

  const severityFilter = and(isOpenEvent(), or(eq(events.severity, 'critical'), eq(events.severity, 'high')))
  const where = assetIds ? and(inArray(events.assetId, assetIds), severityFilter) : severityFilter

  const rows = await db.select({
    eventId:   events.eventId,
    eventType: events.eventType,
    severity:  events.severity,
    timestamp: events.timestamp,
    details:   events.details,
    assetId:   events.assetId,
    hostname:  assets.hostname,
    ipAddress: assets.ipAddress,
  })
    .from(events)
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(where)
    .orderBy(desc(events.timestamp))
    .limit(100)

  // Deduplicate by (cve_id/detail + assetId) — keep most recent occurrence
  const seen = new Set<string>()
  const unique = []
  for (const r of rows) {
    const d = (r.details ?? {}) as Record<string, unknown>
    const key = `${r.assetId}::${d.cve_id ?? d.package_name ?? r.eventType}`
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(r)
      if (unique.length === 10) break
    }
  }
  return unique
}

async function queryAdvisories(db: ReturnType<typeof getDb>, tenantId?: string) {
  const selectCols = {
    advisoryId:        advisories.advisoryId,
    summary:           advisories.summary,
    recommendedAction: advisories.recommendedAction,
    status:            advisories.status,
    createdAt:         advisories.createdAt,
  }
  return db.select(selectCols).from(advisories)
    .where(and(inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), tenantId ? advisoryInTenant(db, tenantId) : undefined))
    .orderBy(desc(advisories.createdAt)).limit(10)
}

const CHAT_PER_MINUTE = 12

/** True when the user has used up this minute's AI questions. Fails open if KV is down. */
async function overChatLimit(env: Env, userId: string): Promise<boolean> {
  const key = `rl:chat:${userId}:${Math.floor(Date.now() / 60_000)}`
  try {
    const used = Number((await env.KV_CACHE.get(key)) ?? 0)
    if (used >= CHAT_PER_MINUTE) return true
    await env.KV_CACHE.put(key, String(used + 1), { expirationTtl: 120 })
  } catch { /* a cache problem never blocks the chat */ }
  return false
}

/** The one advisory a typed id (or its start) names, in the user's tenant. A prefix that
 *  fits several is refused, so a short id never acts on the wrong advisory. */
async function findAdvisory(
  db: ReturnType<typeof getDb>, rawId: string, tenantId: string | undefined, activeOnly: boolean,
): Promise<{ advisory?: typeof advisories.$inferSelect; error?: string }> {
  const prefix = advisoryIdPrefix(rawId)
  if (!prefix) return { error: `\`${rawId.slice(0, 40)}\` is not an advisory ID. Use the ID shown by the \`advisories\` command.` }
  const rows = await db.select().from(advisories)
    .where(and(
      advisoryIdStartsWith(prefix),
      activeOnly ? inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]) : undefined,
      tenantId ? advisoryInTenant(db, tenantId) : undefined,
    ))
    .limit(2)
  if (rows.length === 0) return { error: `Advisory \`${prefix}\` not found${activeOnly ? ' or already resolved' : ''}.` }
  if (rows.length > 1) return { error: `More than one advisory starts with \`${prefix}\`. Type more of the ID.` }
  return { advisory: rows[0] }
}

async function queryPosture(db: ReturnType<typeof getDb>, tenantId?: string) {
  // Try latest posture snapshot first
  const snapshotFilter = tenantId ? eq(postureMetrics.tenantId, tenantId) : undefined
  const [snap] = await db.select()
    .from(postureMetrics)
    .where(snapshotFilter)
    .orderBy(desc(postureMetrics.timestamp))
    .limit(1)

  if (snap) {
    return {
      score:    snap.overallScore,
      total:    snap.totalAssets,
      critical: snap.totalCriticalAssets,
      openCrit: snap.openCriticalEvents,
    }
  }

  // Fallback: compute live from assets
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const rows = await db.select({ criticalityScore: assets.criticalityScore }).from(assets).where(af)
  const total = rows.length
  if (total === 0) return { score: 0, total: 0, critical: 0, openCrit: 0 }
  const critical = rows.filter(r => (r.criticalityScore ?? 0) >= 8).length
  const avg = rows.reduce((s, r) => s + (r.criticalityScore ?? 5), 0) / total
  const score = Math.max(0, Math.min(100, Math.round(100 - avg * 8)))
  return { score, total, critical, openCrit: 0 }
}

async function askAI(
  env: Env,
  question: string,
  history: Array<{ role: 'user' | 'assistant'; content: string }> = [],
): Promise<string> {
  const useDeepSeek = !!env.DEEPSEEK_API_KEY
  const apiKey = useDeepSeek ? env.DEEPSEEK_API_KEY : env.OPENROUTER_API_KEY
  const baseUrl = useDeepSeek
    ? 'https://api.deepseek.com/chat/completions'
    : 'https://openrouter.ai/api/v1/chat/completions'
  const model = useDeepSeek ? 'deepseek-chat' : (env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat')

  console.log(`[chatbot] askAI → ${model} via ${baseUrl}`)
  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: 'system',
          content:
            'You are a cybersecurity assistant for the UMEagleEye CAASM platform. ' +
            'Give actionable security advice. Use bullet points for steps. Focus on practical remediation. ' +
            'When the user asks follow-up questions, answer in the context of the ongoing security discussion.',
        },
        ...history,
        { role: 'user', content: question },
      ],
      max_tokens: 2048,
    }),
  })
  if (!res.ok) throw new Error(`AI API error: ${res.status}`)
  const data = await res.json() as { choices?: { message?: { content?: string } }[] }
  return data.choices?.[0]?.message?.content ?? 'No response from AI.'
}

// ── POST /categorize — AI names an advisory session ──────────────
app.post(
  '/categorize',
  authMiddleware,
  zValidator('json', z.object({
    summary:           z.string().max(600),
    recommendedAction: z.string().max(1000),
  })),
  async (c) => {
    const { summary, recommendedAction } = c.req.valid('json')
    if (!c.env.DEEPSEEK_API_KEY && !c.env.OPENROUTER_API_KEY) {
      return c.json({ name: 'Security Advisory', category: 'Security', emoji: '🔴' })
    }
    const prompt =
      `You are categorising a security advisory for a CAASM dashboard.\n` +
      `Summary: ${summary}\n` +
      `Action: ${recommendedAction.slice(0, 300)}\n\n` +
      `Reply with ONLY valid JSON (no markdown) in this exact shape:\n` +
      `{"name":"<4 words max>","category":"<CVE Vulnerability|Network Issue|Config Drift|Access Control|Malware|Other>","emoji":"<one emoji>"}`
    try {
      const raw = await askAI(c.env, prompt)
      const parsed = JSON.parse(raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim()) as {
        name?: string; category?: string; emoji?: string
      }
      return c.json({
        name:     parsed.name     ?? 'Security Advisory',
        category: parsed.category ?? 'Security',
        emoji:    parsed.emoji    ?? '🔴',
      })
    } catch {
      return c.json({ name: 'Security Advisory', category: 'Security', emoji: '🔴' })
    }
  },
)

// ── Streaming AI response (avoids Worker 30s wall-clock timeout) ──
function streamAIResponse(
  env: Env,
  question: string,
  history: Array<{ role: 'user' | 'assistant'; content: string }>,
): Response {
  const useDeepSeek = !!env.DEEPSEEK_API_KEY
  const apiKey = useDeepSeek ? env.DEEPSEEK_API_KEY : env.OPENROUTER_API_KEY
  const baseUrl = useDeepSeek
    ? 'https://api.deepseek.com/chat/completions'
    : 'https://openrouter.ai/api/v1/chat/completions'
  const model = useDeepSeek ? 'deepseek-chat' : (env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat')

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>()
  const writer = writable.getWriter()
  const encoder = new TextEncoder()

  ;(async () => {
    try {
      console.log(`[chatbot] streamAI → ${model}`)
      const res = await fetch(baseUrl, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content:
                'You are a cybersecurity assistant for the UMEagleEye CAASM platform. ' +
                'Give actionable security advice. Use bullet points for steps. Focus on practical remediation. ' +
                'When the user asks follow-up questions, answer in the context of the ongoing security discussion.',
            },
            ...history,
            { role: 'user', content: question },
          ],
          stream: true,
          max_tokens: 2048,
        }),
      })
      if (!res.ok || !res.body) {
        await writer.write(encoder.encode(`data: ${JSON.stringify({ error: `AI API error: ${res.status}` })}\n\n`))
        return
      }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const chunk = line.slice(6).trim()
          if (chunk === '[DONE]') { await writer.write(encoder.encode('data: [DONE]\n\n')); return }
          try {
            const token = (JSON.parse(chunk) as { choices?: { delta?: { content?: string } }[] }).choices?.[0]?.delta?.content
            if (token) await writer.write(encoder.encode(`data: ${JSON.stringify({ token })}\n\n`))
          } catch { /* skip malformed chunk */ }
        }
      }
      await writer.write(encoder.encode('data: [DONE]\n\n'))
    } catch (err) {
      console.error('[chatbot] stream error:', err)
      await writer.write(encoder.encode(`data: ${JSON.stringify({ error: 'Stream failed' })}\n\n`))
    } finally {
      await writer.close()
    }
  })()

  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Transfer-Encoding': 'chunked',
    },
  })
}

// ── Route ─────────────────────────────────────────────────────────
app.post(
  '/',
  authMiddleware,
  zValidator('json', z.object({
    message: z.string().min(1).max(1000),
    history: z.array(z.object({
      role: z.enum(['user', 'assistant']),
      content: z.string().max(8000),
    })).max(10).optional(),
    tenant_id: z.string().optional(),
    stream: z.boolean().optional(),
  })),
  async (c) => {
    const { message, history = [], tenant_id, stream: wantStream = false } = c.req.valid('json')
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    // Superadmin can pass an explicit tenant_id to filter per-tenant; others always use own tenant
    const tenantId = user.role === 'superadmin'
      ? (tenant_id || undefined)
      : (user.tenantId ?? undefined)
    const restricted = user.role === 'business_owner'

    const { intent, query } = detectIntent(message)

    if (restricted && !['help', 'status', 'posture'].includes(intent)) {
      return c.json({
        type: 'text',
        content: 'Your role only has access to `status` and `posture` queries.',
      })
    }

    try {
      switch (intent) {
        case 'help':
          return c.json({ type: 'text', content: helpText(user.role) })

        case 'mcp': {
          const endpoint = `${new URL(c.req.url).origin}/api/v1/mcp`
          return c.json({ type: 'text', content: [
            '**UMEagleEye MCP server**',
            '',
            `Endpoint: \`${endpoint}\` (Streamable HTTP). It shows an MCP client what you can see, read-only.`,
            '',
            'Sign in with your dashboard access token (it expires with your session):',
            '',
            `- Claude Code: \`claude mcp add --transport http umeagleeye ${endpoint} --header "Authorization: Bearer <token>"\``,
            `- Claude Desktop (via mcp-remote): \`npx mcp-remote ${endpoint} --header "Authorization:Bearer <token>"\``,
            '',
            'Tools: security overview, CVE-check coverage, assets, alerts, alert explanations and advisories.',
          ].join('\n') })
        }

        case 'status': {
          const items = await queryStatus(db, tenantId)
          return c.json({ type: 'stats', content: 'System Status', items })
        }

        case 'assets': {
          const items = await queryAssets(db, tenantId)
          return c.json({ type: 'assets', content: 'Top Assets by Criticality', items })
        }

        case 'alerts': {
          const items = await queryAlerts(db, tenantId)
          return c.json({ type: 'alerts', content: 'Recent Critical & High Alerts', items })
        }

        case 'advisories': {
          const items = await queryAdvisories(db, tenantId)
          return c.json({ type: 'advisories', content: 'Open Advisories', items })
        }

        case 'posture': {
          const data = await queryPosture(db, tenantId)
          return c.json({ type: 'posture', content: 'Security Posture', data })
        }

        case 'debug': {
          if (restricted || user.role === 'superadmin') {
            return c.json({ type: 'text', content: 'Your role does not have permission to use the AI debug assistant.' })
          }
          if (!query) {
            return c.json({ type: 'text', content: 'Please provide an advisory ID:\n`debug <advisory_id>`' })
          }
          if (!tenantId) return c.json({ type: 'text', content: 'Your account is not in a tenant.' })
          const found = await findAdvisory(db, query, tenantId, false)
          const adv = found.advisory
          if (!adv) return c.json({ type: 'text', content: found.error ?? 'Advisory not found.' })
          if (!c.env.DEEPSEEK_API_KEY && !c.env.OPENROUTER_API_KEY) {
            return c.json({ type: 'text', content: 'AI assistant is not configured on this instance.' })
          }
          // Grounded in the advisory, its alert and its asset (the tools fetch them), so the
          // guide names the real host, OS, port or package instead of generic examples.
          const prompt = [
            `Walk me through advisory ${adv.advisoryId}, for the asset it is about.`,
            `First call get_advisory with advisory_id "${adv.advisoryId}", then explain_alert with its event_id, and get_asset with the asset_id if you need its services or OS.`,
            'Then write, for that asset only:',
            '1. What was found and why it matters on this asset (exposure, criticality, what the port/package/CVE is).',
            '2. Numbered steps to investigate and fix it, with the exact commands for its operating system, using the real port, service, package and versions.',
            '3. How to verify the fix in UMEagleEye (Discovery > New scan for a port or service; Run SBOM scan for a package or CVE) and on the host.',
            '4. What to do if the change was authorised (Accept change on the Alerts page) or turns out to be malicious (isolate, preserve evidence).',
            'Where a value is unknown, say so and how to find it. Keep it complete but tight: no generic background.',
          ].join('\n')
          const debugCtx = { db, env: c.env, tenantId, user: { userId: user.userId, role: user.role, tenantId: user.tenantId } }
          if (wantStream) return agentStream(debugCtx, prompt, history)
          return c.json(await agentReply(debugCtx, prompt, history))
        }

        case 'fix': {
          // Same rule as PATCH /advisories/:id/status: tenant admins, in their own tenant.
          if (!(ADVISORY_STATUS_ROLES as readonly string[]).includes(user.role) || !tenantId) {
            return c.json({ type: 'text', content: 'Your role does not have permission to resolve advisories.' })
          }
          if (!query) {
            return c.json({ type: 'text', content: 'Please provide an advisory ID:\n`fix <advisory_id>`\n\nUse the `advisories` command to see open advisory IDs.' })
          }
          const found = await findAdvisory(db, query, tenantId, true)
          const target = found.advisory
          if (!target) return c.json({ type: 'text', content: found.error ?? 'Advisory not found.' })
          await db.update(advisories)
            .set({ status: 'resolved', resolvedAt: new Date() })
            .where(eq(advisories.advisoryId, target.advisoryId))
          await db.insert(auditLogs).values({
            userId: user.userId, tenantId, actionType: 'advisory_status_update', targetEntity: target.advisoryId,
            previousState: { status: target.status }, newState: { status: 'resolved', via: 'chatbot' },
          })
          return c.json({
            type: 'fix',
            content: `Advisory \`${target.advisoryId.slice(0, 8)}\` marked as **resolved**.`,
            data: { advisoryId: target.advisoryId, summary: target.summary },
          })
        }


        case 'ai': {
          if (!c.env.DEEPSEEK_API_KEY && !c.env.OPENROUTER_API_KEY) {
            return c.json({ type: 'text', content: 'AI assistant is not configured on this instance.' })
          }
          // The model looks facts up itself with the UMEagleEye tools (mcp/tools.ts), scoped
          // to this user's tenant, instead of getting a fixed summary pasted into the prompt.
          const toolCtx = {
            db, env: c.env, tenantId,
            user: { userId: user.userId, role: user.role, tenantId: user.tenantId },
          }
          const question = query || message
          // Each question can cost several model calls: a per-user limit per minute.
          const limited = await overChatLimit(c.env, user.userId)
          if (limited) {
            const text = 'You have asked a lot of questions in the last minute. Wait a moment, then try again.'
            if (!wantStream) return c.json({ type: 'text', content: text }, 429)
            return new Response(`data: ${JSON.stringify({ error: text })}

data: [DONE]

`,
              { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' } })
          }
          if (wantStream) return agentStream(toolCtx, question, history)
          return c.json(await agentReply(toolCtx, question, history))
        }

        default:
          return c.json({ type: 'text', content: helpText(user.role) })
      }
    } catch (err) {
      console.error('[chatbot]', err)
      return c.json({ type: 'text', content: 'Something went wrong. Please try again.' }, 500)
    }
  },
)

export default app
