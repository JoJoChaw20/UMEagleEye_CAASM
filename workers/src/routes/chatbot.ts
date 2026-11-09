import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { graphReply, graphStream, modelFor } from '../kg/agent'
import { kgQuery } from '../kg/store'
import { confirmAdvisory } from '../kg/confirm'
import { signalKgSyncSafe } from '../kg/sync'

const app = new Hono<{ Bindings: Env }>()

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

/** A one-message event stream: the chatbot's way of refusing in stream mode. */
function sseError(text: string): Response {
  return new Response(`data: ${JSON.stringify({ error: text })}\n\ndata: [DONE]\n\n`, {
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' },
  })
}

// ── Route ─────────────────────────────────────────────────────────
// Every question goes through the graph agent. There are no typed commands: `fix <id>` is an
// ordinary question, and only the Confirm flow can close an advisory.
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

    const ai = modelFor(c.env)
    if (!ai) {
      const text = 'AI assistant is not configured on this instance.'
      return wantStream ? sseError(text) : c.json({ type: 'text', content: text })
    }
    // Each question can cost several model calls: a per-user limit per minute.
    if (await overChatLimit(c.env, user.userId)) {
      const text = 'You have asked a lot of questions in the last minute. Wait a moment, then try again.'
      return wantStream ? sseError(text) : c.json({ type: 'text', content: text }, 429)
    }

    try {
      // The company comes from the signed-in user; accessFor honours tenant_id for a superadmin only.
      const ctx = { query: kgQuery(c.env), env: c.env, ai, user: { userId: user.userId, role: user.role, tenantId: user.tenantId }, pickedTenant: tenant_id ?? null }
      if (wantStream) return graphStream(ctx, message, history)
      const { body, status } = await graphReply(ctx, message, history)
      return c.json(body, status)
    } catch (err) {
      console.error('[chatbot]', err instanceof Error ? err.message : err)
      return c.json({ type: 'text', content: 'Something went wrong. Please try again.' }, 500)
    }
  },
)

// ── POST /confirm — the only way an advisory is closed from the chat ──
// The signal middleware in index.ts skips /chatbot paths, so the graph sync is signalled here.
app.post(
  '/confirm',
  authMiddleware,
  zValidator('json', z.object({ token: z.string().min(1).max(128) })),
  async (c) => {
    const { token } = c.req.valid('json')
    const user = c.get('user')
    const kv = c.env.KV_CACHE
    const result = await confirmAdvisory({
      kv: { get: (k) => kv.get(k), delete: (k) => kv.delete(k) },
      q: kgQuery(c.env),
      user: { userId: user.userId, role: user.role, tenantId: user.tenantId },
      token,
    })
    if (!result.ok) return c.json({ error: result.error }, result.status)
    c.executionCtx.waitUntil(signalKgSyncSafe(c.env))
    return c.json({ ok: true, advisory_id: result.advisoryId, summary: result.summary })
  },
)

export default app
