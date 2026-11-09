import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { secureHeaders } from 'hono/secure-headers'
import { logger } from 'hono/logger'
import type { Env } from './types'

import authRoutes from './routes/auth'
import assetRoutes from './routes/assets'
import scanRoutes from './routes/scans'
import eventRoutes from './routes/events'
import advisoryRoutes from './routes/advisories'
import postureRoutes from './routes/posture'
import ctiRoutes from './routes/cti'
import tiEventRoutes from './routes/tiEvents'
import reportRoutes from './routes/reports'
import relationshipRoutes from './routes/relationships'
import agentRoutes from './routes/agents'
import topologyRoutes from './routes/topology'
import networkRoutes from './routes/network'
import enrolmentRoutes from './routes/enrolment'
import tenantRoutes from './routes/tenants'
import notificationRoutes from './routes/notifications'
import chatbotRoutes from './routes/chatbot'
import mcpRoutes from './routes/mcp'
import dashboardRoutes from './routes/dashboard'
import sbomRoutes from './routes/sbom'

import { handleQueue } from './queues/consumer'
import { shouldSignalKg, signalKgSyncSafe } from './kg/sync'
import { handleCron } from './cron/triggers'

const app = new Hono<{ Bindings: Env }>()

// ── Global middleware ─────────────────────────────────────────────
app.use('*', logger())

// Browser hardening for every API answer (HSTS, nosniff, no framing). Cross-origin resource and
// embedder policies are left off: the dashboard is on another origin and reads the API with CORS.
app.use('*', secureHeaders({ crossOriginResourcePolicy: false, crossOriginEmbedderPolicy: false }))

app.use('*', async (c, next) => {
  const corsHandler = cors({
    origin: [
      'https://umeagleeye.csnet.my',
      'https://umeagleeye.pages.dev',
      c.env.FRONTEND_URL ?? '',
      // A local dev server only outside production (a page on localhost could be anything)
      ...(c.env.APP_ENV === 'production' ? [] : ['http://localhost:5173', 'http://localhost:3000']),
    ].filter(Boolean),
    allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Mcp-Session-Id', 'MCP-Protocol-Version', 'Last-Event-ID'],
    maxAge: 86400,
  })
  return corsHandler(c, next)
})

// After a successful write, ask for one debounced graph sync (kg/sync.ts). Runs after the response
// is sent and cannot fail it. Agent ingest (/api/v1/agents/*) passes through here like any route.
app.use('*', async (c, next) => {
  await next()
  if (!shouldSignalKg(c.req.method, c.req.path, c.res.status)) return
  try { c.executionCtx.waitUntil(signalKgSyncSafe(c.env)) } catch { /* no execution context: skip */ }
})

// ── Health ────────────────────────────────────────────────────────
app.get('/', (c) => c.json({ status: 'ok', service: 'UMEagleEye API', version: '2.0.0' }))
app.get('/health', (c) => c.json({ status: 'healthy', timestamp: new Date().toISOString() }))

// ── API v1 routes ─────────────────────────────────────────────────
const api = new Hono<{ Bindings: Env }>()

api.route('/auth', authRoutes)
api.route('/assets', assetRoutes)
api.route('/scans', scanRoutes)
api.route('/events', eventRoutes)
api.route('/advisories', advisoryRoutes)
api.route('/posture', postureRoutes)
api.route('/cti/events', tiEventRoutes)   // before /cti so /cti/events/* reaches it
api.route('/cti', ctiRoutes)
api.route('/reports', reportRoutes)
api.route('/relationships', relationshipRoutes)
api.route('/agents', agentRoutes)
api.route('/topology', topologyRoutes)
api.route('/network', networkRoutes)
api.route('/enrolment', enrolmentRoutes)
api.route('/tenants', tenantRoutes)
api.route('/notifications', notificationRoutes)
api.route('/chatbot', chatbotRoutes)
api.route('/mcp', mcpRoutes)
api.route('/sboms', sbomRoutes)
api.route('/dashboard', dashboardRoutes)

app.route('/api/v1', api)

// ── 404 handler ───────────────────────────────────────────────────
app.notFound((c) => c.json({ detail: 'Route not found' }, 404))
app.onError((err, c) => {
  console.error('[error]', err)
  return c.json({ detail: 'Internal server error' }, 500)
})

// ── Cloudflare Workers export ─────────────────────────────────────
export default {
  fetch: app.fetch,
  queue: handleQueue,
  scheduled: handleCron,
} satisfies ExportedHandler<Env>
