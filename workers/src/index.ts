import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { CORS_HEADERS, CORS_METHODS, corsOrigins } from './lib/cors'
import { secureHeaders } from 'hono/secure-headers'
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
import ownershipRoutes from './routes/ownership'
import noticeRoutes from './routes/notices'
import notificationRoutes from './routes/notifications'
import chatbotRoutes from './routes/chatbot'
import mcpRoutes from './routes/mcp'
import dashboardRoutes from './routes/dashboard'
import sbomRoutes from './routes/sbom'
import sightingRoutes from './routes/sightings'

import { handleQueue } from './queues/consumer'
import { shouldSignalKg, signalKgSyncSafe } from './kg/sync'
import { handleCron } from './cron/triggers'
import { syncAgentHub } from './services/agentHub'
import { maybeHarvestMycert } from './services/mycert'
import { isDatabaseUnavailable } from './lib/dbErrors'
import { perfMiddleware } from './kg/perf'

const app = new Hono<{ Bindings: Env }>()

// ── Global middleware ─────────────────────────────────────────────
// No request logger: Workers Logs already keeps one invocation log per request (method, URL, status,
// duration), and the logger's two extra lines tripled the events counted against the free 200,000 a day.

// Speed history: route pattern, status, total and database time per request (kg/perf.ts). Never fails a request.
app.use('*', perfMiddleware)

// Browser hardening for every API answer (HSTS, nosniff, no framing). Cross-origin resource and
// embedder policies are left off: the dashboard is on another origin and reads the API with CORS.
app.use('*', secureHeaders({ crossOriginResourcePolicy: false, crossOriginEmbedderPolicy: false }))

app.use('*', async (c, next) => {
  const corsHandler = cors({
    origin: corsOrigins(c.env),
    allowMethods: [...CORS_METHODS],
    allowHeaders: CORS_HEADERS,
    maxAge: 86400,
  })
  return corsHandler(c, next)
})

// After a successful write, ask for one debounced graph sync (kg/sync.ts). Runs after the response
// is sent and cannot fail it. Agent uploads (X-Agent-ID header) use the longer agent window.
app.use('*', async (c, next) => {
  await next()
  if (!shouldSignalKg(c.req.method, c.req.path, c.res.status)) return
  const fromAgent = !!c.req.header('X-Agent-ID')
  try { c.executionCtx.waitUntil(signalKgSyncSafe(c.env, fromAgent)) } catch { /* no execution context: skip */ }
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
api.route('/tenants', ownershipRoutes)
api.route('/notices', noticeRoutes)
api.route('/notifications', notificationRoutes)
api.route('/chatbot', chatbotRoutes)
api.route('/mcp', mcpRoutes)
api.route('/sboms', sbomRoutes)
api.route('/sightings', sightingRoutes)
api.route('/dashboard', dashboardRoutes)

app.route('/api/v1', api)

// ── 404 handler ───────────────────────────────────────────────────
app.notFound((c) => c.json({ detail: 'Route not found' }, 404))
app.onError((err, c) => {
  console.error('[error]', err)
  // Neon refusing (compute suspended, quota used up) or unreachable: say so, so agents' logs and the
  // dashboard show what is wrong instead of a bare 500.
  if (isDatabaseUnavailable(err)) return c.json({ detail: 'The database is not available right now. Try again later.' }, 503)
  return c.json({ detail: 'Internal server error' }, 500)
})

// ── Cloudflare Workers export ─────────────────────────────────────
export { AgentHub } from './durable/agentHub'

// Scheduled jobs and queue batches read agents' last-seen times (who is online, where to route a scan):
// the ones the AgentHub kept in memory are written first (services/agentHub.ts).
// A request from Malaysia or Singapore (agents' check-ins, the dashboard) may fetch MyCERT after it is
// answered: MyCERT refuses the Worker's requests otherwise (services/mycert.ts maybeHarvestMycert).
export default {
  fetch: (request, env, ctx) => {
    const country = (request as unknown as { cf?: { country?: string } }).cf?.country
    ctx.waitUntil(maybeHarvestMycert(env.KV_CACHE, country))
    return app.fetch(request, env, ctx)
  },
  queue: async (batch, env) => {
    await syncAgentHub(env)
    return handleQueue(batch, env)
  },
  scheduled: async (event, env) => {
    await syncAgentHub(env, true)
    return handleCron(event, env)
  },
} satisfies ExportedHandler<Env>
