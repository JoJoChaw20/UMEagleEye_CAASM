import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import type { Env } from './types'

import authRoutes from './routes/auth'
import assetRoutes from './routes/assets'
import scanRoutes from './routes/scans'
import eventRoutes from './routes/events'
import advisoryRoutes from './routes/advisories'
import postureRoutes from './routes/posture'
import ctiRoutes from './routes/cti'
import reportRoutes from './routes/reports'
import relationshipRoutes from './routes/relationships'
import agentRoutes from './routes/agents'
import topologyRoutes from './routes/topology'
import tenantRoutes from './routes/tenants'
import notificationRoutes from './routes/notifications'

import { handleQueue } from './queues/consumer'
import { handleCron } from './cron/triggers'

const app = new Hono<{ Bindings: Env }>()

// ── Global middleware ─────────────────────────────────────────────
app.use('*', logger())

app.use('*', async (c, next) => {
  const corsHandler = cors({
    origin: [
      'https://umeagleeye.csnet.my',
      'https://umeagleeye.pages.dev',
      c.env.FRONTEND_URL ?? '',
      'http://localhost:5173',
      'http://localhost:3000',
    ].filter(Boolean),
    allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  })
  return corsHandler(c, next)
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
api.route('/cti', ctiRoutes)
api.route('/reports', reportRoutes)
api.route('/relationships', relationshipRoutes)
api.route('/agents', agentRoutes)
api.route('/topology', topologyRoutes)
api.route('/tenants', tenantRoutes)
api.route('/notifications', notificationRoutes)

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
