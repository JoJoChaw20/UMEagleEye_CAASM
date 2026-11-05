/**
 * routes/mcp.ts — the MCP endpoint, /api/v1/mcp (Streamable HTTP, stateless, JSON responses).
 *
 * Sign-in is the dashboard's Bearer token, so an MCP client sees exactly what its user sees:
 * one tenant (the platform superadmin: all, or ?tenant_id=). Each request builds a fresh
 * server; there are no MCP sessions to store.
 */
import { Hono } from 'hono'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { buildMcpServer } from '../mcp/server'

const app = new Hono<{ Bindings: Env }>()

app.all('/', authMiddleware, async (c) => {
  if (c.req.method !== 'POST') {
    return c.json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed: this server is stateless, use POST' }, id: null },
      405, { Allow: 'POST' })
  }
  const user = c.get('user')
  const picked = c.req.query('tenant_id')
  const ctx = {
    db: getDb(c.env.DATABASE_URL),
    env: c.env,
    user: { userId: user.userId, role: user.role, tenantId: user.tenantId },
    tenantId: user.role === 'superadmin' ? (picked || undefined) : (user.tenantId ?? undefined),
  }
  const server = buildMcpServer(ctx)
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
  await server.connect(transport)
  try {
    return await transport.handleRequest(c.req.raw)
  } catch (err) {
    console.error('[mcp] request failed:', err)
    return c.json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null }, 500)
  }
})

export default app
