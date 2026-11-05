/**
 * mcp/external.ts — lets the chatbot use tools from other (open-source) MCP servers, such
 * as an OSV, CVE or ATT&CK server you host, over Streamable HTTP.
 *
 * Off unless configured. EXTERNAL_MCP_SERVERS (a Worker variable or secret) is JSON:
 *
 *   [{ "name": "osv", "url": "https://osv-mcp.example.org/mcp",
 *      "tools": ["query_vulnerability"],          // allowlist: only these are offered
 *      "headers": { "Authorization": "Bearer ..." } }]   // optional
 *
 * Safety: these servers are third parties, so
 *   - only allowlisted tools are offered, to analyst roles, and none can change UMEagleEye;
 *   - arguments that carry internal data (private or link-local IPs, MAC addresses, e-mail
 *     addresses) are refused before anything is sent;
 *   - results are untrusted data, truncated, like every tool result (mcp/agent.ts);
 *   - tool lists are cached in KV for an hour, and every call has a timeout.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/cfworker-provider.js'
import type { Env } from '../types'

export interface ExternalServer { name: string; url: string; tools: string[]; headers?: Record<string, string> }

/** A tool the agent can offer: internal (zod) and external (JSON Schema) tools look the same. */
export interface AgentTool {
  name: string
  title: string
  description: string
  parameters: Record<string, unknown>
  proposesAction?: boolean
  call: (args: unknown) => Promise<unknown>
}

type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>

const TOOL_TTL = 3600
const CALL_TIMEOUT_MS = 15_000

/** The configured servers; anything malformed is skipped with a log line, never half-used. */
export function externalServers(env: Env): ExternalServer[] {
  const raw = (env as unknown as { EXTERNAL_MCP_SERVERS?: string }).EXTERNAL_MCP_SERVERS
  if (!raw) return []
  let list: unknown
  try { list = JSON.parse(raw) } catch {
    console.error('[mcp-ext] EXTERNAL_MCP_SERVERS is not JSON')
    return []
  }
  if (!Array.isArray(list)) return []
  const out: ExternalServer[] = []
  for (const s of list as Array<Record<string, unknown>>) {
    const name = String(s?.name ?? '')
    const url = String(s?.url ?? '')
    const tools = Array.isArray(s?.tools) ? (s.tools as unknown[]).map(String).filter(t => /^[A-Za-z0-9_.-]{1,64}$/.test(t)) : []
    if (!/^[a-z0-9]{2,20}$/.test(name) || !/^https:\/\//.test(url) || tools.length === 0) {
      console.error(`[mcp-ext] skipped server "${name}": needs a lowercase name, an https url and a tools allowlist`)
      continue
    }
    const headers = s.headers && typeof s.headers === 'object' ? s.headers as Record<string, string> : undefined
    out.push({ name, url, tools, headers })
  }
  return out
}

// ── Internal data must not leave ────────────────────────────────
const PRIVATE_V4 = /\b(?:10\.\d{1,3}|127\.\d{1,3}|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}(?:\.\d{1,3})?\b/
const LINK_LOCAL_V6 = /\b(?:fe80|fc[0-9a-f]{2}|fd[0-9a-f]{2}):[0-9a-f:]*/i
const MAC = /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/i
const EMAIL = /\b[^\s@"]+@[^\s@"]+\.[a-z]{2,}\b/i

/** Why these arguments may not be sent to a third party, or null when they may. */
export function internalDataIn(args: unknown): string | null {
  const s = JSON.stringify(args ?? {})
  if (PRIVATE_V4.test(s) || LINK_LOCAL_V6.test(s)) return 'a private network address'
  if (MAC.test(s)) return 'a MAC address'
  if (EMAIL.test(s)) return 'an e-mail address'
  return null
}

async function connect(server: ExternalServer, fetchImpl?: FetchLike): Promise<Client> {
  const client = new Client({ name: 'umeagleeye-chatbot', version: '1.0.0' }, { jsonSchemaValidator: new CfWorkerJsonSchemaValidator() })
  const transport = new StreamableHTTPClientTransport(new URL(server.url), {
    requestInit: server.headers ? { headers: server.headers } : undefined,
    ...(fetchImpl ? { fetch: fetchImpl as never } : {}),
  })
  await client.connect(transport, { timeout: CALL_TIMEOUT_MS })
  return client
}

type ListedTool = { name: string; description?: string; title?: string; inputSchema: Record<string, unknown> }

async function listTools(env: Env, server: ExternalServer, fetchImpl?: FetchLike): Promise<ListedTool[]> {
  const key = `mcp:ext:${server.name}:tools`
  try {
    const cached = await env.KV_CACHE?.get(key, 'json') as ListedTool[] | null
    if (cached) return cached
  } catch { /* cache is optional */ }
  const client = await connect(server, fetchImpl)
  try {
    const res = await client.listTools(undefined, { timeout: CALL_TIMEOUT_MS })
    const tools = (res.tools as ListedTool[]).filter(t => server.tools.includes(t.name))
      .map(t => ({ name: t.name, title: t.title, description: (t.description ?? '').slice(0, 600), inputSchema: t.inputSchema }))
    try { await env.KV_CACHE?.put(key, JSON.stringify(tools), { expirationTtl: TOOL_TTL }) } catch { /* ignore */ }
    return tools
  } finally {
    await client.close().catch(() => {})
  }
}

/** The external tools to offer for one chat turn. A server that is down is left out. */
export async function externalTools(env: Env, fetchImpl?: FetchLike): Promise<AgentTool[]> {
  const out: AgentTool[] = []
  for (const server of externalServers(env)) {
    let tools: ListedTool[]
    try {
      tools = await listTools(env, server, fetchImpl)
    } catch (err) {
      console.error(`[mcp-ext] ${server.name} unavailable:`, err instanceof Error ? err.message : err)
      continue
    }
    for (const t of tools) {
      const name = `ext_${server.name}_${t.name}`.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64)
      out.push({
        name,
        title: `${t.title ?? t.name} (${server.name})`,
        description: `[External MCP server "${server.name}". Send only public identifiers (CVE, package names, versions); never internal hostnames, IPs or user data.] ${t.description ?? ''}`,
        parameters: t.inputSchema && typeof t.inputSchema === 'object' ? t.inputSchema : { type: 'object', properties: {} },
        async call(args) {
          const why = internalDataIn(args)
          if (why) return { error: `Not sent: the arguments contain ${why}, which must not leave UMEagleEye.` }
          const client = await connect(server, fetchImpl)
          try {
            const res = await client.callTool({ name: t.name, arguments: (args ?? {}) as Record<string, unknown> }, undefined, { timeout: CALL_TIMEOUT_MS })
            const text = ((res.content ?? []) as Array<{ type: string; text?: string }>)
              .filter(c => c.type === 'text' && c.text).map(c => c.text).join('\n')
            return { server: server.name, is_error: !!res.isError, result: res.structuredContent ?? text.slice(0, 6000) }
          } finally {
            await client.close().catch(() => {})
          }
        },
      })
    }
  }
  return out
}
