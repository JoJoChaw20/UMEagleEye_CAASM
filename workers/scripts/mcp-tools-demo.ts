/**
 * mcp-tools-demo.ts — checks the MCP tools without a model and without touching data.
 *
 *  1. Every tool's access rules hold per role.
 *  2. Every tool runs against a RECORDING database (returns no rows), and each SQL statement it
 *     built is then EXPLAINed (planned, never executed) on the real database, which catches
 *     type and enum errors. Skipped when DATABASE_URL is not set.
 *  3. The MCP server lists the read-only tools over Streamable HTTP (in-process).
 *
 * Run from workers/:
 *   npx esbuild scripts/mcp-tools-demo.ts --bundle --platform=node --format=cjs --outfile=.m.cjs
 *   node --env-file=../.env .m.cjs
 */
import { drizzle } from 'drizzle-orm/neon-http'
import { neon } from '@neondatabase/serverless'
import * as schema from '../src/db/schema'
import type { DB } from '../src/db/client'
import type { Env } from '../src/types'
import { TOOLS, toolsFor, runTool, type ToolContext } from '../src/mcp/tools'
import { externalTools, internalDataIn } from '../src/mcp/external'
import { buildMcpServer } from '../src/mcp/server'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'

let pass = 0, fail = 0
function check(label: string, ok: boolean, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || !detail ? '' : `  ${detail}`}`)
  ok ? pass++ : fail++
}

// ── a database that records statements and returns nothing ──
const recorded: Array<{ sql: string; params: unknown[] }> = []
const fakeClient = Object.assign(
  async (query: string, params: unknown[] = []) => {
    recorded.push({ sql: query, params })
    return { rows: [], fields: [], rowCount: 0, command: 'SELECT' }
  },
  { transaction: async () => [] },
)
const db = drizzle(fakeClient as never, { schema }) as unknown as DB
const kv = new Map<string, string>()
const KV_CACHE = {
  async get(k: string, type?: string) { const v = kv.get(k); return v == null ? null : type === 'json' ? JSON.parse(v) : v },
  async put(k: string, v: string) { kv.set(k, v) },
}
const env = { DEEPSEEK_API_KEY: 'test-key', KV_CACHE } as unknown as Env
const T = '00000000-0000-0000-0000-0000000000aa'
const A = '00000000-0000-0000-0000-0000000000bb'
const admin: ToolContext = { db, env, user: { userId: 'u1', role: 'tenant_admin', tenantId: T }, tenantId: T }

async function main() {
  // 1. access
  const names = (role: string, actions = true) => toolsFor({ userId: 'x', role, tenantId: T }, { actions }).map(t => t.name)
  check('business_owner gets aggregate and public tools only',
    JSON.stringify(names('business_owner')) === JSON.stringify(['get_security_overview', 'get_cve_coverage', 'lookup_attack_technique', 'lookup_cwe']),
    JSON.stringify(names('business_owner')))
  check('tenant_admin may propose resolving', names('tenant_admin').includes('resolve_advisory'))
  check('superadmin may not propose resolving', !names('superadmin').includes('resolve_advisory'))
  check('MCP clients get no action tools', !names('tenant_admin', false).includes('resolve_advisory'))

  // 2. every tool's SQL
  const calls: Array<[string, unknown]> = [
    ['get_security_overview', {}], ['get_cve_coverage', {}],
    ['search_assets', { query: '10.0_%', device_type: 'server', internet_facing: true, limit: 5 }],
    ['get_asset', { asset_id: A }],
    ['list_alerts', { severity: ['critical', 'high'], event_type: 'cve_detected', asset_id: A, cve_id: 'cve-2024-1234' }],
    ['explain_alert', { event_id: A }], ['list_advisories', { status: 'live' }], ['list_advisories', { status: 'all' }],
    ['get_advisory', { advisory_id: '3f2a91c0' }], ['resolve_advisory', { advisory_id: '3f2a91c0', reason: 'patched' }],
    ['lookup_cve', { cve_id: 'cve-2024-3094' }],
  ]
  for (const [name, args] of calls) {
    const tool = TOOLS.find(t => t.name === name)!
    const before = recorded.length
    const out = await runTool(admin, tool, args) as Record<string, unknown>
    const failed = out && typeof out === 'object' && out.error === 'The tool failed; try again or ask differently.'
    check(`runs ${name}`, !failed && recorded.length > before, JSON.stringify(out).slice(0, 160))
  }
  check('bad arguments are reported, not run', !!((await runTool(admin, TOOLS.find(t => t.name === 'list_alerts')!, { severity: ['info'] })) as { error?: string }).error)
  check('unknown argument refused', !!((await runTool(admin, TOOLS.find(t => t.name === 'search_assets')!, { tenant_id: T })) as { error?: string }).error)
  // cti_indicators (the CISA KEV catalogue) is global public data; every tenant table is filtered
  const tenantData = recorded.filter(r => /"(assets|events|advisories)"/.test(r.sql))
  check('every query on tenant data is tenant-filtered', tenantData.length > 0 && tenantData.every(r => r.params.includes(T)),
    tenantData.filter(r => !r.params.includes(T)).map(r => r.sql.slice(0, 120)).join(' | '))

  const url = (process.env.DATABASE_URL ?? '').replace(/^postgresql\+asyncpg:\/\//, 'postgresql://').replace(/([?&])ssl=require/, '$1sslmode=require')
  if (url) {
    const real = neon(url) as unknown as (s: string, p: unknown[]) => Promise<unknown>
    let planned = 0
    for (const r of recorded) {
      try { await real(`EXPLAIN ${r.sql}`, r.params); planned++ } catch (err) {
        check(`plan: ${r.sql.slice(0, 90)}`, false, (err as Error).message)
      }
    }
    check(`all ${recorded.length} tool statements plan on the real schema`, planned === recorded.length)
  } else {
    console.log('SKIP  EXPLAIN (no DATABASE_URL)')
  }

  // 2b. public intel without the database
  const tool = (n: string) => TOOLS.find(x => x.name === n)!
  const t1059 = await runTool(admin, tool('lookup_attack_technique'), { query: 'T1059' }) as { name?: string; sub_techniques?: unknown[] }
  check('ATT&CK by id', t1059.name === 'Command and Scripting Interpreter' && (t1059.sub_techniques?.length ?? 0) > 5, JSON.stringify(t1059).slice(0, 120))
  const phish = await runTool(admin, tool('lookup_attack_technique'), { query: 'phishing' }) as { matches?: Array<{ technique_id: string }> }
  check('ATT&CK by words', (phish.matches ?? []).some(m => m.technique_id === 'T1566'), JSON.stringify(phish).slice(0, 120))
  const cwe = await runTool(admin, tool('lookup_cwe'), { cwe_id: 'CWE-79' }) as { name?: string }
  check('CWE by id', /Cross-site Scripting/.test(cwe.name ?? ''), JSON.stringify(cwe))
  const cve = await runTool(admin, tool('lookup_cve'), { cve_id: 'CVE-2024-3094' }) as { nvd?: { attackVector?: string } | null; references?: unknown[]; sources_missing?: string[] }
  check('lookup_cve answers (NVD/OSV/EPSS live, only the id sent)', Array.isArray(cve.references), JSON.stringify(cve).slice(0, 200))
  console.log(`      lookup_cve live sources missing: ${JSON.stringify(cve.sources_missing)}`)

  // 2c. scope fails closed
  const before2 = recorded.length
  await runTool({ ...admin, tenantId: undefined }, tool('list_alerts'), {})
  check('tenant admin without a tenant reads nothing', recorded.slice(before2).every(r => /\bfalse\b/.test(r.sql)), recorded.slice(before2).map(r => r.sql.slice(0, 80)).join(' | '))
  check('internal data guard', [
    internalDataIn({ q: '192.168.1.5' }), internalDataIn({ q: 'fe80::1' }), internalDataIn({ q: 'aa:bb:cc:dd:ee:ff' }),
    internalDataIn({ q: 'a@b.com' }), internalDataIn({ q: 'CVE-2024-3094 openssl 3.0.1' }), internalDataIn({ q: '8.8.8.8' }),
  ].map(Boolean).join() === 'true,true,true,true,false,false')

  // 2d. an external MCP server: UMEagleEye's own MCP server stands in for it
  const extFetch = async (url: string | URL, init?: RequestInit) => {
    const s = buildMcpServer(admin)
    const tr = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
    await s.connect(tr)
    return tr.handleRequest(new Request(String(url), init))
  }
  const extEnv = { ...env, EXTERNAL_MCP_SERVERS: JSON.stringify([
    { name: 'self', url: 'https://ext.example/mcp', tools: ['lookup_cwe', 'search_assets'] },
    { name: 'BAD NAME', url: 'http://insecure', tools: [] },
  ]) } as unknown as Env
  const ext = await externalTools(extEnv, extFetch)
  check('external: only allowlisted tools, bad config skipped', JSON.stringify(ext.map(x => x.name)) === JSON.stringify(['ext_self_search_assets', 'ext_self_lookup_cwe']) || JSON.stringify(ext.map(x => x.name).sort()) === JSON.stringify(['ext_self_lookup_cwe', 'ext_self_search_assets']), JSON.stringify(ext.map(x => x.name)))
  check('external: tool list cached in KV', kv.has('mcp:ext:self:tools'))
  const extCwe = await ext.find(x => x.name === 'ext_self_lookup_cwe')!.call({ cwe_id: '787' }) as { result?: unknown }
  check('external: call goes through MCP', JSON.stringify(extCwe).includes('Out-of-bounds Write'), JSON.stringify(extCwe).slice(0, 160))
  const refused = await ext.find(x => x.name === 'ext_self_search_assets')!.call({ query: '10.0.0.12' }) as { error?: string }
  check('external: private IP never sent', /private network address/.test(refused.error ?? ''), JSON.stringify(refused))

  // 3. MCP server over Streamable HTTP
  const server = buildMcpServer(admin)
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
  await server.connect(transport)
  const rpc = (body: unknown) => transport.handleRequest(new Request('https://x/api/v1/mcp', {
    method: 'POST', body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
  }))
  const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'demo', version: '1' } } })
  check('MCP initialize', init.status === 200, String(init.status))
  const server2 = buildMcpServer(admin)
  const transport2 = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
  await server2.connect(transport2)
  const list = await transport2.handleRequest(new Request('https://x/api/v1/mcp', {
    method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' },
  }))
  const listed = await list.json() as { result?: { tools?: Array<{ name: string; annotations?: { readOnlyHint?: boolean } }> } }
  const mcpNames = (listed.result?.tools ?? []).map(t => t.name)
  check('MCP lists the read-only tools', mcpNames.length === toolsFor(admin.user, { actions: false }).length && !mcpNames.includes('resolve_advisory'), JSON.stringify(listed).slice(0, 200))
  check('MCP tools are marked read-only', (listed.result?.tools ?? []).every(t => t.annotations?.readOnlyHint === true))

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
}
void main()
