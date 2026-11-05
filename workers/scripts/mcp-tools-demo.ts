/**
 * mcp-tools-demo.ts — checks the chatbot / MCP tools without a model and without touching data.
 *
 *  1. Every tool converts to an OpenAI function schema, and its access rules hold per role.
 *  2. Every tool runs against a RECORDING database (returns no rows), and each SQL statement it
 *     built is then EXPLAINed (planned, never executed) on the real database, which catches
 *     type and enum errors. Skipped when DATABASE_URL is not set.
 *  3. The agent loop runs against a fake model that streams tool calls, then an answer:
 *     events, the proposal for resolve_advisory, unknown tools and the call limit.
 *  4. The MCP server lists the read-only tools over Streamable HTTP (in-process).
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
import { runAgent, toOpenAiTool, resultText, MAX_TOOL_CALLS } from '../src/mcp/agent'
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
  // 1. schemas and access
  for (const t of TOOLS) {
    const f = toOpenAiTool(t)
    check(`schema ${t.name}`, f.function.parameters.type === 'object' && !('$schema' in f.function.parameters))
  }
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

  // 3. the agent loop against a fake model
  const script: Array<Record<string, unknown>> = []
  const sse = (chunks: unknown[]) => new Response(chunks.map(c => `data: ${JSON.stringify(c)}\n\n`).join('') + 'data: [DONE]\n\n')
  const toolCall = (i: number, name: string, args: unknown) => ({ choices: [{ delta: { tool_calls: [{ index: i, id: `c${i}`, function: { name, arguments: JSON.stringify(args) } }] } }] })
  const bodies: Array<{ tools?: unknown[]; messages: unknown[] }> = []
  globalThis.fetch = (async (_url: string, init: { body: string }) => {
    bodies.push(JSON.parse(init.body))
    return sse((script.shift() as { chunks: unknown[] }).chunks)
  }) as never

  script.push({ chunks: [{ choices: [{ delta: { content: 'Checking. ' } }] }, toolCall(0, 'list_alerts', { limit: 3 }), toolCall(1, 'resolve_advisory', { advisory_id: '3f2a91c0', reason: 'patched yesterday' })] })
  script.push({ chunks: [{ choices: [{ delta: { content: 'Done.' } }] }] })
  const events: Array<Record<string, unknown>> = []
  const answer = await runAgent(admin, 'what is open?', [], async e => { events.push(e) })
  check('answer streams across rounds, one paragraph per round', answer === 'Checking. \n\nDone.', JSON.stringify(answer))
  check('tool progress events', events.filter(e => e.tool).length === 4)
  check('tool results go back as untrusted data', JSON.stringify(bodies[1]!.messages).includes('UNTRUSTED TOOL DATA'))
  check('resolve_advisory errors cleanly when nothing matches (no proposal)', !events.some(e => e.proposal))
  check('first call offers tools', Array.isArray(bodies[0]!.tools) && bodies[0]!.tools!.length === toolsFor(admin.user, { actions: true }).length)

  bodies.length = 0
  script.push({ chunks: Array.from({ length: MAX_TOOL_CALLS + 2 }, (_, i) => toolCall(i, 'get_security_overview', {})) })
  script.push({ chunks: [{ choices: [{ delta: { content: 'Summary.' } }] }] })
  const ev2: Array<Record<string, unknown>> = []
  const a2 = await runAgent(admin, 'overview x8', [], async e => { ev2.push(e) })
  const ran = ev2.filter(e => (e.tool as { status?: string } | undefined)?.status === 'done').length
  check(`tool calls capped at ${MAX_TOOL_CALLS}`, ran === MAX_TOOL_CALLS, String(ran))
  check('calls over the cap get an error result', JSON.stringify(bodies[1]!.messages).includes('Tool call limit reached'))
  check('after the cap no tools are offered, so it answers', bodies[1]!.tools === undefined && a2 === 'Summary.', a2)

  bodies.length = 0
  script.push({ chunks: [toolCall(0, 'nope', {})] })
  script.push({ chunks: [{ choices: [{ delta: { content: 'OK.' } }] }] })
  await runAgent(admin, 'x', [], async () => {})
  check('unknown tool answered with an error', JSON.stringify(bodies[1]!.messages).includes('Unknown tool nope'))

  bodies.length = 0
  for (let i = 0; i < 3; i++) script.push({ chunks: [toolCall(0, 'get_cve_coverage', {})] })
  script.push({ chunks: [{ choices: [{ delta: { content: 'Final.' } }] }] })
  const a4 = await runAgent(admin, 'loop', [], async () => {})
  check('a model that keeps calling tools is stopped at the last round', bodies.length === 4 && bodies[3]!.tools === undefined && a4 === 'Final.', `${bodies.length} ${a4}`)

  // continuation: an answer cut by the output limit carries on, at most twice
  bodies.length = 0
  script.push({ chunks: [{ choices: [{ delta: { content: 'Step 1. Step 2' }, finish_reason: 'length' }] }] })
  script.push({ chunks: [{ choices: [{ delta: { content: '. Step 3' }, finish_reason: 'length' }] }] })
  script.push({ chunks: [{ choices: [{ delta: { content: '. Done.' }, finish_reason: 'stop' }] }] })
  const a6 = await runAgent(admin, 'long', [], async () => {})
  check('a cut-off answer is continued to the end', a6 === 'Step 1. Step 2. Step 3. Done.' && bodies.length === 3, JSON.stringify(a6))
  check('the continuation asks to carry on, without tools', JSON.stringify(bodies[1]!.messages).includes('Continue exactly where you stopped') && bodies[1]!.tools === undefined)
  bodies.length = 0
  for (let i = 0; i < 4; i++) script.push({ chunks: [{ choices: [{ delta: { content: `p${i}` }, finish_reason: 'length' }] }] })
  await runAgent(admin, 'endless', [], async () => {})
  check('continuations are capped', bodies.length === 3, String(bodies.length))
  script.length = 0

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
  const big = resultText({ rows: Array.from({ length: 2000 }, (_, i) => ({ i, text: 'x'.repeat(20) })) })
  check('oversized tool result stays valid JSON', big.length <= 6000 && JSON.parse(big).truncated === true, String(big.length))
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

  bodies.length = 0
  script.push({ chunks: [toolCall(0, 'ext_self_lookup_cwe', { cwe_id: '79' })] })
  script.push({ chunks: [{ choices: [{ delta: { content: 'XSS.' } }] }] })
  const realFetch = globalThis.fetch
  const ev5: Array<Record<string, unknown>> = []
  await runAgent({ ...admin, env: extEnv }, 'what is cwe 79 via the external server', [], async e => { ev5.push(e) }, extFetch)
  globalThis.fetch = realFetch
  check('agent offers and calls external tools', JSON.stringify(bodies[0]!.tools).includes('ext_self_lookup_cwe') && JSON.stringify(bodies[1]!.messages).includes('Cross-site'))
  const boEnv = { ...admin, env: extEnv, user: { ...admin.user, role: 'business_owner' } }
  bodies.length = 0
  script.push({ chunks: [{ choices: [{ delta: { content: 'ok' } }] }] })
  await runAgent(boEnv, 'x', [], async () => {}, extFetch)
  check('business_owner gets no external tools', !JSON.stringify(bodies[0]!.tools ?? []).includes('ext_self'))

  // 4. MCP server over Streamable HTTP
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
