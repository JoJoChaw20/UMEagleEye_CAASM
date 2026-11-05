/**
 * agent-live-demo.ts — runs the chatbot agent against the REAL model (OpenRouter, the key in
 * ../.env) but a recording database that returns no rows, so no tenant data is read or sent.
 * Checks that the model really calls the tools in the streamed OpenAI format we parse.
 * Run from workers/:
 *   npx esbuild scripts/agent-live-demo.ts --bundle --platform=node --format=cjs --outfile=.l.cjs
 *   node --env-file=../.env .l.cjs [model]
 */
import { drizzle } from 'drizzle-orm/neon-http'
import * as schema from '../src/db/schema'
import type { DB } from '../src/db/client'
import type { Env } from '../src/types'
import { runAgent } from '../src/mcp/agent'

const client = Object.assign(async () => ({ rows: [], fields: [], rowCount: 0, command: 'SELECT' }), { transaction: async () => [] })
const db = drizzle(client as never, { schema }) as unknown as DB
const env = {
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY, OPENROUTER_MODEL: process.argv[2] ?? 'deepseek/deepseek-chat', NVD_API_KEY: process.env.NVD_API_KEY,
} as unknown as Env

async function main() {
  const ctx = { db, env, user: { userId: 'demo', role: 'tenant_admin', tenantId: 't' }, tenantId: 't' }
  for (const q of ['Is CVE-2024-3094 exploited in the wild and how likely is exploitation? Short answer.', 'Which ATT&CK technique is T1566 and what tactic? One line.']) {
    const tools: string[] = []
    let text = ''
    await runAgent(ctx, q, [], async (e) => {
      if (e.token) text += e.token as string
      if (e.tool && (e.tool as { status: string }).status === 'done') tools.push((e.tool as { name: string }).name)
      if (e.error) console.log('ERROR', e.error)
    })
    console.log(`\nQ: ${q}\nTOOLS: ${tools.join(', ') || '(none)'}\nA: ${text.slice(0, 500)}`)
  }
}
void main()
