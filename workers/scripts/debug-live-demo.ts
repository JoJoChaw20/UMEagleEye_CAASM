/**
 * debug-live-demo.ts — runs the chatbot's `debug <advisory_id>` flow for one REAL advisory:
 * the real database (read-only tools), the real model (OpenRouter key in ../.env), as a
 * tenant admin of the advisory's tenant. Prints the tools used and the full answer, so the
 * answer can be checked against the alert's facts. Nothing is written.
 * Run from workers/:
 *   npx esbuild scripts/debug-live-demo.ts --bundle --platform=node --format=cjs --outfile=.d.cjs
 *   node --env-file=../.env .d.cjs <advisory_id> [model]
 */
import { sql } from 'drizzle-orm'
import { getDb } from '../src/db/client'
import type { Env } from '../src/types'
import { runAgent } from '../src/mcp/agent'

const url = (process.env.DATABASE_URL ?? '').replace(/^postgresql\+asyncpg:\/\//, 'postgresql://').replace(/([?&])ssl=require/, '$1sslmode=require')
const advisoryId = process.argv[2] ?? ''
const env = {
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY, OPENROUTER_MODEL: process.argv[3] ?? 'deepseek/deepseek-v4-pro',
  NVD_API_KEY: process.env.NVD_API_KEY,
} as unknown as Env

async function main() {
  const db = getDb(url)
  const rows = await db.execute(sql`
    SELECT a.tenant_id, e.event_type, e.details, a.hostname, a.ip_address
    FROM advisories adv JOIN events e ON e.event_id = adv.event_id JOIN assets a ON a.asset_id = e.asset_id
    WHERE adv.advisory_id::text = ${advisoryId}`)
  const row = rows.rows[0] as { tenant_id: string; event_type: string; details: unknown; hostname: string | null; ip_address: string } | undefined
  if (!row) { console.log('advisory not found in this database'); return }
  console.log(`ALERT FACTS: ${row.event_type} on ${row.hostname ?? row.ip_address} ${JSON.stringify(row.details)}`)
  const ctx = { db, env, user: { userId: 'demo', role: 'tenant_admin', tenantId: row.tenant_id }, tenantId: row.tenant_id }
  const prompt = [
    `Walk me through advisory ${advisoryId}, for the asset it is about.`,
    `First call get_advisory with advisory_id "${advisoryId}", then explain_alert with its event_id, and get_asset with the asset_id if you need its services or OS.`,
    'Then write, for that asset only:',
    '1. What was found and why it matters on this asset (exposure, criticality, what the port/package/CVE is).',
    '2. Numbered steps to investigate and fix it, with the exact commands for its operating system, using the real port, service, package and versions.',
    '3. How to verify the fix in UMEagleEye (Discovery > New scan for a port or service; Run SBOM scan for a package or CVE) and on the host.',
    '4. What to do if the change was authorised (Accept change on the Alerts page) or turns out to be malicious (isolate, preserve evidence).',
    'Where a value is unknown, say so and how to find it. Keep it complete but tight: no generic background.',
  ].join('\n')
  const tools: string[] = []
  let text = ''
  const t0 = Date.now()
  await runAgent(ctx, prompt, [], async (e) => {
    if (e.token) text += e.token as string
    if (e.tool && (e.tool as { status: string }).status === 'done') tools.push((e.tool as { name: string }).name)
    if (e.error) console.log('ERROR', e.error)
  })
  console.log(`TOOLS: ${tools.join(', ')}\nCHARS: ${text.length}  SECONDS: ${Math.round((Date.now() - t0) / 1000)}\n----\n${text}\n----`)
}
void main()
