/**
 * kg/store.ts — reads and writes of the graph tables, and embeddings. Raw SQL through one
 * query function: vector and tsvector columns are not in the Drizzle schema.
 */
import { neon } from '@neondatabase/serverless'
import type { Env } from '../types'
import { wellFormed, type KgEdge, type KgNode, type Row } from './extract'

export type Q = (text: string, params?: unknown[]) => Promise<Row[]>

export function kgQuery(env: Env): Q {
  const sql = neon(env.DATABASE_URL)
  return (text, params = []) => sql(text, params) as unknown as Promise<Row[]>
}

const EMBED_MODEL = '@cf/baai/bge-base-en-v1.5'
const EMBED_BATCH = 96
const EMBED_CHARS = 1500

/** Bulk rows (software, packages, addresses) are found by keyword; embedding them adds cost, not recall. */
export const EMBEDDED_TYPES = ['asset', 'event', 'advisory', 'problem', 'status', 'posture', 'agent', 'scan', 'cve', 'ti_event',
  'doc', 'page', 'route', 'table', 'file', 'chunk', 'technique', 'cwe']

/** Vectors for the texts, or null for the whole batch when the service fails. */
export async function embed(env: Env, texts: string[]): Promise<number[][] | null> {
  if (!env.AI || texts.length === 0) return null
  try {
    const res = await (env.AI as unknown as { run: (m: string, i: unknown) => Promise<{ data?: number[][] }> })
      .run(EMBED_MODEL, { text: texts.map(t => t.slice(0, EMBED_CHARS)) })
    return res.data && res.data.length === texts.length ? res.data : null
  } catch (err) {
    console.error('[kg] embedding failed:', err instanceof Error ? err.message : err)
    return null
  }
}

const embedText = (n: { title: string; body: string }) => `${n.title}\n${n.body}`
const vectorLiteral = (v: number[]) => `[${v.join(',')}]`

function lastByKey<T>(items: T[], keyOf: (t: T) => string): T[] {
  return [...new Map(items.map(i => [keyOf(i), i])).values()]
}

/** Writes nodes. Text that did not change keeps its embedding; embedding failure still stores the node. */
export async function upsertNodes(q: Q, env: Env, input: KgNode[]): Promise<void> {
  const nodes = lastByKey(input, n => n.key)
  if (nodes.length === 0) return
  const toEmbed = nodes.filter(n => EMBEDDED_TYPES.includes(n.type))
  const vectors = new Map<string, string>()
  if (toEmbed.length) {
    const known = await q(`SELECT key, title, body FROM kg_nodes WHERE key = ANY($1::text[]) AND embedding IS NOT NULL`, [toEmbed.map(n => n.key)])
    const same = new Map(known.map(k => [k.key as string, embedText(k as { title: string; body: string })]))
    const changed = toEmbed.filter(n => same.get(n.key) !== embedText(n))
    for (let i = 0; i < changed.length; i += EMBED_BATCH) {
      const part = changed.slice(i, i + EMBED_BATCH)
      const out = await embed(env, part.map(embedText))
      if (!out) break
      part.forEach((n, j) => { const v = out[j]; if (v) vectors.set(n.key, vectorLiteral(v)) })
    }
  }
  const rows = nodes.map(n => ({
    key: n.key, tenant_id: n.tenantId, visibility: n.visibility, role_group: n.roleGroup, type: n.type,
    title: n.title.replace(/\u0000/g, ''), body: n.body.replace(/\u0000/g, ''), props: n.props,
    source_ref: n.sourceRef ?? null, embedding: vectors.get(n.key) ?? null,
  }))
  await q(`
    INSERT INTO kg_nodes (key, tenant_id, visibility, role_group, type, title, body, props, source_ref, embedding, updated_at)
    SELECT x.key, x.tenant_id, x.visibility, x.role_group, x.type, x.title, x.body, x.props, x.source_ref, x.embedding::vector, now()
    FROM jsonb_to_recordset($1::jsonb) AS x(key text, tenant_id uuid, visibility text, role_group text, type text, title text, body text, props jsonb, source_ref text, embedding text)
    ON CONFLICT (key) DO UPDATE SET
      tenant_id = EXCLUDED.tenant_id, visibility = EXCLUDED.visibility, role_group = EXCLUDED.role_group, type = EXCLUDED.type,
      embedding = COALESCE(EXCLUDED.embedding, CASE WHEN kg_nodes.title = EXCLUDED.title AND kg_nodes.body = EXCLUDED.body THEN kg_nodes.embedding END),
      title = EXCLUDED.title, body = EXCLUDED.body, props = EXCLUDED.props, source_ref = EXCLUDED.source_ref, updated_at = now()`,
  // Every string is made well-formed: one lone surrogate would make Postgres reject the whole batch.
  [JSON.stringify(rows, (_k, v) => (typeof v === 'string' ? wellFormed(v) : v))])
}

/** Replaces the outgoing edges of the given owner nodes. */
export async function replaceEdges(q: Q, ownerKeys: string[], input: KgEdge[]): Promise<void> {
  if (ownerKeys.length) await q(`DELETE FROM kg_edges WHERE from_key = ANY($1::text[])`, [ownerKeys])
  const edges = lastByKey(input, e => `${e.from}|${e.to}|${e.relation}`)
  if (edges.length === 0) return
  await q(`
    INSERT INTO kg_edges (from_key, to_key, relation, tenant_id)
    SELECT x.from_key, x.to_key, x.relation, x.tenant_id
    FROM jsonb_to_recordset($1::jsonb) AS x(from_key text, to_key text, relation text, tenant_id uuid)
    ON CONFLICT DO NOTHING`,
  [JSON.stringify(edges.map(e => ({ from_key: e.from, to_key: e.to, relation: e.relation, tenant_id: e.tenantId })))])
}

export async function deleteNodes(q: Q, keys: string[]): Promise<void> {
  if (keys.length === 0) return
  await q(`DELETE FROM kg_nodes WHERE key = ANY($1::text[])`, [keys])
  await q(`DELETE FROM kg_edges WHERE from_key = ANY($1::text[])`, [keys])
}

/** Fills in embeddings a failed or bulk write left empty. Returns how many were filled. */
export async function backfillEmbeddings(q: Q, env: Env, limit = EMBED_BATCH): Promise<number> {
  const rows = await q(`SELECT key, title, body FROM kg_nodes WHERE embedding IS NULL AND type = ANY($1::text[]) ORDER BY updated_at LIMIT $2`, [EMBEDDED_TYPES, limit])
  if (rows.length === 0) return 0
  const out = await embed(env, rows.map(r => embedText(r as { title: string; body: string })))
  if (!out) return 0
  await q(`
    UPDATE kg_nodes n SET embedding = x.embedding::vector
    FROM jsonb_to_recordset($1::jsonb) AS x(key text, embedding text) WHERE n.key = x.key`,
  [JSON.stringify(rows.flatMap((r, i) => { const v = out[i]; return v ? [{ key: r.key, embedding: vectorLiteral(v) }] : [] }))])
  return rows.length
}
