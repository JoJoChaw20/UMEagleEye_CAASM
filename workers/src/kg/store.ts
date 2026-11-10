/**
 * kg/store.ts — reads and writes of the graph tables, and embeddings. Raw SQL through one
 * query function: vector and tsvector columns are not in the Drizzle schema.
 */
import { neon } from '@neondatabase/serverless'
import type { Env } from '../types'
import { wellFormed, type KgEdge, type KgNode, type Row } from './extract'

export interface Stmt { text: string; params?: unknown[] }
/** One query, plus an optional way to send many as a single request (one Worker subrequest). */
export type Q = ((text: string, params?: unknown[]) => Promise<Row[]>) & { batch?: (stmts: Stmt[]) => Promise<Row[][]> }

export function kgQuery(env: Env): Q {
  const sql = neon(env.DATABASE_URL)
  const q: Q = (text, params = []) => sql(text, params) as unknown as Promise<Row[]>
  q.batch = (stmts) => sql.transaction(stmts.map(s => sql(s.text, s.params ?? [])) as never) as unknown as Promise<Row[][]>
  return q
}

/**
 * Runs the statements as one request when the driver can, else one after another. A Worker on the
 * free plan has 50 subrequests per run and each query is one, so per-table round trips do not fit.
 */
export async function runBatch(q: Q, stmts: Stmt[]): Promise<Row[][]> {
  if (stmts.length === 0) return []
  if (q.batch) return q.batch(stmts)
  const out: Row[][] = []
  for (const s of stmts) out.push(await q(s.text, s.params ?? []))
  return out
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

/** Row locks last the whole transaction, so every writer takes shared keys in this one order and cannot deadlock. */
function inKeyOrder<T>(items: T[], keyOf: (t: T) => string): T[] {
  return [...items].sort((a, b) => { const x = keyOf(a), y = keyOf(b); return x < y ? -1 : x > y ? 1 : 0 })
}

/** Vectors for the nodes whose text changed. One read plus the AI calls; a failure leaves them out. */
export async function embedChanged(q: Q, env: Env, nodes: KgNode[]): Promise<Map<string, string>> {
  const vectors = new Map<string, string>()
  const toEmbed = lastByKey(nodes, n => n.key).filter(n => EMBEDDED_TYPES.includes(n.type))
  if (toEmbed.length === 0) return vectors
  const known = await q(`SELECT key, title, body FROM kg_nodes WHERE key = ANY($1::text[]) AND embedding IS NOT NULL`, [toEmbed.map(n => n.key)])
  const same = new Map(known.map(k => [k.key as string, embedText(k as { title: string; body: string })]))
  const changed = toEmbed.filter(n => same.get(n.key) !== embedText(n))
  for (let i = 0; i < changed.length; i += EMBED_BATCH) {
    const part = changed.slice(i, i + EMBED_BATCH)
    const out = await embed(env, part.map(embedText))
    if (!out) break
    part.forEach((n, j) => { const v = out[j]; if (v) vectors.set(n.key, vectorLiteral(v)) })
  }
  return vectors
}

/** The write for these nodes, as one statement. Text that did not change keeps its embedding. */
export function nodesStatement(input: KgNode[], vectors: Map<string, string>): Stmt | null {
  const nodes = inKeyOrder(lastByKey(input, n => n.key), n => n.key)
  if (nodes.length === 0) return null
  const rows = nodes.map(n => ({
    key: n.key, tenant_id: n.tenantId, visibility: n.visibility, role_group: n.roleGroup, type: n.type,
    title: n.title.replace(/\u0000/g, ''), body: n.body.replace(/\u0000/g, ''), props: n.props,
    source_ref: n.sourceRef ?? null, embedding: vectors.get(n.key) ?? null,
  }))
  return {
    text: `
    INSERT INTO kg_nodes (key, tenant_id, visibility, role_group, type, title, body, props, source_ref, embedding, updated_at)
    SELECT x.key, x.tenant_id, x.visibility, x.role_group, x.type, x.title, x.body, x.props, x.source_ref, x.embedding::vector, now()
    FROM jsonb_to_recordset($1::jsonb) AS x(key text, tenant_id uuid, visibility text, role_group text, type text, title text, body text, props jsonb, source_ref text, embedding text)
    ON CONFLICT (key) DO UPDATE SET
      tenant_id = EXCLUDED.tenant_id, visibility = EXCLUDED.visibility, role_group = EXCLUDED.role_group, type = EXCLUDED.type,
      embedding = COALESCE(EXCLUDED.embedding, CASE WHEN kg_nodes.title = EXCLUDED.title AND kg_nodes.body = EXCLUDED.body THEN kg_nodes.embedding END),
      title = EXCLUDED.title, body = EXCLUDED.body, props = EXCLUDED.props, source_ref = EXCLUDED.source_ref, updated_at = now()`,
    // Every string is made well-formed: one lone surrogate would make Postgres reject the whole batch.
    params: [JSON.stringify(rows, (_k, v) => (typeof v === 'string' ? wellFormed(v) : v))],
  }
}

/** Writes nodes. An embedding failure still stores the node. */
export async function upsertNodes(q: Q, env: Env, input: KgNode[]): Promise<void> {
  const nodes = lastByKey(input, n => n.key)
  if (nodes.length === 0) return
  const stmt = nodesStatement(nodes, await embedChanged(q, env, nodes))
  if (stmt) await q(stmt.text, stmt.params)
}

/** The statements that replace the outgoing edges of the given owner nodes. */
export function edgesStatements(ownerKeys: string[], input: KgEdge[]): Stmt[] {
  const out: Stmt[] = []
  if (ownerKeys.length) out.push({ text: `DELETE FROM kg_edges WHERE from_key = ANY($1::text[])`, params: [ownerKeys] })
  const edgeKey = (e: KgEdge) => `${e.from}|${e.to}|${e.relation}`
  const edges = inKeyOrder(lastByKey(input, edgeKey), edgeKey)
  if (edges.length) {
    out.push({
      text: `
    INSERT INTO kg_edges (from_key, to_key, relation, tenant_id)
    SELECT x.from_key, x.to_key, x.relation, x.tenant_id
    FROM jsonb_to_recordset($1::jsonb) AS x(from_key text, to_key text, relation text, tenant_id uuid)
    ON CONFLICT DO NOTHING`,
      params: [JSON.stringify(edges.map(e => ({ from_key: e.from, to_key: e.to, relation: e.relation, tenant_id: e.tenantId })))],
    })
  }
  return out
}

export async function replaceEdges(q: Q, ownerKeys: string[], input: KgEdge[]): Promise<void> {
  await runBatch(q, edgesStatements(ownerKeys, input))
}

/** The statements that delete the nodes and their outgoing edges. */
export function deleteStatements(keys: string[]): Stmt[] {
  if (keys.length === 0) return []
  return [
    { text: `DELETE FROM kg_nodes WHERE key = ANY($1::text[])`, params: [keys] },
    { text: `DELETE FROM kg_edges WHERE from_key = ANY($1::text[])`, params: [keys] },
  ]
}

export async function deleteNodes(q: Q, keys: string[]): Promise<void> {
  await runBatch(q, deleteStatements(keys))
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
