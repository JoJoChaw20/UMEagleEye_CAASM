/**
 * kg/retrieve.ts — finding things in the graph: meaning plus keyword search, walking links,
 * and exact counts. Every query is limited by the caller's Access. The vector search is exact
 * (no approximate index): it is filtered per company, and an approximate index would filter
 * after searching and could return nothing for a small company.
 */
import type { Env } from '../types'
import { accessSql, type Access } from './access'
import { clip, type Row } from './extract'
import { embed, type Q } from './store'

const STOP = new Set(('a an and are as at be but by can could did do does for from had has have how i in is it its me my of on or our '
  + 'please show should tell than that the their them there these they this to us was we were what when where which who why will with would you your').split(' '))

/** A tsquery matching any meaningful word of the question, or null when there is none. */
export function keywordQuery(text: string): string | null {
  const words = [...new Set((text.toLowerCase().match(/[\w.-]+/g) ?? [])
    .map(w => w.replace(/^[.-]+|[.-]+$/g, ''))
    .filter(w => w.length > 1 && !STOP.has(w)))].slice(0, 24)
  return words.length ? words.map(w => `'${w}'`).join(' | ') : null
}

export interface NodeView { key: string; type: string; title: string; body: string; props: Row; source: string | null }

const view = (r: Row): NodeView => ({ key: r.key, type: r.type, title: r.title, body: clip(r.body, 700), props: r.props, source: r.source_ref ?? null })

const RRF = 60

export async function searchGraph(q: Q, env: Env, a: Access, text: string, opts: { types?: string[]; limit?: number } = {}): Promise<NodeView[]> {
  const limit = Math.min(opts.limit ?? 12, 25)
  const typeFilter = (params: unknown[]) => {
    if (!opts.types?.length) return ''
    params.push(opts.types)
    return ` AND n.type = ANY($${params.length}::text[])`
  }
  const tsq = keywordQuery(text)
  const keyword = async (): Promise<Row[]> => {
    if (!tsq) return []
    const params: unknown[] = [tsq]
    const where = accessSql(a, 'n', params)
    const types = typeFilter(params)
    return q(`SELECT n.key, n.type, n.title, n.body, n.props, n.source_ref FROM kg_nodes n
      WHERE ${where}${types} AND n.tsv @@ to_tsquery('simple', $1)
      ORDER BY ts_rank(n.tsv, to_tsquery('simple', $1)) DESC LIMIT 40`, params)
  }
  const semantic = async (): Promise<Row[]> => {
    const vec = (await embed(env, [text]))?.[0]
    if (!vec) return []
    const params: unknown[] = [`[${vec.join(',')}]`]
    const where = accessSql(a, 'n', params)
    const types = typeFilter(params)
    return q(`SELECT n.key, n.type, n.title, n.body, n.props, n.source_ref FROM kg_nodes n
      WHERE ${where}${types} AND n.embedding IS NOT NULL
      ORDER BY n.embedding <=> $1::vector LIMIT 40`, params)
  }
  const [kw, sem] = await Promise.all([keyword(), semantic()])
  const scores = new Map<string, { row: Row; score: number }>()
  for (const list of [kw, sem]) {
    list.forEach((row, i) => {
      const cur = scores.get(row.key) ?? { row, score: 0 }
      cur.score += 1 / (RRF + i)
      scores.set(row.key, cur)
    })
  }
  return [...scores.values()].sort((x, y) => y.score - x.score).slice(0, limit).map(x => view(x.row))
}

export async function getNode(q: Q, a: Access, key: string): Promise<NodeView | null> {
  const params: unknown[] = [key]
  const where = accessSql(a, 'n', params)
  const [row] = await q(`SELECT n.key, n.type, n.title, n.body, n.props, n.source_ref FROM kg_nodes n WHERE n.key = $1 AND ${where}`, params)
  return row ? { ...view(row), body: clip(row.body, 2500) } : null
}

export interface LinkView { relation: string; from: string; to: string; node: NodeView }

/** Nodes linked to `key`, up to `depth` (at most 2) steps away, within a budget. */
export async function followLinks(q: Q, a: Access, key: string, depth = 1, budget = 30): Promise<LinkView[]> {
  if (!(await getNode(q, a, key))) return []
  const out: LinkView[] = []
  const seen = new Set([key])
  let frontier = [key]
  for (let d = 0; d < Math.min(depth, 2) && frontier.length && out.length < budget; d++) {
    const params: unknown[] = [frontier, budget * 4]
    const where = accessSql(a, 'n', params)
    const rows = await q(`
      SELECT e.from_key, e.to_key, e.relation, n.key, n.type, n.title, n.body, n.props, n.source_ref
      FROM kg_edges e JOIN kg_nodes n ON n.key = CASE WHEN e.from_key = ANY($1::text[]) THEN e.to_key ELSE e.from_key END
      WHERE (e.from_key = ANY($1::text[]) OR e.to_key = ANY($1::text[])) AND ${where}
      ORDER BY n.updated_at DESC LIMIT $2`, params)
    const next: string[] = []
    for (const r of rows) {
      if (seen.has(r.key) || out.length >= budget) continue
      seen.add(r.key)
      next.push(r.key)
      out.push({ relation: r.relation, from: r.from_key, to: r.to_key, node: { ...view(r), body: clip(r.body, 300) } })
    }
    frontier = next
  }
  return out
}

const SAFE_FIELD = /^[a-zA-Z_]{1,40}$/
const MAX_LIST = 100

export interface CountResult {
  total: number
  groups?: Array<{ value: unknown; count: number }>
  items: Array<{ key: string; title: string }>
  shown: number
}

/** Exact count of nodes of one type, with property filters; optionally grouped or listed. */
export async function countNodes(q: Q, a: Access, input: { type: string; where?: Record<string, string | number | boolean>; groupBy?: string }): Promise<CountResult | { error: string }> {
  const filter = Object.fromEntries(Object.entries(input.where ?? {}).slice(0, 6))
  if (Object.keys(filter).some(k => !SAFE_FIELD.test(k))) return { error: 'Invalid filter name.' }
  if (input.groupBy && !SAFE_FIELD.test(input.groupBy)) return { error: 'Invalid group name.' }
  const params: unknown[] = [input.type, JSON.stringify(filter)]
  const where = `n.type = $1 AND n.props @> $2::jsonb AND ${accessSql(a, 'n', params)}`
  const [countRow] = await q(`SELECT count(*)::int AS total FROM kg_nodes n WHERE ${where}`, params)
  const result: CountResult = { total: Number(countRow?.total ?? 0), items: [], shown: 0 }
  if (input.groupBy) {
    const rows = await q(`SELECT n.props ->> '${input.groupBy}' AS value, count(*)::int AS count FROM kg_nodes n WHERE ${where} GROUP BY 1 ORDER BY 2 DESC LIMIT 50`, params)
    result.groups = rows.map(r => ({ value: r.value, count: r.count as number }))
    return result
  }
  const items = await q(`SELECT n.key, n.title FROM kg_nodes n WHERE ${where} ORDER BY n.title LIMIT ${MAX_LIST}`, params)
  result.items = items.map(r => ({ key: r.key, title: clip(r.title, 90) }))
  result.shown = result.items.length
  return result
}
