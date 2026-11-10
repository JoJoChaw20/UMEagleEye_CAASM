import test from 'node:test'
import assert from 'node:assert/strict'
import { edgesStatements, embedChanged, nodesStatement, type Q } from './store'
import type { KgEdge, KgNode } from './extract'
import type { Env } from '../types'

const A = '22222222-2222-2222-2222-222222222222'
const node = (key: string, body = 'text', type = 'cve'): KgNode => ({ key, tenantId: A, visibility: 'company', roleGroup: 'analyst', type, title: key, body, props: {} })
const edge = (from: string, to: string, relation = 'ABOUT_CVE'): KgEdge => ({ from, to, relation, tenantId: A })

test('a node that several rows produce is embedded once', async () => {
  const texts: string[] = []
  const env = { AI: { run: async (_m: string, i: { text: string[] }) => { texts.push(...i.text); return { data: i.text.map(() => [0.1]) } } } } as unknown as Env
  let read: unknown
  const q = (async (_t: string, params?: unknown[]) => { read = params?.[0]; return [] }) as Q
  const cve = 'cve:t:CVE-2024-1'
  const vectors = await embedChanged(q, env, [node(cve, 'older'), node('event:1', 'alert', 'event'), node(cve, 'newest'), node(cve, 'newest')])
  assert.equal(texts.length, 2, 'one text per key')
  assert.ok(texts.includes(`${cve}\nnewest`), 'the last version of the node is the one embedded')
  assert.deepEqual(read, [cve, 'event:1'])
  assert.deepEqual([...vectors.keys()].sort(), [cve, 'event:1'].sort())
})

test('nodes are written in key order, so two drains take shared keys in the same order', () => {
  const stmt = nodesStatement([node('cve:c'), node('asset:b', 'x', 'asset'), node('cve:a'), node('cve:c', 'latest')], new Map())!
  const rows = JSON.parse(String(stmt.params?.[0])) as Array<{ key: string; body: string }>
  assert.deepEqual(rows.map(r => r.key), ['asset:b', 'cve:a', 'cve:c'])
  assert.equal(rows[2]?.body, 'latest', 'the last version of a key still wins')
})

test('edges are written in key order', () => {
  const stmts = edgesStatements(['event:2', 'event:1'], [edge('event:2', 'cve:b'), edge('event:1', 'cve:z'), edge('event:1', 'cve:a'), edge('event:1', 'asset:9', 'ALERT_ON')])
  const insert = stmts.find(s => s.text.includes('INSERT INTO kg_edges'))!
  const rows = JSON.parse(String(insert.params?.[0])) as Array<{ from_key: string; to_key: string }>
  assert.deepEqual(rows.map(r => `${r.from_key}>${r.to_key}`), ['event:1>asset:9', 'event:1>cve:a', 'event:1>cve:z', 'event:2>cve:b'])
})
