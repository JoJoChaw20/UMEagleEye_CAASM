import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  HOTSPOT_RULES, LARGE_FILE_LINES, SHARED_MODULE_IMPORTERS, SYSTEM_PREFIX,
  chunkMarkdown, classifyFile, hotspotNodes, isEnvFile, matchRoute, normalizeApiPath, resolveImport,
  screenNodes, staleKeys, systemKey, visibilityFor,
} from './systemGraph'
import { PLATFORM_RULES } from './rules'
import type { KgNode } from './extract'

const node = (over: Partial<KgNode> = {}): KgNode => ({
  key: 'system:file:a.ts', tenantId: null, visibility: 'platform', roleGroup: 'analyst', type: 'file', title: 'a.ts', body: 'plain text', props: {}, ...over,
})

test('isEnvFile: any .env* name in any folder', () => {
  for (const p of ['.env', '.env.staging', 'workers/.env.production', 'frontend/.env.staging.example', 'a/b/.envrc', 'x/prod.env', '.env/secrets.txt', 'a/.env/b/c.ts', 'cfg/x.env.example', 'a.env.local']) assert.equal(isEnvFile(p), true, p)
  for (const p of ['workers/src/env.ts', 'docs/environment.md', 'workers/src/types.ts']) assert.equal(isEnvFile(p), false, p)
})

test('classifyFile: env and key files are skipped, never recorded even by name', () => {
  assert.equal(classifyFile('workers/.env.staging.example').mode, 'skip')
  assert.equal(classifyFile('certs/server.pem').mode, 'skip')
})

test('classifyFile: lockfiles, generated files, data and binaries are name only', () => {
  for (const p of ['workers/package-lock.json', 'frontend/package-lock.json', 'workers/drizzle/meta/0001_snapshot.json', 'workers/drizzle/meta/_journal.json',
    'workers/scores.csv', 'frontend/public/brand/x.webp', 'agent-gui/eagleeye/gui/assets/fonts/Geist-400.ttf', 'workers/src/data/attack.json',
    'agent-gui/tests/fixtures/grype_sample.json', 'agent-gui/eagleeye/data/ieee_oui.tsv.gz']) {
    assert.equal(classifyFile(p).mode, 'name_only', p)
  }
})

test('classifyFile: kinds', () => {
  const kind = (p: string) => classifyFile(p).kind
  assert.equal(kind('workers/src/routes/assets.ts'), 'route_file')
  assert.equal(kind('workers/src/services/exposure.ts'), 'service')
  assert.equal(kind('workers/src/kg/rules.test.ts'), 'test')
  assert.equal(kind('agent-gui/tests/test_api.py'), 'test')
  assert.equal(kind('workers/drizzle/0029_knowledge_graph.sql'), 'migration')
  assert.equal(kind('workers/migrations/event_triage_lifecycle.sql'), 'migration')
  assert.equal(kind('frontend/src/pages/AlertsPage.jsx'), 'page')
  assert.equal(kind('frontend/src/components/common/WhyAlert.jsx'), 'component')
  assert.equal(kind('agent-gui/eagleeye/api.py'), 'module')
  assert.equal(kind('README.md'), 'doc')
  assert.equal(kind('workers/wrangler.toml'), 'config')
  assert.equal(classifyFile('workers/src/queues/consumer.ts').mode, 'text')
})

test('visibility: product docs are all_staff, code is platform, every node is analyst-only', () => {
  for (const p of ['PRODUCT.md', 'AGENT_SETUP_GUIDE.md']) assert.equal(visibilityFor(p).visibility, 'all_staff', p)
  assert.equal(visibilityFor('README.md').visibility, 'platform') // holds the production URL and deployment steps
  for (const p of ['workers/src/routes/assets.ts', 'workers/src/kg/rules.test.ts', 'workers/drizzle/0029_knowledge_graph.sql', 'STAGING.md', 'DESIGN.md', 'docs/kg-chatbot/DEV_LOG.md']) {
    assert.equal(visibilityFor(p).visibility, 'platform', p)
  }
  // business_owner is filtered by role_group = 'all'; nothing from this layer may carry it.
  assert.equal(visibilityFor('README.md').roleGroup, 'analyst')
  assert.equal(visibilityFor('workers/src/index.ts').roleGroup, 'analyst')
})

test('keys: one distinct prefix; paths are not altered beyond slashes', () => {
  assert.equal(SYSTEM_PREFIX, 'system:')
  assert.equal(systemKey('file', 'workers/src/index.ts'), 'system:file:workers/src/index.ts')
  assert.equal(systemKey('route', 'GET', '/api/v1/assets/:id'), 'system:route:GET /api/v1/assets/:id')
  assert.equal(systemKey('file', 'a\\b.ts'), 'system:file:a/b.ts')
})

test('normalizeApiPath: params, query, base prefix', () => {
  assert.equal(normalizeApiPath('/events/${id}/status?x=1'), '/events/:p/status')
  assert.equal(normalizeApiPath('/api/v1/assets/:assetId/'), '/assets/:p')
  assert.equal(normalizeApiPath('assets'), '/assets')
})

test('matchRoute: method and shape must agree; static beats param', () => {
  const routes = [
    { key: 'r1', method: 'GET', path: '/api/v1/assets/:id' },
    { key: 'r2', method: 'GET', path: '/api/v1/assets/summary' },
    { key: 'r3', method: 'POST', path: '/api/v1/assets/:id' },
  ]
  assert.equal(matchRoute('GET', '/assets/summary', routes), 'r2')
  assert.equal(matchRoute('GET', '/assets/${id}', routes), 'r1')
  assert.equal(matchRoute('POST', '/assets/${id}', routes), 'r3')
  assert.equal(matchRoute('DELETE', '/assets/${id}', routes), null)
  assert.equal(matchRoute('GET', '/nothing/here', routes), null)
})

test('resolveImport: relative only, tries extensions and index files', () => {
  const files = new Set(['workers/src/lib/a.ts', 'workers/src/kg/index.ts', 'frontend/src/x/Comp.jsx', 'frontend/src/utils/reportPdf.js'])
  assert.equal(resolveImport('workers/src/routes/r.ts', '../lib/a', files), 'workers/src/lib/a.ts')
  assert.equal(resolveImport('workers/src/routes/r.ts', '../kg', files), 'workers/src/kg/index.ts')
  assert.equal(resolveImport('frontend/src/pages/P.jsx', '../x/Comp', files), 'frontend/src/x/Comp.jsx')
  assert.equal(resolveImport('workers/src/queues/c.ts', '../../../frontend/src/utils/reportPdf.js', files), 'frontend/src/utils/reportPdf.js')
  assert.equal(resolveImport('workers/src/routes/r.ts', 'hono', files), null)
  assert.equal(resolveImport('workers/src/routes/r.ts', '../missing', files), null)
})

test('chunkMarkdown: splits by heading and long sections by size', () => {
  const md = ['# Title', 'intro', '## One', 'a'.repeat(50), '## Two', ('para ' + 'b'.repeat(80) + '\n\n').repeat(10)].join('\n')
  const chunks = chunkMarkdown(md, 300)
  assert.equal(chunks[0]?.heading, 'Title')
  assert.ok(chunks.some(c => c.heading === 'One'))
  const two = chunks.filter(c => c.heading === 'Two')
  assert.ok(two.length > 1)
  assert.ok(chunks.every(c => c.body.length <= 400))
  assert.ok(!chunks.some(c => c.body.trim() === ''))
})

test('hotspots: thresholds, distinct rule names, platform visibility, no tenant, a solution', () => {
  const { nodes, edges } = hotspotNodes([
    { path: 'workers/src/routes/big.ts', kind: 'route_file', lines: LARGE_FILE_LINES, importers: [], largest: [{ name: 'handler', lines: 400 }] },
    { path: 'workers/src/routes/ok.ts', kind: 'route_file', lines: LARGE_FILE_LINES - 1, importers: [] },
    { path: 'workers/src/lib/shared.ts', kind: 'module', lines: 100, importers: Array.from({ length: SHARED_MODULE_IMPORTERS }, (_, i) => `workers/src/routes/r${i}.ts`) },
    { path: 'workers/src/lib/few.ts', kind: 'module', lines: 100, importers: ['a.ts'] },
    { path: 'agent-gui/eagleeye/__init__.py', kind: 'module', lines: 5, importers: Array.from({ length: 30 }, (_, i) => `m${i}.py`) },
    { path: 'workers/src/kg/big.test.ts', kind: 'test', lines: 5000, importers: [] },
    { path: 'workers/drizzle/0001.sql', kind: 'migration', lines: 5000, importers: [] },
  ])
  assert.equal(nodes.length, 2)
  for (const n of nodes) {
    assert.equal(n.type, 'problem')
    assert.equal(n.visibility, 'platform')
    assert.equal(n.tenantId, null)
    assert.ok(n.key.startsWith(SYSTEM_PREFIX))
    assert.match(n.body, /Recommended solution: \S/)
    assert.ok(HOTSPOT_RULES.includes(n.props.rule as string))
    assert.ok(!(PLATFORM_RULES as readonly string[]).includes(n.props.rule as string),'must not collide with the rules problems.ts replaces')
  }
  assert.ok(edges.every(e => e.tenantId === null && e.from.startsWith(SYSTEM_PREFIX) && e.relation === 'EVIDENCE'))
})

test('staleKeys: only keys with our prefix and absent from the new build', () => {
  const existing = ['system:file:a', 'system:file:b', 'problem:platform:slow', 'perf:2026', 'status:t1', 'systemic:x', 'system:']
  assert.deepEqual(staleKeys(existing, new Set(['system:file:a'])).sort(), ['system:', 'system:file:b'].sort())
})

test('screenNodes: blocks secrets, env paths and foreign keys; reports keys only', () => {
  const secret = 'password = "' + 'Zx9'.repeat(8) + '"'
  const r = screenNodes([
    node(),
    node({ key: 'system:file:s.ts', body: `config ${secret}` }),
    node({ key: 'system:file:.env.staging', title: 'x' }),
    node({ key: 'company:t1', title: 'foreign' }),
    node({ key: 'system:file:t.ts', tenantId: 'f3b1c3a2-0000-4000-8000-000000000000' }),
    node({ key: 'system:file:n.ts', visibility: 'company' }),
  ])
  assert.deepEqual(r.nodes.map(n => n.key), ['system:file:a.ts'])
  assert.equal(r.blockedSecret, 1)
  assert.equal(r.blockedEnv, 1)
  assert.equal(r.rejected, 3)
  assert.ok(!JSON.stringify(r).includes('Zx9'), 'matched text is never returned')
})
