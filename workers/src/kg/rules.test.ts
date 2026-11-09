import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluateRules, type AssetFact, type Facts } from './rules'

const NOW = new Date('2026-11-09T12:00:00Z')
const base: Facts = { assets: [], advisories: [], agingAlerts: [], agingTotal: 0, agents: [], scans: [], postureMeasuredAt: null }
const asset = (o: Partial<AssetFact>): AssetFact => ({ key: 'asset:1', title: 'web-01', criticality: 5, internetFacing: false, inMyAssets: false, ports: [], hasSbom: true, ...o })
const rules = (f: Partial<Facts>) => evaluateRules({ ...base, ...f }, NOW).map(p => p.rule)

test('quiet facts raise nothing', () => assert.deepEqual(rules({ assets: [asset({})] }), []))

test('internet-facing critical device with an open advisory', () => {
  const f = { assets: [asset({ internetFacing: true, criticality: 9 })], advisories: [{ key: 'advisory:1', assetKey: 'asset:1', severity: 'high' }] }
  assert.deepEqual(rules(f), ['exposed_critical_with_advisory'])
})

test('the same device with no advisory does not fire', () => {
  assert.deepEqual(rules({ assets: [asset({ internetFacing: true, criticality: 9 })] }), [])
})

test('a risky port only counts when internet-facing', () => {
  assert.deepEqual(rules({ assets: [asset({ internetFacing: true, ports: [3389] })] }), ['exposed_risky_port'])
  assert.deepEqual(rules({ assets: [asset({ ports: [3389] })] }), [])
})

test('devices without an SBOM are counted only in My Assets', () => {
  const out = evaluateRules({ ...base, assets: [asset({ inMyAssets: true, hasSbom: false }), asset({ key: 'asset:2', hasSbom: false })] }, NOW)
  assert.equal(out[0].rule, 'asset_without_sbom')
  assert.equal(out[0].count, 1)
})

test('ageing alerts report the full total, not the sample', () => {
  const out = evaluateRules({ ...base, agingTotal: 250, agingAlerts: [{ key: 'event:1', title: 't', severity: 'high', timestamp: '2026-01-01T00:00:00Z' }] }, NOW)
  assert.equal(out[0].count, 250)
})

test('agents: silent or offline fire, retired does not', () => {
  const recent = '2026-11-09T11:00:00Z', old = '2026-11-01T00:00:00Z'
  const agent = (o: object) => ({ key: 'agent:1', name: 'a', status: 'online', lastHeartbeat: recent, retired: false, ...o })
  assert.deepEqual(rules({ agents: [agent({})] }), [])
  assert.deepEqual(rules({ agents: [agent({ lastHeartbeat: old })] }), ['agent_offline'])
  assert.deepEqual(rules({ agents: [agent({ status: 'offline' })] }), ['agent_offline'])
  assert.deepEqual(rules({ agents: [agent({ status: 'offline', retired: true })] }), [])
})

test('three failed scans of the last ten fire', () => {
  const scan = (i: number, status: string) => ({ key: `scan:${i}`, agentKey: 'agent:1', status, startedAt: `2026-11-0${i}T00:00:00Z` })
  assert.deepEqual(rules({ scans: [scan(1, 'failed'), scan(2, 'failed'), scan(3, 'failed')] }), ['scans_failing'])
  assert.deepEqual(rules({ scans: [scan(1, 'failed'), scan(2, 'failed'), scan(3, 'completed')] }), [])
})

test('a stale score fires only when old', () => {
  assert.deepEqual(rules({ postureMeasuredAt: '2026-11-01T00:00:00Z' }), ['stale_posture'])
  assert.deepEqual(rules({ postureMeasuredAt: '2026-11-09T00:00:00Z' }), [])
})

test('the most urgent problem ranks first', () => {
  const f = { ...base, assets: [asset({ internetFacing: true, criticality: 9, inMyAssets: true, hasSbom: false })], advisories: [{ key: 'advisory:1', assetKey: 'asset:1', severity: 'high' }] }
  assert.equal(evaluateRules(f, NOW)[0].rule, 'exposed_critical_with_advisory')
})

// ── Platform rules (performance, feeds, graph sync) ─────────────────

import { evaluatePlatformRules, type PlatformFacts } from './rules'
import type { PerfWindow, RouteStat } from './perf'

const route = (o: Partial<RouteStat> = {}): RouteStat => ({ route: '/api/v1/events', requests: 20, avgMs: 2500, maxMs: 6000, errorRate: 0, slow: true, ...o })
const win = (hour: number, o: Partial<PerfWindow> = {}): PerfWindow => ({
  start: `2026-11-09T${String(hour).padStart(2, '0')}:00:00.000Z`, end: `2026-11-09T${String(hour + 1).padStart(2, '0')}:00:00.000Z`,
  requests: 100, errors: 0, errorRate: 0, avgMs: 120, dbShare: 0.4, slowRoutes: [], jobs: [], scanRequests: 0, slow: false, ...o,
})
const pbase: PlatformFacts = { windows: [], feeds: [], outbox: null }
const prules = (f: Partial<PlatformFacts>) => evaluatePlatformRules({ ...pbase, ...f }, NOW).map(p => p.rule)

test('platform: quiet facts raise nothing', () => {
  assert.deepEqual(prules({ windows: [win(9), win(10)], feeds: [{ source: 'kev', ok: true, lastOkAt: '2026-11-09T01:00:00Z' }], outbox: { count: 3, oldestAt: '2026-11-09T11:58:00Z', stuck: 0 } }), [])
})

test('platform: a route slow in three windows is persistently slow, in two it is not', () => {
  const slow = (h: number) => win(h, { slow: true, slowRoutes: [route()] })
  assert.deepEqual(prules({ windows: [slow(8), slow(9)] }), [])
  const out = evaluatePlatformRules({ ...pbase, windows: [slow(8), slow(9), slow(10)] }, NOW)
  assert.deepEqual(out.map(p => p.rule), ['route_persistently_slow'])
  assert.equal(out[0]!.id, 'perf_slow:/api/v1/events')
  assert.equal(out[0]!.count, 3)
  assert.deepEqual(out[0]!.evidence, ['perf:window:2026-11-09T08:00:00.000Z', 'perf:window:2026-11-09T09:00:00.000Z', 'perf:window:2026-11-09T10:00:00.000Z'])
})

test('platform: a route that is fast is never persistently slow', () => {
  const w = (h: number) => win(h, { slowRoutes: [route({ slow: false, avgMs: 90 })] })
  assert.deepEqual(prules({ windows: [w(8), w(9), w(10)] }), [])
})

test('platform: an error spike needs enough requests and a high rate', () => {
  assert.deepEqual(prules({ windows: [win(9, { requests: 5, errors: 5, errorRate: 1 })] }), [])
  assert.deepEqual(prules({ windows: [win(9, { requests: 200, errors: 4, errorRate: 0.02 })] }), [])
  const out = evaluatePlatformRules({ ...pbase, windows: [win(9, { requests: 100, errors: 30, errorRate: 0.3 })] }, NOW)
  assert.deepEqual(out.map(p => p.rule), ['error_spike'])
  assert.equal(out[0]!.severity, 'high')
})

test('platform: slowness with a job in the same hour states what lined up, not a cause', () => {
  const job = { name: 'cti_ingest', runs: 2, failed: 0, avgMs: 30000, maxMs: 40000 }
  const out = evaluatePlatformRules({ ...pbase, windows: [win(9, { slow: true, slowRoutes: [route()], jobs: [job] }), win(10, { jobs: [job] })] }, NOW)
  assert.deepEqual(out.map(p => p.rule), ['slow_with_job'])
  assert.match(out[0]!.detail, /cti_ingest/)
  assert.match(out[0]!.detail, /not proof/i)
  assert.deepEqual(out[0]!.evidence, ['perf:window:2026-11-09T09:00:00.000Z'])
})

test('platform: slowness with a scan in the same hour counts; slowness alone does not', () => {
  assert.deepEqual(prules({ windows: [win(9, { slow: true, slowRoutes: [route()], scanRequests: 4 })] }), ['slow_with_job'])
  assert.deepEqual(prules({ windows: [win(9, { slow: true, slowRoutes: [route()] })] }), [])
})

test('platform: a failing threat feed fires per feed and names the last good load', () => {
  const out = evaluatePlatformRules({ ...pbase, feeds: [
    { source: 'otx', ok: false, lastOkAt: '2026-11-06T22:00:00Z' }, { source: 'kev', ok: true, lastOkAt: '2026-11-09T01:00:00Z' }, { source: 'threatfox', ok: false, lastOkAt: null },
  ] }, NOW)
  assert.deepEqual(out.map(p => p.id).sort(), ['feed:otx', 'feed:threatfox'])
  assert.match(out.find(p => p.id === 'feed:otx')!.detail, /2026-11-06/)
  assert.match(out.find(p => p.id === 'feed:threatfox')!.detail, /never/)
})

test('platform: sync backlog by size or age, counting every row', () => {
  assert.deepEqual(prules({ outbox: { count: 0, oldestAt: null, stuck: 0 } }), [])
  assert.deepEqual(prules({ outbox: { count: 500, oldestAt: '2026-11-09T11:59:00Z', stuck: 0 } }), ['graph_sync_backlog'])
  assert.deepEqual(prules({ outbox: { count: 2, oldestAt: '2026-11-09T09:00:00Z', stuck: 0 } }), ['graph_sync_backlog'])
  const out = evaluatePlatformRules({ ...pbase, outbox: { count: 2, oldestAt: '2026-11-09T09:00:00Z', stuck: 1 } }, NOW)
  assert.match(out[0]!.detail, /2 change/)
  assert.match(out[0]!.detail, /1 .*retr/i)
})
