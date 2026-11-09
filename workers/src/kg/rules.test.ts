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
