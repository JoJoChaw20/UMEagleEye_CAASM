import { test } from 'node:test'
import assert from 'node:assert/strict'
import { observedBy, planIngest, type PlanHost } from './ingest-plan'

const host = (extra: Partial<PlanHost>): PlanHost => ({
  ip: '10.10.1.41', rawMac: '00:50:79:66:68:04', hostname: null, hostKeyRaw: null, deviceType: 'unknown',
  observedOsInfo: {}, ports: [], hardwareVendor: null, internetFacing: false, isPassive: true, tenantId: 't', ...extra,
})

test('how a device was seen names its source and its new-device alert', () => {
  assert.deepEqual(observedBy({ isPassive: false }), { source: 'scan_active', event: 'active_scan' })
  assert.deepEqual(observedBy({ isPassive: true }), { source: 'scan_passive', event: 'passive_scan' })
  assert.deepEqual(observedBy({ isPassive: true, isNetwork: true }), { source: 'scan_network', event: 'network_agent' })
})

test('a device the network agent found is a network-agent asset', () => {
  let n = 0
  const plan = planIngest([host({ isNetwork: true })], { addresses: [], assets: [] }, { newId: () => `id-${++n}` })
  const ops = plan.perHost[0]!.ops ?? []
  const asset = ops.find((o) => o.k === 'insertAsset') as { values: Record<string, unknown> } | undefined
  const event = ops.find((o) => o.k === 'insertEvent') as { values: { details: Record<string, unknown> } } | undefined
  assert.equal(asset?.values.source, 'scan_network')
  assert.equal(event?.values.details.source, 'network_agent')
})
