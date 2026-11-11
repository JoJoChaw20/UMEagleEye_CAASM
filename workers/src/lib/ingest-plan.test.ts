import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ROTATION_GAP_MS, matchAsset, type CandidateAddress } from './identity'
import { planIngest, type IdentityPrefetch, type PlanHost, type PrefetchAsset } from './ingest-plan'

// Rule 2-name: an iPad that rotated its private MAC is the same iPad, by its specific name.
const HOME = '192.168.100.0/24'
const OLD_MAC = '6a:11:22:33:44:55'      // private (locally administered)
const NEW_MAC = 'ee:89:d5:a2:89:6a'      // private
const now = new Date('2026-11-11T10:00:00Z')
const longAgo = now.getTime() - ROTATION_GAP_MS - 60_000

const asset = (assetId: string, hostname: string | null): PrefetchAsset => ({
  assetId, deviceType: 'mobile', hostKey: null, osInfo: {}, hostname, owner: null, hardwareVendor: 'Apple', macAddress: OLD_MAC,
  source: 'scan_passive', deviceTypeSource: 'auto', hasBaseline: true, baseline: null, internetFacingOverride: null,
})
const addr = (addressId: string, assetId: string, mac: string, lastSeen: number, ip = '192.168.100.80') =>
  ({ addressId, assetId, networkKey: HOME, ipAddress: ip, macAddress: mac, deviceType: 'mobile', lastSeen, assetCreatedAt: 1 })
const host = (mac: string, hostname: string | null, ip = '192.168.100.81'): PlanHost => ({
  ip, rawMac: mac, hostname, hostKeyRaw: null, deviceType: 'mobile', observedOsInfo: {}, ports: [],
  hardwareVendor: null, internetFacing: false, isPassive: true, tenantId: 't',
})
const plan = (prefetch: IdentityPrefetch, hosts: PlanHost[]) => {
  let n = 0
  return planIngest(hosts, prefetch, { newId: () => `new-${++n}`, now, networkKeyFor: () => HOME }).perHost
}

test('matcher: one named device with a quiet private MAC is the same device; two are not', () => {
  const c = (assetId: string): CandidateAddress => ({ addressId: `a-${assetId}`, assetId, networkKey: HOME, ipAddress: '192.168.100.80', macAddress: OLD_MAC, assetDeviceType: 'mobile' })
  const input = { macClass: 'local' as const, mac: NEW_MAC, ip: '192.168.100.81', hostKey: null, networkKey: HOME }
  const base = { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [] }
  assert.deepEqual(matchAsset(input, { ...base, nameAddresses: [c('IPAD')] }), { rule: '2-name', assetId: 'IPAD', matchedAddressId: 'a-IPAD' })
  assert.equal(matchAsset(input, { ...base, nameAddresses: [c('IPAD'), c('OTHER')] }).rule, 6)
  assert.equal(matchAsset({ ...input, macClass: 'global' }, { ...base, nameAddresses: [c('IPAD')] }).rule, 6)   // a burned-in MAC is another device
})

test('a rotated private MAC with the same specific name joins the device', () => {
  const prefetch: IdentityPrefetch = { addresses: [addr('old', 'IPAD', OLD_MAC, longAgo)], assets: [asset('IPAD', 'Jojos-iPad')] }
  const [ph] = plan(prefetch, [host(NEW_MAC, 'jojos-ipad')])
  assert.deepEqual([ph!.rule, ph!.assetId, ph!.isNew], ['2-name', 'IPAD', false])
})

test('no match when the name is generic, the old MAC is still heard, or two devices have the name', () => {
  const quiet = { addresses: [addr('old', 'IPAD', OLD_MAC, longAgo)], assets: [asset('IPAD', 'iPad')] }
  assert.equal(plan(quiet, [host(NEW_MAC, 'iPad')])[0]!.isNew, true)                         // "iPad" is generic

  const recent: IdentityPrefetch = { addresses: [addr('old', 'IPAD', OLD_MAC, now.getTime() - 60_000)], assets: [asset('IPAD', 'Jojos-iPad')] }
  assert.equal(plan(recent, [host(NEW_MAC, 'Jojos-iPad')])[0]!.isNew, true)                  // seen a minute ago: two devices

  const both: IdentityPrefetch = { addresses: [addr('old', 'IPAD', OLD_MAC, longAgo)], assets: [asset('IPAD', 'Jojos-iPad')] }
  const hosts = [host(NEW_MAC, 'Jojos-iPad'), host(OLD_MAC, 'Jojos-iPad', '192.168.100.80')]
  assert.equal(plan(both, hosts)[0]!.isNew, true)                                           // the old MAC is in this upload

  const twins: IdentityPrefetch = {
    addresses: [addr('a', 'IPAD', OLD_MAC, longAgo), addr('b', 'IPAD2', '6a:99:99:99:99:99', longAgo, '192.168.100.90')],
    assets: [asset('IPAD', 'Jojos-iPad'), asset('IPAD2', 'Jojos-iPad')],
  }
  assert.equal(plan(twins, [host(NEW_MAC, 'Jojos-iPad')])[0]!.isNew, true)                  // which one? left to review
})
