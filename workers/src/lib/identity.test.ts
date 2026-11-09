import { test } from 'node:test'
import assert from 'node:assert/strict'
import { addressesToEnd, matchAsset, type CandidateAddress, type MatcherInput } from './identity'

const MAC = '00:0c:29:04:6c:77'
const input: MatcherInput = { macClass: 'global', mac: MAC, ip: '192.168.36.50', hostKey: 'lab-ubuntu', networkKey: '192.168.36.0/24' }
const addr = (assetId: string, ip: string, networkKey: string, assetDeviceType = 'server'): CandidateAddress =>
  ({ addressId: `${assetId}-${ip}`, assetId, networkKey, ipAddress: ip, macAddress: MAC, assetDeviceType })

test("an agent's own NIC wins over another asset that has the same MAC on a more recent address", () => {
  // Lab VM, 9 Nov: the network agent had made "LAB-UBUNTU" from a router's ARP entry for the VM's
  // second NIC (10.99.0.10); the VM's agent lists that NIC. The more recent address was LAB-UBUNTU's.
  const cand = {
    macAddresses: [addr('lab-ubuntu', '10.99.0.10', '10.99.0.0/24', 'network'), addr('vm', '192.168.36.50', '192.168.36.0/24')],
    hostKeyAssetIds: [], netIpAddresses: [], agentMacAssetIds: ['vm'],
  }
  assert.deepEqual(matchAsset(input, cand), { rule: 1, assetId: 'vm', matchedAddressId: 'vm-192.168.36.50' })
  // The agent's machine has no address with that MAC yet: still the agent's machine, not the other asset.
  assert.deepEqual(matchAsset(input, { ...cand, macAddresses: [cand.macAddresses[0]!] }),
    { rule: '1-agent', assetId: 'vm', matchedAddressId: null })
})

test('without an agent vouching, the same MAC still matches the most recent address (rule 1 as before)', () => {
  const cand = { macAddresses: [addr('a', '192.168.36.50', '192.168.36.0/24')], hostKeyAssetIds: [], netIpAddresses: [], agentMacAssetIds: [] }
  assert.deepEqual(matchAsset(input, cand), { rule: 1, assetId: 'a', matchedAddressId: 'a-192.168.36.50' })
  assert.deepEqual(matchAsset(input, { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [] }), { rule: 6, assetId: null })
})

test("one card on two networks: the network agent's ARP sighting is the agent's machine, and both addresses stay", () => {
  // Lab VM, 9 Nov (evening): R1's ARP had 10.99.0.10 with ens33's MAC; the VM's asset (a server)
  // had that MAC at 192.168.36.50, so the server rule made a nameless new device.
  const crawl: MatcherInput = { macClass: 'global', mac: MAC, ip: '10.99.0.10', hostKey: null, networkKey: '10.99.0.0/24' }
  const cand = { macAddresses: [addr('vm', '192.168.36.50', '192.168.36.0/24')], hostKeyAssetIds: [], netIpAddresses: [], agentMacAssetIds: ['vm'] }
  assert.deepEqual(matchAsset(crawl, cand), { rule: 1, assetId: 'vm', matchedAddressId: 'vm-192.168.36.50' })
  // Not vouched: still a possible second device (a router's MAC on another network)
  assert.equal(matchAsset(crawl, { ...cand, agentMacAssetIds: [] }).rule, '1-possible-duplicate')

  const rows = [{ addressId: 'lab', assetId: 'vm', networkKey: '192.168.36.0/24', ipAddress: '192.168.36.50', macAddress: MAC }]
  const rec = { assetId: 'vm', networkKey: '10.99.0.0/24', ip: '10.99.0.10', mac: MAC }
  assert.deepEqual(addressesToEnd(rows, { ...rec, ownIps: ['192.168.36.50', '10.99.0.10'] }), [])   // the card holds both
  assert.deepEqual(addressesToEnd(rows, { ...rec, ownIps: ['10.99.0.10'] }), ['lab'])               // it moved
  assert.deepEqual(addressesToEnd(rows, rec), ['lab'])                                               // no inventory: as before
})
