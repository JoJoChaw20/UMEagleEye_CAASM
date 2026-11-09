import { test } from 'node:test'
import assert from 'node:assert/strict'
import { matchAsset, type CandidateAddress, type MatcherInput } from './identity'

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
