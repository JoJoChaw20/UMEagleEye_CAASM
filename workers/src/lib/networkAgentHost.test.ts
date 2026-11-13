import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cleanSelf, pickHostAsset } from './networkAgentHost'

test('a heartbeat self report is cleaned; one with no address or MAC says nothing', () => {
  assert.deepEqual(cleanSelf({ ip: '10.99.0.20', mac: '00:0C:29:AA:BB:CC', hostname: ' gns3-netagent ' }),
    { ip: '10.99.0.20', mac: '00:0c:29:aa:bb:cc', hostname: 'gns3-netagent' })
  assert.equal(cleanSelf({ ip: '127.0.0.1', hostname: 'x' }), null)
  assert.equal(cleanSelf({ ip: 'not an ip' }), null)
  assert.equal(cleanSelf('10.99.0.20'), null)
  assert.deepEqual(cleanSelf({ ip: '10.99.0.20', hostname: 'bad name!' }), { ip: '10.99.0.20', mac: null, hostname: null })
})

test('the MAC decides first, then the address; a router the crawl polled never is the agent', () => {
  const self = { ip: '10.99.0.20', mac: '00:0c:29:aa:bb:cc', hostname: null }
  assert.equal(pickHostAsset(self, [
    { assetId: 'vm', ip: '10.99.0.21', mac: '00:0C:29:AA:BB:CC', networkDevice: false },
    { assetId: 'other', ip: '10.99.0.20', mac: null, networkDevice: false },
  ]), 'vm')
  assert.equal(pickHostAsset(self, [{ assetId: 'vm', ip: '10.99.0.20', mac: null, networkDevice: false }]), 'vm')
  assert.equal(pickHostAsset(self, [{ assetId: 'r1', ip: '10.99.0.20', mac: null, networkDevice: true }]), null)
})

test('two assets with the address and no MAC to tell them apart: no link', () => {
  const self = { ip: '10.99.0.20', mac: null, hostname: null }
  assert.equal(pickHostAsset(self, [
    { assetId: 'a', ip: '10.99.0.20', mac: null, networkDevice: false },
    { assetId: 'b', ip: '10.99.0.20', mac: null, networkDevice: false },
  ]), null)
  // one asset seen twice (its own column and its address row) is still one
  assert.equal(pickHostAsset(self, [
    { assetId: 'a', ip: '10.99.0.20', mac: null, networkDevice: false },
    { assetId: 'a', ip: '10.99.0.20', mac: null, networkDevice: false },
  ]), 'a')
})
