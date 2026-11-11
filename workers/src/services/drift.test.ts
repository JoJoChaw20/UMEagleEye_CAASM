import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openAlertAction, shouldReopen, sightingFor } from './drift'

const passive = '2026-11-11T10:00:00Z'      // a passive upload moved last_scanned
const active = '2026-11-10T08:00:00Z'       // the last active scan that checked the ports

test('a port alert only counts an active scan as a sighting', () => {
  const asset = { lastScanned: passive, inventoryCollectedAt: null, portsSeenAt: active }
  assert.equal(sightingFor('port_opened', asset)!.toISOString(), new Date(active).toISOString())
  assert.equal(sightingFor('port_closed', asset)!.toISOString(), new Date(active).toISOString())
  // other alerts: any scan or the agent's inventory
  assert.equal(sightingFor('config_change', asset)!.toISOString(), new Date(passive).toISOString())
  // never actively scanned: no sighting for its port alerts
  assert.equal(sightingFor('port_opened', { lastScanned: passive, portsSeenAt: null }), null)
})

test('a passive upload neither refreshes nor reopens a port alert', () => {
  const asset = { lastScanned: passive, portsSeenAt: active }
  const alertLastSeen = '2026-11-10T09:00:00Z'      // after the active scan, before the passive upload
  assert.equal(openAlertAction(sightingFor('port_opened', asset), alertLastSeen, false), 'none')
  assert.equal(openAlertAction(sightingFor('config_change', asset), alertLastSeen, false), 'bump')
  assert.equal(shouldReopen(sightingFor('port_opened', asset), alertLastSeen), false)
  // the next active scan does
  const scanned = { ...asset, portsSeenAt: '2026-11-11T11:00:00Z' }
  assert.equal(openAlertAction(sightingFor('port_opened', scanned), alertLastSeen, false), 'bump')
  assert.equal(shouldReopen(sightingFor('port_opened', scanned), alertLastSeen), true)
})
