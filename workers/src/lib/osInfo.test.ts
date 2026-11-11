import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mergeOsInfo } from './osInfo'

const svc = (port: number, product: string | null = null) => ({ port, protocol: 'tcp', service: null, product, version: null })
const scan = (ports: number[], products: string[] = []) => ({
  ports: ports.map((p) => `${p}/tcp`), products, versions: [],
  services: ports.map((p, i) => svc(p, products[i] ?? null)),
})
const now = new Date('2026-11-11T10:00:00Z')

test('a passive upload never touches the ports', () => {
  const stored = { ports: ['22/tcp'], services: [svc(22)], os_family: 'Linux' }
  const { incoming, merged } = mergeOsInfo(stored, { ports: [], hostname_hint: 'x' }, true, { ip: '10.0.0.5' })
  assert.equal('ports' in incoming, false)
  assert.deepEqual(merged.ports, ['22/tcp'])
})

test('a device with two cards keeps the ports seen on each (no flapping)', () => {
  // NIC A (192.168.36.50) has Docker's 6379 and 22; NIC B (10.99.0.50) only 22
  const a = mergeOsInfo({}, scan([22, 6379], ['OpenSSH', 'Redis']), false, { ip: '192.168.36.50', now }).merged
  const b = mergeOsInfo(a, scan([22]), false, { ip: '10.99.0.50', currentIps: ['192.168.36.50', '10.99.0.50'], now }).merged
  assert.deepEqual([...(b.ports as string[])].sort(), ['22/tcp', '6379/tcp'])         // 6379 is not "closed"
  assert.equal((b.services as { port: number; product: string | null }[]).find((s) => s.port === 6379)?.product, 'Redis')
  assert.deepEqual(b.products, ['Redis'])
  assert.deepEqual(Object.keys(b.ports_by_ip as object).sort(), ['10.99.0.50', '192.168.36.50'])
  // a rescan of NIC A without 6379 does close it
  const c = mergeOsInfo(b, scan([22]), false, { ip: '192.168.36.50', currentIps: ['192.168.36.50', '10.99.0.50'], now }).merged
  assert.deepEqual(c.ports, ['22/tcp'])
  assert.equal((c.services as unknown[]).length, 1)
})

test('an address the device no longer has is dropped', () => {
  const a = mergeOsInfo({}, scan([80]), false, { ip: '192.168.0.20', now }).merged
  // the laptop moved: 192.168.0.20 is not one of its addresses any more
  const b = mergeOsInfo(a, scan([22]), false, { ip: '192.168.100.71', currentIps: ['192.168.100.71'], now }).merged
  assert.deepEqual(b.ports, ['22/tcp'])
  assert.deepEqual(Object.keys(b.ports_by_ip as object), ['192.168.100.71'])
  // without the device's addresses (the slow path), other addresses are kept
  const kept = mergeOsInfo(a, scan([22]), false, { ip: '192.168.100.71', now }).merged
  assert.deepEqual([...(kept.ports as string[])].sort(), ['22/tcp', '80/tcp'])
})

test('ports stored before per-address ports (no ports_by_ip) are replaced once, as before', () => {
  const legacy = { ports: ['21/tcp', '22/tcp'], services: [svc(21), svc(22)] }
  const m = mergeOsInfo(legacy, scan([22]), false, { ip: '10.0.0.9', currentIps: ['10.0.0.9'], now }).merged
  assert.deepEqual(m.ports, ['22/tcp'])
  assert.deepEqual(m.ports_by_ip, { '10.0.0.9': { ports: ['22/tcp'], seen_at: now.toISOString() } })
})
