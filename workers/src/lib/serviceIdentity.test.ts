import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cpe23, recognize } from './recog'
import { identifyServices, inSbom, planServices, productKey, serviceFinding } from './serviceIdentity'

test('Recog identifies the lab banners and gives NVD a CPE with the version', () => {
  const ssh = recognize('ssh', 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.10')
  assert.equal(ssh?.['service.product'], 'OpenSSH')
  assert.equal(ssh?.['service.version'], '8.9p1')
  assert.equal(cpe23(ssh?.['service.cpe23']), 'cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*')
  assert.equal(recognize('http_server', 'nginx/1.28.3 (Ubuntu)')?.['service.product'], 'nginx')
  assert.equal(recognize('http_server', 'Microsoft-IIS/10.0')?.['service.product'], 'IIS')
  assert.equal(cpe23('cpe:/a:f5:nginx:-'), null)                  // no version: not looked up
})

test('services are identified from the SSH banner and the HTTP Server header, with the distribution noted', () => {
  const ids = identifyServices([
    { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.9p1', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10' },
    { port: 80, protocol: 'tcp', service: 'http', facts: { http: { server: 'nginx/1.20.0' } } },
    { port: 6379, protocol: 'tcp', service: 'redis', product: 'Redis', version: '7.4.1' },     // no banner Recog knows
    { port: 161, protocol: 'udp', service: 'snmp' },
  ])
  assert.deepEqual(ids.map((s) => [s.port, s.product, s.version, s.distro]),
    [[22, 'OpenSSH', '8.9p1', 'Ubuntu'], [80, 'nginx', '1.20.0', null]])
  assert.equal(ids[1]!.cpe, 'cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*')
})

test('the alert: worst CVSS, at least high when exploited, lower for a distribution build, higher on the internet', () => {
  const [ssh, nginx] = identifyServices([
    { port: 22, service: 'ssh', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10' },
    { port: 80, service: 'http', facts: { http: { server: 'nginx/1.20.0' } } },
  ])
  const cves = [{ id: 'CVE-2023-48795', cvss: 5.9 }, { id: 'CVE-2024-6387', cvss: 8.1, kev: true }]
  const f = serviceFinding(ssh!, cves, false)!
  assert.equal(f.severity, 'medium')                                  // high (8.1, KEV) minus one: Ubuntu may have patched
  assert.equal((f.details.cves as { id: string }[])[0]!.id, 'CVE-2024-6387')   // exploited first
  assert.equal(f.details.kev_count, 1)
  assert.equal(serviceFinding(nginx!, [{ id: 'CVE-2021-23017', cvss: 9.4 }], true)!.severity, 'critical')
  assert.equal(serviceFinding(nginx!, [{ id: 'CVE-x', cvss: 3.1 }], false)!.severity, 'low')
  assert.equal(serviceFinding(nginx!, [], false), null)
})

test('one alert per device and product: refreshed, closed when patched or gone, closed when the SBOM covers it', () => {
  const [nginx] = identifyServices([{ port: 80, service: 'http', facts: { http: { server: 'nginx/1.20.0' } } }])
  const f = serviceFinding(nginx!, [{ id: 'CVE-2021-23017', cvss: 9.4 }], false)!
  const existing = [{ eventId: 'n', status: 'open', key: productKey(nginx!) }, { eventId: 'old', status: 'open', key: 'openbsd:openssh' }]
  const on = (v: 'sbom' | 'no_cve' | null) => (key: string) => key === productKey(nginx!) ? v : null
  let plan = planServices([f], existing, { onAlertPort: on(null), checkedPortsOf: () => true })
  assert.deepEqual(plan.refresh.map((r) => r.eventId), ['n'])
  assert.deepEqual(plan.resolve.map((r) => r.eventId), ['old'])      // OpenSSH no longer seen on a checked port
  plan = planServices([], existing, { onAlertPort: on('no_cve'), checkedPortsOf: () => false })
  assert.match(plan.resolve.find((r) => r.eventId === 'n')!.why, /no known CVE/)   // upgraded: identified, no CVE
  assert.equal(plan.resolve.some((r) => r.eventId === 'old'), false)                 // port not checked: stays
  plan = planServices([], existing, { onAlertPort: on('sbom'), checkedPortsOf: () => false })
  assert.match(plan.resolve.find((r) => r.eventId === 'n')!.why, /SBOM/)                 // now the packaged version
  assert.equal(plan.resolve.some((r) => r.eventId === 'old'), false)
  // the container on 8000 removed, the packaged nginx still on 80: nothing on the alert's port
  plan = planServices([], existing, { onAlertPort: on(null), checkedPortsOf: () => true })
  assert.match(plan.resolve.find((r) => r.eventId === 'n')!.why, /No longer seen/)
})

test("on a device with an SBOM only what the package list lacks counts (the lab VM's container nginx)", () => {
  const [ssh, nginx80, nginx8000, apache] = identifyServices([
    { port: 22, service: 'ssh', banner: 'SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8' },
    { port: 80, service: 'http', facts: { http: { server: 'nginx/1.28.3 (Ubuntu)' } } },
    { port: 8000, service: 'http', facts: { http: { server: 'nginx/1.20.0' } } },
    { port: 8080, service: 'http', facts: { http: { server: 'Apache/2.4.58 (Ubuntu)' } } },
  ])
  const sbom = [
    { name: 'openssh-server', version: '1:10.2p1-2ubuntu3.8' }, { name: 'nginx', version: '1.28.3-2ubuntu1.12' },
    { name: 'apache2', version: '2.4.58-1ubuntu8.5' },
  ]
  assert.equal(inSbom(ssh!, sbom), true)
  assert.equal(inSbom(nginx80!, sbom), true)
  assert.equal(inSbom(nginx8000!, sbom), false)                     // a container: not in the package list
  assert.equal(inSbom(apache!, sbom), true)                         // Apache HTTPD is packaged as apache2
  assert.equal(inSbom(nginx80!, [{ name: 'nginx', version: '1.28.30' }]), false)
  assert.equal(inSbom(nginx80!, []), false)
})
