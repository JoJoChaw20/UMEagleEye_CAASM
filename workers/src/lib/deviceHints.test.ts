import { test } from 'node:test'
import assert from 'node:assert/strict'
import { deviceTypeHint } from './deviceHints'
import { AI_PROMPT_VERSION, aiEvidenceKey, reusableDescription } from './hostEvidence'

const input = (osInfo: Record<string, unknown>) => ({ hostname: null, mac: null, vendor: null, osInfo })

test("an SNMP agent of a network-equipment maker is a network device; a server's SNMP is not", () => {
  const huawei = deviceTypeHint(input({ snmp_engine: { vendor: 'Huawei', enterprise: 2011, uptime_seconds: 86400 } }))
  assert.deepEqual([huawei?.type, huawei?.rule, huawei?.confidence], ['network', 'snmp_engine', 'medium'])
  assert.equal(deviceTypeHint(input({ snmp_engine: { vendor: 'net-snmp', enterprise: 8072 } })), null)
  assert.equal(deviceTypeHint(input({ snmp_engine: { vendor: 'Microsoft' } })), null)
})

test('a phone that only looked for a Chromecast is not one; a device that announces Google Cast is', () => {
  assert.equal(deviceTypeHint(input({ mdns_services: ['_googlecast._tcp'] })), null)
  // an active scan's mDNS answer: the services it answered with are offered
  const cast = deviceTypeHint(input({ mdns_offered: ['_googlecast._tcp'], mdns_services: ['_googlecast._tcp'] }))
  assert.equal(cast?.type, 'iot')
})

test('a new prompt version describes every host again; the same evidence reuses its description', () => {
  assert.equal(AI_PROMPT_VERSION, 2)
  const key = aiEvidenceKey({ hostname: 'JINGROU', mac: 'd4:1b:81:79:4e:db', vendor: null, ports: [], os: { netbios_name: 'JINGROU' } })
  assert.equal(key, aiEvidenceKey({ hostname: 'jingrou', mac: 'D4-1B-81-79-4E-DB', vendor: null, ports: [], os: { netbios_name: 'JINGROU' } }))
  const stored = { ai_description: 'Windows PC (JINGROU)', ai_evidence: key }
  assert.deepEqual(reusableDescription(stored, key), { description: 'Windows PC (JINGROU)', suggestion: null })
  assert.equal(reusableDescription({ ...stored, ai_evidence: 'made-with-the-old-prompt' }, key), null)
})
