import { test } from 'node:test'
import assert from 'node:assert/strict'
import { feedRefresh, feodoRow, otxPulseAttack, threatFoxAttack, urlhausRow } from './cti'
import { kevTechniques } from '../lib/kevAttack'

test('feeds: on schedule in production, by hand only on staging (no crons there)', () => {
  assert.deepEqual(feedRefresh('production'), { scheduled: true, manual: false })
  assert.deepEqual(feedRefresh(undefined), { scheduled: true, manual: false })
  assert.deepEqual(feedRefresh('staging'), { scheduled: false, manual: true })
})

test('an OTX pulse keeps the techniques its author tagged, as strings or objects, dropping unknown ids', () => {
  const r = otxPulseAttack({
    attack_ids: ['T1071', { id: 'T1566.001', name: 'Spearphishing Attachment' }, { display_name: 'T1059.001 - PowerShell' }, 'T9999'],
    malware_families: [],
  })
  assert.deepEqual(r.named, ['T1071', 'T1566.001', 'T1059.001'])
  assert.deepEqual([r.software, r.family], [null, null])
})

test('an OTX pulse prefers a family ATT&CK documents over the first one listed', () => {
  const r = otxPulseAttack({ malware_families: ['Unknown malware', { display_name: 'Some New Loader' }, { id: 'Emotet' }] })
  assert.deepEqual(r, { named: [], software: 'S0367', family: 'Emotet' })
  // no documented family: the first real name is kept, with no ATT&CK software
  assert.deepEqual(otxPulseAttack({ malware_families: ['Some New Loader'] }), { named: [], software: null, family: 'Some New Loader' })
})

test('a ThreatFox indicator resolves its family by printable name, alias or Malpedia key', () => {
  assert.deepEqual(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'Cobalt Strike' }),
    { malwareFamily: 'Cobalt Strike', attackSoftware: 'S0154', attackTechniques: null })
  assert.equal(threatFoxAttack({ malware_printable: 'Heodo', malware_alias: 'Some Alias, Geodo' }).attackSoftware, 'S0367')
  assert.equal(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'CS Beacon' }).attackSoftware, 'S0154')
  assert.deepEqual(threatFoxAttack({ malware: 'win.new_thing', malware_printable: 'New Thing' }),
    { malwareFamily: 'New Thing', attackSoftware: null, attackTechniques: null })
})

test('a ThreatFox indicator with an unknown family gets no family and no ATT&CK software', () => {
  assert.deepEqual(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'Unknown malware' }),
    { malwareFamily: null, attackSoftware: null, attackTechniques: null })
  assert.deepEqual(threatFoxAttack({}), { malwareFamily: null, attackSoftware: null, attackTechniques: null })
  // its role still says something: a command-and-control server
  assert.deepEqual(threatFoxAttack({ threat_type: 'botnet_cc' }).attackTechniques, ['T1071'])
})

test('a family ATT&CK does not describe gets the techniques of its kind and role (inferred)', () => {
  assert.deepEqual(threatFoxAttack({ malware: 'osx.amos', malware_printable: 'AMOS', threat_type: 'payload_delivery' }).attackTechniques,
    ['T1555', 'T1539', 'T1005', 'T1041', 'T1105'])
  assert.deepEqual(threatFoxAttack({ malware_printable: 'IClickFix' }).attackTechniques, ['T1204.004', 'T1059'])
  assert.deepEqual(threatFoxAttack({ malware: 'elf.mirai', malware_printable: 'Mirai', threat_type: 'botnet_cc' }).attackTechniques, ['T1110', 'T1498', 'T1071'])
  assert.deepEqual(threatFoxAttack({ malware_printable: 'SalatStealer' }).attackTechniques, ['T1555', 'T1539', 'T1005', 'T1041'])
  assert.deepEqual(threatFoxAttack({ malware_printable: 'php.shin_webshell' }).attackTechniques, ['T1505.003', 'T1059'])
  // ATT&CK describes Cobalt Strike: its documented techniques are used, nothing is inferred from the kind
  assert.equal(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'Cobalt Strike', threat_type: 'botnet_cc' }).attackTechniques?.join(), 'T1071')
})

test('URLhaus: a malware-download URL, confidence from its status, family and techniques from its tags', () => {
  const now = new Date('2026-11-22T00:00:00Z')
  const r = urlhausRow({ url: 'http://182.117.29.181:43715/i', url_status: 'online', threat: 'malware_download', tags: ['32-bit', 'elf', 'mips', 'Mozi'] }, now)!
  assert.equal(r.source, 'URLhaus')
  assert.equal(r.indicatorType, 'url')
  assert.equal(r.confidenceScore, '0.90')
  assert.equal(r.malwareFamily, 'Mozi')
  assert.deepEqual(r.attackTechniques, ['T1110', 'T1498', 'T1071', 'T1105'])   // an IoT botnet, delivered by this URL
  assert.equal(urlhausRow({ url: 'http://x.example/a', url_status: 'offline' }, now)!.confidenceScore, '0.50')
  // topic and host tags are not families; a known family wins wherever it sits
  assert.equal(urlhausRow({ url: 'http://x.example/a', tags: ['github', 'crypto', 'AsyncRAT'] }, now)!.malwareFamily, 'AsyncRAT')
  assert.equal(urlhausRow({ url: 'http://x.example/a', tags: ['206-189-84-190', 'github'] }, now)!.malwareFamily, null)
  assert.equal(urlhausRow({ url: 'http://x.example/a', tags: ['DEVPOPPER'] }, now)!.malwareFamily, 'DEVPOPPER')
  assert.equal(urlhausRow({ url: 'ftp://x.example/a' }, now), null)
  assert.equal(urlhausRow({}, now), null)
})

test('Feodo Tracker: a botnet C2 address, sure while online', () => {
  const now = new Date('2026-11-22T00:00:00Z')
  const r = feodoRow({ ip_address: '162.243.103.246', status: 'online', malware: 'Emotet' }, now)!
  assert.equal(r.indicatorType, 'ip')
  assert.equal(r.confidenceScore, '0.95')
  assert.equal(r.attackSoftware, 'S0367')                                   // Emotet is ATT&CK software
  assert.deepEqual(r.attackTechniques, ['T1071'])                           // nothing inferred from the kind
  assert.equal(feodoRow({ ip_address: '162.243.103.246', status: 'offline' }, now)!.confidenceScore, '0.60')
  assert.equal(feodoRow({ ip_address: 'not-an-ip' }, now), null)
})

test('KEV CVEs carry MITRE CTID\'s techniques: how exploited, what it leads to', () => {
  const t = kevTechniques('CVE-2024-34102')
  assert.ok(t.exploit.includes('T1190'))
  assert.ok(t.all.length >= t.exploit.length)
  assert.deepEqual(kevTechniques('CVE-1999-0001'), { exploit: [], primary: [], secondary: [], all: [] })
})
