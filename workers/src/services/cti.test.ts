import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PgDialect } from 'drizzle-orm/pg-core'
import type { SQL } from 'drizzle-orm'
import { ACTIVE_FEEDS, CTI_STEPS, FEED_UNITS, batchUpsert, feedRefresh, nextCtiStep, otxPulseAttack, threatFoxAttack } from './cti'
import { RETIRED_SOURCES } from './threatIntel'
import { purgeStaleCti } from './retention'
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

// a database that records the statement instead of running it
function recordingDb() {
  const seen: { sql: string; params: unknown[] }[] = []
  const db = { execute: async (q: SQL) => { const r = new PgDialect().sqlToQuery(q); seen.push({ sql: r.sql, params: r.params }); return { rows: [] } } }
  return { db: db as unknown as Parameters<typeof batchUpsert>[0], seen }
}

test('a value a retired feed stored first becomes the listing feed\'s (source and confidence), instead of never matching', async () => {
  const { db, seen } = recordingDb()
  await batchUpsert(db, [{ source: 'ThreatFox', indicatorType: 'ip', value: '203.0.113.9', confidenceScore: '0.75' }])
  const q = seen[0]!
  assert.match(q.sql, /source\s+= CASE WHEN c\.source IN \(\$\d+, \$\d+, \$\d+\) THEN excluded\.source ELSE c\.source END/)
  assert.match(q.sql, /CASE WHEN c\.source = excluded\.source OR c\.source IN \(\$\d+, \$\d+, \$\d+\) THEN excluded\.confidence_score/)
  for (const s of RETIRED_SOURCES) assert.ok(q.params.includes(s))
})

test('retention deletes feed rows that can no longer alert (retired, safe-listed, expired), unless an alert references them', async () => {
  const { db, seen } = recordingDb()
  await purgeStaleCti(db)
  const q = seen[0]!
  assert.match(q.sql, /c\.ti_event_id IS NULL\s+AND \(c\.last_seen < now\(\) - make_interval\(days => \$\d+\) OR c\.source IN \(\$\d+, \$\d+, \$\d+\)\s+OR c\.warning IS NOT NULL OR NOT \(\(c\.ti_event_id IS NOT NULL AND c\.source <> 'MyCERT'\)/)
  assert.match(q.sql, /c\.last_seen > now\(\) - \(CASE WHEN c\.indicator_type = 'ip' THEN 30\s+ELSE 90 END\)/)
  assert.match(q.sql, /NOT EXISTS \(SELECT 1 FROM event_cti_indicators e WHERE e\.indicator_id = c\.indicator_id\)/)
  for (const s of RETIRED_SOURCES) assert.ok(q.params.includes(s))
})

test('the nightly chain: MyCERT first, then CVE data, bulk indicators and the rest; URLhaus, Feodo and DROP gone', () => {
  assert.deepEqual(CTI_STEPS, ['mycert', 'kev', 'threatfox', 'epss', 'malpkg', 'finish'])
  assert.deepEqual(ACTIVE_FEEDS, ['MyCERT', 'CISA KEV', 'ThreatFox'])
  assert.deepEqual(ACTIVE_FEEDS.map((s) => FEED_UNITS[s]![1]), ['advisories', 'CVEs', 'indicators'])
  assert.equal(nextCtiStep('mycert'), 'kev')
  assert.equal(nextCtiStep('finish'), null)
  for (const s of ['AlienVault OTX', 'URLhaus', 'Feodo Tracker']) assert.ok(RETIRED_SOURCES.includes(s))
  assert.ok(!RETIRED_SOURCES.includes('MyCERT'))
})

test('KEV CVEs carry MITRE CTID\'s techniques: how exploited, what it leads to', () => {
  const t = kevTechniques('CVE-2024-34102')
  assert.ok(t.exploit.includes('T1190'))
  assert.ok(t.all.length >= t.exploit.length)
  assert.deepEqual(kevTechniques('CVE-1999-0001'), { exploit: [], primary: [], secondary: [], all: [] })
})
