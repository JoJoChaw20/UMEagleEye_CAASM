import { test } from 'node:test'
import assert from 'node:assert/strict'
import { feedRefresh, otxPulseAttack, threatFoxAttack } from './cti'

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
    { malwareFamily: 'Cobalt Strike', attackSoftware: 'S0154' })
  assert.equal(threatFoxAttack({ malware_printable: 'Heodo', malware_alias: 'Some Alias, Geodo' }).attackSoftware, 'S0367')
  assert.equal(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'CS Beacon' }).attackSoftware, 'S0154')
  assert.deepEqual(threatFoxAttack({ malware: 'win.new_thing', malware_printable: 'New Thing' }),
    { malwareFamily: 'New Thing', attackSoftware: null })
})

test('a ThreatFox indicator with an unknown family gets no family and no ATT&CK software', () => {
  assert.deepEqual(threatFoxAttack({ malware: 'win.cobalt_strike', malware_printable: 'Unknown malware' }),
    { malwareFamily: null, attackSoftware: null })
  assert.deepEqual(threatFoxAttack({}), { malwareFamily: null, attackSoftware: null })
})
