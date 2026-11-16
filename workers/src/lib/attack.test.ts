import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ATTACK, buildMatrix, expandTechniques, normName, parentOf, resolveSoftware, softwareName,
  softwareUsing, tacticsOf, techniqueIds, techniqueName, techniquesFor,
} from './attack'

test('the bundled data is MITRE ATT&CK Enterprise, its tactics in matrix order and its references intact', () => {
  assert.match(ATTACK.source, /MITRE ATT&CK Enterprise/)
  assert.equal(ATTACK.tactics.length, 15)
  assert.deepEqual(ATTACK.tactics[0], ['TA0043', 'reconnaissance', 'Reconnaissance'])
  // every technique points at tactics that exist, every software at techniques that exist
  for (const [, [, tx]] of Object.entries(ATTACK.techniques)) for (const i of tx) assert.ok(ATTACK.tactics[i])
  for (const [, [, techs]] of Object.entries(ATTACK.software)) for (const t of techs) assert.ok(ATTACK.techniques[t], t)
})

test('a malware family resolves to ATT&CK software by name or alias, ignoring case, spaces and punctuation', () => {
  assert.equal(normName('Cobalt-Strike '), 'cobaltstrike')
  for (const n of ['Cobalt Strike', 'cobalt_strike', 'COBALT-STRIKE']) assert.equal(resolveSoftware([n]), 'S0154')
  assert.equal(resolveSoftware(['Geodo']), 'S0367')            // an alias of Emotet
  assert.equal(softwareName('S0367'), 'Emotet')
  // the first candidate ATT&CK knows wins; blanks and unknown names are skipped
  assert.equal(resolveSoftware([null, '', 'Some New Loader', 'Emotet', 'Cobalt Strike']), 'S0367')
  assert.equal(resolveSoftware(['Some New Loader', undefined]), null)
  assert.equal(softwareName(null), null)
})

test('technique ids are read from free text; ids ATT&CK does not have are dropped, nothing is guessed', () => {
  assert.deepEqual(
    techniqueIds(['T1071', 't1059.001', 'T1566 - Phishing', ' T1071 ', 'T9999', 'TA0002', 'phishing', null, undefined]),
    ['T1071', 'T1059.001', 'T1566'])
  assert.deepEqual(techniqueIds([]), [])
  assert.equal(techniqueName('T1566.001'), 'Spearphishing Attachment')
  assert.equal(techniqueName('T9999'), null)
  assert.equal(parentOf('T1059.001'), 'T1059')
  assert.equal(parentOf('T1059'), 'T1059')
})

test('a technique reports its tactics from the matrix', () => {
  assert.deepEqual(tacticsOf('T1059'), ['execution'])
  assert.deepEqual(tacticsOf('T1071'), ['command-and-control'])
  assert.deepEqual(tacticsOf('T9999'), [])
})

test("an indicator's techniques are its family's documented ones plus any the feed named, without duplicates", () => {
  const cs = techniquesFor('S0154', null)
  assert.equal(cs.length, ATTACK.software['S0154']![1].length)
  assert.ok(cs.includes('T1059.001'))
  assert.deepEqual(techniquesFor(null, ['T1566']), ['T1566'])
  assert.deepEqual(techniquesFor(null, null), [])
  assert.deepEqual(techniquesFor('S9999', null), [])            // unknown software: nothing invented
  const both = techniquesFor('S0154', ['T1059.001', 'T1566'])
  assert.equal(both.length, cs.length + 1)
  assert.equal(new Set(both).size, both.length)
})

test('a parent technique expands to itself and its sub-techniques only', () => {
  const ex = expandTechniques(['t1059'])
  assert.ok(ex.includes('T1059') && ex.includes('T1059.001'))
  assert.equal(ex.length, 1 + Object.keys(ATTACK.techniques).filter((t) => t.startsWith('T1059.')).length)
  assert.ok(ex.every((t) => parentOf(t) === 'T1059'))
  assert.deepEqual(expandTechniques(['T1059.001']), ['T1059.001'])
})

test('softwareUsing lists exactly the software that documents a technique', () => {
  const users = softwareUsing(['T1059.001'])
  assert.ok(users.includes('S0154'))
  for (const id of users) assert.ok(ATTACK.software[id]![1].includes('T1059.001'))
  assert.equal(users.length, Object.values(ATTACK.software).filter(([, t]) => t.includes('T1059.001')).length)
})

test('the matrix counts indicators once per technique, rolls sub-techniques up and reports coverage', () => {
  const m = buildMatrix([
    { family: 'Cobalt Strike', software: 'S0154', named: null, count: 10 },
    { family: 'Some New Loader', software: null, named: null, count: 4 },
    { family: null, software: null, named: ['T1059.001'], count: 3 },
    { family: null, software: null, named: null, count: 5 },
  ])
  assert.deepEqual(m.coverage, {
    total: 22, with_family: 14, with_attack: 13, families: 2, families_matched: 1,
    top_unmatched: [{ name: 'Some New Loader', iocs: 4 }],
  })
  // Cobalt Strike documents five T1059 sub-techniques: its 10 indicators count once for T1059
  const t1059 = m.techniques.find((t) => t.id === 'T1059')!
  assert.equal(t1059.iocs, 13)
  assert.deepEqual(t1059.tactics, ['execution'])
  assert.equal(t1059.family_count, 2)
  assert.deepEqual(t1059.families.map((f) => [f.name, f.iocs]), [['Cobalt Strike', 10], ['Techniques named by the feed', 3]])
  assert.deepEqual(t1059.subs[0], { id: 'T1059.001', name: 'PowerShell', iocs: 13 })
  // only parent techniques are rows, sorted by indicator count
  assert.ok(m.techniques.every((t) => !t.id.includes('.')))
  for (let i = 1; i < m.techniques.length; i++) assert.ok(m.techniques[i - 1]!.iocs >= m.techniques[i]!.iocs)
  assert.equal(m.tactics.length, 15)
})

test('an event title is counted as its own family in the matrix', () => {
  const m = buildMatrix([
    { family: 'Cobalt Strike', software: 'S0154', named: null, count: 1, label: 'Campaign A' },
    { family: 'Cobalt Strike', software: 'S0154', named: null, count: 1, label: 'Campaign B' },
  ])
  assert.equal(m.coverage.families, 2)
  assert.deepEqual(m.techniques.find((t) => t.id === 'T1059')!.families.map((f) => f.name).sort(), ['Campaign A', 'Campaign B'])
})
