import test from 'node:test'
import assert from 'node:assert/strict'
import { ALLOWED_SOURCE_HOSTS, GUIDANCE_MAX, KNOWLEDGE, entryProblems, searchKnowledge } from './knowledge'
import { confidenceProblems, expertCitationProblems } from './guard'

test('every KB entry has an allowed source domain, ≤ 900 chars, and a reviewed date', () => {
  assert.ok(KNOWLEDGE.length >= 60, `at least 60 entries, got ${KNOWLEDGE.length}`)
  assert.equal(GUIDANCE_MAX, 900)
  for (const e of KNOWLEDGE) assert.equal(entryProblems(e), null)
  assert.equal(new Set(KNOWLEDGE.map(e => e.id)).size, KNOWLEDGE.length, 'ids are unique')
  // the rule itself refuses a source outside the list, plain http, and an over-long entry
  const ok = KNOWLEDGE[0]!
  assert.match(String(entryProblems({ ...ok, source: { name: 'x', url: 'https://example.com/a' } })), /not an allowed source/)
  assert.match(String(entryProblems({ ...ok, source: { name: 'x', url: 'http://csrc.nist.gov/a' } })), /not an allowed source/)
  assert.match(String(entryProblems({ ...ok, source: { name: 'x', url: 'https://csrc.nist.gov.evil.com/a' } })), /not an allowed source/)
  assert.match(String(entryProblems({ ...ok, guidance: 'x'.repeat(901) })), /over 900/)
  assert.match(String(entryProblems({ ...ok, reviewed: '' })), /reviewed/)
  assert.ok(ALLOWED_SOURCE_HOSTS.every(h => !h.includes('/') && !h.includes(':')))
})

test('searchKnowledge finds SSH hardening for "port 22 exposed"', () => {
  const hits = searchKnowledge('port 22 exposed')
  assert.ok(hits.length > 0)
  assert.ok(hits.slice(0, 3).some(h => h.tags.includes('ssh')), hits.map(h => h.title).join(' | '))
})

test('searchKnowledge is deterministic, honours tags and limits, and finds nothing for noise', () => {
  assert.deepEqual(searchKnowledge('rollback a bad apt update').map(e => e.id), searchKnowledge('rollback a bad apt update').map(e => e.id))
  assert.ok(searchKnowledge('restrict a port', ['rdp'])[0]!.tags.includes('rdp'))
  assert.equal(searchKnowledge('patch', [], 2).length, 2)
  assert.ok(searchKnowledge('patch', [], 99).length <= 8)
  assert.deepEqual(searchKnowledge('zzzz qqqq'), [])
  assert.deepEqual(searchKnowledge(''), [])
  assert.ok(searchKnowledge('openssl library restart after update').some(e => e.id === 'kb-015'))
  assert.ok(searchKnowledge('known exploited KEV').some(e => e.tags.includes('kev')))
  assert.ok(searchKnowledge('3389 open to internet').some(e => e.tags.includes('rdp')))
})

const GOOD = [
  '## From your environment',
  'Port 22 is open on `web-01` [S1].',
  '',
  '## Expert guidance',
  '1. Restrict SSH to the admin network [K2].',
  '2. Use keys instead of passwords [K2][L1].',
  '',
  'Confidence: High - the port and the hardening guidance are both cited.',
].join('\n')

test('paragraph citing K2 is fine', () => {
  assert.deepEqual(expertCitationProblems(GOOD, new Set(['K2']), new Set(['L1'])), [])
  assert.deepEqual(confidenceProblems(GOOD, 'fix'), [])
})

test('uncited expert paragraph is a problem', () => {
  const bad = GOOD.replace('2. Use keys instead of passwords [K2][L1].', '\nAlso turn on automatic updates.')
  const p = expertCitationProblems(bad, new Set(['K2']), new Set(['L1']))
  assert.equal(p.length, 1)
  assert.match(p[0]!, /without a \[K#\] or \[L#\]/)
  // an S citation does not count as expert backing
  assert.equal(expertCitationProblems(GOOD.replace(/\[K2\]/g, '[S1]').replace('[L1]', ''), new Set(['K2']), new Set()).length, 1)
})

test('unknown K ref is a problem', () => {
  assert.deepEqual(expertCitationProblems(GOOD, new Set(['K1']), new Set(['L1'])).slice(0, 1), ['[K2]'])
  assert.ok(expertCitationProblems(GOOD, new Set(['K2']), new Set()).includes('[L1]'))
})

test('expert guidance check ignores code blocks, the note and the confidence lines, and other sections', () => {
  const text = [
    '## From your environment', 'Uncited facts are checked elsewhere.', '',
    '## Expert guidance', '> General guidance from the cited references.', '1. Block the port [K3].', '```', 'sudo ufw deny 3306/tcp', '```', '',
    'Confidence: Low - the device model is unknown.', 'Check with: the database owner.',
  ].join('\n')
  assert.deepEqual(expertCitationProblems(text, new Set(['K3']), new Set()), [])
})

test('confidence line: missing, no reason, or Low without Check with is a problem', () => {
  assert.match(confidenceProblems(GOOD.replace(/Confidence:.*$/m, ''), 'fix')[0]!, /missing line: Confidence/)
  assert.match(confidenceProblems(GOOD.replace(/Confidence:.*$/m, 'Confidence: High'), 'fix')[0]!, /no reason/)
  assert.match(confidenceProblems(GOOD.replace(/Confidence:.*$/m, 'Confidence: Low - unknown OS.'), 'fix')[0]!, /Check with/)
  assert.deepEqual(confidenceProblems(`${GOOD.replace(/Confidence:.*$/m, '**Confidence:** Low - unknown OS.')}\nCheck with: the vendor.`, 'fix'), [])
  assert.deepEqual(confidenceProblems('Short system answer [S1].', 'system'), [])
})

test('a capped fix answer (ends with the too-long note) needs no Confidence line, and the note is not an uncited paragraph', () => {
  const capped = `${GOOD.replace(/\n\nConfidence:.*$/m, '')}\n\nThis answer was too long to finish. Ask about one step at a time.`
  assert.deepEqual(confidenceProblems(capped, 'fix'), [])
  assert.deepEqual(expertCitationProblems(capped, new Set(['K2']), new Set(['L1'])), [])
})
