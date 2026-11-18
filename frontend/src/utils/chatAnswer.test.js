import test from 'node:test'
import assert from 'node:assert/strict'
import { SAFE_REFUSAL, checkWithOf, confidenceOf, isSafeRefusal, parseCitations, safeSourceUrl, sourcesByRef } from './chatAnswer.js'

test('parseCitations splits text and citation groups', () => {
  assert.deepEqual(parseCitations('Port 22 is open [S1]. Restrict it [K2, L1].'), [
    { type: 'text', text: 'Port 22 is open ' },
    { type: 'cite', refs: ['S1'] },
    { type: 'text', text: '. Restrict it ' },
    { type: 'cite', refs: ['K2', 'L1'] },
    { type: 'text', text: '.' },
  ])
  assert.deepEqual(parseCitations('No citations here.'), [{ type: 'text', text: 'No citations here.' }])
  assert.deepEqual(parseCitations(''), [])
  // only S, K and L refs are citations; [1] and [X2] stay text
  assert.deepEqual(parseCitations('See [1] and [X2].'), [{ type: 'text', text: 'See [1] and [X2].' }])
})

test('confidenceOf reads the confidence line', () => {
  assert.deepEqual(confidenceOf('Confidence: High - both facts are cited.'), { level: 'High', reason: 'both facts are cited.' })
  assert.deepEqual(confidenceOf('**Confidence:** low — the OS is unknown'), { level: 'Low', reason: 'the OS is unknown' })
  assert.equal(confidenceOf('My confidence is high'), null)
  assert.equal(checkWithOf('Check with: the system owner'), 'the system owner')
  assert.equal(checkWithOf('check the logs'), null)
})

test('isSafeRefusal recognises the fixed refusals only', () => {
  assert.equal(isSafeRefusal(SAFE_REFUSAL), true)
  assert.equal(isSafeRefusal(`  ${SAFE_REFUSAL}\n`), true)
  assert.equal(isSafeRefusal('The Platform Superadmin can view overall statistics and ask general security questions, but cannot debug advisories.'), true)
  assert.equal(isSafeRefusal(`${SAFE_REFUSAL} But here is how anyway.`), false)
})

test('safeSourceUrl allows https links only', () => {
  assert.equal(safeSourceUrl('https://csrc.nist.gov/pubs/sp/800/40/r4/final'), 'https://csrc.nist.gov/pubs/sp/800/40/r4/final')
  assert.equal(safeSourceUrl('javascript:alert(1)'), null)
  assert.equal(safeSourceUrl('data:text/html,hi'), null)
  assert.equal(safeSourceUrl('http://example.com'), null)
  assert.equal(safeSourceUrl(undefined), null)
})

test('sourcesByRef maps refs case-insensitively and ignores junk', () => {
  const m = sourcesByRef([{ ref: 'k1', title: 'SSH', url: 'https://www.openssh.com/manual.html' }, null, { title: 'no ref' }])
  assert.equal(m.get('K1').title, 'SSH')
  assert.equal(m.size, 1)
})
