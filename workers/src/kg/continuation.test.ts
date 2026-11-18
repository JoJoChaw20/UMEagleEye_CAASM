import test from 'node:test'
import assert from 'node:assert/strict'
import { LONG_NOTE, joinContinuation } from './continuation'

test('continuation joins parts and ends on a sentence', () => {
  assert.equal(
    joinContinuation(['The fix has two steps. First, restrict', ' SSH to the admin network. Second, use keys.'], false),
    'The fix has two steps. First, restrict SSH to the admin network. Second, use keys.',
  )
  // a part that starts mid-word is joined without a space
  assert.equal(joinContinuation(['Upgrade open', 'ssl to 3.0.15.'], false), 'Upgrade openssl to 3.0.15.')
  assert.equal(joinContinuation(['Only one part.'], false), 'Only one part.')
})

test('capped answer ends at last full sentence with the verbatim note', () => {
  assert.equal(LONG_NOTE, 'This answer was too long to finish. Ask about one step at a time.')
  assert.equal(
    joinContinuation(['One. Two is long and', ' still going. Three is cut mid'], true),
    `One. Two is long and still going.\n\n${LONG_NOTE}`,
  )
  // a citation after the full stop stays with its sentence
  assert.equal(joinContinuation(['Restrict SSH. [K1] Then use keys and'], true), `Restrict SSH. [K1]\n\n${LONG_NOTE}`)
  // a finished list line counts as complete; an open code block is dropped
  assert.equal(
    joinContinuation(['## Expert guidance\n1. Restrict SSH [K1]\n```bash\nsudo ufw allow from 10.0.5.0/24 to any port 22 proto tcp\nsudo ufw de'], true),
    `## Expert guidance\n1. Restrict SSH [K1]\n\n${LONG_NOTE}`,
  )
  // nothing complete at all: only the note
  assert.equal(joinContinuation(['no sentence end here'], true), LONG_NOTE)
})

test('no duplicate overlap when the model repeats the last words', () => {
  assert.equal(joinContinuation(['Restrict SSH to the admin', 'to the admin network.'], false), 'Restrict SSH to the admin network.')
  assert.equal(joinContinuation(['First part ends here. ', 'First part ends here. Second part.'], false), 'First part ends here. Second part.')
  // a short coincidence is not an overlap
  assert.equal(joinContinuation(['Use the', ' the firewall.'], false), 'Use the the firewall.')
  // an overlap inside a word is not removed
  assert.equal(joinContinuation(['Set unattended', 'attended-upgrades on.'], false), 'Set unattendedattended-upgrades on.')
})
