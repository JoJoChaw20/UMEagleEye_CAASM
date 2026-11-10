import test from 'node:test'
import assert from 'node:assert/strict'
import journal from '../../drizzle/meta/_journal.json'

// Drizzle's migrator applies only the entries whose `when` is newer than the latest migration the
// database has applied. An entry older than the one before it is skipped on a database that already
// has its predecessors, and every migration that depends on it then fails.
test('migration timestamps rise with their index, so no migration is skipped', () => {
  const entries = [...journal.entries].sort((a, b) => a.idx - b.idx)
  entries.forEach((e, i) => assert.equal(e.idx, i, `${e.tag} has idx ${e.idx}`))
  for (let i = 1; i < entries.length; i++) {
    const before = entries[i - 1]!, entry = entries[i]!
    assert.ok(entry.when > before.when, `${entry.tag} (${entry.when}) is not newer than ${before.tag} (${before.when})`)
  }
})
