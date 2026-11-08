import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LIMITS, WINDOW_SECONDS, clearFailures, overLimit, recordFailure } from './loginLimit'

function memoryKv() {
  const m = new Map<string, string>()
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => { m.set(k, v) },
    delete: async (k: string) => { m.delete(k) },
  }
}

test('an account is locked after its wrong passwords, for the rest of the window', async () => {
  const kv = memoryKv(), now = Date.UTC(2026, 10, 9, 10, 0, 0)
  for (let i = 0; i < LIMITS.password_account; i++) {
    assert.equal(await overLimit(kv, 'password_account', 'Alice', now), false)
    await recordFailure(kv, 'password_account', 'alice', now)
  }
  assert.equal(await overLimit(kv, 'password_account', 'ALICE', now), true)         // usernames ignore case
  assert.equal(await overLimit(kv, 'password_account', 'bob', now), false)
  assert.equal(await overLimit(kv, 'password_account', 'alice', now + WINDOW_SECONDS * 1000), false)
})

test('a successful sign-in clears the account count; MFA codes have their own, smaller limit', async () => {
  const kv = memoryKv(), now = Date.UTC(2026, 10, 9, 10, 0, 0)
  await recordFailure(kv, 'password_account', 'alice', now)
  await clearFailures(kv, 'password_account', 'alice', now)
  assert.equal(kv.m.size, 0)
  for (let i = 0; i < LIMITS.mfa_account; i++) await recordFailure(kv, 'mfa_account', 'user-1', now)
  assert.equal(await overLimit(kv, 'mfa_account', 'user-1', now), true)
})

test('a broken cache never blocks sign-in', async () => {
  const broken = { get: async () => { throw new Error('kv down') }, put: async () => { throw new Error('kv down') }, delete: async () => {} }
  assert.equal(await overLimit(broken, 'password_address', '1.2.3.4'), false)
  await recordFailure(broken, 'password_address', '1.2.3.4')
})
