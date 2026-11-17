import { test } from 'node:test'
import assert from 'node:assert/strict'
import { noticeVisible } from './notices'

const NOW = new Date('2026-11-18T00:00:00Z')
const ME = { userId: 'u1', tenantId: 't1' }
const N = { tenantId: 't1', userId: null as string | null, expiresAt: null as Date | null, dismissedAt: null as Date | null }

test('tenant-wide and own notices are visible', () => {
  assert.equal(noticeVisible(N, ME, NOW), true)
  assert.equal(noticeVisible({ ...N, userId: 'u1' }, ME, NOW), true)
})

test("another user's notice, or another tenant's, is hidden", () => {
  assert.equal(noticeVisible({ ...N, userId: 'u2' }, ME, NOW), false)
  assert.equal(noticeVisible({ ...N, tenantId: 't2' }, ME, NOW), false)
  assert.equal(noticeVisible(N, { userId: 'u1', tenantId: null }, NOW), false)
})

test('expired (at or before now) and dismissed notices are hidden', () => {
  assert.equal(noticeVisible({ ...N, expiresAt: new Date(NOW.getTime() + 1) }, ME, NOW), true)
  assert.equal(noticeVisible({ ...N, expiresAt: NOW }, ME, NOW), false)
  assert.equal(noticeVisible({ ...N, expiresAt: new Date(NOW.getTime() - 1) }, ME, NOW), false)
  assert.equal(noticeVisible({ ...N, userId: 'u1', dismissedAt: NOW }, ME, NOW), false)
})
