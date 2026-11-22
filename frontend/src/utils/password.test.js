import { test } from 'node:test'
import assert from 'node:assert/strict'
import { inviteBody, inviteDoneText, isStrongPassword, passwordChecks } from './password.js'

test('password checks mirror the server rules', () => {
  assert.equal(isStrongPassword('Start-Pass-2026!'), true)
  assert.equal(isStrongPassword('short1!A'), false)
  assert.equal(isStrongPassword('Has Space 2026!'), false)
  assert.equal(passwordChecks('abc').lowercase, true)
  assert.equal(passwordChecks('abc').uppercase, false)
})

test('invite body by email leaves the password out', () => {
  assert.deepEqual(inviteBody('email', { email: ' a@b.com ', username: '', password: 'x', actions: [] }),
    { email: 'a@b.com', username: undefined, actions: [] })
})

test('invite body with a starting password leaves the email out', () => {
  assert.deepEqual(inviteBody('password', { email: 'a@b.com', username: ' ann ', password: 'P', as_tenant_superadmin: true }),
    { username: 'ann', password: 'P', as_tenant_superadmin: true })
})

test('done text says how the person signs in', () => {
  assert.match(inviteDoneText('password', { action: 'created', username: 'ann' }), /starting password/)
  assert.match(inviteDoneText('email', { action: 'created', email: 'a@b.com' }), /Google using this email/)
  assert.equal(inviteDoneText('email', { action: 'assigned', username: 'ann' }), 'ann added to this tenant.')
  assert.match(inviteDoneText('password', { action: 'created', username: 'ann' }, ' as Tenant Superadmin'), /^Created ann as Tenant Superadmin\./)
})
