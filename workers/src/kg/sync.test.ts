import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldSignalKg } from './sync'

test('a successful write asks for a sync', () => {
  for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.equal(shouldSignalKg(m, '/api/v1/assets', 200), true)
  assert.equal(shouldSignalKg('POST', '/api/v1/agents/a1/inventory', 201), true)
})

test('reads, failed writes and redirects do not', () => {
  assert.equal(shouldSignalKg('GET', '/api/v1/assets', 200), false)
  assert.equal(shouldSignalKg('OPTIONS', '/api/v1/assets', 204), false)
  assert.equal(shouldSignalKg('POST', '/api/v1/assets', 400), false)
  assert.equal(shouldSignalKg('POST', '/api/v1/assets', 500), false)
})

test('heartbeats and chat do not write graph tables', () => {
  assert.equal(shouldSignalKg('POST', '/api/v1/agents/a1/heartbeat', 200), false)
  assert.equal(shouldSignalKg('POST', '/api/v1/chatbot', 200), false)
  assert.equal(shouldSignalKg('POST', '/api/v1/chatbot/chat', 200), false)
  assert.equal(shouldSignalKg('POST', '/api/v1/auth/login', 200), false)
})
