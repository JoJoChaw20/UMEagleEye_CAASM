import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldSignalKg, signalKgSync } from './sync'
import type { Env } from '../types'

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

function signalEnv() {
  const kv = new Map<string, string>()
  const sent: unknown[] = []
  const env = {
    KV_CACHE: { get: async (k: string) => kv.get(k) ?? null, put: async (k: string, v: string) => { kv.set(k, v) } },
    ADVISORY_QUEUE: { send: async (m: unknown) => { sent.push(m) } },
  } as unknown as Env
  return { env, sent }
}

test('writes inside a debounce window send one message; an agent has its own window', async () => {
  const { env, sent } = signalEnv()
  await signalKgSync(env, true)
  await signalKgSync(env, true)
  assert.equal(sent.length, 1, 'the second agent upload waits for the 30-minute window')
  await signalKgSync(env)
  assert.equal(sent.length, 2, 'a dashboard write is not held up by the agent window')
  await signalKgSync(env)
  assert.equal(sent.length, 2)
})
