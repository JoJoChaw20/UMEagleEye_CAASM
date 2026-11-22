import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sendMail } from './mailer'
import type { Env } from '../types'

const msg = { to: 'a@example.com', subject: 'Hi', text: 'Body' }
const env = (extra: Partial<Env>) => extra as Env

test('sendMail without binding returns sent:false and does not throw', async () => {
  assert.deepEqual(await sendMail(env({}), msg), { sent: false })
  assert.deepEqual(await sendMail(env({ MAIL_FROM: 'no-reply@example.com' }), msg), { sent: false })
  assert.deepEqual(await sendMail(env({ EMAIL: { send: async () => ({}) } }), msg), { sent: false })
})

test('sendMail with a fake binding passes to/from/subject/text', async () => {
  const sent: unknown[] = []
  const r = await sendMail(env({ EMAIL: { send: async (m) => { sent.push(m) } }, MAIL_FROM: 'no-reply@example.com' }), msg)
  assert.deepEqual(r, { sent: true })
  assert.deepEqual(sent, [{ to: 'a@example.com', from: { email: 'no-reply@example.com', name: 'UMEagleEye' }, subject: 'Hi', text: 'Body' }])
})

test('an account with no email: nothing is sent', async () => {
  const sent: unknown[] = []
  const configured = env({ EMAIL: { send: async (m) => { sent.push(m) } }, MAIL_FROM: 'no-reply@example.com' })
  assert.deepEqual(await sendMail(configured, { ...msg, to: null }), { sent: false })
  assert.deepEqual(await sendMail(configured, { ...msg, to: undefined }), { sent: false })
  assert.deepEqual(sent, [])
})

test('binding that throws gives sent:false', async () => {
  const r = await sendMail(env({ EMAIL: { send: async () => { throw new Error('boom') } }, MAIL_FROM: 'x@example.com' }), msg)
  assert.deepEqual(r, { sent: false })
})
