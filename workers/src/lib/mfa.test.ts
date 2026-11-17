import { test } from 'node:test'
import assert from 'node:assert/strict'
import { authenticator } from 'otplib'
import { SignJWT, decodeJwt } from 'jose'
import { createToken } from './auth'
import {
  acceptStep, clockSkewMinutes, createMfaToken, generateRecoveryCodes, hashRecoveryCode,
  matchTotpStep, normalizeRecoveryCode, sha256Hex, timingSafeEqualStr, verifyMfaToken,
} from './mfa'

const SECRET = 'JBSWY3DPEHPK3PXP'
const T0 = 1_700_000_010_000 // fixed time, step boundary irrelevant
const STEP = 30_000
const codeAt = (ms: number, secret = SECRET) =>
  authenticator.clone({ epoch: ms }).generate(secret)

test('matchTotpStep accepts the current, previous and next step and refuses two steps away', () => {
  const cur = Math.floor(T0 / STEP)
  assert.equal(matchTotpStep(SECRET, codeAt(T0), T0), cur)
  assert.equal(matchTotpStep(SECRET, codeAt(T0 - STEP), T0), cur - 1)
  assert.equal(matchTotpStep(SECRET, codeAt(T0 + STEP), T0), cur + 1)
  assert.equal(matchTotpStep(SECRET, codeAt(T0 - 2 * STEP), T0), null)
  assert.equal(matchTotpStep(SECRET, codeAt(T0 + 2 * STEP), T0), null)
})

test('replay of the same step is refused', () => {
  const s = matchTotpStep(SECRET, codeAt(T0), T0) as number
  assert.equal(acceptStep(s, s), false)
  assert.equal(acceptStep(s, s + 1), true)
  assert.equal(acceptStep(null, s), true)
  assert.equal(acceptStep(s, s - 1), false)
})

test('recovery codes: 10, unique, format', () => {
  const codes = generateRecoveryCodes()
  assert.equal(codes.length, 10)
  assert.equal(new Set(codes).size, 10)
  for (const c of codes) assert.match(c, /^[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}$/)
})

test('normalize ignores case, spaces and dashes', () => {
  assert.equal(normalizeRecoveryCode(' abcde-fghjk '), 'ABCDEFGHJK')
  assert.equal(normalizeRecoveryCode('abcde fghjk'), 'ABCDEFGHJK')
})

test('recovery code hash is stable, 64 hex, format-insensitive', async () => {
  const a = await hashRecoveryCode('ABCDE-FGHJK')
  assert.match(a, /^[0-9a-f]{64}$/)
  assert.equal(a, await hashRecoveryCode('abcde fghjk'))
  assert.equal(a, await sha256Hex('ABCDEFGHJK'))
  assert.notEqual(a, await hashRecoveryCode('ABCDE-FGHJL'))
})

test('timingSafeEqualStr', () => {
  assert.equal(timingSafeEqualStr('abc', 'abc'), true)
  assert.equal(timingSafeEqualStr('abc', 'abd'), false)
  assert.equal(timingSafeEqualStr('abc', 'abcd'), false)
})

test('mfa token round-trip; wrong secret, expired, or missing purpose are refused', async () => {
  const t = await createMfaToken('u1', 'verify', 'k1')
  assert.deepEqual(await verifyMfaToken(t, 'k1'), { sub: 'u1', stage: 'verify' })
  assert.equal(await verifyMfaToken(t, 'k2'), null)
  assert.equal(await verifyMfaToken('garbage', 'k1'), null)

  const key = new TextEncoder().encode('k1')
  const expired = await new SignJWT({ purpose: 'mfa', stage: 'verify' })
    .setProtectedHeader({ alg: 'HS256' }).setSubject('u1')
    .setIssuedAt(Math.floor(Date.now() / 1000) - 600)
    .setExpirationTime(Math.floor(Date.now() / 1000) - 300).sign(key)
  assert.equal(await verifyMfaToken(expired, 'k1'), null)

  const noPurpose = await new SignJWT({ stage: 'verify' })
    .setProtectedHeader({ alg: 'HS256' }).setSubject('u1').setIssuedAt()
    .setExpirationTime('5m').sign(key)
  assert.equal(await verifyMfaToken(noPurpose, 'k1'), null)

  const access = await createToken({ sub: 'u1' } as never, 'k1')
  assert.equal(await verifyMfaToken(access, 'k1'), null)

  const badStage = await new SignJWT({ purpose: 'mfa', stage: 'x' })
    .setProtectedHeader({ alg: 'HS256' }).setSubject('u1').setIssuedAt()
    .setExpirationTime('5m').sign(key)
  assert.equal(await verifyMfaToken(badStage, 'k1'), null)
})

test('enrol token lives 15 minutes, verify token 5', async () => {
  const v = decodeJwt(await createMfaToken('u1', 'verify', 'k'))
  const e = decodeJwt(await createMfaToken('u1', 'enrol', 'k'))
  assert.equal(v.exp! - v.iat!, 300)
  assert.equal(e.exp! - e.iat!, 900)
  assert.equal(v.purpose, 'mfa')
  assert.equal(e.stage, 'enrol')
})

test('a secret keeps working months later', () => {
  const later = T0 + 180 * 86_400_000
  assert.equal(matchTotpStep(SECRET, codeAt(later), later), Math.floor(later / STEP))
})

test('clockSkewMinutes reports a phone 3 minutes behind and stays null for a random wrong code', () => {
  assert.equal(clockSkewMinutes(SECRET, codeAt(T0 - 180_000), T0), -3)
  assert.equal(clockSkewMinutes(SECRET, codeAt(T0 + 300_000), T0), 5)
  assert.equal(clockSkewMinutes(SECRET, codeAt(T0 - 2 * STEP), T0), -1)
  assert.equal(clockSkewMinutes(SECRET, codeAt(T0), T0), null) // in window, not skew
  assert.equal(clockSkewMinutes(SECRET, codeAt(T0 - 20 * STEP), T0), null)
  // a code not in the +-10 step range for this secret
  const near = new Set<string>()
  for (let d = -10; d <= 10; d++) near.add(codeAt(T0 + d * STEP))
  let wrong = '000000'
  for (let i = 0; near.has(wrong); i++) wrong = String(100000 + i)
  assert.equal(clockSkewMinutes(SECRET, wrong, T0), null)
})
