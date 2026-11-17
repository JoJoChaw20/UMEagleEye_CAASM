import { authenticator } from 'otplib'
import { SignJWT, jwtVerify } from 'jose'

// Use clones only; never set the global authenticator.options (shared singleton).
const STEP_MS = 30_000
const SKEW_MAX_STEPS = 10
const SKEW_MIN_STEPS = 2

function checkDelta(secret: string, code: string, nowMs: number, window: number): number | null {
  try {
    const delta = authenticator.clone({ window, epoch: nowMs }).checkDelta(code, secret)
    return delta === null || delta === undefined ? null : delta
  } catch {
    return null
  }
}

/** Absolute 30-second step that matched within +-1 step, or null. */
export function matchTotpStep(secret: string, code: string, nowMs: number = Date.now()): number | null {
  const delta = checkDelta(secret, code, nowMs, 1)
  return delta === null ? null : Math.floor(nowMs / STEP_MS) + delta
}

/** Replay guard: a step is accepted only if later than the last used one. */
export function acceptStep(lastStep: number | null, step: number): boolean {
  return lastStep === null || step > lastStep
}

/**
 * For the "phone clock is off" message only; never accepts a code.
 * Returns the signed offset in whole minutes (min magnitude 1) when the code
 * matches 2..10 steps away, else null.
 */
export function clockSkewMinutes(secret: string, code: string, nowMs: number = Date.now()): number | null {
  const delta = checkDelta(secret, code, nowMs, SKEW_MAX_STEPS)
  if (delta === null || Math.abs(delta) < SKEW_MIN_STEPS) return null
  const minutes = Math.max(1, Math.round((Math.abs(delta) * STEP_MS) / 60_000))
  return delta < 0 ? -minutes : minutes
}

// ── Recovery codes ───────────────────────────────────────────────
const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ' // 32 chars, 5 bits each

function randomGroup(n: number): string {
  // 256 % 32 === 0, so masking is unbiased
  const bytes = crypto.getRandomValues(new Uint8Array(n))
  let out = ''
  for (const b of bytes) out += RECOVERY_ALPHABET[b & 31]
  return out
}

export function generateRecoveryCodes(): string[] {
  const codes = new Set<string>()
  while (codes.size < 10) codes.add(`${randomGroup(5)}-${randomGroup(5)}`)
  return [...codes]
}

export function normalizeRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '')
}

export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function hashRecoveryCode(code: string): Promise<string> {
  return sha256Hex(normalizeRecoveryCode(code))
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a)
  const eb = new TextEncoder().encode(b)
  let diff = ea.length ^ eb.length
  const n = Math.max(ea.length, eb.length)
  for (let i = 0; i < n; i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0)
  return diff === 0
}

// ── MFA token ────────────────────────────────────────────────────
export type MfaStage = 'verify' | 'enrol'

export async function createMfaToken(userId: string, stage: MfaStage, secret: string): Promise<string> {
  return new SignJWT({ purpose: 'mfa', stage })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(stage === 'enrol' ? '15m' : '5m')
    .sign(new TextEncoder().encode(secret))
}

export async function verifyMfaToken(
  token: string,
  secret: string,
): Promise<{ sub: string; stage: MfaStage } | null> {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), { algorithms: ['HS256'], requiredClaims: ['exp', 'iat'] })
    if (payload.purpose !== 'mfa') return null
    if (payload.stage !== 'verify' && payload.stage !== 'enrol') return null
    if (typeof payload.sub !== 'string' || !payload.sub) return null
    return { sub: payload.sub, stage: payload.stage }
  } catch {
    return null
  }
}
