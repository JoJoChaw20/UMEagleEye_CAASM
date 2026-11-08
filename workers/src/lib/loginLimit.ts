// Failed sign-in attempts, counted in KV (KV_CACHE) per window: per account and per address for
// passwords, per account for MFA codes. Over the limit, sign-in is refused until the window ends,
// even with the right password or code. Only failures count; a success clears the account's
// password count. KV is eventually consistent, so a burst can pass a few extra tries; the point is
// that guessing a password or a 6-digit code (10^6) at scale is no longer possible.

export const WINDOW_SECONDS = 15 * 60
export const LIMITS = {
  password_account: 10,       // wrong passwords for one username
  password_address: 30,       // wrong passwords from one address, any username
  mfa_account: 5,             // wrong MFA codes for one account
} as const
export type LimitKind = keyof typeof LIMITS

interface Kv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<void>
}

const window = (now: number) => Math.floor(now / 1000 / WINDOW_SECONDS)
export const limitKey = (kind: LimitKind, who: string, now = Date.now()) =>
  `rl:login:${kind}:${who.toLowerCase()}:${window(now)}`

/** Whether `who` has used up its failures of this kind in the current window. */
export async function overLimit(kv: Kv, kind: LimitKind, who: string, now = Date.now()): Promise<boolean> {
  try {
    return Number((await kv.get(limitKey(kind, who, now))) ?? 0) >= LIMITS[kind]
  } catch { return false }     // a cache problem never blocks sign-in
}

export async function recordFailure(kv: Kv, kind: LimitKind, who: string, now = Date.now()): Promise<void> {
  const key = limitKey(kind, who, now)
  try {
    const used = Number((await kv.get(key)) ?? 0)
    await kv.put(key, String(used + 1), { expirationTtl: WINDOW_SECONDS * 2 })
  } catch { /* ignore */ }
}

export async function clearFailures(kv: Kv, kind: LimitKind, who: string, now = Date.now()): Promise<void> {
  try { await kv.delete(limitKey(kind, who, now)) } catch { /* ignore */ }
}

export const TOO_MANY = 'Too many failed attempts. Try again in 15 minutes.'
