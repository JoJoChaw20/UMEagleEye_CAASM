// Install codes (routes/enrolment.ts): one code that lets many computers each register an
// agent of their own. PURE: no database; tested by enrolment.test.ts.

export type TokenState = 'active' | 'expired' | 'revoked' | 'used_up'

export interface TokenFacts { expiresAt: Date; revokedAt: Date | null; maxUses: number | null; uses: number }

export function tokenState(t: TokenFacts, now: Date = new Date()): TokenState {
  if (t.revokedAt) return 'revoked'
  if (t.expiresAt.getTime() <= now.getTime()) return 'expired'
  if (t.maxUses !== null && t.uses >= t.maxUses) return 'used_up'
  return 'active'
}

export const REFUSAL: Record<Exclude<TokenState, 'active'>, string> = {
  expired: 'This install code has expired. Ask your administrator for a new one (Agents page, Install codes).',
  revoked: 'This install code was withdrawn. Ask your administrator for a new one (Agents page, Install codes).',
  used_up: 'This install code has been used as many times as allowed. Ask your administrator for a new one.',
}

/** The name the new agent gets: the computer's name as it sent it, kept printable and short. */
export function agentName(raw: unknown): string {
  const text = typeof raw === 'string' ? raw.replace(/[\u0000-\u001f\u007f]/g, '').trim() : ''
  return (text || 'New agent').slice(0, 100)
}
