// Platform break-glass MFA reset: the pure rules (the routes and the apply step are in
// routes/auth.ts and services/breakGlass.ts).

export const HOLD_HOURS = 24

export interface Eligibility {
  role: string
  active: boolean
  passwordOk: boolean
  secretSet: boolean         // env.PLATFORM_MFA_RESET exists
  secretMatches: boolean     // the supplied secret equals it
  secretUsedBefore: boolean  // its hash is in an earlier row
}

/** A request acts only for an active Platform Superadmin with the right password and a fresh secret. */
export function breakGlassEligible(e: Eligibility): boolean {
  return e.role === 'superadmin' && e.active && e.passwordOk && e.secretSet && e.secretMatches && !e.secretUsedBefore
}

export type BreakGlassStatus = 'requested' | 'confirmed' | 'cancelled' | 'done'
export type BreakGlassAction = 'confirm' | 'cancel' | 'apply'

/** The status a row moves to, or null when the action is not allowed from where it is. */
export function nextState(
  status: string, action: BreakGlassAction, now: Date, effectiveAt: Date | null,
): BreakGlassStatus | null {
  if (action === 'confirm') return status === 'requested' ? 'confirmed' : null
  if (action === 'cancel') return status === 'requested' || status === 'confirmed' ? 'cancelled' : null
  return status === 'confirmed' && effectiveAt !== null && effectiveAt.getTime() <= now.getTime() ? 'done' : null
}
