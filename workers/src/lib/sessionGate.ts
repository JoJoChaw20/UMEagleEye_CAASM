// Per-request checks on a verified access token and its freshly loaded users row (middleware/auth.ts).
// Pure, so it is tested without a database (sessionGate.test.ts).

export type GateResult = null | { status: 401 | 403; body: { detail: string; mfa_setup_required?: true } }

export const DEACTIVATED_DETAIL = 'Your account is deactivated. Contact your Tenant Superadmin.'

/** Switched off, or its scheduled deactivation time (users.scheduled_deactivation_at) has come. */
export function isDeactivated(
  row: { isActive: boolean | null; scheduledDeactivationAt?: Date | null }, now: Date = new Date(),
): boolean {
  if (!row.isActive) return true
  return !!row.scheduledDeactivationAt && row.scheduledDeactivationAt.getTime() <= now.getTime()
}

export function sessionGate(
  payload: { iat?: number; purpose?: unknown },
  row: { isActive: boolean; mfaEnabled: boolean; sessionsValidAfter: Date | null; scheduledDeactivationAt?: Date | null },
  path: string,
  now: Date = new Date(),
  mfaExempt = false,
): GateResult {
  // An MFA step token (purpose claim) is never an access token.
  if (payload.purpose !== undefined) return { status: 401, body: { detail: 'Token expired or invalid' } }
  if (isDeactivated(row, now)) return { status: 401, body: { detail: DEACTIVATED_DETAIL } }
  if (row.sessionsValidAfter && (payload.iat ?? 0) < Math.floor(row.sessionsValidAfter.getTime() / 1000)) {
    return { status: 401, body: { detail: 'Your session has ended. Sign in again.' } }
  }
  if (!row.mfaEnabled && !mfaExempt && !path.startsWith('/api/v1/auth/')) {
    return { status: 403, body: { detail: 'Set up MFA to continue.', mfa_setup_required: true } }
  }
  return null
}
