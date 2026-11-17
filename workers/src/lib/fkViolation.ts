// True when a Postgres error is a foreign key violation (23503). Neon and Drizzle wrap the
// driver error differently, so check the error, its cause, then the message.
export function isFkViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  const e = err as { code?: unknown; cause?: { code?: unknown }; message?: unknown }
  if (e.code === '23503' || e.cause?.code === '23503') return true
  return typeof e.message === 'string' && /violates foreign key constraint|23503/i.test(e.message)
}

// True when a Postgres error is a unique violation (23505); same shapes as above.
export function isUniqueViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  const e = err as { code?: unknown; cause?: { code?: unknown; message?: unknown }; message?: unknown }
  if (e.code === '23505' || e.cause?.code === '23505') return true
  return typeof e.message === 'string' && /duplicate key value violates unique constraint/i.test(e.message)
}

// True when a Postgres error is a NOT NULL violation (23502); same shapes as above.
export function isNotNullViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  const e = err as { code?: unknown; cause?: { code?: unknown }; message?: unknown }
  if (e.code === '23502' || e.cause?.code === '23502') return true
  return typeof e.message === 'string' && /violates not-null constraint/i.test(e.message)
}

// True when a unique violation (23505) is the one-Tenant-Superadmin-per-tenant index, not a username or email clash.
export function isOwnerIndexViolation(err: unknown): boolean {
  if (!isUniqueViolation(err)) return false
  const e = err as { cause?: { message?: unknown }; message?: unknown }
  return /uq_users_one_tenant_superadmin/.test(String(e.message ?? '') + String(e.cause?.message ?? ''))
}
