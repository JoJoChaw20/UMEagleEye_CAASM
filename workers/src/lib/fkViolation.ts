// True when a Postgres error is a foreign key violation (23503). Neon and Drizzle wrap the
// driver error differently, so check the error, its cause, then the message.
export function isFkViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  const e = err as { code?: unknown; cause?: { code?: unknown }; message?: unknown }
  if (e.code === '23503' || e.cause?.code === '23503') return true
  return typeof e.message === 'string' && /violates foreign key constraint|23503/i.test(e.message)
}
