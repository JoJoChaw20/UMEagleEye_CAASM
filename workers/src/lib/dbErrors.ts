// Telling "the database is not there" from other failures, so the API can answer 503 instead of 500.
// Neon's serverless driver reports a refused or unreachable compute as a NeonDbError whose message
// names the HTTP status ("Server error (HTTP status 402): ...exceeded the quota...") or the connection.

const UNAVAILABLE = /HTTP status (402|5\d\d)|exceeded the quota|couldn't connect to compute node|endpoint is disabled|compute .*suspended|fetch failed|ECONNREFUSED|ETIMEDOUT/i

export function isDatabaseUnavailable(err: unknown): boolean {
  let e: unknown = err
  for (let depth = 0; depth < 4 && e; depth++) {
    if (e instanceof Error || (typeof e === 'object' && e !== null)) {
      const { name, message } = e as { name?: unknown; message?: unknown }
      const text = typeof message === 'string' ? message : ''
      if ((name === 'NeonDbError' || /HTTP status/i.test(text)) && UNAVAILABLE.test(text)) return true
      e = (e as { cause?: unknown }).cause
    } else {
      return false
    }
  }
  return false
}
