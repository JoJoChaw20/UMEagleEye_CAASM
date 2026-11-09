import { neon, neonConfig } from '@neondatabase/serverless'
import { drizzle } from 'drizzle-orm/neon-http'
import * as schema from './schema'
import { addDbWait } from '../kg/perf'

// Time spent waiting on the database, added to the request that asked (kg/perf.ts keeps it per
// request). Neon's HTTP driver sends each query with fetch; the time to the response is the wait.
neonConfig.fetchFunction = async (...args: Parameters<typeof fetch>) => {
  const start = performance.now()
  try {
    return await fetch(...args)
  } finally {
    addDbWait(performance.now() - start)
  }
}

// Neon is the only application database. Keep this client bound to the
// DATABASE_URL secret so every route, queue, and cron job uses Neon directly.
export function getDb(databaseUrl: string) {
  const sql = neon(databaseUrl)
  return drizzle(sql, { schema })
}

export type DB = ReturnType<typeof getDb>
