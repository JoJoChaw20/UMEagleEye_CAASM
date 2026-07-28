import { neon } from '@neondatabase/serverless'
import { drizzle } from 'drizzle-orm/neon-http'
import * as schema from './schema'

// Neon is the only application database. Keep this client bound to the
// DATABASE_URL secret so every route, queue, and cron job uses Neon directly.
export function getDb(databaseUrl: string) {
  const sql = neon(databaseUrl)
  return drizzle(sql, { schema })
}

export type DB = ReturnType<typeof getDb>
