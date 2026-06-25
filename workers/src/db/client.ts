import { Pool } from 'pg'
import { drizzle } from 'drizzle-orm/node-postgres'
import * as schema from './schema'

export function getDb(connectionString: string) {
  const pool = new Pool({ connectionString })
  // pg emits 'error' on the underlying socket asynchronously; with no listener,
  // Node's EventEmitter throws and crashes the whole Worker invocation instead
  // of rejecting the query promise being awaited.
  pool.on('error', () => {})
  return drizzle(pool, { schema })
}

export type DB = ReturnType<typeof getDb>
