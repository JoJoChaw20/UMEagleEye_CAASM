import { sql } from 'drizzle-orm'
import type { getDb } from '../db/client'

type DB = ReturnType<typeof getDb>

// Retention windows. Deletes are batched so one run never holds a long lock or exceeds
// the free-tier request budget; anything left over is picked up by the next daily run.
const CTI_MAX_AGE_DAYS = 90
const EVENT_MAX_AGE_DAYS = 365
const BATCH_SIZE = 5000
const MAX_BATCHES = 6   // per table, per run

/**
 * Delete CTI indicators not re-seen by any feed within CTI_MAX_AGE_DAYS (feeds refresh
 * last_seen on every re-ingest) and not referenced by an event.
 */
async function purgeStaleCti(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM cti_indicators
    WHERE indicator_id IN (
      SELECT c.indicator_id FROM cti_indicators c
      WHERE c.last_seen < now() - make_interval(days => ${CTI_MAX_AGE_DAYS})
        AND NOT EXISTS (SELECT 1 FROM event_cti_indicators e WHERE e.indicator_id = c.indicator_id)
      LIMIT ${BATCH_SIZE}
    )
    RETURNING 1
  `)
  return res.rows.length
}

/** Delete closed events (resolved / false positive) older than EVENT_MAX_AGE_DAYS. Open ones are never touched. */
async function purgeClosedEvents(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM events
    WHERE event_id IN (
      SELECT event_id FROM events
      WHERE status IN ('resolved', 'false_positive')
        AND updated_at < now() - make_interval(days => ${EVENT_MAX_AGE_DAYS})
      LIMIT ${BATCH_SIZE}
    )
    RETURNING 1
  `)
  return res.rows.length
}

/** Run a batched purge until a batch comes back short or MAX_BATCHES is reached. */
async function drain(purge: (db: DB) => Promise<number>, db: DB): Promise<number> {
  let total = 0
  for (let i = 0; i < MAX_BATCHES; i++) {
    const n = await purge(db)
    total += n
    if (n < BATCH_SIZE) break
  }
  return total
}

export async function purgeOldData(db: DB): Promise<{ cti: number; events: number }> {
  const cti = await drain(purgeStaleCti, db)
  const events = await drain(purgeClosedEvents, db)
  return { cti, events }
}
