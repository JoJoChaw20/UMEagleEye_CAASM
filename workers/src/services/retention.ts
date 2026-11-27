import { sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { pruneUnusedPublicAddresses } from './publicAddresses'
import { RETIRED_SOURCES } from './threatIntel'

type DB = ReturnType<typeof getDb>
const RETIRED = sql.join(RETIRED_SOURCES.map((s) => sql`${s}`), sql`, `)

// Retention windows. Deletes are batched so one run never holds a long lock or exceeds
// the free-tier request budget; anything left over is picked up by the next daily run.
const CTI_MAX_AGE_DAYS = 90
const EVENT_MAX_AGE_DAYS = 365
const SCAN_MAX_AGE_DAYS = 180     // Discovery records and finished jobs (scan_results)
const BATCH_SIZE = 5000
const MAX_BATCHES = 6   // per table, per run

/**
 * Delete feed indicators not re-seen by any feed within CTI_MAX_AGE_DAYS (feeds refresh
 * last_seen on every re-ingest), and every row of a retired feed (RETIRED_SOURCES: they never
 * match again, and were left to age out for 90 days, still counted on the Threat Intel page),
 * unless an alert references it. Attributes of a threat-intel event (ti_event_id set) are never
 * purged: people wrote them (or MyCERT published them), and they go only with their event.
 */
export async function purgeStaleCti(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM cti_indicators
    WHERE indicator_id IN (
      SELECT c.indicator_id FROM cti_indicators c
      WHERE c.ti_event_id IS NULL
        AND (c.last_seen < now() - make_interval(days => ${CTI_MAX_AGE_DAYS}) OR c.source IN (${RETIRED}))
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

/** Delete CVE findings fixed more than EVENT_MAX_AGE_DAYS ago (an open package alert keeps its
 *  present ones; a deleted alert takes its findings with it). */
async function purgeFixedFindings(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM cve_findings
    WHERE finding_id IN (
      SELECT finding_id FROM cve_findings
      WHERE fixed_at < now() - make_interval(days => ${EVENT_MAX_AGE_DAYS})
      LIMIT ${BATCH_SIZE}
    )
    RETURNING 1
  `)
  return res.rows.length
}

/** Delete finished scan records (Discovery log, SBOM and inventory jobs) older than
 *  SCAN_MAX_AGE_DAYS. They were kept forever: each passive upload rewrites its hour's record, so
 *  the table grew without bound. Waiting and running jobs are never touched. */
async function purgeOldScans(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM scan_results
    WHERE scan_id IN (
      SELECT scan_id FROM scan_results
      WHERE status NOT IN ('pending', 'running')
        AND started_at < now() - make_interval(days => ${SCAN_MAX_AGE_DAYS})
      LIMIT ${BATCH_SIZE}
    )
    RETURNING 1
  `)
  return res.rows.length
}

/** Run a batched purge until a batch comes back short or MAX_BATCHES is reached. */
export async function drain(purge: (db: DB) => Promise<number>, db: DB): Promise<number> {
  let total = 0
  for (let i = 0; i < MAX_BATCHES; i++) {
    const n = await purge(db)
    total += n
    if (n < BATCH_SIZE) break
  }
  return total
}

export async function purgeOldData(db: DB): Promise<{ cti: number; events: number; scans: number; findings: number; publicAddresses: number }> {
  const cti = await drain(purgeStaleCti, db)
  const events = await drain(purgeClosedEvents, db)
  const scans = await drain(purgeOldScans, db)
  const findings = await drain(purgeFixedFindings, db)
  const publicAddresses = await pruneUnusedPublicAddresses(db)
  return { cti, events, scans, findings, publicAddresses }
}
