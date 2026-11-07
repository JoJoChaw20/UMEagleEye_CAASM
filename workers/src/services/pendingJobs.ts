// The jobs waiting for an agent (dashboard scans, inventory and SBOM requests), after
// failing those it never picked up or never finished. Served by GET /scans/pending and,
// for agents 2.5.0+, in the heartbeat answer (one request every 30 s instead of two).

import { and, eq, sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { scanResults } from '../db/schema'
import {
  INVESTIGATE_EXPIRE_HOURS, INVESTIGATE_TRIGGER, isInvestigation, recordInvestigationFailure,
} from './autoInvestigate'

type Db = ReturnType<typeof getDb>

// Active scans (New scan, new-device investigations) that no agent picked up within
// ACTIVE_EXPIRE_HOURS fail with a reason instead of staying 'pending' for ever (the agent
// was offline or closed). Runs when an agent polls and when the dashboard lists scans.
const ACTIVE_EXPIRE_HOURS = INVESTIGATE_EXPIRE_HOURS
export async function expireStaleActiveScans(db: Db, scope: SQL | undefined): Promise<void> {
  const expired = await db.update(scanResults)
    .set({
      status: 'failed', completedAt: new Date(),
      failureReason: sql`CASE WHEN ${scanResults.networkInfo}->>'trigger' = ${INVESTIGATE_TRIGGER}
        THEN ${`The agent did not pick up this new-device scan within ${ACTIVE_EXPIRE_HOURS} hours`}
        ELSE ${`The agent did not pick up this scan within ${ACTIVE_EXPIRE_HOURS} hours (it was offline or closed)`} END`,
    })
    .where(and(
      scope,
      eq(scanResults.scanType, 'active'),
      eq(scanResults.status, 'pending'),
      sql`${scanResults.startedAt} < now() - make_interval(hours => ${ACTIVE_EXPIRE_HOURS})`,
    ))
    .returning({ scanId: scanResults.scanId, networkInfo: scanResults.networkInfo, failureReason: scanResults.failureReason })
  for (const row of expired) {
    if (isInvestigation(row.networkInfo)) await recordInvestigationFailure(db, row.networkInfo, row.scanId, row.failureReason ?? 'expired')
  }
}

/** Up to 5 jobs this agent should run now (rows of scan_results). */
export async function pendingJobsFor(db: Db, agentId: string) {
  // Auto-expire passive scans pending > 10 min
  await db.update(scanResults)
    .set({
      status: 'failed',
      completedAt: new Date(),
      failureReason: 'Passive scan was not picked up by the agent within 10 minutes',
    })
    .where(and(
      eq(scanResults.agentId, agentId),
      eq(scanResults.status, 'pending'),
      eq(scanResults.scanType, 'passive'),
      sql`${scanResults.startedAt} < now() - interval '10 minutes'`,
    ))

  // Auto-expire SBOM scans the agent never picked up (pending > 90 min) or never finished
  // (running > 3 h). A full run (agent 2.2.6) may list for 90 minutes of awake time, Grype
  // takes up to 20 (its first run downloads its database), the upload retries for a few
  // minutes, and a laptop asleep in between adds to the clock time. If the agent died
  // without calling /fail, clean up here. A late SBOM still completes the record.
  await db.update(scanResults)
    .set({
      status: 'failed',
      completedAt: new Date(),
      failureReason: sql`CASE WHEN ${scanResults.status} = 'pending'
        THEN 'The agent did not pick up this SBOM job within 90 minutes (it was offline or closed)'
        ELSE 'SBOM scan did not finish within 3 hours (the agent was closed or stuck)' END`,
    })
    .where(and(
      eq(scanResults.agentId, agentId),
      eq(scanResults.scanType, 'sbom'),
      sql`((${scanResults.status} = 'pending' AND ${scanResults.startedAt} < now() - interval '90 minutes')
        OR (${scanResults.status} = 'running' AND ${scanResults.startedAt} < now() - interval '3 hours'))`,
    ))

  // Inventory jobs: a few seconds of work, so give up sooner than SBOM jobs.
  await db.update(scanResults)
    .set({
      status: 'failed',
      completedAt: new Date(),
      failureReason: sql`CASE WHEN ${scanResults.status} = 'pending'
        THEN 'The agent did not pick up this inventory job within 30 minutes (it was offline, closed or older than 2.3.0)'
        ELSE 'The inventory did not arrive within 15 minutes' END`,
    })
    .where(and(
      eq(scanResults.agentId, agentId),
      eq(scanResults.scanType, 'inventory'),
      sql`((${scanResults.status} = 'pending' AND ${scanResults.startedAt} < now() - interval '30 minutes')
        OR (${scanResults.status} = 'running' AND ${scanResults.startedAt} < now() - interval '15 minutes'))`,
    ))

  await expireStaleActiveScans(db, eq(scanResults.agentId, agentId))

  const pending = await db
    .select()
    .from(scanResults)
    .where(and(
      eq(scanResults.agentId, agentId),
      eq(scanResults.status, 'pending'),
      // A new-device investigation waits a few minutes before it is handed out
      sql`(${scanResults.networkInfo}->>'not_before' IS NULL
        OR (${scanResults.networkInfo}->>'not_before')::timestamptz <= now())`,
      // Skip SBOM and inventory jobs whose asset (stored in subnet) no longer exists
      sql`(${scanResults.scanType} NOT IN ('sbom', 'inventory') OR EXISTS (
        SELECT 1 FROM assets WHERE asset_id::text = ${scanResults.subnet}
      ))`,
    ))
    .limit(5)
  return pending
}
