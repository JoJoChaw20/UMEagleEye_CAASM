import { refreshRelationships } from '../services/relationshipRefresh'
import type { Env } from '../types'
import { getDb } from '../db/client'
import { runDriftAudit } from '../services/drift'
import { savePostureSnapshot } from '../services/posture'
import { purgeOldData } from '../services/retention'
import { CTI_INGEST_LOCK } from '../services/cti'
import { runAlertHygiene } from '../services/alertHygiene'
import { rescoreAssets } from '../lib/rescore'
import { refreshTenantBaselines } from '../services/securityBaseline'
import { refreshCveAlertScores } from '../services/alertScores'
import { runKgSyncJob, signalKgSyncSafe } from '../kg/sync'
import { kgQuery } from '../kg/store'
import { recordJob, refreshPerf, timedJob } from '../kg/perf'
import { refreshPlatformProblems } from '../kg/problems'
import { tenants } from '../db/schema'
import { recordWeeks } from '../services/weekly'
import { isoWeek } from '../lib/weekly'

// Maps cron expression to handler name for logging
function getCronName(cron: string): string {
  const names: Record<string, string> = {
    '0 */6 * * *':  'drift-audit',
    '0 22 * * *':   'cti-ingestion',
    '0 16 * * *':   'posture-snapshot',
  }
  return names[cron] ?? cron
}

// One nightly step: its own failure no longer stops the steps after it (they all sat in one try,
// so a failed snapshot silently skipped cleanup and alert tidy-up every night). Each step's last
// result is kept in KV (cron:last:<step>, 30 days) for whoever needs to know it ran.
async function step(env: Env, name: string, run: () => Promise<string>): Promise<void> {
  const at = new Date().toISOString()
  const started = Date.now()
  try {
    const summary = await run()
    recordJob(env, name, Date.now() - started, true)
    console.log(`[${name}] ${summary}`)
    await env.KV_CACHE.put(`cron:last:${name}`, JSON.stringify({ ok: true, at, summary }), { expirationTtl: 30 * 86400 }).catch(() => {})
  } catch (err) {
    recordJob(env, name, Date.now() - started, false)
    console.error(`[${name}] failed:`, err)
    await env.KV_CACHE.put(`cron:last:${name}`, JSON.stringify({ ok: false, at, error: String(err).slice(0, 500) }), { expirationTtl: 30 * 86400 }).catch(() => {})
  }
}

export async function handleCron(controller: ScheduledController, env: Env): Promise<void> {
  const db = getDb(env.DATABASE_URL)
  const name = getCronName(controller.cron)
  console.log(`[cron] Running: ${name} (${controller.cron})`)

  try {
    switch (name) {
      case 'drift-audit': {
        try {
          const count = await timedJob(env, 'drift-audit', () => runDriftAudit(db))
          console.log(`[drift-audit] Generated ${count} drift events`)
          if (count > 0) await signalKgSyncSafe(env)
        } finally {
          // Applies what the knowledge graph still has outstanding; its own failure stops nothing.
          await step(env, 'kg-sync', async () => { await runKgSyncJob(env); return 'Graph sync run' })
          // Pulls the speed history into the graph and refreshes the platform problems; isolated like the rest.
          await step(env, 'perf-refresh', async () => {
            const q = kgQuery(env)
            const r = await refreshPerf(q, env)
            await refreshPlatformProblems(q, env)
            return r.ok ? `${r.windows} performance window(s) stored` : `Performance history not pulled (${r.reason})`
          })
        }
        break
      }

      case 'cti-ingestion': {
        // Queued like "Update feeds now": one feed per queue job (services/cti.ts
        // runIngestStep), since all of them in this run exceed the CPU limit.
        await env.KV_CACHE.put(CTI_INGEST_LOCK, '1', { expirationTtl: 3600 })
        await env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: 'schedule' })
        console.log('[cti-ingestion] CTI feed ingestion queued')
        break
      }

      case 'posture-snapshot': {
        const tenantIds = (await db.select({ tenantId: tenants.tenantId }).from(tenants)).map((t) => t.tenantId)
        // The platform-wide snapshot, and one per tenant: tenant reports read their own trend,
        // which only the manual "Save snapshot" wrote before.
        await step(env, 'posture-snapshot', async () => {
          await savePostureSnapshot(db)
          for (const id of tenantIds) await savePostureSnapshot(db, id)
          return `Posture snapshot saved (platform and ${tenantIds.length} tenant(s))`
        })
        await step(env, 'retention', async () => {
          const purged = await purgeOldData(db)
          return `Purged ${purged.cti} stale CTI indicators, ${purged.events} closed events, ${purged.scans} old scan records, ${purged.findings} long-fixed CVE findings`
        })
        await step(env, 'alert-hygiene', async () => {
          const closed = await runAlertHygiene(db)
          return `Closed ${closed.cve} CVE alerts without an SBOM, ${closed.newDevices} reviewed or stale new-device alerts; resolved ${closed.advisories} advisories of closed alerts`
        })
        // Criticality is recomputed on every scan, inventory and edit; this applies a
        // scoring-rule change to assets nothing has touched since (manual ones, say).
        // One read per tenant, writes only for scores that moved.
        // Then CVE alerts are rescored with the criticality their asset has now, also
        // catching changes made by scans since the alert's last SBOM upload.
        await step(env, 'rescore', async () => {
          let changed = 0, alerts = 0
          for (const id of tenantIds) {
            changed += (await rescoreAssets(db, id)).scoresChanged
            alerts += await refreshCveAlertScores(db, { tenantId: id })
          }
          return `${changed} criticality score(s) changed, ${alerts} CVE alert risk score(s) updated`
        })
        // Security baseline (services/securityBaseline.ts): re-judged from each computer's stored
        // inventory ("OS still supported" depends on today's date), then the Below baseline alerts.
        await step(env, 'security-baseline', async () => {
          let changed = 0, opened = 0, resolved = 0
          for (const id of tenantIds) {
            const r = await refreshTenantBaselines(db, id)
            changed += r.changed; opened += r.opened; resolved += r.resolved
          }
          return `${changed} baseline(s) changed, ${opened} alert(s) opened, ${resolved} resolved`
        })
        // Weekly history (services/weekly.ts): the week that just ended (Monday), and any missing before
        // it; each tenant's Weekly Summary report for a week just ended is queued (the report queue).
        await step(env, 'weekly-history', async () => {
          const r = await recordWeeks(db)
          for (const w of r.live) {
            const name = `weekly_${isoWeek(w.weekStart)}_${w.tenantId.slice(0, 8)}.pdf`
            await env.ADVISORY_QUEUE.send({ type: 'report', reportType: 'weekly', filename: name, r2Key: name,
              requestedBy: 'schedule', tenantId: w.tenantId })
          }
          return `${r.weeks} week(s) recorded for ${r.tenants} tenant(s); ${r.live.length} weekly report(s) queued`
        })
        // Safety net for the relationships (they are also rebuilt when devices come or go).
        await step(env, 'relationships', async () => {
          let made = 0
          for (const id of tenantIds) made += (await refreshRelationships(env, id))?.relationships ?? 0
          return `${made} relationship(s) worked out for ${tenantIds.length} tenant(s)`
        })
        break
      }

    }
  } catch (err) {
    console.error(`[cron] ${name} failed:`, err)
  }
}
