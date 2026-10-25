import { sql } from 'drizzle-orm'
import type { DB } from '../db/client'

// Closes alerts whose reason is gone but that no scan or audit would ever close on its
// own. Runs nightly (cron posture-snapshot), with the manual drift audit (tenant-scoped),
// and for new-device alerts right after an asset is reviewed (assets PATCH).

// A device first found by a scan and not seen again for this long was transient
// (a visitor's phone, a one-off scan of another network).
export const NEW_DEVICE_UNSEEN_DAYS = 14

interface Scope { tenantId?: string | null; assetIds?: string[] }

function scopeSql(s: Scope) {
  const parts = [sql`true`]
  if (s.tenantId) parts.push(sql`a.tenant_id = ${s.tenantId}`)
  if (s.assetIds) parts.push(s.assetIds.length ? sql`a.asset_id IN ${s.assetIds}` : sql`false`)
  return sql.join(parts, sql` AND `)
}

/** CVE alerts on an asset that has no SBOM: the SBOM was deleted, or the alerts came from
 *  the retired pipeline (before agent 2.1.0, which never wrote package_type). With no SBOM
 *  no scan can ever confirm or clear them. The asset's next SBOM raises current ones again. */
export async function closeOrphanCveAlerts(db: DB, s: Scope = {}): Promise<number> {
  const res = await db.execute(sql`
    UPDATE events e SET status = 'resolved', resolved_at = now(), updated_at = now(),
      resolution_note = CASE WHEN e.details ? 'package_type'
        THEN 'Auto-resolved: the asset has no SBOM any more, so this CVE can no longer be checked'
        ELSE 'Auto-resolved: raised by the retired SBOM pipeline (before agent 2.1.0); the asset has no current SBOM' END
    FROM assets a
    WHERE a.asset_id = e.asset_id AND ${scopeSql(s)}
      AND e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress')
      AND NOT EXISTS (SELECT 1 FROM sboms sb WHERE sb.asset_id = e.asset_id)
    RETURNING 1
  `)
  return res.rows.length
}

/** Open new-device alerts whose device has been dealt with: added to My Assets, given an
 *  owner, running an EagleEye agent (it reports its own inventory, so it is known), or not
 *  seen for NEW_DEVICE_UNSEEN_DAYS. Alerts someone is working on (in_progress) are left alone. */
export async function closeReviewedNewDevices(db: DB, s: Scope = {}): Promise<number> {
  const res = await db.execute(sql`
    UPDATE events e SET status = 'resolved', resolved_at = now(), updated_at = now(),
      resolution_note = CASE
        WHEN a.in_my_assets THEN 'Auto-resolved: the device was added to My Assets'
        WHEN NULLIF(trim(a.owner), '') IS NOT NULL THEN 'Auto-resolved: the device was given an owner'
        WHEN EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = a.asset_id)
          THEN 'Auto-resolved: this computer runs an EagleEye agent'
        ELSE ${`Auto-resolved: the device has not been seen for ${NEW_DEVICE_UNSEEN_DAYS} days`} END
    FROM assets a
    WHERE a.asset_id = e.asset_id AND ${scopeSql(s)}
      AND e.event_type = 'new_device' AND e.status = 'open'
      AND (a.in_my_assets OR NULLIF(trim(a.owner), '') IS NOT NULL
           OR EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = a.asset_id)
           OR COALESCE(a.last_scanned, a.created_at) < now() - make_interval(days => ${NEW_DEVICE_UNSEEN_DAYS}))
    RETURNING 1
  `)
  return res.rows.length
}

export async function runAlertHygiene(db: DB, s: Scope = {}): Promise<{ cve: number; newDevices: number }> {
  const cve = await closeOrphanCveAlerts(db, s)
  const newDevices = await closeReviewedNewDevices(db, s)
  return { cve, newDevices }
}
