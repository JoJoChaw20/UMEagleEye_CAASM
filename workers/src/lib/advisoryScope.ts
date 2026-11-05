/**
 * advisoryScope.ts — which advisories a user may see, and keeping an advisory's status in
 * step with its alert.
 *
 * An advisory has no tenant column: it belongs to the tenant of its alert's asset
 * (advisories.event_id → events.asset_id → assets.tenant_id). Every read or write of
 * advisories outside the platform superadmin goes through advisoryInTenant, a subquery,
 * so no list of event ids is ever built in memory.
 */
import { inArray, eq, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { advisories, assets, events } from '../db/schema'

/** Statuses an advisory is still being worked in. */
export const ACTIVE_ADVISORY_STATUSES = ['open', 'acknowledged', 'in_progress'] as const

/** Advisories of one tenant, as a condition on the advisories table. */
export function advisoryInTenant(db: DB, tenantId: string): SQL {
  return inArray(
    advisories.eventId,
    db.select({ id: events.eventId }).from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(eq(assets.tenantId, tenantId)),
  )
}

/** The tenant condition for a user: none for the platform superadmin (all tenants, or the one
 *  they picked), the user's own tenant otherwise. */
export function advisoryScope(db: DB, user: { role: string; tenantId?: string | null }, pickedTenant?: string | null): SQL | undefined {
  const tenantId = user.role === 'superadmin' ? (pickedTenant || null) : (user.tenantId ?? null)
  if (tenantId) return advisoryInTenant(db, tenantId)
  // A non-superadmin with no tenant sees nothing (the auth middleware already refuses them).
  return user.role === 'superadmin' ? undefined : sql`false`
}

/** An advisory id, or the start of one, as a person types it ("3f2a91c0"). Hex and dashes
 *  only: anything else (a % or _ would be a LIKE wildcard) is refused. */
export function advisoryIdPrefix(raw: string): string | null {
  const s = raw.trim().toLowerCase()
  return /^[0-9a-f][0-9a-f-]{3,35}$/.test(s) ? s : null
}

/** Matches an advisory id by prefix. Safe because advisoryIdPrefix allows no wildcards. */
export function advisoryIdStartsWith(prefix: string): SQL {
  return sql`${advisories.advisoryId}::text LIKE ${`${prefix}%`}`
}

/** Advisories whose alert was closed (resolved, false positive, accepted risk) are resolved
 *  too, so the Advisories page never lists work for an alert that is already dealt with.
 *  eventIds limits it to those alerts; without it every tenant (or one) is swept. */
export async function resolveAdvisoriesOfClosedEvents(
  db: DB, scope: { eventIds?: string[]; tenantId?: string | null } = {},
): Promise<number> {
  if (scope.eventIds && scope.eventIds.length === 0) return 0
  const res = await db.execute(resolveClosedSql(scope))
  return res.rows.length
}

export function resolveClosedSql(scope: { eventIds?: string[]; tenantId?: string | null }): SQL {
  const parts = [sql`true`]
  if (scope.eventIds) parts.push(sql`e.event_id IN ${scope.eventIds}`)
  if (scope.tenantId) parts.push(sql`EXISTS (SELECT 1 FROM assets a WHERE a.asset_id = e.asset_id AND a.tenant_id = ${scope.tenantId})`)
  return sql`
    UPDATE advisories adv SET status = 'resolved', resolved_at = now()
    FROM events e
    WHERE e.event_id = adv.event_id
      AND adv.status IN ('open', 'acknowledged', 'in_progress')
      AND e.status IN ('resolved', 'false_positive', 'accepted_risk')
      AND ${sql.join(parts, sql` AND `)}
    RETURNING 1
  `
}

/** The live (not resolved) advisories of one alert. */
export function liveAdvisoryOf(eventId: string): SQL {
  return sql`${advisories.eventId} = ${eventId} AND ${advisories.status} IN ('open', 'acknowledged', 'in_progress')`
}

/** Inserts an advisory for an alert only if it has no live one, in one statement, so two
 *  jobs for the same alert do not both add one. Returns advisory_id, or no row. */
export function insertAdvisoryIfNoneSql(eventId: string, summary: string, recommendedAction: string): SQL {
  return sql`
    INSERT INTO advisories (event_id, summary, recommended_action, status)
    SELECT ${eventId}::uuid, ${summary}::text, ${recommendedAction}::text, 'open'::advisory_status
    WHERE NOT EXISTS (SELECT 1 FROM advisories WHERE ${liveAdvisoryOf(eventId)})
    RETURNING advisory_id
  `
}
