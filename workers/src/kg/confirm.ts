/**
 * kg/confirm.ts — the Confirm step: the only way an advisory is closed from the chat.
 *
 * The agent only stores a proposal (a token in KV, tied to user, company and advisory). Here
 * the person's click is checked again on the server: whose token it is, role, company. KV has
 * no atomic "take", so the database is the single-winner guard: one statement closes the
 * advisory only while it is still active and writes the audit record in the same statement.
 * Two requests with one token can therefore never both close it, and a closed advisory never
 * lacks its audit record.
 *
 * The same statement checks the latest scan: while an alert for the same problem on that device
 * is still open, nothing is closed and the person is told the problem is still detected
 * (kg/detection.ts). The audit record keeps when the device was last scanned.
 */
import { ACTIVE_ADVISORY_STATUSES } from '../lib/advisoryScope'
import { ADVISORY_STATUS_ROLES, parseProposal, proposalKey } from './agent'
import { lastSbomColumn, sameProblemOpen, stillDetectedMessage } from './detection'
import type { Q } from './store'

export interface ConfirmKv {
  get(key: string): Promise<string | null>
  delete(key: string): Promise<void>
}
export interface ConfirmUser { userId: string; role: string; tenantId?: string | null }

export type ConfirmResult =
  | { ok: true; advisoryId: string; summary: string }
  | { ok: false; status: 403 | 404 | 409 | 500; error: string }

const GONE = 'This confirmation has expired or was already used. Ask again to get a new one.'

/**
 * Closes the advisory only while it is active, in this company, and no alert for its problem is
 * still open; audits it in the same statement. Returns one row whenever the advisory is in this
 * company: `advisory_id` is set only when it was closed, and `still_detected` says why it was not.
 */
const CLOSE_SQL = `
  WITH target AS (
    SELECT v.advisory_id, v.status::text AS prev_status, e.asset_id, e.event_type, e.details,
           a.hostname, a.ip_address, a.last_scanned, ${lastSbomColumn('a')}
    FROM advisories v
    JOIN events e ON e.event_id = v.event_id
    JOIN assets a ON a.asset_id = e.asset_id
    WHERE v.advisory_id = $1::uuid AND a.tenant_id = $2::uuid
  ), live AS (
    SELECT o.event_id FROM events o JOIN target t ON ${sameProblemOpen('o', 't')}
    LIMIT 1
  ), upd AS (
    UPDATE advisories SET status = 'resolved', resolved_at = now()
    FROM target t
    WHERE advisories.advisory_id = t.advisory_id
      AND advisories.status::text = ANY($4::text[])
      AND NOT EXISTS (SELECT 1 FROM live)
    RETURNING advisories.advisory_id, advisories.summary, t.prev_status AS previous_status
  ), aud AS (
    INSERT INTO audit_logs (user_id, tenant_id, action_type, target_entity, previous_state, new_state)
    SELECT $3::uuid, $2::uuid, 'advisory_status_update', upd.advisory_id::text,
           jsonb_build_object('status', upd.previous_status),
           jsonb_build_object('status', 'resolved', 'via', 'chatbot', 'alert_open', false,
                              'last_scanned', (SELECT last_scanned FROM target), 'last_sbom', (SELECT last_sbom FROM target))
    FROM upd
    RETURNING 1
  )
  SELECT upd.advisory_id, upd.summary, upd.previous_status, (SELECT count(*) FROM aud) AS audited,
         EXISTS (SELECT 1 FROM live) AS still_detected,
         t.hostname, t.ip_address, t.last_scanned, t.last_sbom, t.event_type::text AS alert_type, t.details->>'port' AS port
  FROM target t LEFT JOIN upd ON true`

export async function confirmAdvisory(input: { kv: ConfirmKv; q: Q; user: ConfirmUser; token: string }): Promise<ConfirmResult> {
  const { kv, q, user, token } = input
  const key = proposalKey(token)
  let record
  try { record = parseProposal(await kv.get(key)) } catch { return { ok: false, status: 500, error: 'The confirmation could not be checked. Try again.' } }
  if (!record) return { ok: false, status: 404, error: GONE }
  // Another user's attempt must not burn the owner's token: refuse without deleting it.
  if (record.userId !== user.userId) return { ok: false, status: 403, error: 'This confirmation belongs to another user.' }
  if (!(ADVISORY_STATUS_ROLES as readonly string[]).includes(user.role)) {
    return { ok: false, status: 403, error: 'Only tenant admins can resolve advisories.' }
  }
  if (!user.tenantId || user.tenantId !== record.tenantId) {
    return { ok: false, status: 403, error: 'This advisory is not in your company.' }
  }

  let rows
  try {
    rows = await q(CLOSE_SQL, [record.advisoryId, record.tenantId, user.userId, [...ACTIVE_ADVISORY_STATUSES]])
  } catch (err) {
    // Nothing is known to have changed: the token stays so the person can press Confirm again.
    console.error('[chatbot] confirm failed:', err instanceof Error ? err.message : err)
    return { ok: false, status: 500, error: 'The advisory could not be updated. Try again.' }
  }
  try { await kv.delete(key) } catch (err) { console.error('[chatbot] confirm token cleanup failed:', err instanceof Error ? err.message : err) }
  const row = rows[0]
  if (row && !row.advisory_id && row.still_detected) return { ok: false, status: 409, error: stillDetectedMessage(row) }
  if (!row?.advisory_id) return { ok: false, status: 409, error: 'This advisory was already resolved or is no longer available. Nothing was changed.' }
  return { ok: true, advisoryId: String(row.advisory_id), summary: String(row.summary ?? '') }
}
