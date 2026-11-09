/**
 * kg/confirm.ts — the Confirm step: the only way an advisory is closed from the chat.
 *
 * The agent only stores a proposal (a token in KV, tied to user, company and advisory). Here
 * the person's click is checked again on the server: whose token it is, role, company. KV has
 * no atomic "take", so the database is the single-winner guard: one statement closes the
 * advisory only while it is still active and writes the audit record in the same statement.
 * Two requests with one token can therefore never both close it, and a closed advisory never
 * lacks its audit record.
 */
import { ACTIVE_ADVISORY_STATUSES } from '../lib/advisoryScope'
import { ADVISORY_STATUS_ROLES, parseProposal, proposalKey } from './agent'
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

/** Closes the advisory only while it is active and in this company; audits it in the same statement. */
const CLOSE_SQL = `
  WITH upd AS (
    UPDATE advisories SET status = 'resolved', resolved_at = now()
    FROM (SELECT status FROM advisories WHERE advisory_id = $1::uuid) prev
    WHERE advisories.advisory_id = $1::uuid
      AND advisories.status::text = ANY($4::text[])
      AND EXISTS (SELECT 1 FROM events e JOIN assets a ON a.asset_id = e.asset_id
                  WHERE e.event_id = advisories.event_id AND a.tenant_id = $2::uuid)
    RETURNING advisories.advisory_id, advisories.summary, prev.status::text AS previous_status
  ), aud AS (
    INSERT INTO audit_logs (user_id, tenant_id, action_type, target_entity, previous_state, new_state)
    SELECT $3::uuid, $2::uuid, 'advisory_status_update', upd.advisory_id::text,
           jsonb_build_object('status', upd.previous_status), '{"status":"resolved","via":"chatbot"}'::jsonb
    FROM upd
    RETURNING 1
  )
  SELECT upd.advisory_id, upd.summary, upd.previous_status, (SELECT count(*) FROM aud) AS audited FROM upd`

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
  if (!row) return { ok: false, status: 409, error: 'This advisory was already resolved or is no longer available. Nothing was changed.' }
  return { ok: true, advisoryId: String(row.advisory_id), summary: String(row.summary ?? '') }
}
