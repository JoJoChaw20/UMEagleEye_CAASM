/**
 * Endpoint posture (weakness): how well a machine is protected, from the security
 * checks the agent on it reports. Kept apart from criticality (importance) — fairness
 * rule 2 — and stored on the asset (posture_score, posture_checks).
 *
 * Each check is good (1), warn (0.5), bad (0), or not readable: unknown (not reported)
 * or admin (needs the agent to run as Administrator). Unreadable checks are left out
 * of the score and listed, never counted as passed (rule 1). With too little readable
 * the asset is "unassessed" (score null), not 100.
 *
 * Moved here from the asset page (EndpointSections.jsx) so the page, the dashboard and
 * reports use one definition. Pure; tested by scripts/scoring-v2-demo.ts.
 */

export const POSTURE_MODEL = 1
export type CheckState = 'good' | 'warn' | 'bad' | 'unknown' | 'admin'
export interface PostureCheck {
  id: string
  label: string
  state: CheckState
  weight: number
  detail: string | null
}
export interface PostureResult {
  model: number
  /** 0-100, or null when too few checks could be read. */
  score: number | null
  checks: PostureCheck[]
  /** Weight of the checks that could be read, of the total. */
  assessedWeight: number
  totalWeight: number
}

/** Below this much readable weight (of 105) the asset is unassessed. */
export const MIN_ASSESSED_WEIGHT = 40
export const PATCH_WARN_DAYS = 30
export const PATCH_BAD_DAYS = 60

const VALUE: Record<string, number> = { good: 1, warn: 0.5, bad: 0 }

type Rec = Record<string, unknown>
const rec = (v: unknown): Rec => (v && typeof v === 'object' && !Array.isArray(v) ? v as Rec : {})
const list = (v: unknown): Rec[] => (Array.isArray(v) ? v.filter(x => x && typeof x === 'object') as Rec[] : [])
const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null)
const num = (v: unknown): number | null => (typeof v === 'number' && isFinite(v) ? v : null)

export function evaluatePosture(inventory: unknown): PostureResult {
  const inv = rec(inventory)
  const s = rec(inv['security'])
  const p = rec(inv['patches'])
  const unavailable = new Set((Array.isArray(inv['unavailable']) ? inv['unavailable'] : []).map(String))
  const checks: PostureCheck[] = []
  const push = (id: string, label: string, weight: number, state: CheckState, detail: string | null = null) =>
    checks.push({ id, label, weight, state, detail })

  // Firewall
  const fw = bool(s['firewall_all_enabled'])
  push('firewall', 'Firewall', 15, fw == null ? 'unknown' : fw ? 'good' : 'bad',
    list(s['firewall']).map(f => `${f['profile']} ${f['enabled'] ? 'on' : 'off'}`).join(', ') || null)

  // Antivirus: one enabled and up to date. Unknown freshness is not "up to date".
  const av = list(s['antivirus'])
  const active = av.filter(a => a['enabled'] === true)
  push('antivirus', 'Antivirus', 15,
    !av.length ? 'unknown' : !active.length ? 'bad' : active.every(a => a['up_to_date'] === true) ? 'good' : 'warn',
    av.length ? av.map(a => `${a['name']}${a['enabled'] ? '' : ' (off)'}${a['enabled'] && a['up_to_date'] === false ? ' (out of date)' : ''}`).join(', ') : null)

  // Disk encryption: every reported volume protected (Windows BitLocker, or the
  // platform-neutral disk_encryption list other collectors send).
  const volumes = list(s['disk_encryption'] ?? s['bitlocker'])
  const encReadable = Array.isArray(s['disk_encryption'] ?? s['bitlocker'])
  push('disk_encryption', 'Disk encryption', 15,
    unavailable.has('bitlocker') || unavailable.has('disk_encryption') ? 'admin'
      : !encReadable || !volumes.length ? 'unknown'
        : volumes.every(v => String(v['protection']).toLowerCase() === 'on') ? 'good' : 'bad',
    volumes.length ? volumes.map(v => `${v['drive'] ?? v['volume'] ?? '?'} ${String(v['protection']).toLowerCase()}`).join(', ') : null)

  // Updates: age of the newest installed update; a pending restart means the last
  // updates are not active yet.
  const days = num(p['days_since_last_patch'])
  const pending = bool(p['pending_reboot'])
  let upd: CheckState = days == null ? 'unknown' : days > PATCH_BAD_DAYS ? 'bad' : days > PATCH_WARN_DAYS ? 'warn' : 'good'
  if (upd === 'good' && pending) upd = 'warn'
  push('updates', 'Updates', 20, upd,
    days == null ? null : `last update ${days} day${days === 1 ? '' : 's'} ago${pending ? ', restart pending' : ''}`)

  const uac = bool(s['uac_enabled'])
  push('uac', 'User Account Control', 10, uac == null ? 'unknown' : uac ? 'good' : 'bad')

  const smb1 = bool(s['smb1_enabled'])
  push('smb1', 'SMBv1', 10, unavailable.has('smb1') ? 'admin' : smb1 == null ? 'unknown' : smb1 ? 'bad' : 'good',
    smb1 ? 'Enabled (obsolete, exploitable)' : smb1 === false ? 'Disabled' : null)

  const sb = bool(s['secure_boot'])
  push('secure_boot', 'Secure Boot', 5, sb == null ? 'unknown' : sb ? 'good' : 'warn')

  const tpm = s['tpm'] && typeof s['tpm'] === 'object' ? rec(s['tpm']) : null
  push('tpm', 'TPM', 5, unavailable.has('tpm') ? 'admin' : !tpm ? 'unknown' : tpm['present'] && tpm['ready'] ? 'good' : 'warn',
    tpm ? `${tpm['present'] ? 'present' : 'absent'}${tpm['present'] ? `, ${tpm['ready'] ? 'ready' : 'not ready'}` : ''}` : null)

  const rdp = bool(s['rdp_enabled'])
  push('rdp', 'Remote Desktop', 5, rdp == null ? 'unknown' : rdp ? 'warn' : 'good', rdp ? 'Enabled' : rdp === false ? 'Disabled' : null)

  // Names are only reported when the agent was told to include them; the count always is.
  const names = list(s['local_admins']).map(a => String(a['name']))
  const admins = num(s['local_admin_count']) ?? (names.length || null)
  push('local_admins', 'Local administrators', 5, admins == null ? 'unknown' : admins > 3 ? 'warn' : 'good',
    admins == null ? null : names.length ? names.join(', ') : `${admins} account${admins === 1 ? '' : 's'} (names not collected)`)

  const totalWeight = checks.reduce((n, c) => n + c.weight, 0)
  const readable = checks.filter(c => c.state in VALUE)
  const assessedWeight = readable.reduce((n, c) => n + c.weight, 0)
  const score = assessedWeight >= MIN_ASSESSED_WEIGHT
    ? Math.round(100 * readable.reduce((n, c) => n + c.weight * VALUE[c.state]!, 0) / assessedWeight)
    : null
  return { model: POSTURE_MODEL, score, checks, assessedWeight, totalWeight }
}

/** Columns to store on the asset for an inventory collected at `collectedAt`
 *  (a null inventory clears them). */
export function postureColumns(inventory: unknown | null, collectedAt: Date | null) {
  if (inventory == null) return { postureScore: null, postureModel: null, postureAssessedAt: null, postureChecks: null }
  const r = evaluatePosture(inventory)
  return { postureScore: r.score, postureModel: r.model, postureAssessedAt: collectedAt, postureChecks: r.checks }
}
