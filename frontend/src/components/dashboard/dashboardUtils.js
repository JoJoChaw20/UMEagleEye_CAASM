const isDirectThreatIntel = (item) => {
  const details = item.details ?? {}
  if (item.event_type === 'cti_match') return details.match_kind !== 'watchlist'
  return item.event_type !== 'cve_detected' && Boolean(details.has_cti_match)
}

// The tier of backend lib/alertRank.ts, read from the priority number ((5 - tier) x 1000 + score)
const TIER_IDS = { 1: { id: 'T1', label: 'Compromise', tone: 'critical' }, 2: { id: 'T2', label: 'Exploited', tone: 'critical' },
  3: { id: 'T3', label: 'Fix', tone: 'high' }, 4: { id: 'T4', label: 'Review', tone: 'routine' } }

export function operationalTier(item) {
  const t = item.tier ?? 5 - Math.floor(Number(item.priority_score ?? 0) / 1000)
  return TIER_IDS[t] ?? TIER_IDS[4]
}

// SBOM alerts are one per vulnerable package (its CVEs inside), so they arrive with the
// other alerts and need no grouping here.
export function buildPriorityActions(alerts = [], limit = 5) {
  const actions = alerts.map(item => ({ ...item, key: `event:${item.event_id}`, kind: 'event' }))

  return actions
    .sort((a, b) => {
      const scoreDiff = Number(b.priority_score ?? 0) - Number(a.priority_score ?? 0)
      if (scoreDiff) return scoreDiff
      const timeDiff = new Date(a.first_seen ?? 0).getTime() - new Date(b.first_seen ?? 0).getTime()
      if (timeDiff) return timeDiff
      return String(a.key).localeCompare(String(b.key))
    })
    .slice(0, limit)
}

export function priorityContext(item) {
  const d = item.details ?? {}
  const context = []
  if (isDirectThreatIntel(item)) context.push('Threat-intel match · possible compromise')
  else if (item.event_type === 'cve_detected' && d.has_cti_match) context.push('CVE named by threat intelligence')
  if (d.kev) context.push(d.kev_count > 1 ? `${d.kev_count} exploited (KEV / MyCERT)` : 'exploited (KEV / MyCERT)')
  if (d.exploited) context.push('Known exploited')
  // a package alert keeps its worst CVE's values as max_epss / max_cvss
  const epss = d.max_epss ?? d.epss_score
  const cvss = d.max_cvss ?? d.cvss_base_score
  if (epss >= 0.1) context.push(`EPSS ${Math.round(epss * 100)}%`)
  if (cvss != null) context.push(`CVSS ${cvss}`)
  if (item.asset?.internet_facing) context.push('Internet-facing')
  if ((item.asset?.criticality ?? 0) >= 8) context.push(`Criticality ${item.asset.criticality}/10`)
  if (d.cve_count > 1) context.push(`${d.cve_count} CVEs in this package`)
  return context.slice(0, 4)
}

export function dashboardAssetTotal(deviceMix) {
  if (!deviceMix || typeof deviceMix !== 'object') return null
  return Object.values(deviceMix).reduce((total, count) => total + (Number(count) || 0), 0)
}

export function historicalScoreChange(history = [], days = 7, now = Date.now()) {
  const valid = history
    .filter(point => Number.isFinite(Number(point.overall_score)) && point.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  if (valid.length < 2) return null
  const target = now - days * 86400000
  const previous = valid.filter(point => new Date(point.timestamp).getTime() <= target).at(-1)
  const current = valid.at(-1)
  return previous ? { previous: Number(previous.overall_score), current: Number(current.overall_score), delta: Number(current.overall_score) - Number(previous.overall_score) } : null
}

// Changes worth a look on the dashboard: a device, port or risky setup that appeared, an OS
// rollback, and a device whose identity or exposure changed. (Upgrades and package changes are
// no longer alerts: workers/src/services/drift.ts.)
const CHANGE_TYPES = new Set(['new_device', 'port_opened', 'exposure', 'version_downgrade'])
const CHANGED_ATTRIBUTES = new Set(['mac_address', 'hostname', 'firmware'])

export function classifyRecentChanges(events = []) {
  return events.filter(event => {
    const details = event.details ?? {}
    if (CHANGE_TYPES.has(event.event_type)) return true
    if (event.event_type !== 'config_change') return false
    if (details.changed_attribute === 'internet_facing') return details.to === true
    return CHANGED_ATTRIBUTES.has(details.changed_attribute)
  }).slice(0, 8)
}

export function dashboardHref(path, params = {}, tenantId = '') {
  const query = new URLSearchParams(params)
  if (tenantId) query.set('tenant_id', tenantId)
  const suffix = query.toString()
  return suffix ? `${path}?${suffix}` : path
}
