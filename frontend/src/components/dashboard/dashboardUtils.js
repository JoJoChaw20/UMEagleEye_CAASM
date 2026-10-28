const isDirectThreatIntel = (item) => {
  const details = item.details ?? {}
  if (item.event_type === 'cti_match') return details.match_kind !== 'watchlist'
  return item.event_type !== 'cve_detected' && Boolean(details.has_cti_match)
}

export function operationalTier(item) {
  if (isDirectThreatIntel(item)) return { id: 'P0', label: 'Investigate', tone: 'critical' }
  const score = Number(item.priority_score ?? 0)
  if (score >= 100) return { id: 'P1', label: 'Urgent', tone: 'critical' }
  if (score >= 75) return { id: 'P2', label: 'High', tone: 'high' }
  return { id: 'P3', label: 'Routine', tone: 'routine' }
}

function cveGroupAction(group) {
  const cves = Number(group.cves ?? 0)
  const asset = {
    asset_id: group.asset_id,
    hostname: group.asset_hostname,
    ip: group.asset_ip,
    owner: group.asset_owner,
    device_type: group.asset_device_type,
    criticality: group.asset_criticality,
    internet_facing: group.asset_internet_facing,
  }
  const topCve = group.top_cves?.[0]
  const severity = group.severity ?? (group.by_severity?.critical ? 'critical' : group.by_severity?.high ? 'high' : 'medium')
  const details = {
    cve_id: topCve,
    kev: Number(group.kev ?? 0) > 0,
    has_cti_match: Number(group.threat_intel ?? 0) > 0,
    epss_score: group.max_epss,
    cvss_base_score: group.max_cvss,
    package_name: group.package_name,
    fix_versions: group.fix_to ? [group.fix_to] : [],
  }
  return {
    key: `cve:${group.asset_id}:${group.package_name}:${group.package_version ?? ''}`,
    kind: 'cve_group',
    event_type: 'cve_detected',
    severity,
    details,
    priority_score: Number(group.priority_score ?? 0),
    first_seen: group.first_seen,
    asset,
    assignee: group.assignees?.[0] ?? null,
    assignees: group.assignees ?? [],
    cve_count: cves,
    fix_to: group.fix_to,
    no_fix: group.no_fix,
    top_cves: group.top_cves ?? [],
    recommended_action: group.fix_to
      ? `Upgrade ${group.package_name} to ${group.fix_to}; this fix group covers ${cves} CVE${cves === 1 ? '' : 's'}.`
      : `Review ${cves} CVE${cves === 1 ? '' : 's'} affecting ${group.package_name}; no fix target is available yet.`,
  }
}

export function buildPriorityActions(alerts = [], groups = [], limit = 5) {
  const actions = alerts
    .filter(item => groups.length === 0 || item.event_type !== 'cve_detected')
    .map(item => ({ ...item, key: `event:${item.event_id}`, kind: 'event' }))
  actions.push(...groups.map(cveGroupAction))

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
  if (d.kev) context.push('CISA KEV')
  if (d.exploited) context.push('Known exploited')
  if (d.epss_score >= 0.1) context.push(`EPSS ${Math.round(d.epss_score * 100)}%`)
  if (d.cvss_base_score != null) context.push(`CVSS ${d.cvss_base_score}`)
  if (item.asset?.internet_facing) context.push('Internet-facing')
  if ((item.asset?.criticality ?? 0) >= 8) context.push(`Criticality ${item.asset.criticality}/10`)
  if (item.kind === 'cve_group') context.push(`${item.cve_count} CVE${item.cve_count === 1 ? '' : 's'} in one fix group`)
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

export function classifyRecentChanges(events = []) {
  return events.filter(event => {
    const details = event.details ?? {}
    if (event.event_type === 'new_device') return true
    if (event.event_type === 'port_opened') return true
    if (event.event_type === 'config_change' && details.changed_attribute === 'internet_facing' && details.to === true) return true
    return ['version_downgrade', 'version_upgrade', 'new_package', 'removed_package'].includes(event.event_type)
  }).slice(0, 8)
}

export function dashboardHref(path, params = {}, tenantId = '') {
  const query = new URLSearchParams(params)
  if (tenantId) query.set('tenant_id', tenantId)
  const suffix = query.toString()
  return suffix ? `${path}?${suffix}` : path
}
