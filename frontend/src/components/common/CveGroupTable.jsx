// Open CVE alerts grouped by fix: one row per vulnerable package on an asset
// (GET /events/cve-groups). Clicking a row lists that package's CVEs.
import { Server, Globe, User, ArrowRight } from 'lucide-react'
import { SEVERITY_COLORS, SevBadge, timeAgo } from './alertMeta'
import { PriorityTier } from './triageViz'

export const groupKey = (g) => `${g.asset_id}|${g.package_name}|${g.package_version ?? ''}`

function SevCounts({ by }) {
  const parts = [['critical', 'crit'], ['high', 'high'], ['medium', 'med'], ['low', 'low']].filter(([k]) => by[k] > 0)
  return (
    <span className="flex flex-wrap gap-1">
      {parts.map(([k, l]) => (
        <span key={k} className="text-[10px] px-1.5 py-0.5 rounded border" style={{ color: SEVERITY_COLORS[k], borderColor: `${SEVERITY_COLORS[k]}66` }}>
          {by[k]} {l}
        </span>
      ))}
    </span>
  )
}

export default function CveGroupTable({ groups, canManage, selected, onToggle, onToggleAll, onOpen }) {
  const allSelected = groups.length > 0 && groups.every(g => selected.has(groupKey(g)))
  return (
    <table className="data-table">
      <thead>
        <tr>
          {canManage && <th className="w-8"><input type="checkbox" checked={allSelected} onChange={onToggleAll} aria-label="Select all fixes" /></th>}
          <th title="Highest priority among the package's CVEs">Priority</th>
          <th>Fix</th>
          <th>CVEs</th>
          <th>Asset</th>
          <th>Worst CVSS / EPSS</th>
          <th>Open since</th>
          <th>Owner</th>
        </tr>
      </thead>
      <tbody>
        {groups.map(g => {
          const key = groupKey(g)
          return (
            <tr key={key} onClick={() => onOpen(g)} className="cursor-pointer" title="List this package's CVEs">
              {canManage && (
                <td onClick={ev => ev.stopPropagation()} style={{ boxShadow: `inset 3px 0 0 ${SEVERITY_COLORS[g.severity]}` }}>
                  <input type="checkbox" checked={selected.has(key)} onChange={() => onToggle(key)} aria-label="Select fix" />
                </td>
              )}
              <td style={canManage ? undefined : { boxShadow: `inset 3px 0 0 ${SEVERITY_COLORS[g.severity]}` }}>
                <div className="flex flex-col items-start gap-1">
                  <PriorityTier score={g.priority_score} />
                  <SevBadge sev={g.severity} />
                </div>
              </td>
              <td className="min-w-[280px]">
                <div className="text-sm text-dark-100 font-medium flex items-center gap-1.5 flex-wrap">
                  {g.fix_to ? (
                    <>
                      Upgrade <span className="font-mono">{g.package_name}</span>
                      <span className="font-mono text-dark-400">{g.package_version}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-dark-400" />
                      <span className="font-mono text-accent-green">{g.fix_to}</span>
                    </>
                  ) : (
                    <>
                      <span className="font-mono">{g.package_name}</span>
                      <span className="font-mono text-dark-400">{g.package_version}</span>
                    </>
                  )}
                </div>
                <p className="text-xs text-dark-400 mt-0.5">
                  {g.fix_to && `fixes ${g.fixed_by_target} of ${g.cves} CVE${g.cves === 1 ? '' : 's'}`}
                  {g.no_fix > 0 && `${g.fix_to ? ' · ' : ''}${g.no_fix} with no fixed version yet`}
                  {g.package_type && <span className="text-dark-500"> · {g.package_type}</span>}
                </p>
              </td>
              <td className="text-xs">
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm text-dark-100 font-semibold">{g.cves}</span>
                  {g.kev > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded border border-red-500/50 bg-red-500/15 text-red-300 font-semibold" title="On CISA's Known Exploited Vulnerabilities list">{g.kev} KEV</span>}
                  {g.threat_intel > g.kev && <span className="text-[10px] text-accent-red">threat intel</span>}
                </div>
                <SevCounts by={g.by_severity} />
                {g.top_cves.length > 0 && <p className="font-mono text-[10px] text-dark-500 mt-1 truncate max-w-[200px]">{g.top_cves.slice(0, 3).join(', ')}{g.cves > 3 ? '…' : ''}</p>}
              </td>
              <td>
                <div className="flex items-start gap-1.5">
                  <Server className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-1">
                      <span className="text-sm text-dark-200 truncate max-w-[140px]">{g.asset_hostname || g.asset_ip}</span>
                      {g.asset_internet_facing && <Globe className="w-3.5 h-3.5 text-accent-amber flex-shrink-0" title="Internet-facing" />}
                    </div>
                    <p className="font-mono text-[11px] text-dark-500">
                      {g.asset_hostname ? g.asset_ip : ''} {g.asset_device_type && <span className="capitalize font-sans">· {g.asset_device_type}</span>}
                      {g.asset_criticality != null && <span className={`font-sans ${g.asset_criticality >= 8 ? 'text-accent-red' : ''}`}> · crit {g.asset_criticality}</span>}
                    </p>
                  </div>
                </div>
              </td>
              <td className="font-mono text-xs whitespace-nowrap">
                {g.max_cvss != null ? <span style={{ color: g.max_cvss >= 9 ? '#ff5252' : g.max_cvss >= 7 ? '#ff9800' : g.max_cvss >= 4 ? '#ffc400' : '#00e676' }}>{g.max_cvss}</span> : '—'}
                <span className="text-dark-500"> / </span>
                {g.max_epss != null ? `${(g.max_epss * 100).toFixed(1)}%` : '—'}
              </td>
              <td className="text-xs text-dark-400 whitespace-nowrap" title={`Last seen ${new Date(g.last_seen).toLocaleString()}`}>
                {timeAgo(g.first_seen)}
                {g.in_progress > 0 && <div className="text-accent-amber">{g.in_progress} in progress</div>}
              </td>
              <td className="text-xs text-dark-300 whitespace-nowrap">
                {g.assignees.length === 0
                  ? <span className="text-dark-500">Unassigned</span>
                  : <span className="inline-flex items-center gap-1"><User className="w-3 h-3" />{g.assignees.join(', ')}{g.unassigned > 0 && <span className="text-dark-500"> +{g.unassigned} unassigned</span>}</span>}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
