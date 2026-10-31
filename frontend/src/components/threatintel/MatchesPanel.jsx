import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Crosshair, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import client from '../../api/client'
import { SevBadge, timeAgo } from '../common/alertMeta'
import { Spinner } from '../common/PageParts'

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const RULE = {
  ioc:      { label: 'Listed IOC',       hint: 'A public IP or hostname of the asset is listed by a feed or event (possible compromise)' },
  watchlist:{ label: 'Watched software', hint: 'Software an event watches is installed on the asset' },
}

// Open threat-intel matches, one group per asset (actions are asset-based).
export default function MatchesPanel({ onLookup, showToast }) {
  const [items, setItems] = useState(null)
  const [open, setOpen] = useState(() => new Set())

  useEffect(() => {
    client.get('/events', { params: { event_type: 'cti_match', status: 'open', page_size: 200, sort: 'priority' } })
      .then((r) => setItems(r.data.items || []))
      .catch((err) => { showToast(err?.response?.data?.detail || 'Failed to load matches', 'error'); setItems([]) })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const groups = useMemo(() => {
    const byAsset = new Map()
    for (const e of items || []) {
      const g = byAsset.get(e.asset_id) ?? {
        asset_id: e.asset_id, name: e.asset_hostname || e.asset_ip, ip: e.asset_ip,
        criticality: e.asset_criticality, alerts: [], worst: -1,
      }
      g.alerts.push(e)
      g.worst = Math.max(g.worst, SEV_RANK[e.severity] ?? 0)
      byAsset.set(e.asset_id, g)
    }
    return [...byAsset.values()].sort((a, b) => b.worst - a.worst || b.alerts.length - a.alerts.length)
  }, [items])

  // The first (worst) asset starts open
  useEffect(() => { if (groups.length) setOpen(new Set([groups[0].asset_id])) }, [groups])

  if (items === null) return <Spinner />

  const toggle = (id) => setOpen((cur) => {
    const next = new Set(cur)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  return (
    <div className="space-y-3">
      <p className="text-sm text-dark-400 max-w-3xl">
        Your assets that threat intelligence names. Checked after every scan, inventory and SBOM, nightly against the feeds,
        and whenever a threat-intel event changes.
      </p>

      {groups.length === 0 ? (
        <div className="glass-card text-center py-16 px-4 text-dark-400">
          <Crosshair className="w-12 h-12 mx-auto mb-3 opacity-20" />
          <p className="font-medium text-dark-200">No matches</p>
          <p className="text-sm mt-1 max-w-lg mx-auto">
            None of your assets' public IPs, hostnames or installed software appear in threat intelligence right now.
            Private addresses (such as 192.168.x.x) are never matched.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {groups.map((g) => {
            const isOpen = open.has(g.asset_id)
            const worst = g.alerts.reduce((w, e) => ((SEV_RANK[e.severity] ?? 0) > (SEV_RANK[w] ?? -1) ? e.severity : w), null)
            return (
              <div key={g.asset_id} className="glass-card overflow-hidden">
                <button onClick={() => toggle(g.asset_id)} aria-expanded={isOpen}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-dark-700/30 transition-colors">
                  {isOpen ? <ChevronDown className="w-4 h-4 text-dark-400 shrink-0" /> : <ChevronRight className="w-4 h-4 text-dark-400 shrink-0" />}
                  <SevBadge sev={worst} />
                  <span className="min-w-0 flex-1">
                    <span className="text-sm font-medium text-dark-100">{g.name}</span>
                    {g.name !== g.ip && g.ip && <span className="ml-2 font-mono text-xs text-dark-500">{g.ip}</span>}
                  </span>
                  <span className="text-xs text-dark-400 shrink-0">{g.alerts.length} match{g.alerts.length === 1 ? '' : 'es'}</span>
                </button>
                {isOpen && (
                  <div className="border-t border-dark-700/50 overflow-x-auto">
                    <table className="data-table">
                      <thead><tr><th>Severity</th><th>Indicator</th><th>Rule</th><th>Matched on</th><th>Listed by</th><th>Since</th><th /></tr></thead>
                      <tbody>
                        {g.alerts.map((e) => {
                          const rule = RULE[e.details?.match_kind] ?? RULE.ioc
                          return (
                            <tr key={e.event_id}>
                              <td><SevBadge sev={e.severity} /></td>
                              <td>
                                <button onClick={() => onLookup(e.details?.indicator_value)} className="font-mono text-xs text-accent-cyan hover:underline text-left break-all" title="Show what threat intel says about it">
                                  {e.details?.indicator_value}
                                </button>
                                <p className="text-[11px] text-dark-500">{e.details?.indicator_type}</p>
                              </td>
                              <td className="text-xs text-dark-300" title={rule.hint}>{rule.label}</td>
                              <td className="font-mono text-xs text-dark-300 break-all">{e.details?.observed}</td>
                              <td className="text-xs text-dark-300">{(e.details?.sources ?? []).join(', ') || '—'}</td>
                              <td className="text-xs text-dark-400 whitespace-nowrap">{timeAgo(e.first_seen)}</td>
                              <td><Link to={`/alerts?event=${e.event_id}`} className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-1 whitespace-nowrap">Alert <ExternalLink className="w-3 h-3" /></Link></td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                    <div className="px-4 py-2 border-t border-dark-700/50 text-xs">
                      <Link to={`/inventory/${g.asset_id}`} className="text-eagle-400 hover:underline">Open asset →</Link>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
          <Link to="/alerts?view=threat_intel" className="text-sm text-eagle-400 hover:underline inline-block">Work them on the Alerts page →</Link>
        </div>
      )}
    </div>
  )
}
