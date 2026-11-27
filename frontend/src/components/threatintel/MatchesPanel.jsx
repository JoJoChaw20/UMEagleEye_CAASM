// Matches: open threat-intel matches on your devices, one table like every other list (worst first), with
// search, severity and kind chips and pages of 20. The rows are alerts (GET /events?event_type=cti_match);
// the chip counts and "N matches on M devices" come from GET /cti/matches/summary. A row opens the match in
// the Threat Intelligence panel (MatchView), with the indicator's details and links to the alert and device.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Crosshair, ExternalLink, ArrowRight } from 'lucide-react'
import client from '../../api/client'
import { SevBadge, timeAgo } from '../common/alertMeta'
import { Spinner } from '../common/PageParts'
import { ClearFilters, ChipDivider, EmptyState, FilterBar, FilterChip, ListPager, ListTotal, pageWithin } from '../common/ListParts'
import { SearchBox, useSettled } from './tiParts'
import { useTiPanel } from './tiPanelContext'
import { IndicatorBody } from './IndicatorPanel'

const PAGE = 20
const SEVERITIES = ['critical', 'high', 'medium', 'low']
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

// details.match_kind (none: 'ioc', the oldest matches)
export const KIND = {
  sighting:          { label: 'Seen by an agent', hint: "The device's agent saw it look up or connect to a listed domain or IP, or run a listed program (possible compromise)" },
  ioc:               { label: 'On a device address or name', hint: "A device's public IP or host name is listed by a feed or event" },
  public_address:    { label: 'Our public address', hint: 'An address the organisation reaches the internet from is listed' },
  watchlist:         { label: 'Watched software', hint: 'Software an event watches is installed on the device' },
  malicious_package: { label: 'Malicious package', hint: 'A package on the device was published as malware' },
}
const kindOf = (e) => KIND[e.details?.match_kind] ?? KIND.ioc
const deviceOf = (e) => e.asset_hostname || e.asset_ip || 'Unknown device'

export default function MatchesPanel({ showToast }) {
  const panel = useTiPanel()
  const [q, setQ] = useState('')
  const search = useSettled(q.trim())
  const [sev, setSev] = useState('')
  const [kind, setKind] = useState('')
  const [page, setPage] = useState(1)
  const [list, setList] = useState(null)
  const [summary, setSummary] = useState(null)

  useEffect(() => { setPage(1) }, [search, sev, kind])
  useEffect(() => {
    const filters = { ...(sev ? { severity: sev } : {}), ...(kind ? { match_kind: kind } : {}), ...(search ? { q: search } : {}) }
    setList(null)
    Promise.all([
      client.get('/events', { params: { event_type: 'cti_match', status: 'open', sort: 'priority', page, page_size: PAGE, ...filters } }),
      client.get('/cti/matches/summary', { params: filters }),
    ]).then(([l, s]) => { setList(l.data); setSummary(s.data) })
      .catch((err) => { showToast(err?.response?.data?.detail || 'Failed to load matches', 'error'); setList({ items: [], total: 0 }) })
  }, [search, sev, kind, page, panel.version]) // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = !!(search || sev || kind)
  const clear = () => { setQ(''); setSev(''); setKind('') }
  const total = list?.total ?? 0
  const bySev = summary?.by_severity ?? {}
  const byKind = summary?.by_kind ?? {}
  const allCount = SEVERITIES.reduce((n, s) => n + (bySev[s] ?? 0), 0)
  const open = (e) => panel.open({ kind: 'match', alert: e, label: `${deviceOf(e)} ↔ ${e.details?.indicator_value ?? ''}` })

  return (
    <div className="space-y-3">
      <FilterBar>
        <SearchBox value={q} onChange={setQ} placeholder="Device or indicator" />
        <FilterChip pressed={!sev} onClick={() => setSev('')} count={allCount}>All</FilterChip>
        {SEVERITIES.filter((s) => bySev[s] || sev === s).map((s) => (
          <FilterChip key={s} pressed={sev === s} onClick={() => setSev(s)} count={bySev[s] ?? 0}>{SEV_LABEL[s]}</FilterChip>
        ))}
        <ChipDivider />
        {Object.entries(KIND).filter(([k]) => byKind[k] || kind === k).map(([k, m]) => (
          <FilterChip key={k} pressed={kind === k} onClick={() => setKind(kind === k ? '' : k)} count={byKind[k] ?? 0} title={m.hint}>{m.label}</FilterChip>
        ))}
        {filtered && <ClearFilters onClick={clear} />}
        <ListTotal><b>{total.toLocaleString()}</b> {total === 1 ? 'match' : 'matches'} on <b>{(summary?.devices ?? 0).toLocaleString()}</b> {summary?.devices === 1 ? 'device' : 'devices'}</ListTotal>
      </FilterBar>

      <div className="glass-card overflow-hidden">
        {!list ? <Spinner className="py-20" /> : list.items.length === 0 ? (
          <EmptyState icon={Crosshair} title="No matches" filtered={filtered} onClear={clear}>
            None of your devices' public IPs, host names, installed software or traffic appear in threat intelligence right now.
            Private addresses (such as 192.168.x.x) are never matched.
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th>Severity</th><th>Device</th><th>Indicator</th><th>How it matched</th><th>Listed by</th><th>Since</th></tr></thead>
                <tbody>
                  {list.items.map((e) => (
                    <tr key={e.event_id} tabIndex={0} className="cursor-pointer hover:bg-dark-700/30" onClick={() => open(e)}
                      onKeyDown={(ev) => { if (ev.key === 'Enter') open(e) }}>
                      <td><SevBadge sev={e.severity} /></td>
                      <td className="text-sm text-dark-100">{deviceOf(e)}{e.asset_hostname && e.asset_ip && <div className="font-mono text-[11px] text-dark-500">{e.asset_ip}</div>}</td>
                      <td className="max-w-[16rem] break-all font-mono text-xs text-accent-cyan">{e.details?.indicator_value}</td>
                      <td className="text-xs text-dark-300" title={kindOf(e).hint}>{kindOf(e).label}
                        {e.details?.observed && <div className="max-w-[16rem] truncate font-mono text-[11px] text-dark-500">{e.details.observed}</div>}</td>
                      <td className="text-xs text-dark-300">{(e.details?.sources ?? []).join(', ') || '—'}</td>
                      <td className="whitespace-nowrap text-xs text-dark-400">{timeAgo(e.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ListPager page={pageWithin(page, PAGE, total)} pageSize={PAGE} total={total} one="match" many="matches" onChange={setPage} />
          </>
        )}
      </div>
      {total > 0 && <Link to="/alerts?view=threat_intel" className="inline-block text-sm text-eagle-400 hover:underline">Work them on the Alerts page<ArrowRight aria-hidden="true" className="ml-1 inline h-3.5 w-3.5 align-[-3px]" /></Link>}
    </div>
  )
}

// A match's view in the Threat Intelligence panel: how it matched, who lists it, what the indicator is.
export function MatchView({ view, setHead }) {
  const e = view.alert
  const d = e.details ?? {}
  useEffect(() => {
    setHead({
      title: <>{deviceOf(e)} <span className="text-dark-500">↔</span> <span className="break-all font-mono">{d.indicator_value}</span></>,
      subtitle: `Threat-intel match · ${kindOf(e).label}`,
      footer: (
        <div className="flex flex-wrap gap-2">
          <Link to={`/alerts?event=${e.event_id}`} className="btn-primary inline-flex items-center gap-1.5 text-sm">Open the alert <ExternalLink className="h-3.5 w-3.5" /></Link>
          <Link to={`/inventory/${e.asset_id}`} className="btn-secondary text-sm">Open the device</Link>
        </div>
      ),
    })
  }, [e, d.indicator_value, setHead])
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2"><SevBadge sev={e.severity} /><span className="text-xs text-dark-400">{e.status === 'in_progress' ? 'In progress' : 'Open'}</span></div>
      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5 text-sm">
        <dt className="text-dark-400">How it matched</dt><dd className="text-dark-100">{kindOf(e).label}<span className="block text-xs text-dark-400">{kindOf(e).hint}</span></dd>
        {d.observed && <><dt className="text-dark-400">Seen as</dt><dd className="break-all font-mono text-xs text-dark-200">{d.observed}</dd></>}
        <dt className="text-dark-400">Listed by</dt><dd className="text-dark-100">{(d.sources ?? []).join(', ') || '—'}</dd>
        <dt className="text-dark-400">Device</dt><dd className="text-dark-100">{deviceOf(e)}{e.asset_ip && e.asset_hostname ? <span className="ml-1.5 font-mono text-xs text-dark-500">{e.asset_ip}</span> : null}</dd>
        <dt className="text-dark-400">Since</dt><dd className="text-dark-100">{timeAgo(e.first_seen)}</dd>
      </dl>
      {d.indicator_value && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">What the indicator is</h3>
          <IndicatorBody value={d.indicator_value} />
        </section>
      )}
    </div>
  )
}
