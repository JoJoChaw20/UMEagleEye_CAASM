// MyCERT advisories: UMEagleEye's main threat-intel source for organisations in Malaysia. Each advisory
// is a platform threat-intel event loaded every morning (workers/src/services/mycert.ts); this lists them,
// 20 a page (GET /cti/mycert), with what each touches here: the devices and open alerts it drives. An
// advisory opens in the Threat Intelligence panel (EventView): MyCERT's facts, the alerts, its CVEs and
// indicators.
import { useState, useEffect } from 'react'
import { ExternalLink, Shield, Flame, Server } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { Spinner } from '../common/PageParts'
import { ClearFilters, EmptyState, FilterBar, FilterChip, ListPager, ListTotal, plural } from '../common/ListParts'
import { LevelBadge, SearchBox, day, useSettled } from './tiParts'
import { useTiPanel } from './tiPanelContext'

const PAGE = 20
const KIND = { advisory: 'Advisory', alert: 'Alert', report: 'Report' }
// "MA-1506.112026" is shown as MyCERT numbers it in its titles: MA-1506
const shortId = (id) => id.replace(/\.\d{6}$/, '')

export default function MycertPanel({ showToast, startAffecting = false }) {
  const panel = useTiPanel()
  const { can } = useAuth()
  const canOpen = can('ti_event.view')            // the advisory's view is its event (GET /cti/events/:id)
  const [data, setData] = useState(null)
  const [affecting, setAffecting] = useState(startAffecting)
  const [exploited, setExploited] = useState(false)
  const [q, setQ] = useState('')
  const search = useSettled(q.trim())
  const [page, setPage] = useState(1)

  useEffect(() => { setPage(1) }, [affecting, exploited, search])
  useEffect(() => {
    const params = { page, page_size: PAGE }
    if (affecting) params.affecting = '1'
    if (exploited) params.exploited = '1'
    if (search) params.q = search
    client.get('/cti/mycert', { params })
      .then((res) => setData(res.data))
      .catch((err) => {
        showToast(err?.response?.data?.detail || 'Failed to load MyCERT advisories', 'error')
        setData({ summary: null, total: 0, items: [] })
      })
  }, [affecting, exploited, search, page, panel.version, showToast])

  const s = data?.summary
  const items = data?.items ?? []
  const filtered = !!(affecting || exploited || search)
  const clear = () => { setAffecting(false); setExploited(false); setQ('') }
  const open = (a) => panel.open({ kind: 'event', id: a.event_id, label: shortId(a.id) })

  return (
    <div className="space-y-3">
      <div className="glass-card flex items-start gap-3 p-4">
        <Shield className="mt-0.5 h-5 w-5 shrink-0 text-eagle-400" />
        <div className="min-w-0 text-sm text-dark-300">
          <p>
            Advisories and alerts from <span className="font-medium text-dark-100">MyCERT</span> (CyberSecurity Malaysia), loaded every morning.
            Their CVEs are checked against your devices' software, their indicators against your devices and agents;
            a CVE MyCERT says is exploited in the wild is fixed first, like one on CISA KEV.
          </p>
          {s && (
            <p className="mt-1.5 text-xs text-dark-400">
              {plural(s.total, 'advisory', 'advisories')} · {s.last_30d} in the last 30 days
              {s.newest_at && ` · newest ${day(s.newest_at)}`}
            </p>
          )}
        </div>
      </div>

      <FilterBar>
        <SearchBox value={q} onChange={setQ} placeholder="Number, title or CVE" label="Search MyCERT advisories" />
        <FilterChip pressed={affecting} onClick={() => setAffecting(!affecting)} icon={Server} count={s?.affecting}>Touching our devices</FilterChip>
        <FilterChip pressed={exploited} onClick={() => setExploited(!exploited)} icon={Flame} count={s?.exploited}>Exploited CVEs</FilterChip>
        {filtered && <ClearFilters onClick={clear} />}
        {data && <ListTotal><b>{data.total.toLocaleString()}</b> {data.total === 1 ? 'advisory' : 'advisories'}</ListTotal>}
      </FilterBar>

      <div className="glass-card overflow-hidden">
        {!data ? <Spinner className="py-20" /> : items.length === 0 ? (
          <EmptyState icon={Shield} title="No advisories" filtered={filtered} onClear={clear}>
            MyCERT's advisories appear here after the next morning's update.
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>Advisory</th><th>Title</th><th>Threat</th><th>CVEs</th><th>Indicators</th><th>Your devices</th><th className="sr-only">On MyCERT</th></tr>
                </thead>
                <tbody>
                  {items.map((a) => (
                    <tr key={a.event_id} className={canOpen ? 'cursor-pointer hover:bg-dark-700/30' : ''}
                      onClick={canOpen ? () => open(a) : undefined} tabIndex={canOpen ? 0 : undefined}
                      onKeyDown={canOpen ? (e) => { if (e.key === 'Enter') open(a) } : undefined}>
                      <td className="whitespace-nowrap">
                        <div className="font-mono text-xs text-dark-100">{shortId(a.id)}</div>
                        <div className="text-[11px] text-dark-500">{day(a.published_at)}</div>
                      </td>
                      <td className="max-w-xl">
                        <div className="line-clamp-2 text-sm text-dark-100" title={a.headline}>{a.headline}</div>
                        <div className="mt-0.5 text-[11px] text-dark-500">
                          {KIND[a.kind] ?? 'Advisory'}{a.rating ? ` · MyCERT rates it ${a.rating.toUpperCase()}` : ''}
                          {a.products?.length > 0 && ` · ${a.products.slice(0, 2).join(', ')}${a.products.length > 2 ? '…' : ''}`}
                        </div>
                      </td>
                      <td><LevelBadge level={a.threat_level} /></td>
                      <td className="whitespace-nowrap text-xs tabular-nums">
                        {a.cve_count > 0 ? (
                          <>
                            <span className="text-dark-200">{a.cve_count}</span>
                            {a.exploited_cves.length > 0 && (
                              <span className="ml-1.5 text-red-300" title={`Exploited in the wild, per MyCERT: ${a.exploited_cves.join(', ')}`}>
                                <Flame className="-mt-0.5 inline h-3 w-3" /> {a.exploited_cves.length} exploited
                              </span>
                            )}
                          </>
                        ) : <span className="text-dark-500">—</span>}
                      </td>
                      <td className="text-xs tabular-nums text-dark-300">{a.ioc_count > 0 ? a.ioc_count : <span className="text-dark-500">—</span>}</td>
                      <td className="whitespace-nowrap text-xs">
                        {a.devices > 0
                          ? <span className="font-medium text-amber-300">{plural(a.devices, 'device')} · {plural(a.alerts, 'alert')}</span>
                          : <span className="text-dark-500">none</span>}
                      </td>
                      <td className="text-right">
                        {a.url && (
                          <a href={a.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-0.5 text-xs text-eagle-400 hover:text-eagle-300" title="Read it on MyCERT">
                            MyCERT <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ListPager page={data.page ?? page} pageSize={PAGE} total={data.total} one="advisory" many="advisories" onChange={setPage} />
          </>
        )}
      </div>
    </div>
  )
}
