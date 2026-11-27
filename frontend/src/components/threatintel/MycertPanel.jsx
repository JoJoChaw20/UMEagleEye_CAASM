// MyCERT advisories: UMEagleEye's main threat-intel source for organisations in Malaysia. Each advisory
// is a platform threat-intel event loaded every morning (workers/src/services/mycert.ts); this lists them
// with what each touches here: the devices and open alerts it drives (GET /cti/mycert). An advisory
// opens as its event (EventDetail): MyCERT's facts, the alerts, its CVEs and indicators.
import { useState, useEffect, useCallback } from 'react'
import { Search, ExternalLink, Shield, Flame, Server } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { EventDetail } from './TiEventsPanel'
import { Spinner } from '../common/PageParts'

const LEVEL = {
  high:   { label: 'High',   cls: 'bg-red-500/15 text-red-300 border-red-500/40' },
  medium: { label: 'Medium', cls: 'bg-orange-500/15 text-orange-300 border-orange-500/40' },
  low:    { label: 'Low',    cls: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' },
}
const KIND = { advisory: 'Advisory', alert: 'Alert', report: 'Report' }
const day = (ts) => (ts ? new Date(ts).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : '—')
// "MA-1506.112026" is shown as MyCERT numbers it in its titles: MA-1506
const shortId = (id) => id.replace(/\.\d{6}$/, '')

function Chip({ on, onClick, icon: Icon, children }) {
  return (
    <button onClick={onClick} aria-pressed={on}
      className={`text-xs px-2.5 py-1 rounded-md border inline-flex items-center gap-1 ${on ? 'bg-eagle-600/20 text-eagle-300 border-eagle-500/40' : 'border-dark-600 text-dark-400 hover:text-dark-200'}`}>
      <Icon className="w-3 h-3" />{children}
    </button>
  )
}

export default function MycertPanel({ showToast }) {
  const { can } = useAuth()
  const canOpen = can('ti_event.view')            // the advisory's page is its event (GET /cti/events/:id)
  const [data, setData] = useState(null)
  const [affecting, setAffecting] = useState(false)
  const [exploited, setExploited] = useState(false)
  const [q, setQ] = useState('')
  const [qDebounced, setQDebounced] = useState('')
  const [openId, setOpenId] = useState(null)

  useEffect(() => {
    const t = setTimeout(() => setQDebounced(q.trim()), 300)
    return () => clearTimeout(t)
  }, [q])

  const load = useCallback(async () => {
    try {
      const params = { limit: 200 }
      if (affecting) params.affecting = '1'
      if (exploited) params.exploited = '1'
      if (qDebounced) params.q = qDebounced
      const res = await client.get('/cti/mycert', { params })
      setData(res.data)
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Failed to load MyCERT advisories', 'error')
      setData({ summary: null, total: 0, items: [] })
    }
  }, [affecting, exploited, qDebounced, showToast])
  useEffect(() => { load() }, [load])

  if (openId) {
    return <EventDetail eventId={openId} backLabel="MyCERT advisories" onBack={() => setOpenId(null)} onChanged={load} showToast={showToast} />
  }

  const s = data?.summary
  const items = data?.items ?? []
  return (
    <div className="space-y-4">
      <div className="glass-card p-4 flex items-start gap-3">
        <Shield className="w-5 h-5 text-eagle-400 mt-0.5 shrink-0" />
        <div className="text-sm text-dark-300 min-w-0">
          <p>
            Advisories and alerts from <span className="text-dark-100 font-medium">MyCERT</span> (CyberSecurity Malaysia), loaded every morning.
            Their CVEs are checked against your devices' software, their indicators against your assets and agents;
            a CVE MyCERT says is exploited in the wild is fixed first, like one on CISA KEV.
          </p>
          {s && (
            <p className="text-xs text-dark-400 mt-1.5">
              {s.total} advisories · {s.last_30d} in the last 30 days ·{' '}
              <span className={s.affecting ? 'text-amber-300' : ''}>{s.affecting} touch your devices</span>
              {s.exploited_affecting > 0 && <span className="text-red-300"> ({s.exploited_affecting} with an exploited CVE)</span>}
              {s.newest_at && ` · newest ${day(s.newest_at)}`}
            </p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-400" />
          <input type="text" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Number, title or CVE…"
            aria-label="Search MyCERT advisories" className="input-field text-sm py-1.5 pl-8 w-60" />
        </div>
        <Chip on={affecting} onClick={() => setAffecting(!affecting)} icon={Server}>Touching our devices</Chip>
        <Chip on={exploited} onClick={() => setExploited(!exploited)} icon={Flame}>Exploited CVEs</Chip>
        <span className="text-dark-400 text-sm ml-auto">{data ? `${data.total} advisories` : ''}</span>
      </div>

      <div className="glass-card overflow-hidden">
        {!data ? <Spinner className="py-20" /> : items.length === 0 ? (
          <div className="text-center py-16 text-dark-400 px-4">
            <Shield className="w-14 h-14 mx-auto mb-4 opacity-20" />
            <p className="font-medium text-dark-200">
              {affecting || exploited || qDebounced ? 'No advisories match these filters' : 'No MyCERT advisories loaded yet'}
            </p>
            {affecting && !exploited && !qDebounced && <p className="text-sm mt-1">None of MyCERT's advisories names software or indicators found on your devices.</p>}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr><th>Advisory</th><th>Title</th><th>Threat</th><th>CVEs</th><th>Indicators</th><th>Your devices</th><th /></tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.event_id} className={canOpen ? 'cursor-pointer hover:bg-dark-700/30' : ''}
                    onClick={canOpen ? () => setOpenId(a.event_id) : undefined} tabIndex={canOpen ? 0 : undefined}
                    onKeyDown={canOpen ? (e) => { if (e.key === 'Enter') setOpenId(a.event_id) } : undefined}>
                    <td className="whitespace-nowrap">
                      <div className="font-mono text-xs text-dark-100">{shortId(a.id)}</div>
                      <div className="text-[11px] text-dark-500">{day(a.published_at)}</div>
                    </td>
                    <td className="max-w-xl">
                      <div className="text-sm text-dark-100 line-clamp-2" title={a.headline}>{a.headline}</div>
                      <div className="text-[11px] text-dark-500 mt-0.5">
                        {KIND[a.kind] ?? 'Advisory'}{a.rating ? ` · MyCERT rates it ${a.rating.toUpperCase()}` : ''}
                        {a.products?.length > 0 && ` · ${a.products.slice(0, 2).join(', ')}${a.products.length > 2 ? '…' : ''}`}
                      </div>
                    </td>
                    <td>
                      <span className={`text-[11px] px-1.5 py-0.5 rounded border whitespace-nowrap ${LEVEL[a.threat_level]?.cls ?? ''}`}>{LEVEL[a.threat_level]?.label ?? a.threat_level}</span>
                    </td>
                    <td className="text-xs whitespace-nowrap">
                      {a.cve_count > 0 ? (
                        <>
                          <span className="text-dark-200">{a.cve_count}</span>
                          {a.exploited_cves.length > 0 && (
                            <span className="ml-1.5 text-red-300" title={`Exploited in the wild, per MyCERT: ${a.exploited_cves.join(', ')}`}>
                              <Flame className="w-3 h-3 inline -mt-0.5" /> {a.exploited_cves.length} exploited
                            </span>
                          )}
                        </>
                      ) : <span className="text-dark-500">—</span>}
                    </td>
                    <td className="text-xs text-dark-300">{a.ioc_count > 0 ? a.ioc_count : <span className="text-dark-500">—</span>}</td>
                    <td className="text-xs whitespace-nowrap">
                      {a.devices > 0
                        ? <span className="text-amber-300 font-medium" title={`${a.alerts} open alert(s) this advisory drives`}>{a.devices} device{a.devices === 1 ? '' : 's'} · {a.alerts} alert{a.alerts === 1 ? '' : 's'}</span>
                        : <span className="text-dark-500">none</span>}
                    </td>
                    <td className="text-right">
                      {a.url && (
                        <a href={a.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
                          className="text-eagle-400 hover:text-eagle-300 inline-flex items-center gap-0.5 text-xs" title="Read it on MyCERT">
                          MyCERT <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
