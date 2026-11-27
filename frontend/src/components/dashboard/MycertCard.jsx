import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Flame, ExternalLink } from 'lucide-react'
import client from '../../api/client'
import PanelHeading from '../ui/PanelHeading'

const day = (ts) => (ts ? new Date(ts).toLocaleDateString([], { day: 'numeric', month: 'short' }) : '')

// MyCERT (CyberSecurity Malaysia), the main threat-intel source: how many of its advisories touch this
// organisation's devices, and the ones to look at first (an exploited CVE, then the most devices).
// GET /cti/mycert (workers/src/routes/cti.ts); tenantId: the superadmin's tenant picker.
export default function MycertCard({ tenantId }) {
  const [data, setData] = useState(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let live = true
    const params = { affecting: '1', limit: 50 }
    if (tenantId) params.tenant_id = tenantId
    client.get('/cti/mycert', { params })
      .then((res) => { if (live) { setData(res.data); setFailed(false) } })
      .catch(() => { if (live) setFailed(true) })
    return () => { live = false }
  }, [tenantId])

  const s = data?.summary
  const top = [...(data?.items ?? [])]
    .sort((a, b) => (b.exploited_cves.length > 0) - (a.exploited_cves.length > 0) || b.devices - a.devices)
    .slice(0, 4)

  return (
    <div className="glass-card p-5 lg:p-6">
      <PanelHeading title="MyCERT advisories" detail="Malaysia's national CERT: which of its advisories touch your devices." />
      {failed ? <p className="py-4 text-sm text-dark-400">MyCERT advisories unavailable.</p>
        : !data ? <div className="h-16 animate-pulse rounded-lg bg-dark-700/35" /> : (
          <>
            <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1">
              <span>
                <span className={`font-display text-2xl font-semibold tabular-nums ${s.affecting ? 'text-amber-400' : 'text-dark-100'}`}>{s.affecting}</span>
                <span className="ml-1.5 text-xs text-dark-400">of {s.total} touch your devices</span>
              </span>
              {s.exploited_affecting > 0 && (
                <span className="text-xs text-red-400"><Flame className="-mt-0.5 inline h-3.5 w-3.5" /> {s.exploited_affecting} with a CVE exploited in the wild</span>
              )}
              <span className="text-xs text-dark-500">{s.last_30d} published in the last 30 days{s.newest_at ? `, newest ${day(s.newest_at)}` : ''}</span>
            </div>
            {top.length === 0 ? (
              <p className="mt-3 text-sm text-dark-400">None of MyCERT's advisories names software or indicators found on your devices.</p>
            ) : (
              <ul className="mt-3 space-y-1.5 text-sm">
                {top.map((a) => (
                  <li key={a.event_id} className="flex items-center gap-2 min-w-0">
                    <Shield className="h-3.5 w-3.5 flex-shrink-0 text-eagle-400" />
                    <span className="font-mono text-xs text-dark-400">{a.id.replace(/\.\d{6}$/, '')}</span>
                    <span className="truncate text-dark-200" title={a.headline}>{a.headline}</span>
                    {a.exploited_cves.length > 0 && <Flame className="h-3.5 w-3.5 flex-shrink-0 text-red-400" title="A CVE exploited in the wild" />}
                    <span className="ml-auto whitespace-nowrap text-xs text-amber-300">{a.devices} device{a.devices === 1 ? '' : 's'}</span>
                    {a.url && <a href={a.url} target="_blank" rel="noreferrer" className="text-dark-500 hover:text-eagle-400" title="Read it on MyCERT"><ExternalLink className="h-3.5 w-3.5" /></a>}
                  </li>
                ))}
              </ul>
            )}
            <Link to="/threat-intel" className="mt-3 inline-block text-xs text-eagle-400 hover:text-eagle-300">All MyCERT advisories</Link>
          </>
        )}
    </div>
  )
}
