// The CVEs of an SBOM package alert (one alert per vulnerable package, workers/src/lib/
// packageAlerts.ts). Loaded on demand from its findings (GET /events/:id/cves): exploited
// first, then the most likely to be exploited, then the most severe; searched and paged on
// the server, with the ones fixed since a click away.
import { useEffect, useState } from 'react'
import { Search, ArrowRight } from 'lucide-react'
import client from '../../api/client'
import { cvssColor, fixFor } from './alertMeta'

const PAGE = 50

/** `copies`: how many versions of the package are installed (one row per CVE and version). */
export default function PackageCveList({ eventId, copies = 1 }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(null)
  const [page, setPage] = useState(1)
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [fixed, setFixed] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 300)
    return () => clearTimeout(t)
  }, [query])
  useEffect(() => { setPage(1) }, [eventId, debounced, fixed])

  useEffect(() => {
    let live = true
    setLoading(true); setError(null)
    client.get(`/events/${eventId}/cves`, { params: { page, page_size: PAGE, q: debounced || undefined, fixed: fixed ? 'true' : undefined } })
      .then(r => {
        if (!live) return
        setItems(prev => (page === 1 ? r.data.items : [...prev, ...r.data.items]))
        setTotal(r.data.total)
      })
      .catch(err => { if (live) setError(err.response?.data?.detail ?? 'Could not load the CVE list') })
      .finally(() => { if (live) setLoading(false) })
    return () => { live = false }
  }, [eventId, page, debounced, fixed])

  if (error) return <p className="text-xs text-red-400 mt-2">{error}</p>

  return (
    <div className="mt-3">
      <div className="flex items-center gap-3 mb-2">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-dark-500 absolute left-2 top-1/2 -translate-y-1/2" />
          <input
            value={query}
            onChange={ev => setQuery(ev.target.value)}
            placeholder={total != null && !debounced
              ? (copies > 1 ? `Search ${total.toLocaleString()} rows (one per CVE and installed version)` : `Search ${total.toLocaleString()} CVE${total === 1 ? '' : 's'}`)
              : 'Search CVE ID'}
            className="input w-full text-xs py-1.5 pl-7"
            aria-label="Search this package's CVEs"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-dark-300 cursor-pointer whitespace-nowrap" title="CVEs a later SBOM no longer found">
          <input type="checkbox" checked={fixed} onChange={ev => setFixed(ev.target.checked)} /> Fixed since
        </label>
      </div>
      <ul className="divide-y divide-dark-700/60 text-xs">
        {items.map(c => {
          const fix = fixFor(c.package_version, c.fix_versions)
          return (
            <li key={`${c.cve_id}-${c.package_version}`} className={`py-1.5 ${c.dismissed ? 'opacity-50' : ''}`}>
              <div className="flex items-start gap-2 flex-wrap">
                <a href={c.cve_id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${c.cve_id}` : `https://github.com/advisories/${c.cve_id}`}
                  target="_blank" rel="noreferrer" className="font-mono text-accent-cyan hover:underline whitespace-nowrap">{c.cve_id}</a>
                <span className="font-mono whitespace-nowrap" style={{ color: cvssColor(c.cvss) }}>CVSS {c.cvss || '—'}</span>
                <span className="text-dark-400 whitespace-nowrap">EPSS {(c.epss * 100).toFixed(1)}%</span>
                {c.kev && <span className="text-red-300 whitespace-nowrap">Exploited (CISA KEV)</span>}
                {c.threat_intel && !c.kev && <span className="text-red-300 whitespace-nowrap">In threat intel</span>}
                <span className={`ml-auto whitespace-nowrap ${fix ? 'text-accent-green' : 'text-dark-500'}`}>
                  {c.fixed_at ? `fixed ${new Date(c.fixed_at).toLocaleDateString()}` : fix ? `fixed in ${fix}` : 'no fix yet'}
                </span>
              </div>
              <div className="text-dark-500 mt-0.5">
                on {c.package_version || 'unknown version'}
                {c.cwes?.length > 0 && <span> · {c.cwes.map(w => w.id).join(', ')}</span>}
                {c.dismissed && <span> · marked not applicable</span>}
              </div>
              {c.description && <p className="text-dark-400 mt-0.5 line-clamp-2">{c.description}</p>}
            </li>
          )
        })}
      </ul>
      {loading && <p className="text-xs text-dark-500 mt-2">Loading the CVE list…</p>}
      {!loading && items.length === 0 && <p className="text-xs text-dark-500">{debounced ? `No CVE matches "${debounced}".` : fixed ? 'None fixed yet.' : 'No CVEs listed.'}</p>}
      {!loading && total != null && items.length < total && (
        <button onClick={() => setPage(p => p + 1)} className="text-xs text-eagle-400 hover:underline mt-2">
          Show {Math.min(PAGE, total - items.length)} more of {(total - items.length).toLocaleString()}<ArrowRight aria-hidden="true" className="ml-1 inline h-3.5 w-3.5 align-[-3px]" />
        </button>
      )}
    </div>
  )
}
