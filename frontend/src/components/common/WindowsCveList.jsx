// The CVEs behind a Windows patch alert (os_patch_missing). The alert itself stores only
// counts; the list is loaded on demand from Microsoft's data (GET /events/:id/windows-cves),
// exploited first, then by severity.
import { useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import client from '../../api/client'

const SEV_CLS = {
  Critical:  'text-red-400',
  Important: 'text-orange-400',
  Moderate:  'text-yellow-400',
  Low:       'text-green-400',
}
const PAGE = 50

export default function WindowsCveList({ eventId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [shown, setShown] = useState(PAGE)

  useEffect(() => {
    let live = true
    setData(null); setError(null)
    client.get(`/events/${eventId}/windows-cves`)
      .then(r => { if (live) setData(r.data) })
      .catch(err => { if (live) setError(err.response?.data?.detail ?? 'Could not load the CVE list') })
    return () => { live = false }
  }, [eventId])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = data?.cves ?? []
    return q ? all.filter(c => c.cve.toLowerCase().includes(q) || c.title.toLowerCase().includes(q)) : all
  }, [data, query])

  if (error) return <p className="text-xs text-red-400 mt-2">{error}</p>
  if (!data) return <p className="text-xs text-dark-500 mt-2">Loading the CVE list…</p>

  return (
    <div className="mt-3">
      <div className="flex items-center gap-2 mb-2">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-dark-500 absolute left-2 top-1/2 -translate-y-1/2" />
          <input
            value={query}
            onChange={ev => { setQuery(ev.target.value); setShown(PAGE) }}
            placeholder={`Search ${data.cves.length.toLocaleString()} CVEs (ID or component)`}
            className="input w-full text-xs py-1.5 pl-7"
          />
        </div>
      </div>
      {data.unavailable?.length > 0 && (
        <p className="text-xs text-dark-500 mb-2">Microsoft's list for {data.unavailable.join(', ')} is not loaded; those CVEs are counted but not listed.</p>
      )}
      <ul className="divide-y divide-dark-700/60 text-xs">
        {rows.slice(0, shown).map(c => (
          <li key={c.cve} className="py-1.5 flex items-start gap-2">
            <a href={`https://msrc.microsoft.com/update-guide/vulnerability/${c.cve}`} target="_blank" rel="noreferrer"
               className="font-mono text-accent-cyan hover:underline whitespace-nowrap">{c.cve}</a>
            <span className={`w-16 shrink-0 ${SEV_CLS[c.severity] ?? 'text-dark-400'}`}>{c.severity ?? '—'}</span>
            <span className="text-dark-300 flex-1">{c.title}</span>
            {c.exploited && <span className="text-red-300 whitespace-nowrap">Exploited</span>}
            <span className="text-dark-500 whitespace-nowrap">{c.month}</span>
          </li>
        ))}
      </ul>
      {rows.length === 0 && <p className="text-xs text-dark-500">No CVE matches "{query}".</p>}
      {rows.length > shown && (
        <button onClick={() => setShown(s => s + PAGE)} className="text-xs text-eagle-400 hover:underline mt-2">
          Show {Math.min(PAGE, rows.length - shown)} more of {(rows.length - shown).toLocaleString()} →
        </button>
      )}
    </div>
  )
}
