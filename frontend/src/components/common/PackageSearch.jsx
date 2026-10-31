// Fleet-wide package search on the SBOM page: which computers have a package (and
// version), from each asset's latest SBOM. What an admin asks when a new CVE is announced,
// before any vulnerability database has it. Server: GET /sboms/packages/search.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, RefreshCw, AlertTriangle } from 'lucide-react'
import client from '../../api/client'

export default function PackageSearch({ tenantId }) {
  const [name, setName] = useState('')
  const [version, setVersion] = useState('')
  const [result, setResult] = useState(null)      // { items, assets, truncated, query }
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const search = async (e) => {
    e.preventDefault()
    if (name.trim().length < 2) { setError('Type at least 2 characters of the package name'); return }
    setLoading(true); setError(null)
    try {
      const params = { q: name.trim(), ...(version.trim() ? { version: version.trim() } : {}), ...(tenantId ? { tenant_id: tenantId } : {}) }
      const { data } = await client.get('/sboms/packages/search', { params })
      setResult({ ...data, query: params })
    } catch (err) {
      setError(err?.response?.data?.detail || 'Search failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="glass-card p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2">
          <Search className="w-4 h-4 text-eagle-400" /> Find a package on every computer
        </h3>
        <p className="text-xs text-dark-500 mt-0.5">
          Searches the latest SBOM of each computer, e.g. when a new vulnerability is announced in a package.
        </p>
      </div>
      <form onSubmit={search} className="flex flex-wrap gap-2">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Package name, e.g. authlib"
          className="input-field text-sm flex-1 min-w-[12rem]" aria-label="Package name" />
        <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Version (optional)"
          className="input-field text-sm w-40" aria-label="Exact version" />
        <button type="submit" disabled={loading} className="btn-primary text-sm flex items-center gap-2">
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Search
        </button>
      </form>
      {error && (
        <p className="text-xs text-red-400 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" />{error}</p>
      )}
      {result && (
        result.items.length === 0 ? (
          <p className="text-xs text-dark-400">
            No computer's latest SBOM has a package matching "{result.query.q}"{result.query.version ? ` ${result.query.version}` : ''}.
          </p>
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-dark-400">
              {result.items.length} match{result.items.length === 1 ? '' : 'es'} on {result.assets} computer{result.assets === 1 ? '' : 's'}
              {result.truncated ? ' (first 500 shown; add a version or a fuller name to narrow it)' : ''}
            </p>
            <div className="overflow-x-auto max-h-80 overflow-y-auto">
              <table className="data-table">
                <thead><tr><th>Package</th><th>Version</th><th>Manager</th><th>Computer</th><th>SBOM from</th></tr></thead>
                <tbody>
                  {result.items.map((r, i) => (
                    <tr key={`${r.asset_id}-${r.name}-${r.version}-${i}`}>
                      <td className="font-mono text-xs">{r.name}</td>
                      <td className="font-mono text-xs">{r.version}</td>
                      <td className="text-xs text-dark-400">{r.package_manager || '—'}</td>
                      <td className="text-xs">
                        <Link to={`/inventory/${r.asset_id}`} className="text-eagle-400 hover:underline">
                          {r.hostname || r.ip_address}
                        </Link>
                        {r.hostname && <span className="text-dark-500 font-mono"> · {r.ip_address}</span>}
                      </td>
                      <td className="text-xs text-dark-400">{r.sbom_generated_at ? new Date(r.sbom_generated_at).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )
      )}
    </div>
  )
}
