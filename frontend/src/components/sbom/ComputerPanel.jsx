import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, Download, ExternalLink } from 'lucide-react'
import client from '../../api/client'
import SbomRunNote from '../common/SbomRunNote'
import { SidePanel, Spinner } from '../common/PageParts'

const DEP_LIMIT = 1000   // the API's maximum per request

const PM_LABEL = {
  pip: 'pip (Python)', npm: 'npm (Node)', maven: 'Maven (Java)', apk: 'apk (Alpine)', deb: 'deb (Debian)',
  rpm: 'rpm (RHEL)', go: 'Go', nuget: 'NuGet (.NET)', gem: 'gem (Ruby)', cargo: 'Cargo (Rust)', system: 'System',
}
export const pmLabel = (pm) => PM_LABEL[pm] ?? pm

// One computer's SBOM: its packages (searched on the server, since a computer can have
// thousands), the package managers in it, and how the agent built it.
export default function ComputerPanel({ computer, onClose, onDownload }) {
  const sbom = computer.sbom
  const [deps, setDeps] = useState(null)
  const [pms, setPms] = useState([])
  const [counts, setCounts] = useState({ all: 0, matching: 0 })
  const [search, setSearch] = useState('')
  const [pm, setPm] = useState('')
  const request = useRef(0)
  const sbomId = sbom?.sbom_id

  useEffect(() => {
    if (!sbomId) return undefined
    const id = ++request.current
    const t = setTimeout(async () => {
      try {
        const res = await client.get(`/sboms/${sbomId}/dependencies`, {
          params: { limit: DEP_LIMIT, ...(search ? { search } : {}), ...(pm ? { package_manager: pm } : {}) },
        })
        if (id !== request.current) return       // a newer request was made meanwhile
        setDeps(res.data.items || [])
        setCounts((cur) => ({ all: !search && !pm ? res.data.total ?? 0 : cur.all, matching: res.data.total ?? 0 }))
        if (!search && !pm) setPms(res.data.package_managers || [])
      } catch {
        if (id === request.current) setDeps([])
      }
    }, search ? 300 : 0)
    return () => clearTimeout(t)
  }, [sbomId, search, pm])

  const name = computer.hostname || computer.ip_address
  return (
    <SidePanel title={name} onClose={onClose} width="sm:w-[720px]"
      subtitle={<>
        <span className="font-mono">{computer.ip_address}</span>
        {computer.agent && <> · agent {computer.agent.name}{computer.agent.version ? ` ${computer.agent.version}` : ''}</>}
      </>}>
      <div className="flex flex-wrap gap-2 text-xs">
        <Link to={`/inventory/${computer.asset_id}`} className="btn-secondary py-1 px-2.5 inline-flex items-center gap-1.5">
          Open asset <ExternalLink className="w-3 h-3" />
        </Link>
        {computer.cves.open > 0 && (
          <Link to={`/alerts?view=cve&asset_id=${computer.asset_id}&label=${encodeURIComponent(name)}`} className="btn-secondary py-1 px-2.5 inline-flex items-center gap-1.5">
            {computer.cves.open} open CVE alerts <ExternalLink className="w-3 h-3" />
          </Link>
        )}
        {sbom && (
          <button onClick={() => onDownload(computer)} className="btn-secondary py-1 px-2.5 inline-flex items-center gap-1.5">
            <Download className="w-3 h-3" /> CycloneDX file
          </button>
        )}
      </div>

      {!sbom ? (
        <p className="text-sm text-dark-400">No SBOM yet. The agent builds one every day; an admin can also start one from the list.</p>
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-2 text-xs">
            {[
              ['Generated', new Date(sbom.generated_at).toLocaleString()],
              ['Format', `${String(sbom.format).toUpperCase()} ${sbom.format_version ?? ''}`],
              ['Built with', sbom.generated_by || sbom.tool_used || '—'],
              ['Folders scanned', sbom.scope?.length ? sbom.scope.join(', ') : '—'],
            ].map(([k, v]) => (
              <div key={k} className="bg-dark-800/60 rounded-lg p-2.5">
                <dt className="text-dark-400">{k}</dt>
                <dd className="text-dark-100 mt-0.5 break-words">{v}</dd>
              </div>
            ))}
          </dl>
          <SbomRunNote run={sbom.run} />

          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-dark-200 mr-1">{counts.all.toLocaleString()} packages</h3>
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-dark-400" />
                <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter packages…"
                  aria-label="Filter packages" className="input-field text-xs pl-7 py-1 w-48" />
              </div>
            </div>
            {pms.length > 0 && (
              <div className="flex flex-wrap gap-1" role="group" aria-label="Package manager">
                <button onClick={() => setPm('')} className={`text-xs px-2 py-0.5 rounded-full border ${!pm ? 'bg-eagle-600/20 text-eagle-300 border-eagle-500/40' : 'border-dark-600 text-dark-400 hover:text-dark-200'}`}>All</button>
                {pms.map(({ package_manager: p, count }) => (
                  <button key={p} onClick={() => setPm(p)} aria-pressed={pm === p}
                    className={`text-xs px-2 py-0.5 rounded-full border ${pm === p ? 'bg-eagle-600/20 text-eagle-300 border-eagle-500/40' : 'border-dark-600 text-dark-400 hover:text-dark-200'}`}>
                    {pmLabel(p)} <span className="text-dark-500">{count}</span>
                  </button>
                ))}
              </div>
            )}
            <p className="text-xs text-dark-500">
              Showing {deps?.length ?? 0} of {counts.matching.toLocaleString()}
              {counts.matching > (deps?.length ?? 0) && ` (first ${DEP_LIMIT}; type to search all)`}
            </p>
            {deps === null ? <Spinner className="py-8" /> : (
              <div className="rounded border border-dark-700/50 overflow-x-auto">
                <table className="w-full text-xs table-fixed min-w-[560px]">
                  <colgroup><col className="w-[34%]" /><col className="w-[18%]" /><col className="w-[14%]" /><col className="w-[34%]" /></colgroup>
                  <thead className="sticky top-0 bg-dark-800">
                    <tr className="text-dark-400 border-b border-dark-700">
                      <th className="text-left py-2 px-3 font-medium">Package</th>
                      <th className="text-left py-2 px-3 font-medium">Version</th>
                      <th className="text-left py-2 px-3 font-medium">Manager</th>
                      <th className="text-left py-2 px-3 font-medium">License</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deps.length === 0 ? (
                      <tr><td colSpan="4" className="text-center py-6 text-dark-500">No matching packages</td></tr>
                    ) : deps.map((d) => (
                      <tr key={d.dependency_id} className="border-b border-dark-700/30 hover:bg-dark-700/20" title={d.purl || ''}>
                        <td className="py-1.5 px-3 text-dark-100 truncate" title={d.name}>{d.name}</td>
                        <td className="py-1.5 px-3 font-mono text-dark-400 truncate" title={d.version || ''}>{d.version || '—'}</td>
                        <td className="py-1.5 px-3 text-dark-300 truncate">{d.package_manager || 'system'}</td>
                        <td className="py-1.5 px-3 text-dark-500 truncate" title={Array.isArray(d.licenses) ? d.licenses.join(', ') : ''}>
                          {Array.isArray(d.licenses) && d.licenses.length ? d.licenses.join(', ') : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </SidePanel>
  )
}
