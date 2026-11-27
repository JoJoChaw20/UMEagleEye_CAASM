// An ATT&CK technique's view in the Threat Intelligence panel (TiPanel.jsx), opened from the matrix
// (AttackMatrixPanel.jsx): the families or events that use it, its sub-techniques, and its indicators listed
// right here, ten a page (GET /cti/indicators?technique=); one opens on top, with "←" back to the technique.
import { useEffect, useState } from 'react'
import { ExternalLink } from 'lucide-react'
import client from '../../api/client'
import { PanelList, plural } from '../common/ListParts'
import { Spinner } from '../common/PageParts'
import { TypeLabel } from './IndicatorPanel'

const techUrl = (id) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
const softUrl = (id) => `https://attack.mitre.org/software/${id}/`
const PAGE = 10

export default function TechniqueView({ view, setHead, panel }) {
  const { tech, scope, tactics } = view
  const isEvents = scope === 'events'
  const listsIndicators = scope === 'feeds' || scope === 'matched'
  const [page, setPage] = useState(1)
  const [data, setData] = useState(null)

  useEffect(() => {
    setHead({
      title: <><span className="font-mono text-dark-400">{tech.id}</span> {tech.name}</>,
      subtitle: `MITRE ATT&CK · ${tech.tactics.map((s) => tactics.find((t) => t.short === s)?.name ?? s).join(', ')}`,
      footer: (
        <a href={techUrl(tech.id)} target="_blank" rel="noreferrer" className="btn-secondary inline-flex items-center gap-1.5 text-sm">
          On attack.mitre.org <ExternalLink className="h-3.5 w-3.5" />
        </a>
      ),
    })
  }, [tech, tactics, setHead])

  useEffect(() => {
    if (!listsIndicators) return
    setData(null)
    client.get('/cti/indicators', { params: { technique: tech.id, page, limit: PAGE, ...(scope === 'matched' ? { matched: 'true' } : {}) } })
      .then((r) => setData(r.data))
      .catch(() => setData({ items: [], total: 0 }))
  }, [tech.id, page, scope, listsIndicators])

  const label = `${tech.id} ${tech.name}`
  return (
    <div className="space-y-5">
      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5 text-sm">
        <dt className="text-dark-400">Indicators</dt><dd className="tabular-nums text-dark-100">{tech.iocs.toLocaleString()}</dd>
        <dt className="text-dark-400">{isEvents ? 'Events' : 'Malware families'}</dt><dd className="tabular-nums text-dark-100">{tech.family_count}</dd>
      </dl>

      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">{isEvents ? 'Events with it' : 'Families that use it'}</h3>
        {tech.families.length === 0 ? <p className="text-sm text-dark-500">None named.</p> : (
          <div className="flex flex-wrap gap-1.5">
            {tech.families.map((f) => (
              <span key={f.software ?? f.name} className="inline-flex items-center gap-1.5 rounded border border-dark-700 bg-dark-800/60 px-2 py-0.5 text-xs text-dark-200">
                {f.name}
                {f.software && <a href={softUrl(f.software)} target="_blank" rel="noreferrer" className="font-mono text-dark-500 hover:text-eagle-400">{f.software}</a>}
                <span className="tabular-nums text-dark-500">{f.iocs.toLocaleString()}</span>
              </span>
            ))}
            {tech.family_count > tech.families.length && <span className="text-xs text-dark-500">and {tech.family_count - tech.families.length} more</span>}
          </div>
        )}
      </section>

      {tech.subs.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">Sub-techniques · {tech.subs.length}</h3>
          <div className="space-y-1">
            {tech.subs.map((s) => (
              <a key={s.id} href={techUrl(s.id)} target="_blank" rel="noreferrer" className="flex items-center gap-2 rounded bg-dark-800/60 px-2 py-1.5 text-xs hover:bg-dark-700/60">
                <span className="w-16 font-mono text-dark-400">{s.id}</span><span className="flex-1 truncate text-dark-100">{s.name}</span>
                <span className="tabular-nums text-dark-400">{plural(s.iocs, 'indicator')}</span>
              </a>
            ))}
          </div>
        </section>
      )}

      {listsIndicators && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">
            Indicators{data ? ` · ${data.total.toLocaleString()}` : ''}{scope === 'matched' ? ' matching your devices' : ''}
          </h3>
          {!data ? <Spinner className="py-8" /> : (
            <PanelList rows={data.items} total={data.total} page={page} onPage={setPage} pageSize={PAGE}
              head={['Type', 'Value', 'Source', 'Family']} one="indicator"
              row={(i) => (
                <tr key={i.indicator_id} tabIndex={0} className="cursor-pointer hover:bg-dark-700/30"
                  onClick={() => panel.push({ kind: 'indicator', value: i.value, label })}
                  onKeyDown={(e) => { if (e.key === 'Enter') panel.push({ kind: 'indicator', value: i.value, label }) }}>
                  <td><TypeLabel type={i.indicator_type} /></td>
                  <td className="max-w-[18rem] break-all font-mono text-xs text-accent-cyan">{i.value}</td>
                  <td className="text-xs text-dark-300">{i.source}</td>
                  <td className="text-xs text-dark-300">{i.malware_family || '—'}</td>
                </tr>
              )} />
          )}
        </section>
      )}
    </div>
  )
}
