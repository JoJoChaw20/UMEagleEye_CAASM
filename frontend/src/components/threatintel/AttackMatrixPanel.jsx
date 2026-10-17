import { useEffect, useMemo, useState } from 'react'
import { Download, ExternalLink, Info, RefreshCw, X } from 'lucide-react'
import client from '../../api/client'

// MITRE ATT&CK view of the feeds (GET /cti/matrix). Techniques come from MITRE's own
// data for each indicator's malware family; nothing is inferred from type or tags.

const SHADE = '#3393ff'
const COLUMN_ROWS = 14

const rgba = (hex, a) => {
  const n = parseInt(hex.slice(1), 16)
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a.toFixed(2)})`
}
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0)
const fmtDate = (d) => (d ? new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '')
const techUrl = (id) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
const softUrl = (id) => `https://attack.mitre.org/software/${id}/`

// ATT&CK Navigator layer (format 4.5): open at https://mitre-attack.github.io/attack-navigator/
function navigatorLayer(data) {
  const entries = []
  for (const t of data.techniques) {
    entries.push({
      techniqueID: t.id,
      score: t.iocs,
      comment: `${t.iocs} feed indicator(s); families: ${t.families.map((f) => f.name).join(', ')}`,
      showSubtechniques: t.subs.length > 0,
    })
    for (const s of t.subs) entries.push({ techniqueID: s.id, score: s.iocs, comment: `${s.iocs} feed indicator(s)` })
  }
  return {
    name: 'UMEagleEye threat-intel feeds',
    versions: { attack: data.attack.version.split('.')[0], navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Feed indicators per technique, from the techniques MITRE ATT&CK v${data.attack.version} documents for each indicator's malware family. Exported ${new Date().toISOString().slice(0, 10)}.`,
    sorting: 3,
    layout: { layout: 'side', showID: true, showName: true },
    hideDisabled: false,
    techniques: entries,
    gradient: { colors: ['#e3f2fd', '#1565c0'], minValue: 0, maxValue: Math.max(1, ...data.techniques.map((t) => t.iocs)) },
    legendItems: [],
    metadata: [{ name: 'source', value: 'UMEagleEye' }],
  }
}

function downloadLayer(data) {
  const blob = new Blob([JSON.stringify(navigatorLayer(data), null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `umeagleeye-attack-layer-${new Date().toISOString().slice(0, 10)}.json`
  a.click()
  URL.revokeObjectURL(a.href)
}

export default function AttackMatrixPanel({ onShowIndicators }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [shadeBy, setShadeBy] = useState('iocs')    // iocs | families
  const [selected, setSelected] = useState(null)    // technique id
  const [expanded, setExpanded] = useState({})      // tactic short -> true

  const load = async () => {
    setError('')
    try {
      const res = await client.get('/cti/matrix')
      setData(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load the ATT&CK matrix.')
    }
  }
  useEffect(() => { load() }, [])

  const columns = useMemo(() => {
    if (!data) return []
    const metric = (t) => (shadeBy === 'iocs' ? t.iocs : t.family_count)
    return data.tactics.map((tac) => ({
      ...tac,
      techniques: data.techniques.filter((t) => t.tactics.includes(tac.short)).sort((a, b) => metric(b) - metric(a)),
    }))
  }, [data, shadeBy])

  if (error) {
    return (
      <div className="glass-card p-6 text-sm text-red-500 flex items-center gap-2">
        {error}
        <button onClick={load} className="btn-secondary text-xs py-1 px-2 ml-auto">Retry</button>
      </div>
    )
  }
  if (!data) {
    return (
      <div className="flex justify-center py-20">
        <RefreshCw className="w-6 h-6 animate-spin text-dark-400" />
      </div>
    )
  }

  const { coverage: cov, attack } = data
  const max = Math.max(1, ...data.techniques.map((t) => (shadeBy === 'iocs' ? t.iocs : t.family_count)))
  const sel = selected && data.techniques.find((t) => t.id === selected)

  return (
    <div className="space-y-4">
      {/* Where the techniques come from, and how much of the feed they cover */}
      <div className="glass-card p-5 space-y-3">
        <div className="flex items-start gap-3 flex-wrap">
          <div className="flex-1 min-w-[260px]">
            <h3 className="text-sm font-semibold text-dark-100">
              {pct(cov.with_attack, cov.total)}% of feed indicators have ATT&CK techniques
            </h3>
            <p className="text-xs text-dark-400 mt-1">
              {cov.with_attack.toLocaleString()} of {cov.total.toLocaleString()} indicators (OTX, ThreatFox; CISA KEV CVEs are not malware and are not counted).
              An indicator gets the techniques MITRE documents for its malware family, or the ones the feed names itself. Nothing is guessed from the indicator type.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] px-2 py-1 rounded bg-dark-800 text-dark-300 border border-dark-700/60" title={attack.source}>
              MITRE ATT&CK v{attack.version} · {fmtDate(attack.modified)}
            </span>
            <button onClick={() => downloadLayer(data)} disabled={!data.techniques.length}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 disabled:opacity-40"
              title="Download a layer file to open in MITRE's ATT&CK Navigator">
              <Download className="w-3.5 h-3.5" /> Navigator layer
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
          <div className="bg-dark-800/60 rounded-lg p-2.5">
            <p className="text-dark-400">Family matched in ATT&CK</p>
            <p className="text-dark-100 font-medium">{cov.families_matched} of {cov.families} families</p>
          </div>
          <div className="bg-dark-800/60 rounded-lg p-2.5">
            <p className="text-dark-400">Family not documented by MITRE</p>
            <p className="text-dark-100 font-medium">{(cov.with_family - Math.min(cov.with_family, cov.with_attack)).toLocaleString()} indicators</p>
          </div>
          <div className="bg-dark-800/60 rounded-lg p-2.5">
            <p className="text-dark-400">No family named by the feed</p>
            <p className="text-dark-100 font-medium">{(cov.total - cov.with_family).toLocaleString()} indicators</p>
          </div>
        </div>

        {cov.top_unmatched.length > 0 && (
          <p className="text-[11px] text-dark-500">
            <Info className="w-3 h-3 inline mr-1 -mt-0.5" />
            Largest families ATT&CK does not document yet: {cov.top_unmatched.map((f) => `${f.name} (${f.iocs.toLocaleString()})`).join(', ')}.
          </p>
        )}
      </div>

      {/* Matrix */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between gap-3 mb-1 flex-wrap">
          <h3 className="text-sm font-semibold text-dark-200">Techniques seen in the feeds</h3>
          <div className="flex items-center gap-1 bg-dark-800 rounded-md p-0.5 text-[11px]">
            {[['iocs', 'Indicators'], ['families', 'Families']].map(([id, label]) => (
              <button key={id} onClick={() => setShadeBy(id)}
                className={`px-2 py-1 rounded ${shadeBy === id ? 'bg-eagle-600 text-white' : 'text-dark-400 hover:text-dark-100'}`}>
                {label}
              </button>
            ))}
          </div>
        </div>
        <p className="text-[11px] text-dark-500 mb-4">
          Shade = {shadeBy === 'iocs' ? 'indicators whose family uses the technique' : 'malware families that use the technique'}.
          {' '}A family with many techniques counts towards all of them, so also compare by families. Click a technique for details.
        </p>

        {data.techniques.length === 0 ? (
          <p className="text-center py-12 text-sm text-dark-400">
            No feed indicator has ATT&CK techniques yet. Families are recorded as the feeds are ingested.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <div className="flex gap-1 min-w-max pb-2">
              {columns.map((col) => {
                const rows = expanded[col.short] ? col.techniques : col.techniques.slice(0, COLUMN_ROWS)
                return (
                  <div key={col.short} className="flex flex-col gap-0.5 w-[118px]">
                    <div className="text-center px-1 py-1 rounded bg-dark-800 border border-dark-700/60 h-12 flex flex-col items-center justify-center"
                      title={`${col.name} (${col.id})`}>
                      <span className="text-[10px] font-bold leading-tight text-dark-100">{col.name}</span>
                      <span className="text-[9px] text-dark-500">{col.techniques.length} of {col.technique_total}</span>
                    </div>
                    {rows.map((t) => {
                      const v = shadeBy === 'iocs' ? t.iocs : t.family_count
                      const a = 0.12 + (v / max) * 0.78
                      const isSel = t.id === selected
                      return (
                        <button key={t.id} onClick={() => setSelected(isSel ? null : t.id)}
                          title={`${t.id} ${t.name}: ${t.iocs.toLocaleString()} indicators, ${t.family_count} families`}
                          className={`text-left px-1.5 py-1 rounded text-[10px] leading-tight transition-transform hover:scale-[1.03] ${isSel ? 'ring-2 ring-accent-orange' : ''}`}
                          style={{ background: rgba(SHADE, a), color: a > 0.55 ? '#fff' : undefined, border: `1px solid ${rgba(SHADE, 0.35)}` }}>
                          <span className="block truncate font-medium">{t.name}</span>
                          <span className="flex justify-between font-mono text-[9px] opacity-80">
                            <span>{t.id}</span><span>{v.toLocaleString()}</span>
                          </span>
                        </button>
                      )
                    })}
                    {col.techniques.length === 0 && (
                      <div className="text-center py-1.5 rounded text-[10px] text-dark-600 border border-dark-800/40">—</div>
                    )}
                    {col.techniques.length > COLUMN_ROWS && (
                      <button onClick={() => setExpanded((e) => ({ ...e, [col.short]: !e[col.short] }))}
                        className="text-[10px] text-dark-400 hover:text-dark-100 py-1">
                        {expanded[col.short] ? 'Show fewer' : `+${col.techniques.length - COLUMN_ROWS} more`}
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Technique detail */}
      {sel && (
        <div className="glass-card p-5 space-y-4">
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-semibold text-dark-100">
                {sel.name} <span className="font-mono text-dark-400">{sel.id}</span>
              </h3>
              <p className="text-xs text-dark-400 mt-0.5">
                {sel.tactics.map((s) => data.tactics.find((t) => t.short === s)?.name ?? s).join(', ')}
                {' · '}{sel.iocs.toLocaleString()} indicators · {sel.family_count} families
              </p>
            </div>
            <a href={techUrl(sel.id)} target="_blank" rel="noreferrer"
              className="text-xs text-eagle-400 hover:underline flex items-center gap-1">
              On attack.mitre.org <ExternalLink className="w-3 h-3" />
            </a>
            <button onClick={() => setSelected(null)} className="p-1 text-dark-400 hover:text-dark-100" title="Close">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-medium text-dark-300 mb-2">Families that use it</p>
              <div className="space-y-1">
                {sel.families.map((f) => (
                  <div key={f.software ?? f.name} className="flex items-center gap-2 text-xs bg-dark-800/60 rounded px-2 py-1.5">
                    <span className="flex-1 min-w-0 truncate text-dark-100">
                      {f.name}
                      {f.software && (
                        <a href={softUrl(f.software)} target="_blank" rel="noreferrer" className="ml-1.5 font-mono text-dark-500 hover:text-eagle-400">{f.software}</a>
                      )}
                    </span>
                    <span className="text-dark-400">{f.iocs.toLocaleString()}</span>
                    {f.software && onShowIndicators && (
                      <button onClick={() => onShowIndicators({ family: f.software, label: f.name })}
                        className="text-eagle-400 hover:underline">Indicators</button>
                    )}
                  </div>
                ))}
                {sel.family_count > sel.families.length && (
                  <p className="text-[11px] text-dark-500">and {sel.family_count - sel.families.length} more</p>
                )}
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-dark-300 mb-2">Sub-techniques</p>
              {sel.subs.length ? (
                <div className="space-y-1">
                  {sel.subs.map((s) => (
                    <a key={s.id} href={techUrl(s.id)} target="_blank" rel="noreferrer"
                      className="flex items-center gap-2 text-xs bg-dark-800/60 rounded px-2 py-1.5 hover:bg-dark-700/60">
                      <span className="font-mono text-dark-400 w-16">{s.id}</span>
                      <span className="flex-1 truncate text-dark-100">{s.name}</span>
                      <span className="text-dark-400">{s.iocs.toLocaleString()}</span>
                    </a>
                  ))}
                </div>
              ) : <p className="text-xs text-dark-500">MITRE lists the technique itself, not a sub-technique.</p>}
            </div>
          </div>

          {onShowIndicators && (
            <button onClick={() => onShowIndicators({ technique: sel.id, label: `${sel.id} ${sel.name}` })}
              className="btn-secondary text-xs py-1.5 px-3">
              View the {sel.iocs.toLocaleString()} indicators
            </button>
          )}
        </div>
      )}
    </div>
  )
}
