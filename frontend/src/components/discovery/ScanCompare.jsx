// Active vs passive comparison (Discovery page, Compare tab): devices found by both a
// full scan and passive listening, and what each method captured. Server: GET /scans/compare.
import { useState, useEffect } from 'react'
import client from '../../api/client'

// ── Scan Compare Panel ────────────────────────────────────────────
// A passive-scan value next to its active counterpart: ✓ same, ≠ different,
// + only the passive scan saw it (the active scan captured nothing to compare).
function PassiveValue({ value, activeValue, match }) {
  if (!activeValue) return <p className="text-cyan-500" title="Only seen by the passive scan">+ {value}</p>
  return <p className={match ? 'text-green-500' : 'text-amber-500'}>{match ? '✓ ' : '≠ '}{value}</p>
}

export default function ScanCompare() {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    client.get('/scans/compare')
      .then(r => setData(r.data))
      .catch(e => setError(e?.response?.data?.detail || 'Failed to load comparison'))
      .finally(() => setLoading(false))
  }, [])

  const richBar = (score, max = 4) => (
    <div className="flex gap-0.5">
      {Array.from({ length: max }).map((_, i) => (
        <div key={i} className={`h-1.5 w-4 rounded-sm ${i < score ? 'bg-eagle-500' : 'bg-dark-700'}`} />
      ))}
    </div>
  )

  return (
    <div className="glass-card p-5 space-y-5 overflow-x-auto">
      <div className="min-w-[860px] space-y-5">
        <div>
          <h2 className="text-sm font-semibold text-dark-100">Active vs passive</h2>
          <p className="text-xs text-dark-400 mt-0.5">Devices found by both a full scan and passive listening, side by side: what each method captured.</p>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-16">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        )}

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        {data && (
          <>
            {/* Summary stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Both Scans',   value: data.total_overlap,     color: 'text-eagle-500' },
                { label: 'Active Total', value: data.total_active_ips,  color: 'text-blue-500'  },
                { label: 'Passive Total',value: data.total_passive_ips, color: 'text-cyan-500'  },
                { label: 'Active Only',  value: data.active_only_count, color: 'text-amber-500' },
              ].map(s => (
                <div key={s.label} className="bg-dark-850 rounded-xl border border-dark-700 p-3 text-center">
                  <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                  <p className="text-xs text-dark-300 mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-4 text-xs text-dark-300 border border-dark-700 rounded-lg p-3 bg-dark-850">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> Active scan data</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" /> Passive scan data</span>
              <span className="flex items-center gap-1.5"><span className="text-green-500 font-bold">✓</span> Match between scans</span>
              <span className="flex items-center gap-1.5"><span className="text-amber-500 font-bold">≠</span> Mismatch between scans</span>
              <span className="flex items-center gap-1.5"><span className="text-cyan-500 font-bold">+</span> Only seen by the passive scan</span>
              <span className="flex items-center gap-1.5"><span className="text-dark-400">—</span> Not captured</span>
            </div>

            {data.overlap.length === 0 ? (
              <div className="text-center py-10 text-dark-400">
                <p className="text-sm">No assets found in both active and passive scan results yet.</p>
                <p className="text-xs mt-1">Run at least one active and one passive scan targeting the same subnet.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {/* Column headers */}
                <div className="grid grid-cols-12 gap-2 text-[10px] text-dark-400 uppercase tracking-wide px-3">
                  <div className="col-span-2">IP Address</div>
                  <div className="col-span-2">Hostname</div>
                  <div className="col-span-2">MAC Address</div>
                  <div className="col-span-2">Open Ports (Active)</div>
                  <div className="col-span-2">OS (Active)</div>
                  <div className="col-span-1 text-center">Active Rich.</div>
                  <div className="col-span-1 text-center">Passive Rich.</div>
                </div>

                {data.overlap.map((row) => {
                  const isExpanded = expanded === row.ip
                  const osName = row.active.os
                    ? (row.active.os.name || row.active.os.fingerbank_device || row.active.os.dhcp_device_hint || null)
                    : null
                  const portStr = row.delta.ports_found > 0
                    ? row.active.ports.slice(0, 4).map(p => `${p.port}/${p.protocol}`).join('  ') +
                      (row.active.ports.length > 4 ? ` +${row.active.ports.length - 4}` : '')
                    : null

                  return (
                    <div key={row.ip} className="rounded-xl border border-dark-700 overflow-hidden bg-dark-850">
                      {/* Row */}
                      <button
                        className="w-full grid grid-cols-12 gap-2 items-center px-3 py-2.5 hover:bg-dark-700/40 transition-colors text-left"
                        onClick={() => setExpanded(isExpanded ? null : row.ip)}
                      >
                        {/* IP */}
                        <div className="col-span-2 font-mono text-sm text-accent-cyan">{row.ip}</div>

                        {/* Hostname */}
                        <div className="col-span-2 text-xs space-y-0.5">
                          {row.active.hostname
                            ? <p className="text-blue-500">{row.active.hostname}</p>
                            : <p className="text-dark-400">—</p>}
                          {row.passive.hostname
                            ? <PassiveValue value={row.passive.hostname} activeValue={row.active.hostname} match={row.delta.hostname_match} />
                            : <p className="text-dark-400">— passive</p>}
                        </div>

                        {/* MAC */}
                        <div className="col-span-2 text-xs space-y-0.5 font-mono">
                          {row.active.mac
                            ? <p className="text-blue-500">{row.active.mac}</p>
                            : <p className="text-dark-400">—</p>}
                          {row.passive.mac
                            ? <PassiveValue value={row.passive.mac} activeValue={row.active.mac} match={row.delta.mac_match} />
                            : <p className="text-dark-400">— passive</p>}
                        </div>

                        {/* Ports */}
                        <div className="col-span-2 text-xs font-mono">
                          {portStr
                            ? <span className="text-blue-500">{portStr}</span>
                            : <span className="text-dark-400">none detected</span>}
                          <span className="block text-dark-400 text-[10px]">— passive</span>
                        </div>

                        {/* OS */}
                        <div className="col-span-2 text-xs">
                          {osName
                            ? <span className="text-blue-500">{String(osName).slice(0, 30)}</span>
                            : <span className="text-dark-400">not identified</span>}
                          <span className="block text-dark-400 text-[10px]">— passive</span>
                        </div>

                        {/* Active richness */}
                        <div className="col-span-1 flex justify-center">{richBar(row.delta.active_richness)}</div>

                        {/* Passive richness */}
                        <div className="col-span-1 flex justify-center">{richBar(row.delta.passive_richness)}</div>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="grid grid-cols-2 gap-4 px-4 py-4 border-t border-dark-700 bg-dark-900 text-xs">
                          {/* Active detail */}
                          <div className="space-y-2">
                            <p className="text-blue-500 font-semibold uppercase tracking-wide text-[10px]">Active Scan Detail</p>
                            <div className="space-y-1 text-dark-200">
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scan ID</span><span className="font-mono text-[10px] break-all">{row.active.scan_id}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Subnet</span><span>{row.active.subnet || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scanned</span><span>{new Date(row.active.scanned_at).toLocaleString()}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Hostname</span><span>{row.active.hostname || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">MAC</span><span className="font-mono">{row.active.mac || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">OS</span><span>{osName ? String(osName) : '—'}</span></div>
                              {row.active.ports.length > 0 && (
                                <div>
                                  <span className="text-dark-400">Ports</span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {row.active.ports.map((p, i) => (
                                      <span key={i} className="bg-blue-500/15 text-blue-500 border border-blue-500/40 px-1.5 py-0.5 rounded font-mono text-[10px]">
                                        {p.port}/{p.protocol}{p.service ? ` (${p.service})` : ''}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {row.active.description && (
                                <div className="flex gap-2 pt-1 border-t border-dark-700">
                                  <span className="text-dark-400 w-20 shrink-0">AI Analysis</span>
                                  <span className="text-dark-200">{row.active.description}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Passive detail */}
                          <div className="space-y-2">
                            <p className="text-cyan-500 font-semibold uppercase tracking-wide text-[10px]">Passive Scan Detail</p>
                            <div className="space-y-1 text-dark-200">
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scan ID</span><span className="font-mono text-[10px] break-all">{row.passive.scan_id}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Source</span><span>{row.passive.subnet || 'ARP Discovery'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Seen at</span><span>{new Date(row.passive.scanned_at).toLocaleString()}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Hostname</span><span>{row.passive.hostname || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">MAC</span><span className="font-mono">{row.passive.mac || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Ports</span><span className="text-dark-400 italic">not available (ARP only)</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">OS</span><span className="text-dark-400 italic">not available (ARP only)</span></div>
                              {row.passive.description && (
                                <div className="flex gap-2 pt-1 border-t border-dark-700">
                                  <span className="text-dark-400 w-20 shrink-0">AI Analysis</span>
                                  <span className="text-dark-200">{row.passive.description}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
