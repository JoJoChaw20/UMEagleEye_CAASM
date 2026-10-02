import { useState, useEffect, useCallback } from 'react'
import { X, RefreshCw, Layers, AlertTriangle, ShieldCheck } from 'lucide-react'
import client from '../../api/client'

// Modal panel listing duplicate asset groups with per-group preview/merge and a
// "merge all safe" loop. Styling follows the existing dark-theme component patterns.
export default function DuplicatesPanel({ tenantId, canMerge, onClose, onMerged }) {
  const [groups, setGroups] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [survivors, setSurvivors] = useState({})   // groupId -> chosen survivorId
  const [previews, setPreviews] = useState({})     // groupId -> dry_run result
  const [busy, setBusy] = useState(null)           // groupId | 'all' while working
  const [progress, setProgress] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = tenantId ? { tenant_id: tenantId } : {}
      const res = await client.get('/assets/duplicates', { params })
      const gs = res.data.groups || []
      setGroups(gs)
      setSurvivors(Object.fromEntries(gs.map((g) => [g.groupId, g.suggestedSurvivorId])))
      setPreviews({})
      setError(null)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load duplicates')
    } finally {
      setLoading(false)
    }
  }, [tenantId])

  useEffect(() => { load() }, [load])

  const safeGroups = groups.filter((g) => g.confidence === 'safe')

  const preview = async (g) => {
    const survivorId = survivors[g.groupId]
    const loser_ids = g.assets.map((a) => a.assetId).filter((id) => id !== survivorId)
    setBusy(g.groupId)
    try {
      const res = await client.post('/assets/merge', { survivor_id: survivorId, loser_ids, dry_run: true })
      setPreviews((p) => ({ ...p, [g.groupId]: res.data }))
    } catch (err) {
      setError(err?.response?.data?.detail || 'Preview failed')
    } finally { setBusy(null) }
  }

  const mergeGroup = async (g) => {
    const survivorId = survivors[g.groupId]
    const loser_ids = g.assets.map((a) => a.assetId).filter((id) => id !== survivorId)
    const names = g.assets.filter((a) => a.assetId !== survivorId).map((a) => a.hostname || a.ipAddress).join(', ')
    if (!window.confirm(`Merge and PERMANENTLY remove ${loser_ids.length} asset(s) into the survivor?\n\nRemoved: ${names}\n\nThis cannot be undone from the UI.`)) return
    setBusy(g.groupId)
    try {
      await client.post('/assets/merge', { survivor_id: survivorId, loser_ids })
      await load()
      onMerged?.()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Merge failed')
    } finally { setBusy(null) }
  }

  const mergeAllSafe = async () => {
    if (!window.confirm(`Merge all ${safeGroups.length} safe group(s) using each group's suggested survivor?\n\nThis permanently removes the duplicate rows and cannot be undone from the UI.`)) return
    setBusy('all')
    setProgress({ done: 0 })
    try {
      let guard = 0
      // Loop the server endpoint (it merges up to 4 groups/request) until none remain.
      while (guard++ < 50) {
        const res = await client.post('/assets/duplicates/merge-safe', {})
        setProgress((p) => ({ done: (p?.done || 0) + (res.data.merged?.length || 0) }))
        if (!res.data.remaining || res.data.remaining <= 0) break
      }
      await load()
      onMerged?.()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Merge-all failed')
    } finally { setBusy(null); setProgress(null) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 overflow-y-auto">
      <div className="w-full max-w-4xl bg-dark-900 border border-dark-700 rounded-xl shadow-xl my-8">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-accent-cyan" />
            <h2 className="text-lg font-semibold text-white">Duplicate Assets</h2>
            <span className="text-xs text-dark-400">{groups.length} group(s), {safeGroups.length} safe</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={load} className="btn-secondary text-xs flex items-center gap-1.5" disabled={loading || !!busy}>
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </button>
            <button onClick={onClose} className="text-dark-400 hover:text-white"><X className="w-5 h-5" /></button>
          </div>
        </div>

        <div className="p-5 space-y-4">
          {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{error}</div>}

          {canMerge && safeGroups.length > 0 && (
            <div className="flex items-center justify-between bg-dark-850 border border-dark-700 rounded-lg px-4 py-3">
              <div className="text-sm text-dark-200 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-green-500" />
                Merge all safe groups ({safeGroups.length}) using the suggested survivor each.
              </div>
              <button onClick={mergeAllSafe} disabled={!!busy} className="btn-primary text-sm">
                {busy === 'all' ? `Merging… ${progress?.done ?? 0}` : 'Merge all safe'}
              </button>
            </div>
          )}

          {loading ? (
            <p className="text-dark-400 text-sm">Loading…</p>
          ) : groups.length === 0 ? (
            <p className="text-dark-400 text-sm">No duplicate groups found. 🎉</p>
          ) : (
            groups.map((g) => (
              <div key={g.groupId} className="border border-dark-700 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 bg-dark-850 border-b border-dark-700">
                  <div className="flex items-center gap-2">
                    {g.confidence === 'safe'
                      ? <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-500 border border-green-500/40 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> Safe</span>
                      : <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Review</span>}
                    <span className="text-xs text-dark-300">{g.reasons.join('; ')}</span>
                  </div>
                  <span className="text-xs text-dark-500">{g.assets.length} assets</span>
                </div>

                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-dark-400 border-b border-dark-800">
                      <th className="px-4 py-1.5 w-8">Keep</th>
                      <th className="px-2 py-1.5">Hostname</th>
                      <th className="px-2 py-1.5">IP</th>
                      <th className="px-2 py-1.5">MAC</th>
                      <th className="px-2 py-1.5">Source</th>
                      <th className="px-2 py-1.5">Last scanned</th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.assets.map((a) => (
                      <tr key={a.assetId} className="border-b border-dark-800 last:border-0">
                        <td className="px-4 py-1.5">
                          <input type="radio" name={`survivor-${g.groupId}`} checked={survivors[g.groupId] === a.assetId}
                            onChange={() => setSurvivors((s) => ({ ...s, [g.groupId]: a.assetId }))} disabled={!canMerge} />
                        </td>
                        <td className="px-2 py-1.5 text-dark-100">{a.hostname || <span className="text-dark-500">—</span>}</td>
                        <td className="px-2 py-1.5 font-mono text-accent-cyan">{a.ipAddress}</td>
                        <td className="px-2 py-1.5 font-mono text-dark-300">{a.macAddress || '—'}</td>
                        <td className="px-2 py-1.5">{a.source === 'manual'
                          ? <span className="text-green-500">My Assets</span>
                          : <span className="text-dark-400">{a.source?.replace('scan_', '') || 'scan'}</span>}</td>
                        <td className="px-2 py-1.5 text-dark-400">{a.lastScanned ? new Date(a.lastScanned).toLocaleString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {previews[g.groupId] && (
                  <div className="px-4 py-2 text-xs text-dark-300 bg-dark-850/60 border-t border-dark-800">
                    Will move: {previews[g.groupId].counts.addressesMoved} address(es)
                    ({previews[g.groupId].counts.addressesEnded} ended),
                    {' '}{previews[g.groupId].counts.eventsMoved} event(s),
                    {' '}{previews[g.groupId].counts.sbomsMoved} sbom(s),
                    {' '}{previews[g.groupId].counts.dependenciesMoved} dep(s),
                    {' '}{previews[g.groupId].counts.relationshipsMoved} rel moved / {previews[g.groupId].counts.relationshipsDropped} dropped.
                  </div>
                )}

                {canMerge && (
                  <div className="flex items-center justify-end gap-2 px-4 py-2 border-t border-dark-800">
                    <button onClick={() => preview(g)} disabled={!!busy} className="btn-secondary text-xs">
                      {busy === g.groupId ? '…' : 'Preview'}
                    </button>
                    <button onClick={() => mergeGroup(g)} disabled={!!busy} className="btn-primary text-xs">Merge</button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
