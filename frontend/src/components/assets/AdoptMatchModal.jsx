import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { X, Layers, CheckCircle, AlertTriangle } from 'lucide-react'
import { assetName } from './assetMeta'

// ── Adopt with matches: shown when a discovered asset looks like one already in My Assets ──
export default function AdoptMatchModal({ asset, matches, reasons, onAdopt, onReviewDuplicates, onClose, reviewLabel = 'Review duplicates' }) {
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="adopt-match-title" className="glass-card w-full max-w-lg p-6 space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
            <div>
              <h2 id="adopt-match-title" className="text-lg font-semibold text-white">This may already be in My Assets</h2>
              <p className="text-sm text-dark-300 mt-1">
                <span className="text-white font-medium">{assetName(asset)}</span> matches {matches.length === 1 ? 'an asset' : `${matches.length} assets`} you already manage.
                Adopting it would track the same device twice.
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close" className="text-dark-400 hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>

        <ul className="space-y-2">
          {matches.map((m) => (
            <li key={m.assetId} className="flex items-center justify-between gap-3 rounded-lg border border-dark-700/70 bg-dark-900/40 px-3 py-2">
              <div className="min-w-0">
                <div className="text-sm text-white font-medium truncate">{assetName(m)}</div>
                <div className="font-mono text-xs text-accent-cyan">{m.ipAddress}{m.macAddress ? ` · ${m.macAddress.toLowerCase()}` : ''}</div>
              </div>
              <Link to={`/inventory/${m.assetId}`} onClick={onClose} className="text-xs text-eagle-400 hover:underline whitespace-nowrap">Open</Link>
            </li>
          ))}
        </ul>

        <div className="rounded-lg border border-dark-700/70 bg-dark-900/30 px-3 py-2">
          <p className="text-xs text-dark-400 mb-1">Why they match</p>
          <ul className="text-xs text-dark-200 space-y-0.5 list-disc list-inside">
            {reasons.map((r) => <li key={r}>{r}</li>)}
          </ul>
        </div>

        <div className="flex flex-wrap gap-2 justify-end pt-1">
          <button onClick={onClose} className="btn-secondary text-sm">Cancel</button>
          <button onClick={onReviewDuplicates} className="btn-secondary text-sm flex items-center gap-2">
            <Layers className="w-4 h-4" /> {reviewLabel}
          </button>
          <button
            disabled={busy}
            onClick={async () => { setBusy(true); try { await onAdopt() } finally { setBusy(false) } }}
            className="btn-primary text-sm flex items-center gap-2"
          >
            <CheckCircle className="w-4 h-4" /> Adopt anyway
          </button>
        </div>
      </div>
    </div>
  )
}

