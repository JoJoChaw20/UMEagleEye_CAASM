import { useEffect, useState, useCallback } from 'react'
import { X, CheckCircle2, Info, AlertTriangle } from 'lucide-react'

// Building blocks shared by the Threat Intel, SBOM and Discovery pages.

// ── Tabs (the Inventory page's tab-toggle style) ──────────────────
// tabs: [{ id, label, count? }]
export function Tabs({ tabs, active, onChange, label }) {
  return (
    <div className="flex items-center gap-1 p-1 bg-dark-800/60 rounded-xl w-fit max-w-full overflow-x-auto border border-dark-700/50" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id} onClick={() => onChange(t.id)}
          className={`tab-toggle whitespace-nowrap ${active === t.id ? 'active' : ''}`}>
          {t.label}
          {t.count != null && <span className="text-xs text-dark-400 ml-1">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

// ── Summary tile; clickable when onClick is given ─────────────────
const TONES = {
  default: 'text-white',
  danger:  'text-red-400',
  warning: 'text-amber-400',
  good:    'text-accent-green',
  muted:   'text-dark-300',
}

export function StatTile({ label, value, sub, tone = 'default', icon: Icon, onClick, title }) {
  const body = (
    <>
      <div className="flex items-center justify-between mb-2 gap-2">
        <span className="text-dark-400 text-xs">{label}</span>
        {Icon && <Icon className={`w-4 h-4 ${tone === 'default' ? 'text-eagle-400' : TONES[tone]}`} />}
      </div>
      <p className={`text-2xl font-bold ${TONES[tone] ?? TONES.default}`}>{value}</p>
      {sub && <p className="text-xs text-dark-500 mt-1">{sub}</p>}
    </>
  )
  return onClick
    ? <button type="button" onClick={onClick} title={title} className="stat-card text-left w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-eagle-500">{body}</button>
    : <div className="stat-card" title={title}>{body}</div>
}

// ── Right-hand side panel (closes on Esc or the backdrop) ─────────
export function SidePanel({ title, subtitle, onClose, children, width = 'sm:w-[560px]' }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <aside role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined}
        className={`w-full ${width} h-full flex flex-col bg-dark-900 border-l border-dark-700 shadow-2xl`}
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 p-4 border-b border-dark-700">
          <div className="min-w-0">
            <h2 className="font-semibold text-dark-100 break-words">{title}</h2>
            {subtitle && <div className="text-xs text-dark-400 mt-0.5">{subtitle}</div>}
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-100 transition-colors shrink-0" title="Close">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-4">{children}</div>
      </aside>
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────
export function useToast() {
  const [toast, setToast] = useState(null)
  const show = useCallback((msg, type = 'success') => setToast({ msg, type, at: Date.now() }), [])
  useEffect(() => {
    if (!toast) return undefined
    const t = setTimeout(() => setToast(null), 4500)
    return () => clearTimeout(t)
  }, [toast])
  return { toast, show }
}

export function Toast({ toast }) {
  if (!toast) return null
  const style = toast.type === 'success' ? 'bg-green-900/90 text-green-200 border-green-700'
    : toast.type === 'info' ? 'bg-blue-900/90 text-blue-200 border-blue-700'
    : 'bg-red-900/90 text-red-200 border-red-700'
  const Icon = toast.type === 'success' ? CheckCircle2 : toast.type === 'info' ? Info : AlertTriangle
  return (
    <div role="status" className={`fixed top-4 right-4 z-[60] flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg text-sm font-medium border max-w-md ${style}`}>
      <Icon className="w-4 h-4 flex-shrink-0" />
      {toast.msg}
    </div>
  )
}

export function Spinner({ className = 'py-16' }) {
  return (
    <div className={`flex justify-center ${className}`}>
      <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
    </div>
  )
}

export function Pager({ page, totalPages, onChange }) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-center gap-2">
      <button onClick={() => onChange(Math.max(1, page - 1))} disabled={page === 1} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Previous</button>
      <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
      <button onClick={() => onChange(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Next</button>
    </div>
  )
}

/** "3 h ago" style, or the fallback for no value. */
export function ago(ts, fallback = '—') {
  if (!ts) return fallback
  const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (Number.isNaN(sec)) return fallback
  if (sec < 60) return 'just now'
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`
  return `${Math.floor(sec / 86400)} d ago`
}
