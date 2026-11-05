import { useEffect, useState, useCallback } from 'react'
import { X, CheckCircle2, Info, AlertTriangle } from 'lucide-react'

// Building blocks shared by the Threat Intel, SBOM and Discovery pages.

// ── Tabs (the Inventory page's tab-toggle style) ──────────────────
// tabs: [{ id, label, count? }]
export function Tabs({ tabs, active, onChange, label }) {
  return (
    <div className="flex w-fit max-w-full items-center gap-1 overflow-x-auto rounded-lg border border-dark-700 bg-dark-900 p-1" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id} onClick={() => onChange(t.id)}
          className={`tab-toggle whitespace-nowrap ${active === t.id ? 'active' : ''}`}>
          {t.label}
          {t.count != null && <span className={`ml-1 rounded px-1.5 text-[11px] tabular-nums ${active === t.id ? 'bg-eagle-500/15 text-eagle-400' : 'bg-dark-700/60 text-dark-400'}`}>{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

// ── Summary tile; clickable when onClick is given ─────────────────
const TONES = {
  default: 'text-dark-50',
  danger:  'text-red-400',
  warning: 'text-amber-400',
  good:    'text-accent-green',
  muted:   'text-dark-300',
}

export function StatTile({ label, value, sub, tone = 'default', icon: Icon, onClick, title }) {
  const body = (
    <>
      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-dark-400">{label}</span>
        {Icon && <span className="flex h-7 w-7 items-center justify-center rounded-md border border-dark-700 bg-dark-900"><Icon className={`h-3.5 w-3.5 ${tone === 'default' ? 'text-eagle-400' : TONES[tone]}`} /></span>}
      </div>
      <p className={`font-display text-[26px] font-semibold leading-none tabular-nums ${TONES[tone] ?? TONES.default}`}>{value}</p>
      {sub && <p className="mt-2 text-xs text-dark-400">{sub}</p>}
    </>
  )
  return onClick
    ? <button type="button" onClick={onClick} title={title} className="stat-card w-full text-left">{body}</button>
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
    <div className="fixed inset-0 z-50 flex justify-end bg-dark-950/70 animate-[palette-fade_160ms_ease-out]" onClick={onClose}>
      <aside role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined}
        className={`flex h-full w-full flex-col border-l border-dark-700 bg-dark-900 shadow-float animate-[panel-slide_260ms_cubic-bezier(0.16,1,0.3,1)] ${width}`}
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 border-b border-dark-700 bg-dark-800 px-5 py-4">
          <div className="min-w-0">
            <h2 className="break-words text-base font-semibold text-dark-50">{title}</h2>
            {subtitle && <div className="text-xs text-dark-400 mt-0.5">{subtitle}</div>}
          </div>
          <button type="button" onClick={onClose} className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-dark-400 transition-colors hover:bg-dark-700/40 hover:text-dark-50" title="Close" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 space-y-4 overflow-y-auto p-5">{children}</div>
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
  const style = toast.type === 'success' ? 'text-emerald-400'
    : toast.type === 'info' ? 'text-eagle-400'
    : 'text-red-400'
  const Icon = toast.type === 'success' ? CheckCircle2 : toast.type === 'info' ? Info : AlertTriangle
  return (
    <div role="status" className="fixed right-4 top-4 z-[60] flex max-w-md items-start gap-2.5 rounded-lg border border-dark-700 bg-dark-800 px-4 py-3 text-sm font-medium text-dark-100 shadow-float animate-[palette-rise_220ms_cubic-bezier(0.16,1,0.3,1)]">
      <Icon className={`mt-0.5 h-4 w-4 flex-shrink-0 ${style}`} />
      {toast.msg}
    </div>
  )
}

export function Spinner({ className = 'py-16' }) {
  return (
    <div className={`flex justify-center ${className}`} role="status" aria-label="Loading">
      <span className="trace-loader" />
    </div>
  )
}

export function Pager({ page, totalPages, onChange }) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-center gap-2">
      <button onClick={() => onChange(Math.max(1, page - 1))} disabled={page === 1} className="btn-secondary px-3 py-1.5">Previous</button>
      <span className="text-sm tabular-nums text-dark-400">Page {page} of {totalPages}</span>
      <button onClick={() => onChange(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="btn-secondary px-3 py-1.5">Next</button>
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
