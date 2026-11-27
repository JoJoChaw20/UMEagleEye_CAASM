// Small parts the Threat Intelligence pages share, so each looks the same everywhere: the threat-level
// badge, dates, and the search box of a filter bar.
import { useEffect, useState } from 'react'
import { Search } from 'lucide-react'

export const LEVELS = {
  high:   { label: 'High',   cls: 'bg-red-500/15 text-red-300 border-red-500/40' },
  medium: { label: 'Medium', cls: 'bg-orange-500/15 text-orange-300 border-orange-500/40' },
  low:    { label: 'Low',    cls: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' },
}

/** An event's or advisory's threat level. */
export function LevelBadge({ level, suffix = '' }) {
  const l = LEVELS[level]
  return <span className={`inline-flex h-5 items-center whitespace-nowrap rounded border px-1.5 text-[11px] font-medium ${l?.cls ?? 'border-dark-600 text-dark-300'}`}>{l?.label ?? level}{suffix}</span>
}

/** A plain badge (status, sharing, tags). */
export function Badge({ cls = 'border-dark-600 bg-dark-700/60 text-dark-200', title, children }) {
  return <span title={title} className={`inline-flex h-5 items-center whitespace-nowrap rounded border px-1.5 text-[11px] font-medium ${cls}`}>{children}</span>
}

/** Dates in lists: "28 Nov 2026". */
export const day = (ts) => (ts ? new Date(ts).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : '—')

/** The search box at the start of a filter bar. */
export function SearchBox({ value, onChange, placeholder, label }) {
  return (
    <div className="relative">
      <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-dark-400" />
      <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        aria-label={label ?? placeholder} className="input-field w-60 max-w-full py-1.5 pl-8 text-sm" />
    </div>
  )
}

/** The value a search box holds, settled for 300 ms (so typing does not ask the server on every key). */
export function useSettled(value, ms = 300) {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return settled
}
