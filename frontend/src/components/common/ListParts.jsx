// The parts every list is built from (Threat Intelligence first): one filter bar of chips and toggles,
// the total in words, the "Showing 1–20 of 89 advisories" pager with Previous and Next, and one empty state.
// A count always names what it counts.
import { useState } from 'react'

/** "1 advisory", "89 advisories". */
export const plural = (n, one, many) => `${Number(n ?? 0).toLocaleString()} ${n === 1 ? one : (many ?? `${one}s`)}`

/** The row of search, chips, toggles and the total above a list. */
export function FilterBar({ children }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>
}

/** A chip: one choice of a group (All / Ours / Shared) or an on/off toggle. `count`: how many it keeps. */
export function FilterChip({ pressed, onClick, children, count, icon: Icon, title }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={!!pressed} title={title}
      className={`inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-xs transition-colors ${pressed
        ? 'border-eagle-500/50 bg-eagle-600/15 text-eagle-300'
        : 'border-dark-600 text-dark-300 hover:border-dark-500 hover:text-dark-100'}`}>
      {Icon && <Icon className="h-3.5 w-3.5" />}
      {children}
      {count != null && <span className={`tabular-nums ${pressed ? 'text-eagle-300/80' : 'text-dark-500'}`}>{Number(count).toLocaleString()}</span>}
    </button>
  )
}

/** A thin divider between chip groups. */
export const ChipDivider = () => <span className="hidden h-5 w-px bg-dark-700 sm:inline-block" aria-hidden="true" />

/** "Clear", shown while any filter is set. */
export function ClearFilters({ onClick }) {
  return <button type="button" onClick={onClick} className="text-xs text-dark-400 underline underline-offset-2 hover:text-dark-200">Clear</button>
}

/** The list's total at the right of the filter bar: "89 advisories", "6 matches on 3 devices". */
export function ListTotal({ children }) {
  return <span className="ml-auto whitespace-nowrap text-sm text-dark-400 [&_b]:font-semibold [&_b]:text-dark-100 [&_b]:tabular-nums">{children}</span>
}

/** Under a list: "Showing 21–40 of 89 advisories" and Previous / Page 2 of 5 / Next. */
export function ListPager({ page, pageSize, total, one, many, onChange }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total ? (page - 1) * pageSize + 1 : 0
  const to = Math.min(total, page * pageSize)
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-dark-700/50 px-4 py-2.5 text-xs text-dark-400">
      <span className="tabular-nums">Showing {from.toLocaleString()}–{to.toLocaleString()} of {plural(total, one, many)}</span>
      <span className="flex items-center gap-2">
        <button type="button" onClick={() => onChange(page - 1)} disabled={page <= 1} className="btn-secondary px-3 py-1 text-xs disabled:opacity-40">Previous</button>
        <span className="tabular-nums">Page {page} of {pages}</span>
        <button type="button" onClick={() => onChange(page + 1)} disabled={page >= pages} className="btn-secondary px-3 py-1 text-xs disabled:opacity-40">Next</button>
      </span>
    </div>
  )
}

/**
 * A list inside a side panel: ten rows a page with the same pager. `rows` are all of them (an event's
 * indicators), or one page from the server when `total` and `page`/`onPage` are given (a technique's).
 * `head`: the column titles; `row(item)`: one <tr>.
 */
export function PanelList({ rows, head, row, one, many, total, page: serverPage, onPage, pageSize = 10, empty = 'None.' }) {
  const [localPage, setLocalPage] = useState(1)
  const paged = onPage == null
  const count = paged ? rows.length : total
  const page = paged ? pageWithin(localPage, pageSize, rows.length) : serverPage
  const shown = paged ? rows.slice((page - 1) * pageSize, page * pageSize) : rows
  return (
    <div className="overflow-hidden rounded-lg border border-dark-700/60">
      <div className="overflow-x-auto">
        <table className="data-table">
          <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>
            {shown.length ? shown.map(row) : <tr><td colSpan={head.length} className="text-sm text-dark-500">{empty}</td></tr>}
          </tbody>
        </table>
      </div>
      {count > pageSize && <ListPager page={page} pageSize={pageSize} total={count} one={one} many={many} onChange={paged ? setLocalPage : onPage} />}
    </div>
  )
}

/** The page a list should show after its total changed (a filter, a deletion). */
export const pageWithin = (page, pageSize, total) => Math.min(page, Math.max(1, Math.ceil(total / pageSize)))

/** A list with nothing to show: what is missing, and a way out when filters caused it. */
export function EmptyState({ icon: Icon, title, filtered, onClear, children }) {
  return (
    <div className="px-4 py-14 text-center text-dark-400">
      {Icon && <Icon className="mx-auto mb-3 h-12 w-12 opacity-20" />}
      <p className="font-medium text-dark-200">{filtered ? `${title} match these filters` : title}</p>
      {!filtered && children && <div className="mx-auto mt-1 max-w-lg text-sm">{children}</div>}
      {filtered && onClear && <button type="button" onClick={onClear} className="mt-2 text-sm text-eagle-400 hover:underline">Clear filters</button>}
    </div>
  )
}
