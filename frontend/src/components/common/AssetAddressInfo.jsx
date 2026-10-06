import { useState, useEffect } from 'react'
import { History, ChevronRight, ChevronDown } from 'lucide-react'
import client from '../../api/client'

const fmtDate = (d) => (d ? new Date(d).toLocaleDateString() : '—')
const stripSep = (s) => (s || '').toLowerCase().replace(/[:.\-]/g, '')

// Does the search term look like a MAC (address) rather than an IP/hostname?
function isMacTerm(term) {
  if (!term) return false
  const s = stripSep(term)
  const looksMac = /[a-f]/i.test(term) || /[:\-]/.test(term)
  return looksMac && /^[0-9a-f]+$/.test(s) && s.length >= 2
}

// Local mirror of the worker matcher — only used to highlight the timeline rows
// that matched the search term (purely cosmetic).
function rowMatchesTerm(row, term) {
  if (!term) return false
  if ((row.ipAddress || '').toLowerCase().includes(term.toLowerCase())) return true
  if (isMacTerm(term)) return stripSep(row.macAddress).includes(stripSep(term))
  return false
}

// One-line, truncating trigger shown INSIDE the IP/hostname cell. Renders at most a
// single line so a row is never more than one line taller while collapsed: either a
// "History match" summary (when the search hit an older address) or an "N addresses"
// hint. Clicking it toggles the full-width timeline row (rendered by the page).
export function AddressCellInfo({ asset, searchTerm, expanded, onToggle }) {
  const history = (asset?.matches || []).filter((m) => m.field === 'address_history')
  const hasHistory = history.length > 0
  const multi = (asset?.addressCount ?? 0) > 1
  if (!hasHistory && !multi) return null

  let text
  if (hasHistory) {
    const total = asset.matchedAddressCount ?? history.length
    if (isMacTerm(searchTerm)) {
      const mac = history[0].mac || searchTerm
      text = `Matched MAC ${mac} on ${total} earlier address${total === 1 ? '' : 'es'}`
    } else {
      const f = history[0]
      text = total > 1
        ? `earlier ${f.ip} +${total - 1} more`
        : `earlier ${f.ip}${f.networkKey ? ` (${f.networkKey})` : ''}`
    }
  } else {
    text = `${asset.addressCount} addresses`
  }

  const full = hasHistory ? `History match · ${text}` : text
  const Chevron = expanded ? ChevronDown : ChevronRight

  return (
    <button
      onClick={onToggle}
      title={full}
      className="mt-1 flex items-center gap-1 max-w-[240px] min-w-0 text-[11px] text-dark-400 hover:text-dark-200"
    >
      <Chevron className="w-3 h-3 shrink-0" />
      {hasHistory && (
        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
          <History className="w-3 h-3" /> History match
        </span>
      )}
      <span className="truncate">{hasHistory ? `· ${text}` : text}</span>
    </button>
  )
}

// Full-width expansion ROW (<tr> spanning every column) holding the address
// timeline. Fetched lazily on mount. Isolated from the main table's column widths
// via its OWN table-fixed layout, overflow-x hidden and a max-height scroll area, so
// it can never push the outer table wider than the page.
export function AddressTimelineRow({ asset, colSpan, searchTerm, tenantId }) {
  const [rows, setRows] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const params = tenantId ? { tenant_id: tenantId } : {}
        const res = await client.get(`/assets/${asset.assetId}/addresses`, { params })
        if (alive) setRows(res.data.addresses || [])
      } catch {
        if (alive) setRows([])
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [asset.assetId, tenantId])

  return (
    <tr className="bg-dark-850/40">
      <td colSpan={colSpan} className="p-0">
        <div className="border-l-2 border-amber-500/40 px-4 py-2 overflow-x-hidden">
          <div className="max-h-[240px] overflow-y-auto">
            {loading ? (
              <div className="text-[11px] text-dark-400">Loading addresses…</div>
            ) : (rows || []).length === 0 ? (
              <div className="text-[11px] text-dark-400">No address history.</div>
            ) : (
              <table className="w-full table-fixed text-[11px]">
                <thead>
                  <tr className="text-dark-400 text-left">
                    <th className="w-[24%] font-medium pb-1">IP</th>
                    <th className="w-[28%] font-medium pb-1">MAC</th>
                    <th className="w-[26%] font-medium pb-1">Network</th>
                    <th className="w-[22%] font-medium pb-1">Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((t) => {
                    const hit = rowMatchesTerm(t, searchTerm)
                    return (
                      <tr key={t.addressId} className={hit ? 'bg-amber-500/10' : ''}>
                        <td className="py-0.5 pr-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${t.isCurrent ? 'bg-green-400' : 'bg-dark-500'}`} />
                            <span className="truncate font-mono text-accent-cyan">{t.ipAddress}</span>
                          </div>
                        </td>
                        <td className="py-0.5 pr-2 truncate font-mono text-dark-400">{t.macAddress || '—'}</td>
                        <td className="py-0.5 pr-2 truncate text-dark-400">{t.networkKey || 'unscoped'}</td>
                        <td className="py-0.5 truncate text-dark-400">
                          {fmtDate(t.firstSeen)} → {t.isCurrent ? 'current' : fmtDate(t.lastSeen)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}
