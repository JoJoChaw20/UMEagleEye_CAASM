import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import {
  Search, CornerDownLeft, ArrowRight, ArrowUp, ArrowDown, Server, Monitor, Network, Cpu, Smartphone, HelpCircle,
  Moon, Sun, MonitorSmartphone, Bell, MessageCircle, Radar, Boxes,
} from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'
import { buildNavSections } from './navConfig'

const DEVICE_ICONS = { server: Server, workstation: Monitor, network: Network, iot: Cpu, mobile: Smartphone }

const matches = (q, ...fields) => {
  if (!q) return true
  const hay = fields.filter(Boolean).join(' ').toLowerCase()
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w))
}

// Ctrl+K (or "/") opens a palette: jump to any page, find an asset, or run a quick
// action, all from the keyboard.
export default function CommandPalette({ open, onClose }) {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { theme, setTheme } = useTheme()
  const [query, setQuery] = useState('')
  const [assets, setAssets] = useState([])
  const [assetState, setAssetState] = useState('idle') // idle | loading | done | error
  const [active, setActive] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)
  const restoreRef = useRef(null)

  const canSeeOps = user?.role !== 'business_owner'
  const q = query.trim()

  // Reset on open, give focus back on close
  useEffect(() => {
    if (!open) return undefined
    restoreRef.current = document.activeElement
    setQuery(''); setAssets([]); setAssetState('idle'); setActive(0)
    const raf = requestAnimationFrame(() => inputRef.current?.focus())
    return () => {
      cancelAnimationFrame(raf)
      restoreRef.current?.focus?.()
    }
  }, [open])

  // Live asset search, debounced
  useEffect(() => {
    if (!open || q.length < 2) { setAssets([]); setAssetState('idle'); return undefined }
    setAssetState('loading')
    let cancelled = false
    const timer = setTimeout(() => {
      client.get('/assets', { params: { search: q, limit: 6 } })
        .then((res) => { if (!cancelled) { setAssets(res.data.items || []); setAssetState('done') } })
        .catch(() => { if (!cancelled) { setAssets([]); setAssetState('error') } })
    }, 220)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [q, open])

  const groups = useMemo(() => {
    const go = (to, state) => () => navigate(to, state ? { state } : undefined)
    const pages = buildNavSections(user?.role)
      .flatMap((s) => s.items.map((item) => ({ ...item, section: s.label })))
      .filter((item) => matches(q, item.label, item.section, item.keywords))
      .map((item) => ({ id: `page:${item.to}`, icon: item.icon, label: item.label, hint: item.section, run: go(item.to) }))

    const actions = [
      { id: 'act:priority', icon: Bell, label: 'Open alerts by priority', keywords: 'urgent triage', run: go('/alerts?sort=priority') },
      ...(canSeeOps ? [{ id: 'act:scan', icon: Radar, label: 'Start a discovery scan', keywords: 'scan network nmap', run: go('/discovery') }] : []),
      { id: 'act:chat', icon: MessageCircle, label: 'Ask the security assistant', keywords: 'chatbot ai question', run: go('/chatbot') },
      { id: 'theme:dark', icon: Moon, label: 'Switch to dark theme', keywords: 'theme mode appearance', hint: theme === 'dark' ? 'Current' : '', run: () => setTheme('dark') },
      { id: 'theme:light', icon: Sun, label: 'Switch to light theme', keywords: 'theme mode bright appearance', hint: theme === 'light' ? 'Current' : '', run: () => setTheme('light') },
      { id: 'theme:system', icon: MonitorSmartphone, label: 'Match system theme', keywords: 'theme mode auto appearance', hint: theme === 'system' ? 'Current' : '', run: () => setTheme('system') },
    ].filter((a) => matches(q, a.label, a.keywords))

    const assetItems = assets.map((a) => ({
      id: `asset:${a.assetId}`,
      icon: DEVICE_ICONS[a.deviceType] ?? HelpCircle,
      label: a.hostname || a.ipAddress || 'Unnamed asset',
      mono: a.hostname ? a.ipAddress : null,
      hint: a.deviceType || 'unknown type',
      deviceHint: true,
      run: go(`/inventory/${encodeURIComponent(a.assetId)}`),
    }))
    if (q.length >= 2) {
      assetItems.push({
        id: 'asset:all', icon: Boxes, label: `Search the inventory for “${q}”`, hint: 'All known assets',
        run: go(`/inventory?${new URLSearchParams({ scope: 'any', q })}`),
      })
    }

    return [
      { title: 'Assets', items: assetItems, status: assetState },
      { title: 'Pages', items: pages },
      { title: 'Actions', items: actions },
    ].filter((g) => g.items.length || (g.title === 'Assets' && q.length >= 2))
  }, [q, assets, assetState, user?.role, canSeeOps, theme, navigate, setTheme])

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups])

  useEffect(() => { setActive(0) }, [q])
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [active])

  if (!open) return null

  const run = (item) => { onClose(); item.run() }
  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => (flat.length ? (i + 1) % flat.length : 0)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => (flat.length ? (i - 1 + flat.length) % flat.length : 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); if (flat[active]) run(flat[active]) }
    else if (e.key === 'Escape') { e.preventDefault(); onClose() }
    else if (e.key === 'Tab') { e.preventDefault() }
  }

  let index = -1
  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-start justify-center bg-dark-950/70 px-4 pt-[12vh] animate-[palette-fade_160ms_ease-out]" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-label="Command palette"
        className="w-full max-w-[640px] overflow-hidden rounded-xl border border-dark-700 bg-dark-800 shadow-float animate-[palette-rise_220ms_cubic-bezier(0.16,1,0.3,1)]"
        onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-dark-700 px-4">
          <Search className="h-4 w-4 flex-shrink-0 text-eagle-400" />
          <input ref={inputRef} value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={onKeyDown}
            role="combobox" aria-expanded="true" aria-controls="palette-list" aria-autocomplete="list"
            aria-activedescendant={flat[active] ? `palette-${active}` : undefined}
            placeholder="Search assets by hostname or IP, or jump to a page…"
            className="h-14 flex-1 bg-transparent text-[15px] text-dark-50 placeholder:text-dark-500 focus:outline-none" />
          <span className="kbd">Esc</span>
        </div>

        <div ref={listRef} id="palette-list" role="listbox" aria-label="Results" className="max-h-[min(60vh,440px)] overflow-y-auto p-2">
          {groups.map((group) => (
            <div key={group.title} role="group" aria-label={group.title} className="mb-1 last:mb-0">
              <div className="flex items-center gap-2 px-2.5 pb-1 pt-2">
                <span className="font-display text-[11px] font-semibold uppercase tracking-[0.12em] text-dark-400">{group.title}</span>
                {group.status === 'loading' && <span className="trace-loader scale-75" aria-label="Searching" />}
              </div>
              {group.title === 'Assets' && group.status === 'error' && <p className="px-2.5 py-2 text-sm text-dark-400">Asset search is unavailable right now.</p>}
              {group.title === 'Assets' && group.status === 'done' && group.items.length === 1 && (
                <p className="px-2.5 pb-1 text-xs text-dark-500">No asset matches “{q}” by hostname or IP.</p>
              )}
              {group.items.map((item) => {
                index += 1
                const i = index
                const selected = i === active
                const Icon = item.icon
                return (
                  <div key={item.id} id={`palette-${i}`} data-index={i} role="option" aria-selected={selected}
                    onMouseMove={() => setActive(i)} onClick={() => run(item)}
                    className={`relative flex cursor-pointer items-center gap-3 rounded-md px-2.5 py-2 text-sm transition-colors duration-100 ${selected ? 'bg-eagle-500/10 text-dark-50' : 'text-dark-200'}`}>
                    {selected && <span aria-hidden="true" className="absolute left-0 top-1/2 h-4 w-px -translate-y-1/2 bg-eagle-400" />}
                    <span className={`flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md border ${selected ? 'border-eagle-500/40 text-eagle-400' : 'border-dark-700 text-dark-400'}`}>
                      <Icon className="h-3.5 w-3.5" />
                    </span>
                    <span className="min-w-0 flex-1 truncate">
                      {item.label}
                      {item.mono && <span className="ml-2 font-mono text-xs text-dark-400">{item.mono}</span>}
                    </span>
                    {item.hint && <span className={`flex-shrink-0 text-xs text-dark-500 ${item.deviceHint ? 'capitalize' : ''}`}>{item.hint}</span>}
                    {selected && <CornerDownLeft className="h-3.5 w-3.5 flex-shrink-0 text-eagle-400" />}
                  </div>
                )
              })}
            </div>
          ))}
          {flat.length === 0 && q.length < 2 && (
            <p className="px-3 py-8 text-center text-sm text-dark-400">Nothing matches “{q}”. Try a page name, or type two letters to search assets.</p>
          )}
        </div>

        <div className="flex items-center gap-4 border-t border-dark-700 bg-dark-900/60 px-4 py-2 text-[11px] text-dark-400">
          <span className="flex items-center gap-1.5"><span className="kbd py-[3px]"><ArrowUp className="h-3 w-3" /></span><span className="kbd py-[3px]"><ArrowDown className="h-3 w-3" /></span> move</span>
          <span className="flex items-center gap-1.5"><span className="kbd">Enter</span> open</span>
          <span className="ml-auto flex items-center gap-1.5"><ArrowRight className="h-3 w-3" />Ctrl K anywhere</span>
        </div>
      </div>
    </div>,
    document.body,
  )
}
