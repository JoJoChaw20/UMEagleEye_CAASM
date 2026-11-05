import { useEffect, useRef, useState } from 'react'
import { Bell, Search, Sun, Moon, Monitor, PanelLeft, Settings, LogOut, ChevronDown, ArrowRight } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'
import client from '../../api/client'
import BrandLogo from '../ui/BrandLogo'

const THEME_OPTIONS = [
  { value: 'dark',   label: 'Dark',   Icon: Moon },
  { value: 'light',  label: 'Light',  Icon: Sun },
  { value: 'system', label: 'System', Icon: Monitor },
]

function formatRelTime(ts) {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60)    return 'just now'
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function severityDot(s) {
  if (s === 'critical') return 'bg-accent-red'
  if (s === 'warning')  return 'bg-accent-amber'
  return 'bg-eagle-400'
}
function severityText(s) {
  if (s === 'critical') return 'text-red-400'
  if (s === 'warning')  return 'text-amber-400'
  return 'text-dark-400'
}

export default function Header({ onToggleSidebar, onOpenPalette }) {
  const { user, logout } = useAuth()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()

  // ── Theme ─────────────────────────────────────────────────────────
  // (a three-way switch, always visible)

  // ── Notifications ─────────────────────────────────────────────────
  const [notifs, setNotifs]       = useState([])
  const [notifOpen, setNotifOpen] = useState(false)
  const [seenIds, setSeenIds]     = useState(() => {
    try {
      const raw = localStorage.getItem('notif-seen-ids')
      return new Set(raw ? JSON.parse(raw) : [])
    } catch { return new Set() }
  })
  const notifRef      = useRef(null)
  const seenIdsRef    = useRef(seenIds)
  const prevIdsRef    = useRef(null)   // null = first fetch (skip sound)
  const audioCtxRef   = useRef(null)

  // Mirror seenIds into a ref so the poll closure can read it without staling
  useEffect(() => { seenIdsRef.current = seenIds }, [seenIds])

  // Initialise AudioContext on first user interaction (browser autoplay policy)
  useEffect(() => {
    const init = () => {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)()
      }
    }
    document.addEventListener('click', init, { once: true })
    return () => document.removeEventListener('click', init)
  }, [])

  // ── Sound helper ──────────────────────────────────────────────────
  const playNotifSound = (severity) => {
    const ctx = audioCtxRef.current
    if (!ctx) return
    try {
      if (ctx.state === 'suspended') ctx.resume()
      const osc  = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.connect(gain)
      gain.connect(ctx.destination)
      const now = ctx.currentTime

      if (severity === 'critical') {
        // Double ding — urgent (SLA breach, critical advisory)
        osc.type = 'sine'
        osc.frequency.setValueAtTime(1047, now)
        osc.frequency.setValueAtTime(784,  now + 0.13)
        osc.frequency.setValueAtTime(1047, now + 0.26)
        gain.gain.setValueAtTime(0,    now)
        gain.gain.linearRampToValueAtTime(0.28, now + 0.01)
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.55)
        osc.start(now)
        osc.stop(now + 0.55)
      } else {
        // Soft single ding — advisory generated, agent offline
        osc.type = 'sine'
        osc.frequency.setValueAtTime(880,  now)
        osc.frequency.exponentialRampToValueAtTime(1047, now + 0.08)
        gain.gain.setValueAtTime(0,    now)
        gain.gain.linearRampToValueAtTime(0.18, now + 0.01)
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.38)
        osc.start(now)
        osc.stop(now + 0.38)
      }
    } catch { /* ignore if audio not available */ }
  }

  // ── Profile ───────────────────────────────────────────────────────
  const [profileOpen, setProfileOpen] = useState(false)
  const profileRef = useRef(null)

  // ── Poll notifications every 20 s + on window focus ──────────────
  useEffect(() => {
    const fetchNotifs = () => {
      client.get('/notifications')
        .then(r => {
          const items = r.data.items || []
          setNotifs(items)

          const isFirstFetch = prevIdsRef.current === null
          if (!isFirstFetch) {
            // Find IDs that weren't in the previous response AND aren't marked seen
            const newUnread = items.filter(
              n => !prevIdsRef.current.has(n.id) && !seenIdsRef.current.has(n.id)
            )
            if (newUnread.length > 0) {
              const hasCritical = newUnread.some(n => n.severity === 'critical')
              playNotifSound(hasCritical ? 'critical' : 'warning')
            }
          }
          prevIdsRef.current = new Set(items.map(n => n.id))
        })
        .catch(() => {})
    }
    fetchNotifs()
    const interval = setInterval(fetchNotifs, 20_000)
    window.addEventListener('focus', fetchNotifs)
    return () => {
      clearInterval(interval)
      window.removeEventListener('focus', fetchNotifs)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const unreadCount = notifs.filter(n => !seenIds.has(n.id)).length

  // ── Close all dropdowns on outside click ──────────────────────────
  useEffect(() => {
    const close = (e) => {
      if (notifRef.current   && !notifRef.current.contains(e.target))   setNotifOpen(false)
      if (profileRef.current && !profileRef.current.contains(e.target)) setProfileOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  // ── Map notification type → route + state ────────────────────────
  const handleNotifClick = (n) => {
    setNotifOpen(false)
    if (n.type === 'agent_offline' || n.type === 'agent_degraded') {
      navigate('/agents')
    } else if (
      (n.type === 'advisory_generated' || n.type === 'advisory_resolved') &&
      n.metadata?.advisory_id
    ) {
      navigate('/advisories', { state: { openAdvisoryId: n.metadata.advisory_id } })
    } else {
      navigate('/advisories')
    }
  }

  // ── Open notifications: mark all visible IDs as seen ────────────
  const openNotifications = () => {
    setNotifOpen(o => {
      if (!o) {
        setSeenIds(prev => {
          const next = new Set(prev)
          notifs.forEach(n => next.add(n.id))
          const arr = [...next].slice(-300)
          localStorage.setItem('notif-seen-ids', JSON.stringify(arr))
          return new Set(arr)
        })
      }
      return !o
    })
  }

  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
  const iconBtn = 'relative flex h-9 w-9 items-center justify-center rounded-md text-dark-400 transition-colors duration-150 hover:bg-dark-700/40 hover:text-dark-50'

  return (
    <header className="sticky top-0 z-40 flex h-16 items-center justify-between gap-4 border-b border-dark-700/80 bg-dark-900 px-4 lg:px-6">

      {/* Left: sidebar toggle + command palette trigger */}
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <button type="button" onClick={onToggleSidebar} className={iconBtn} title="Toggle sidebar" aria-label="Toggle sidebar">
          <PanelLeft className="h-4 w-4" />
        </button>

        {/* The rail is a drawer below 1024px, so the mark keeps the logo in view */}
        <Link to="/" title="UMEagleEye · Dashboard" className="flex-shrink-0 lg:hidden">
          <BrandLogo variant="mark" className="h-9 w-9" />
        </Link>

        <button type="button" id="global-search" onClick={onOpenPalette} aria-haspopup="dialog" aria-label="Search assets or jump to a page"
          className="group flex h-9 w-9 flex-shrink-0 items-center justify-center gap-2.5 rounded-md border border-dark-700 bg-dark-800 text-left text-sm text-dark-400 transition-[border-color,box-shadow] duration-150 hover:border-dark-600 focus-visible:border-eagle-500 sm:w-full sm:max-w-md sm:flex-shrink sm:justify-start sm:px-3">
          <Search className="h-4 w-4 flex-shrink-0 text-dark-400 transition-colors group-hover:text-eagle-400" />
          <span className="hidden min-w-0 flex-1 truncate sm:block">Search assets or jump to a page…</span>
          <span className="hidden items-center gap-1 sm:flex">
            <span className="kbd">{isMac ? 'Cmd' : 'Ctrl'}</span><span className="kbd">K</span>
          </span>
        </button>
      </div>

      {/* Right */}
      <div className="flex flex-shrink-0 items-center gap-1.5">

        {/* Theme: dark / light / system, one click each */}
        <div role="group" aria-label="Theme" className="hidden items-center rounded-md border border-dark-700 bg-dark-800 p-0.5 sm:flex">
          {THEME_OPTIONS.map(({ value, label, Icon }) => (
            <button key={value} type="button" onClick={() => setTheme(value)} aria-pressed={theme === value} title={`${label} theme`}
              className={`flex h-7 w-8 items-center justify-center rounded transition-colors duration-150 ${theme === value
                ? 'bg-eagle-500/15 text-eagle-400 shadow-[inset_0_0_0_1px_rgb(var(--eagle-500)/0.35)]'
                : 'text-dark-400 hover:text-dark-100'}`}>
              <Icon className="h-3.5 w-3.5" />
              <span className="sr-only">{label}</span>
            </button>
          ))}
        </div>

        {/* Notifications bell */}
        <div className="relative" ref={notifRef}>
          <button type="button" onClick={openNotifications} className={iconBtn} title="Notifications" id="notifications-btn"
            aria-label={unreadCount > 0 ? `Notifications, ${unreadCount} unread` : 'Notifications'} aria-expanded={notifOpen}>
            <Bell className="h-4 w-4" />
            {unreadCount > 0 && (
              <span className="absolute right-0.5 top-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-accent-red px-1 text-[10px] font-semibold leading-none text-on-brand ring-2 ring-dark-900">
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="absolute right-0 top-full z-50 mt-2 flex max-h-[480px] w-96 flex-col overflow-hidden rounded-xl border border-dark-700 bg-dark-800 shadow-float animate-[palette-rise_200ms_cubic-bezier(0.16,1,0.3,1)]">
              <div className="flex flex-shrink-0 items-center justify-between border-b border-dark-700 px-4 py-3">
                <span className="font-display text-sm font-semibold text-dark-50">Notifications</span>
                <div className="flex items-center gap-2">
                  {unreadCount > 0 && (
                    <span className="rounded-md bg-eagle-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-eagle-400">
                      {unreadCount} new
                    </span>
                  )}
                  <span className="text-xs text-dark-500">{notifs.length} total</span>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto">
                {notifs.length === 0 ? (
                  <div className="py-10 text-center text-sm text-dark-400">
                    <Bell className="mx-auto mb-2 h-7 w-7 text-dark-600" />
                    All quiet. New advisories, SLA breaches and agent outages appear here.
                  </div>
                ) : notifs.slice(0, 30).map(n => {
                  const isUnread = !seenIds.has(n.id)
                  return (
                    <button key={n.id} type="button" onClick={() => handleNotifClick(n)}
                      className={`w-full border-b border-dark-700/60 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-eagle-500/[0.06] ${isUnread ? 'bg-eagle-500/[0.04]' : ''}`}>
                      <div className="flex items-start gap-2.5">
                        <span className={`mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full ${isUnread ? 'bg-eagle-400' : severityDot(n.severity)}`} />
                        <div className="min-w-0 flex-1">
                          <p className={`text-sm leading-tight ${isUnread ? 'font-semibold text-dark-50' : 'font-medium text-dark-100'}`}>{n.title}</p>
                          <p className="mt-0.5 line-clamp-2 text-xs text-dark-400">{n.message}</p>
                        </div>
                        <span className={`flex-shrink-0 text-[11px] ${severityText(n.severity)}`}>
                          {formatRelTime(n.timestamp)}
                        </span>
                      </div>
                    </button>
                  )
                })}
              </div>

              <div className="flex-shrink-0 border-t border-dark-700 px-4 py-2.5">
                <button type="button" onClick={() => { navigate('/advisories'); setNotifOpen(false) }}
                  className="text-xs font-medium text-eagle-400 transition-colors hover:text-eagle-300">
                  View all advisories<ArrowRight aria-hidden="true" className="ml-1 inline h-3.5 w-3.5 align-[-3px]" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Profile dropdown */}
        <div className="relative" ref={profileRef}>
          <button type="button" onClick={() => setProfileOpen(o => !o)} title="Account" aria-expanded={profileOpen}
            className="ml-1 flex items-center gap-2 rounded-md py-1 pl-1.5 pr-1.5 transition-colors hover:bg-dark-700/40">
            <span className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md bg-eagle-600 font-display text-xs font-semibold text-on-brand">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </span>
            <span className="hidden max-w-28 truncate text-sm font-medium text-dark-200 md:inline">
              {user?.username}
            </span>
            <ChevronDown className={`hidden h-3 w-3 text-dark-400 transition-transform md:block ${profileOpen ? 'rotate-180' : ''}`} />
          </button>

          {profileOpen && (
            <div className="absolute right-0 top-full z-50 mt-2 w-60 overflow-hidden rounded-xl border border-dark-700 bg-dark-800 py-1 shadow-float animate-[palette-rise_200ms_cubic-bezier(0.16,1,0.3,1)]">
              <div className="border-b border-dark-700 px-4 py-3">
                <div className="mb-1 flex items-center gap-2.5">
                  <span className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md bg-eagle-600 font-display text-xs font-semibold text-on-brand">
                    {user?.username?.[0]?.toUpperCase() || 'U'}
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-dark-50">{user?.username}</p>
                    <p className="text-[11px] capitalize text-dark-400">{user?.role?.replace(/_/g, ' ')}</p>
                  </div>
                </div>
                {user?.tenantName && <p className="mt-1 truncate text-[11px] text-dark-400">{user.tenantName}</p>}
                {user?.email && <p className="truncate text-[11px] text-dark-500">{user.email}</p>}
              </div>

              {/* Theme for narrow screens, where the header switch is hidden */}
              <div className="flex items-center gap-1 border-b border-dark-700 px-3 py-2 sm:hidden">
                {THEME_OPTIONS.map(({ value, label, Icon }) => (
                  <button key={value} type="button" onClick={() => setTheme(value)} aria-pressed={theme === value}
                    className={`flex flex-1 items-center justify-center gap-1.5 rounded py-1.5 text-xs ${theme === value ? 'bg-eagle-500/15 text-eagle-400' : 'text-dark-400'}`}>
                    <Icon className="h-3.5 w-3.5" />{label}
                  </button>
                ))}
              </div>

              <Link to="/settings" onClick={() => setProfileOpen(false)}
                className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-dark-300 transition-colors hover:bg-dark-700/40 hover:text-dark-50">
                <Settings className="h-4 w-4" />
                Profile &amp; Settings
              </Link>
              <button type="button" onClick={() => { setProfileOpen(false); logout() }}
                className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left text-sm text-dark-300 transition-colors hover:bg-dark-700/40 hover:text-red-400">
                <LogOut className="h-4 w-4" />
                Log out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
