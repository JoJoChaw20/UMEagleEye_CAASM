import { useEffect, useRef, useState } from 'react'
import { Bell, Search, Sun, Moon, Monitor, PanelLeft, Settings, LogOut, ChevronDown, X } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'
import client from '../../api/client'

const THEME_OPTIONS = [
  { value: 'dark',   label: 'Dark',   Icon: Moon },
  { value: 'light',  label: 'Light',  Icon: Sun },
  { value: 'system', label: 'System', Icon: Monitor },
]

const DEVICE_ICONS = { server: '🖥️', workstation: '💻', network: '🌐', iot: '📡' }

function formatRelTime(ts) {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60)    return 'just now'
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function severityDot(s) {
  if (s === 'critical') return 'bg-red-500'
  if (s === 'warning')  return 'bg-amber-400'
  return 'bg-blue-400'
}
function severityText(s) {
  if (s === 'critical') return 'text-red-400'
  if (s === 'warning')  return 'text-amber-400'
  return 'text-blue-400'
}

export default function Header({ onToggleSidebar }) {
  const { user, logout } = useAuth()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()

  // ── Theme ─────────────────────────────────────────────────────────
  const [themeOpen, setThemeOpen] = useState(false)
  const themeRef = useRef(null)
  const CurrentIcon = THEME_OPTIONS.find(o => o.value === theme)?.Icon ?? Moon

  // ── Search ────────────────────────────────────────────────────────
  const [query, setQuery]         = useState('')
  const [results, setResults]     = useState([])
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef   = useRef(null)
  const searchTimer = useRef(null)

  // ── Notifications ─────────────────────────────────────────────────
  const [notifs, setNotifs]     = useState([])
  const [notifOpen, setNotifOpen] = useState(false)
  const [lastSeen, setLastSeen] = useState(
    () => parseInt(localStorage.getItem('notif-last-seen') ?? '0', 10)
  )
  const notifRef = useRef(null)

  // ── Profile ───────────────────────────────────────────────────────
  const [profileOpen, setProfileOpen] = useState(false)
  const profileRef = useRef(null)

  // ── Load notifications on mount ───────────────────────────────────
  useEffect(() => {
    client.get('/notifications')
      .then(r => setNotifs(r.data.items || []))
      .catch(() => {})
  }, [])

  const unreadCount = notifs.filter(n => new Date(n.timestamp).getTime() > lastSeen).length

  // ── Close all dropdowns on outside click ──────────────────────────
  useEffect(() => {
    const close = (e) => {
      if (themeRef.current   && !themeRef.current.contains(e.target))   setThemeOpen(false)
      if (notifRef.current   && !notifRef.current.contains(e.target))   setNotifOpen(false)
      if (profileRef.current && !profileRef.current.contains(e.target)) setProfileOpen(false)
      if (searchRef.current  && !searchRef.current.contains(e.target))  setSearchOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  // ── Search with 300ms debounce ────────────────────────────────────
  const handleQueryChange = (e) => {
    const q = e.target.value
    setQuery(q)
    clearTimeout(searchTimer.current)
    if (!q.trim()) { setResults([]); setSearchOpen(false); return }
    searchTimer.current = setTimeout(async () => {
      try {
        const res = await client.get('/assets', { params: { search: q, limit: 6 } })
        setResults(res.data.items || [])
        setSearchOpen(true)
      } catch { setResults([]) }
    }, 300)
  }

  const clearSearch = () => { setQuery(''); setResults([]); setSearchOpen(false) }

  const handleResultClick = (assetId) => {
    clearSearch()
    navigate('/assets')
  }

  // ── Open notifications: mark all as seen ─────────────────────────
  const openNotifications = () => {
    setNotifOpen(o => {
      if (!o) {
        const now = Date.now()
        localStorage.setItem('notif-last-seen', String(now))
        setLastSeen(now)
      }
      return !o
    })
  }

  return (
    <header className="h-14 bg-dark-900/80 backdrop-blur-lg border-b border-dark-700/50 flex items-center justify-between px-4 sticky top-0 z-40">

      {/* Left: sidebar toggle + search */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <button
          onClick={onToggleSidebar}
          className="p-2 text-dark-400 hover:text-dark-100 hover:bg-dark-800 rounded-lg transition-all flex-shrink-0"
          title="Toggle sidebar"
        >
          <PanelLeft className="w-4 h-4" />
        </button>

        {/* Global search */}
        <div className="relative flex-1" ref={searchRef}>
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400 pointer-events-none" />
          <input
            id="global-search"
            type="text"
            value={query}
            onChange={handleQueryChange}
            onFocus={() => results.length > 0 && setSearchOpen(true)}
            onKeyDown={(e) => { if (e.key === 'Escape') clearSearch() }}
            placeholder="Search assets, CVEs, alerts..."
            className="input-field w-full pl-10 pr-8 py-2 text-sm bg-dark-850"
          />
          {query && (
            <button onClick={clearSearch} className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300">
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Search dropdown */}
          {searchOpen && (
            <div className="absolute top-full left-0 right-0 mt-1.5 bg-dark-800 border border-dark-700 rounded-xl shadow-2xl z-50 overflow-hidden">
              {results.length === 0 ? (
                <div className="px-4 py-3 text-sm text-dark-400">No assets found for "{query}"</div>
              ) : (
                <>
                  <div className="px-4 py-2 border-b border-dark-700/50">
                    <span className="text-[10px] text-dark-500 uppercase tracking-wider">Assets</span>
                  </div>
                  {results.map(a => (
                    <button
                      key={a.assetId}
                      onClick={() => handleResultClick(a.assetId)}
                      className="flex items-center gap-3 px-4 py-2.5 hover:bg-dark-700 w-full text-left transition-colors"
                    >
                      <span className="text-base flex-shrink-0">{DEVICE_ICONS[a.deviceType] || '❓'}</span>
                      <div className="min-w-0">
                        <p className="text-sm text-white truncate">{a.hostname || '—'}</p>
                        <p className="text-xs text-dark-400 font-mono">{a.ipAddress}</p>
                      </div>
                      <span className="ml-auto text-xs text-dark-500 capitalize flex-shrink-0">{a.deviceType}</span>
                    </button>
                  ))}
                  <button
                    onClick={() => { navigate('/assets'); clearSearch() }}
                    className="w-full px-4 py-2.5 text-xs text-eagle-400 hover:text-eagle-300 hover:bg-dark-700/50 border-t border-dark-700/50 text-center transition-colors"
                  >
                    View all in Asset Inventory →
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right */}
      <div className="flex items-center gap-1">

        {/* Theme picker */}
        <div className="relative" ref={themeRef}>
          <button
            onClick={() => setThemeOpen(o => !o)}
            className="p-2 text-dark-400 hover:text-dark-100 hover:bg-dark-800 rounded-lg transition-all"
            title="Change theme"
          >
            <CurrentIcon className="w-4 h-4" />
          </button>
          {themeOpen && (
            <div className="absolute right-0 top-full mt-1.5 bg-dark-800 border border-dark-700 rounded-xl shadow-xl z-50 py-1 w-36 overflow-hidden">
              {THEME_OPTIONS.map(({ value, label, Icon }) => (
                <button
                  key={value}
                  onClick={() => { setTheme(value); setThemeOpen(false) }}
                  className={`flex items-center gap-2.5 px-3 py-2 text-sm w-full hover:bg-dark-700 transition-colors ${theme === value ? 'text-eagle-400' : 'text-dark-300'}`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                  {theme === value && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-eagle-400" />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Notifications bell */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={openNotifications}
            className="relative p-2 text-dark-400 hover:text-dark-100 hover:bg-dark-800 rounded-lg transition-all"
            title="Notifications"
            id="notifications-btn"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 min-w-[16px] h-4 bg-accent-red rounded-full flex items-center justify-center text-[9px] text-white font-bold px-0.5 leading-none">
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-96 max-h-[480px] bg-dark-800 border border-dark-700 rounded-xl shadow-2xl z-50 flex flex-col overflow-hidden">
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-dark-700/50 flex-shrink-0">
                <span className="text-sm font-semibold text-white">Notifications</span>
                <span className="text-xs text-dark-500">{notifs.length} total</span>
              </div>

              {/* List */}
              <div className="overflow-y-auto flex-1">
                {notifs.length === 0 ? (
                  <div className="py-10 text-center text-dark-400 text-sm">
                    <Bell className="w-8 h-8 mx-auto mb-2 opacity-20" />
                    No notifications
                  </div>
                ) : notifs.slice(0, 30).map(n => (
                  <div key={n.id} className="px-4 py-3 border-b border-dark-800/60 hover:bg-dark-750/30 transition-colors">
                    <div className="flex items-start gap-2.5">
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${severityDot(n.severity)}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-dark-100 leading-tight">{n.title}</p>
                        <p className="text-xs text-dark-400 mt-0.5 line-clamp-2">{n.message}</p>
                      </div>
                      <span className={`text-[10px] flex-shrink-0 mt-0.5 ${severityText(n.severity)}`}>
                        {formatRelTime(n.timestamp)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Footer */}
              <div className="border-t border-dark-700/50 px-4 py-2.5 flex-shrink-0">
                <button
                  onClick={() => { navigate('/advisories'); setNotifOpen(false) }}
                  className="text-xs text-eagle-400 hover:text-eagle-300 transition-colors"
                >
                  View all advisories →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Profile dropdown */}
        <div className="relative" ref={profileRef}>
          <button
            onClick={() => setProfileOpen(o => !o)}
            className="flex items-center gap-2 pl-2 ml-1 border-l border-dark-700/50 pr-1.5 py-1 rounded-lg hover:bg-dark-800 transition-all"
            title="Account"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-eagle-500 to-accent-cyan flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            <span className="text-sm text-dark-200 font-medium hidden md:inline truncate max-w-28">
              {user?.username}
            </span>
            <ChevronDown className={`w-3 h-3 text-dark-400 transition-transform hidden md:block ${profileOpen ? 'rotate-180' : ''}`} />
          </button>

          {profileOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-56 bg-dark-800 border border-dark-700 rounded-xl shadow-2xl z-50 py-1 overflow-hidden">
              {/* Identity block */}
              <div className="px-4 py-3 border-b border-dark-700/50">
                <div className="flex items-center gap-2.5 mb-1">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-eagle-500 to-accent-cyan flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
                    {user?.username?.[0]?.toUpperCase() || 'U'}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-white truncate">{user?.username}</p>
                    <p className="text-[10px] text-dark-400 capitalize">{user?.role?.replace(/_/g, ' ')}</p>
                  </div>
                </div>
                {user?.tenantName && (
                  <p className="text-[10px] text-dark-500 mt-1 truncate">{user.tenantName}</p>
                )}
                {user?.email && (
                  <p className="text-[10px] text-dark-500 truncate">{user.email}</p>
                )}
              </div>

              {/* Actions */}
              <Link
                to="/settings"
                onClick={() => setProfileOpen(false)}
                className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-dark-300 hover:bg-dark-700 hover:text-white transition-colors"
              >
                <Settings className="w-4 h-4" />
                Profile &amp; Settings
              </Link>
              <button
                onClick={() => { setProfileOpen(false); logout() }}
                className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-dark-300 hover:bg-dark-700 hover:text-red-400 transition-colors w-full text-left"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
