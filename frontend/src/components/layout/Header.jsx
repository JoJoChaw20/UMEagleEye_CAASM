import { useEffect, useRef, useState } from 'react'
import { Bell, Search, Sun, Moon, Monitor, PanelLeft } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'

const THEME_OPTIONS = [
  { value: 'dark',   label: 'Dark',   Icon: Moon },
  { value: 'light',  label: 'Light',  Icon: Sun },
  { value: 'system', label: 'System', Icon: Monitor },
]

export default function Header({ onToggleSidebar }) {
  const { user } = useAuth()
  const { theme, setTheme } = useTheme()
  const [themeOpen, setThemeOpen] = useState(false)
  const menuRef = useRef(null)

  const CurrentIcon = THEME_OPTIONS.find((o) => o.value === theme)?.Icon ?? Moon

  useEffect(() => {
    if (!themeOpen) return
    const close = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setThemeOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [themeOpen])

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
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
          <input
            type="text"
            placeholder="Search assets, CVEs, alerts..."
            className="input-field w-full pl-10 py-2 text-sm bg-dark-850"
            id="global-search"
          />
        </div>
      </div>

      {/* Right */}
      <div className="flex items-center gap-1">
        {/* Theme picker */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setThemeOpen((o) => !o)}
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

        {/* Notifications */}
        <button
          className="relative p-2 text-dark-400 hover:text-dark-100 transition-colors"
          id="notifications-btn"
          title="Notifications"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-accent-red rounded-full" />
        </button>

        {/* User avatar + name */}
        <div className="flex items-center gap-2 pl-2 border-l border-dark-700/50 ml-1">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-eagle-500 to-accent-cyan flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            {user?.username?.[0]?.toUpperCase() || 'U'}
          </div>
          <span className="text-sm text-dark-200 font-medium hidden md:inline truncate max-w-28">
            {user?.username}
          </span>
        </div>
      </div>
    </header>
  )
}
