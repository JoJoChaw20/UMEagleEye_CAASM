import { Bell, Search, ChevronDown } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

export default function Header() {
  const { user } = useAuth()

  return (
    <header className="h-14 bg-dark-900/80 backdrop-blur-lg border-b border-dark-700/50 flex items-center justify-between px-6 sticky top-0 z-40">
      {/* Search */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
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

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* Notifications */}
        <button className="relative text-dark-300 hover:text-white transition-colors" id="notifications-btn">
          <Bell className="w-5 h-5" />
          <span className="absolute -top-1 -right-1 w-4 h-4 bg-accent-red rounded-full text-[10px] flex items-center justify-center font-bold">
            3
          </span>
        </button>

        {/* User */}
        <div className="flex items-center gap-2 text-sm">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-eagle-500 to-accent-cyan flex items-center justify-center text-white text-xs font-bold">
            {user?.username?.[0]?.toUpperCase() || 'U'}
          </div>
          <span className="text-dark-200 font-medium hidden md:inline">{user?.username}</span>
        </div>
      </div>
    </header>
  )
}
