import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Server, Bell, FileSearch, Globe, FileText,
  Settings, LogOut, Eye, Network, Radar, GitBranch, Bot, Building2
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const navItems = [
  { label: 'OVERVIEW', items: [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  ]},
  { label: 'ASSETS', items: [
    { to: '/my-assets',  icon: Server,    label: 'My Assets' },
    { to: '/discovery',  icon: Radar,     label: 'Discovery' },
    { to: '/topology',   icon: GitBranch, label: 'Topology' },
  ]},
  { label: 'SECURITY', items: [
    { to: '/alerts',     icon: Bell,      label: 'Alerts' },
    { to: '/advisories', icon: FileSearch,label: 'Advisories' },
    { to: '/threat-intel',icon: Globe,    label: 'Threat Intel' },
  ]},
  { label: 'REPORTS', items: [
    { to: '/reports',    icon: FileText,  label: 'Reports' },
  ]},
  { label: 'SYSTEM', items: [
    { to: '/agents',     icon: Bot,       label: 'Agents' },
    { to: '/settings',   icon: Settings,  label: 'Settings' },
  ]},
]

// SuperAdmin-only section
const adminNavItems = [
  { label: 'ADMIN', items: [
    { to: '/tenants', icon: Building2, label: 'Tenants' },
  ]},
]

export default function Sidebar() {
  const { logout, user } = useAuth()
  const isSuperAdmin = user?.role === 'superadmin'

  const sections = isSuperAdmin ? [...navItems, ...adminNavItems] : navItems

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-dark-900 border-r border-dark-700/50 flex flex-col z-50">
      {/* Logo */}
      <div className="p-5 border-b border-dark-700/50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-gradient-to-br from-eagle-500 to-accent-cyan rounded-lg flex items-center justify-center">
            <Eye className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold gradient-text">UMEagleEye</h1>
            <p className="text-[10px] text-dark-400 tracking-wider uppercase">CAASM Platform</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        {sections.map((section) => (
          <div key={section.label} className="mb-5">
            <p className="text-[10px] font-semibold text-dark-500 tracking-widest uppercase px-3 mb-2">
              {section.label}
            </p>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `nav-link mb-0.5 ${isActive ? 'active' : ''}`}
                end={item.to === '/'}
              >
                <item.icon className="w-4 h-4" />
                <span className="text-sm">{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* User info & logout */}
      <div className="p-4 border-t border-dark-700/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-eagle-600/30 flex items-center justify-center text-eagle-400 text-xs font-bold">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            <div>
              <p className="text-sm font-medium text-dark-200">{user?.username || 'User'}</p>
              <p className="text-[10px] text-dark-400 capitalize">{user?.role?.replace(/_/g, ' ') || 'Role'}</p>
            </div>
          </div>
          <button onClick={logout} className="text-dark-400 hover:text-red-400 transition-colors" title="Logout">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}
