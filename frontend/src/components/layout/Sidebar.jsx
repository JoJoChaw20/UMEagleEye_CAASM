import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Server, Bell, FileSearch, Globe, FileText,
  Settings, LogOut, Eye, Network, Radar, GitBranch, Bot, Building2,
  ChevronLeft,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const navSections = [
  { label: 'OVERVIEW', items: [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  ]},
  { label: 'ASSETS', items: [
    { to: '/my-assets',    icon: Server,     label: 'My Assets' },
    { to: '/assets',       icon: Network,    label: 'All Assets' },
    { to: '/discovery',    icon: Radar,      label: 'Discovery' },
    { to: '/topology',     icon: GitBranch,  label: 'Topology' },
  ]},
  { label: 'SECURITY', items: [
    { to: '/alerts',       icon: Bell,       label: 'Alerts' },
    { to: '/advisories',   icon: FileSearch, label: 'Advisories' },
    { to: '/threat-intel', icon: Globe,      label: 'Threat Intel' },
  ]},
  { label: 'REPORTS', items: [
    { to: '/reports',      icon: FileText,   label: 'Reports' },
  ]},
  { label: 'SYSTEM', items: [
    { to: '/agents',       icon: Bot,        label: 'Agents' },
    { to: '/settings',     icon: Settings,   label: 'Settings' },
  ]},
]

const adminSections = [
  { label: 'ADMIN', items: [
    { to: '/tenants', icon: Building2, label: 'Tenants' },
  ]},
]

export default function Sidebar({ collapsed, onToggle }) {
  const { logout, user } = useAuth()
  const sections = user?.role === 'superadmin'
    ? [...navSections, ...adminSections]
    : navSections

  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-dark-900 border-r border-dark-700/50 flex flex-col z-50 transition-all duration-300 ease-in-out overflow-hidden ${collapsed ? 'w-16' : 'w-64'}`}
    >
      {/* Logo row */}
      <div className="flex items-center justify-between border-b border-dark-700/50 px-3 h-14 flex-shrink-0">
        <div className={`flex items-center gap-3 ${collapsed ? 'w-full justify-center' : ''}`}>
          <div className="w-8 h-8 bg-gradient-to-br from-eagle-500 to-accent-cyan rounded-lg flex items-center justify-center flex-shrink-0">
            <Eye className="w-4 h-4 text-white" />
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <h1 className="text-base font-bold gradient-text leading-tight">UMEagleEye</h1>
              <p className="text-[9px] text-dark-400 tracking-wider uppercase">CAASM Platform</p>
            </div>
          )}
        </div>
        {!collapsed && (
          <button
            onClick={onToggle}
            className="p-1.5 text-dark-400 hover:text-dark-100 hover:bg-dark-800 rounded-lg transition-all flex-shrink-0"
            title="Collapse sidebar"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {sections.map((section, idx) => (
          <div key={section.label} className={collapsed ? 'mb-0' : 'mb-4'}>
            {collapsed
              ? idx > 0 && <div className="h-px bg-dark-700/40 my-2 mx-1" />
              : <p className="text-[9px] font-semibold text-dark-500 tracking-widest uppercase px-3 pt-2 pb-1.5">{section.label}</p>
            }
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  collapsed
                    ? `flex items-center justify-center w-10 h-10 mx-auto mb-0.5 rounded-lg transition-all duration-150 ${isActive ? 'bg-eagle-600/20 text-eagle-400' : 'text-dark-400 hover:bg-dark-800 hover:text-dark-100'}`
                    : `nav-link mb-0.5 ${isActive ? 'active' : ''}`
                }
              >
                <item.icon className="w-4 h-4 flex-shrink-0" />
                {!collapsed && <span className="text-sm">{item.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* User row */}
      <div className={`border-t border-dark-700/50 ${collapsed ? 'p-2' : 'p-3'}`}>
        <div className={`flex items-center ${collapsed ? 'flex-col gap-2' : 'justify-between'}`}>
          <div className={`flex items-center gap-2.5 min-w-0 ${collapsed ? '' : 'flex-1'}`}>
            <div
              className="w-8 h-8 rounded-full bg-eagle-600/30 flex items-center justify-center text-eagle-400 text-xs font-bold flex-shrink-0"
              title={collapsed ? `${user?.username} · ${user?.role?.replace(/_/g, ' ')}` : undefined}
            >
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <p className="text-sm font-medium text-dark-200 truncate">{user?.username || 'User'}</p>
                <p className="text-[10px] text-dark-400 capitalize truncate">{user?.role?.replace(/_/g, ' ') || 'Role'}</p>
              </div>
            )}
          </div>
          <button
            onClick={logout}
            className="text-dark-400 hover:text-accent-red transition-colors flex-shrink-0"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}
