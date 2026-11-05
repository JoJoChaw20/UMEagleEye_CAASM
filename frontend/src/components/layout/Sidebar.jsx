import { NavLink, Link } from 'react-router-dom'
import { ChevronsLeft, ChevronsRight, LogOut } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import BrandLogo from '../ui/BrandLogo'
import { buildNavSections } from './navConfig'
import useAgentPulse from './useAgentPulse'

// The navy rail. Same in every theme: it carries the logo's world. Nav items sit on a
// circuit "bus" (the logo's wing traces); the active page lights its ring node.

function NavItem({ item, collapsed }) {
  if (collapsed) {
    return (
      <NavLink to={item.to} end={item.to === '/'} title={item.label} aria-label={item.label}
        className={({ isActive }) =>
          `relative mx-auto mb-1 flex h-10 w-10 items-center justify-center rounded-md transition-colors duration-150 ${
            isActive ? 'bg-rail-raised text-eagle-300 shadow-[inset_0_0_0_1px_rgb(var(--eagle-500)/0.35)]' : 'text-rail-muted hover:bg-rail-raised/60 hover:text-rail-text'}`}>
        <item.icon className="h-[18px] w-[18px]" />
      </NavLink>
    )
  }
  return (
    <NavLink to={item.to} end={item.to === '/'}
      className={({ isActive }) => `group relative ml-5 flex h-9 items-center gap-3 rounded-md px-2.5 text-sm transition-colors duration-150 ${
        isActive ? 'bg-rail-raised text-on-brand' : 'text-rail-muted hover:bg-rail-raised/60 hover:text-rail-text'}`}>
      {({ isActive }) => (
        <>
          {/* bus node + the trace that joins it to the active item */}
          <span aria-hidden="true" className={`absolute top-1/2 -translate-y-1/2 rounded-full transition-all duration-200 ease-out ${
            isActive
              ? '-left-[16.5px] h-[9px] w-[9px] border-2 border-eagle-400 bg-rail'
              : '-left-[14.5px] h-[5px] w-[5px] bg-rail-line group-hover:bg-rail-muted'}`} />
          <span aria-hidden="true" className={`absolute -left-[8px] top-1/2 h-px origin-left bg-eagle-400 transition-transform duration-300 ease-out ${
            isActive ? 'w-[8px] scale-x-100' : 'w-[8px] scale-x-0'}`} />
          <item.icon className={`h-4 w-4 flex-shrink-0 transition-colors ${isActive ? 'text-eagle-300' : ''}`} />
          <span className="truncate">{item.label}</span>
        </>
      )}
    </NavLink>
  )
}

function AgentPulse({ collapsed }) {
  const pulse = useAgentPulse()
  if (!pulse) return null
  const down = pulse.total - pulse.online
  const tone = pulse.total === 0 ? 'bg-rail-muted' : pulse.online === 0 ? 'bg-accent-red' : down > 0 ? 'bg-accent-amber' : 'bg-accent-cyan'
  const live = pulse.online > 0
  const text = pulse.total === 0 ? 'No agents registered' : `${pulse.online} of ${pulse.total} agents online`
  return (
    <Link to="/agents" title={collapsed ? text : undefined}
      className={`flex items-center gap-2.5 rounded-md text-xs text-rail-muted transition-colors hover:bg-rail-raised/60 hover:text-rail-text ${collapsed ? 'mx-auto h-10 w-10 justify-center' : 'px-2.5 py-2'}`}>
      <span className={`${live ? 'live-dot' : 'inline-block h-2 w-2 rounded-full'} ${tone}`} />
      {!collapsed && (
        <span className="min-w-0 leading-tight">
          <span className="block truncate text-rail-text">{text}</span>
          {pulse.degraded > 0 && <span className="block truncate">{pulse.degraded} reporting late</span>}
        </span>
      )}
    </Link>
  )
}

export default function Sidebar({ collapsed, onToggle, drawer = false, open = false }) {
  const { logout, user } = useAuth()
  const sections = buildNavSections(user?.role)
  const role = user?.role?.replace(/_/g, ' ')

  return (
    <aside
      aria-hidden={drawer && !open ? true : undefined}
      className={`fixed left-0 top-0 z-50 flex h-screen flex-col overflow-hidden border-r border-rail-line bg-rail text-rail-text transition-[width,transform,visibility] duration-300 ease-out ${collapsed ? 'w-16' : 'w-64'} ${
        drawer ? (open ? 'translate-x-0 shadow-float' : '-translate-x-full invisible') : ''}`}
    >
      {/* Brand */}
      <div className={`flex h-16 flex-shrink-0 items-center border-b border-rail-line ${collapsed ? 'justify-center px-2' : 'justify-between pl-4 pr-2'}`}>
        <Link to="/" title="UMEagleEye · Dashboard" className="flex min-w-0 items-center gap-2 rounded-md transition-opacity hover:opacity-90">
          {collapsed
            ? <BrandLogo variant="mark" className="h-10 w-10" />
            : <>
                <BrandLogo tone="onDark" className="h-[54px] w-auto" />
              </>}
        </Link>
        {!collapsed && (
          <button type="button" onClick={onToggle} title={drawer ? 'Close menu' : 'Collapse sidebar'} aria-label={drawer ? 'Close menu' : 'Collapse sidebar'}
            className="rounded-md p-1.5 text-rail-muted transition-colors hover:bg-rail-raised hover:text-rail-text">
            <ChevronsLeft className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav aria-label="Main" className="flex-1 overflow-y-auto overflow-x-hidden px-3 py-4 [scrollbar-color:rgb(var(--rail-line))_transparent]">
        {sections.map((section, idx) => (
          <div key={section.label} className={collapsed ? '' : 'mb-5'}>
            {collapsed
              ? idx > 0 && <div className="mx-2 my-2 h-px bg-rail-line" />
              : <p className="mb-1.5 px-1 font-display text-[11px] font-semibold uppercase tracking-[0.12em] text-rail-muted/80">{section.label}</p>}
            <div className="relative">
              {!collapsed && <span aria-hidden="true" className="absolute bottom-[18px] left-[8px] top-[18px] w-px bg-rail-line" />}
              <div className="space-y-0.5">
                {section.items.map((item) => <NavItem key={item.to} item={item} collapsed={collapsed} />)}
              </div>
            </div>
          </div>
        ))}
      </nav>

      {/* Foot: live agents + who is signed in */}
      <div className={`flex-shrink-0 space-y-1 border-t border-rail-line ${collapsed ? 'px-2 py-2' : 'p-3'}`}>
        <AgentPulse collapsed={collapsed} />
        {collapsed && (
          <button type="button" onClick={onToggle} title="Expand sidebar" aria-label="Expand sidebar"
            className="mx-auto flex h-10 w-10 items-center justify-center rounded-md text-rail-muted transition-colors hover:bg-rail-raised hover:text-rail-text">
            <ChevronsRight className="h-4 w-4" />
          </button>
        )}
        <div className={`flex items-center ${collapsed ? 'flex-col gap-1' : 'gap-2.5 px-1 pt-1'}`}>
          <span title={collapsed ? `${user?.username} · ${role}` : undefined}
            className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md bg-eagle-600 font-display text-sm font-semibold text-on-brand">
            {user?.username?.[0]?.toUpperCase() || 'U'}
          </span>
          {!collapsed && (
            <span className="min-w-0 flex-1 leading-tight">
              <span className="block truncate text-sm font-medium text-rail-text">{user?.username || 'User'}</span>
              <span className="block truncate text-[11px] capitalize text-rail-muted">{role || 'Role'}</span>
            </span>
          )}
          <button type="button" onClick={logout} title="Log out" aria-label="Log out"
            className={`flex-shrink-0 rounded-md text-rail-muted transition-colors hover:bg-rail-raised hover:text-accent-red ${collapsed ? 'flex h-10 w-10 items-center justify-center' : 'p-1.5'}`}>
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}
