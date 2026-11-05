import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import CommandPalette from './CommandPalette'

const isTypingTarget = (el) =>
  el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)

const DESKTOP = '(min-width: 1024px)'

function useIsDesktop() {
  const [desktop, setDesktop] = useState(() => window.matchMedia(DESKTOP).matches)
  useEffect(() => {
    const mq = window.matchMedia(DESKTOP)
    const onChange = () => setDesktop(mq.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return desktop
}

export default function MainLayout() {
  const location = useLocation()
  const isDesktop = useIsDesktop()
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar-collapsed') === 'true'
  )
  const [drawerOpen, setDrawerOpen] = useState(false) // below 1024px the rail is a drawer
  const [paletteOpen, setPaletteOpen] = useState(false)

  const toggle = () => {
    if (!isDesktop) { setDrawerOpen((o) => !o); return }
    setCollapsed((c) => {
      const next = !c
      localStorage.setItem('sidebar-collapsed', String(next))
      return next
    })
  }

  // Close the drawer after navigating, and when growing to desktop width
  useEffect(() => { setDrawerOpen(false) }, [location.pathname, isDesktop])

  // Ctrl/Cmd+K anywhere, or "/" when not typing, opens the command palette
  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      } else if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !isTypingTarget(e.target)) {
        e.preventDefault()
        setPaletteOpen(true)
      } else if (e.key === 'Escape') {
        setDrawerOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const railCollapsed = isDesktop && collapsed

  return (
    <div className="flex min-h-screen bg-dark-950">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[80] focus:rounded-md focus:bg-eagle-600 focus:px-3 focus:py-2 focus:text-sm focus:text-on-brand">
        Skip to content
      </a>
      <Sidebar collapsed={railCollapsed} onToggle={toggle} drawer={!isDesktop} open={drawerOpen} />
      {!isDesktop && drawerOpen && (
        <div className="fixed inset-0 z-40 bg-dark-950/70 animate-[palette-fade_160ms_ease-out]" onClick={() => setDrawerOpen(false)} aria-hidden="true" />
      )}
      <div
        className={`min-w-0 flex-1 transition-[margin] duration-300 ease-out ${isDesktop ? (collapsed ? 'ml-16' : 'ml-64') : 'ml-0'}`}
      >
        <Header onToggleSidebar={toggle} onOpenPalette={() => setPaletteOpen(true)} />
        <main id="main" key={location.pathname} className="p-4 animate-[page-in_240ms_cubic-bezier(0.16,1,0.3,1)] lg:p-6">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}
