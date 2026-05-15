import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'

export default function MainLayout() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar-collapsed') === 'true'
  )

  const toggle = () =>
    setCollapsed((c) => {
      const next = !c
      localStorage.setItem('sidebar-collapsed', String(next))
      return next
    })

  return (
    <div className="flex min-h-screen bg-dark-950">
      <Sidebar collapsed={collapsed} onToggle={toggle} />
      <div
        className={`flex-1 min-w-0 transition-all duration-300 ease-in-out ${collapsed ? 'ml-16' : 'ml-64'}`}
      >
        <Header onToggleSidebar={toggle} />
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
