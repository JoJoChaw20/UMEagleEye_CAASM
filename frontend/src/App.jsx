import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import MainLayout from './components/layout/MainLayout'
import ProtectedRoute from './components/common/ProtectedRoute'
import LoginPage from './pages/LoginPage'
import MfaRecoveryPage from './pages/MfaRecoveryPage'
import DashboardPage from './pages/DashboardPage'
import InventoryPage from './pages/InventoryPage'
import NetworkMapPage from './pages/NetworkMapPage'
import AssetDetailPage from './pages/AssetDetailPage'
import DiscoveryPage from './pages/DiscoveryPage'
import AlertsPage from './pages/AlertsPage'
import AdvisoriesPage from './pages/AdvisoriesPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import SBOMPage from './pages/SBOMPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import AgentsPage from './pages/AgentsPage'
import TenantsPage from './pages/TenantsPage'
import TenantSettingsPage from './pages/TenantSettingsPage'
import OwnershipPage from './pages/OwnershipPage'
import { useEffect } from 'react'
import { useChatbot } from './context/ChatbotContext'
import { useAuth } from './context/AuthContext'
import PermissionsError from './components/common/PermissionsError'
import { buildNavSections } from './components/layout/navConfig'

// Route guards: pages need a view action; users and tenants are role-only
const isTenantSuperadmin = (u) => u.role === 'tenant_superadmin'
const isPlatformSuperadmin = (u) => u.role === 'superadmin'
const isTenantMember = (u) => u.role === 'tenant_user' || u.role === 'tenant_superadmin'

// Without dashboard.view the user is sent to their first page; a tenant user with no
// page at all gets this instead of an empty dashboard.
function DashboardRoute() {
  const { can, ready, user, catalogError } = useAuth()
  if (!ready) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
      </div>
    )
  }
  if (user?.role === 'superadmin' && catalogError) return <PermissionsError />
  if (!can('dashboard.view')) {
    // Open the first page the user can see instead (never '/' itself, never Settings)
    const first = buildNavSections(can, user?.role)
      .flatMap((s) => s.items)
      .find((i) => i.to !== '/' && i.to !== '/settings')
    if (first) return <Navigate to={first.to} replace />
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="glass-card p-8 text-center max-w-md">
          <p className="text-dark-300">You have no access yet. Ask your Tenant Superadmin to grant you actions.</p>
        </div>
      </div>
    )
  }
  return <DashboardPage />
}

// The old /assets (All Assets) and /my-assets pages were retired for /inventory. Old
// links and bookmarks keep working: a single-asset link opens that asset's page, any
// other query (filters) is carried over to the inventory.
function LegacyAssetsRedirect({ scope }) {
  const { search } = useLocation()
  const params = new URLSearchParams(search)
  const assetId = params.get('asset_id')
  if (assetId) return <Navigate to={`/inventory/${encodeURIComponent(assetId)}`} replace />
  if (scope && !params.has('scope')) params.set('scope', scope)
  const qs = params.toString()
  return <Navigate to={`/inventory${qs ? `?${qs}` : ''}`} replace />
}

// The assistant is a bubble in the bottom-right corner now, not a page. An old /chatbot
// link or bookmark opens the bubble's panel over the dashboard.
function ChatbotRedirect() {
  const { setWidgetOpen } = useChatbot()
  const { can, ready } = useAuth()
  const allowed = ready && can('chatbot.use')
  useEffect(() => { if (allowed) setWidgetOpen(true) }, [allowed, setWidgetOpen])
  if (!ready) return null
  return <Navigate to="/" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Public: the confirm and cancel links of the break-glass MFA reset email */}
      <Route path="/mfa-recovery" element={<MfaRecoveryPage />} />
      <Route path="/" element={
        <ProtectedRoute><MainLayout /></ProtectedRoute>
      }>
        {/* OVERVIEW */}
        <Route index element={<DashboardRoute />} />

        {/* ASSETS — each page needs its view action */}
        {/* Merged inventory (My Assets + Discovered) and asset detail. */}
        <Route path="assets"    element={<LegacyAssetsRedirect />} />
        <Route path="my-assets" element={<LegacyAssetsRedirect scope="mine" />} />
        <Route path="inventory"          element={<ProtectedRoute action="asset.view"><InventoryPage /></ProtectedRoute>} />
        <Route path="inventory/:assetId" element={<ProtectedRoute action="asset.view"><AssetDetailPage /></ProtectedRoute>} />

        {/* DISCOVERY / NETWORK */}
        <Route path="discovery" element={<ProtectedRoute action="scan.view"><DiscoveryPage /></ProtectedRoute>} />
        <Route path="network-map" element={<ProtectedRoute action="network.view"><NetworkMapPage /></ProtectedRoute>} />

        {/* SECURITY */}
        <Route path="alerts"       element={<ProtectedRoute action="alert.view"><AlertsPage /></ProtectedRoute>} />
        <Route path="advisories"   element={<ProtectedRoute action="advisory.view"><AdvisoriesPage /></ProtectedRoute>} />
        <Route path="threat-intel" element={<ProtectedRoute action="cti.view"><ThreatIntelPage /></ProtectedRoute>} />
        <Route path="sbom"         element={<ProtectedRoute action="sbom.view"><SBOMPage /></ProtectedRoute>} />

        {/* REPORTS */}
        <Route path="reports" element={<ProtectedRoute action="report.view"><ReportsPage /></ProtectedRoute>} />

        {/* SYSTEM */}
        <Route path="agents"   element={<ProtectedRoute action="agent.view"><AgentsPage /></ProtectedRoute>} />
        <Route path="chatbot"  element={<ChatbotRedirect />} />
        <Route path="settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
        <Route path="ownership" element={<ProtectedRoute check={isTenantMember}><OwnershipPage /></ProtectedRoute>} />

        {/* ADMIN */}
        <Route path="tenants" element={<ProtectedRoute check={isPlatformSuperadmin}><TenantsPage /></ProtectedRoute>} />
        <Route path="users"   element={<ProtectedRoute check={isTenantSuperadmin}><TenantSettingsPage /></ProtectedRoute>} />
      </Route>
    </Routes>
  )
}
