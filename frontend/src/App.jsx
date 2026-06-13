import { Routes, Route } from 'react-router-dom'
import MainLayout from './components/layout/MainLayout'
import ProtectedRoute from './components/common/ProtectedRoute'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AssetsPage from './pages/AssetsPage'
import MyAssetsPage from './pages/MyAssetsPage'
import DiscoveryPage from './pages/DiscoveryPage'
import AlertsPage from './pages/AlertsPage'
import AdvisoriesPage from './pages/AdvisoriesPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import SBOMPage from './pages/SBOMPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import TopologyPage from './pages/TopologyPage'
import AgentsPage from './pages/AgentsPage'
import TenantsPage from './pages/TenantsPage'
import TenantSettingsPage from './pages/TenantSettingsPage'
import ChatbotPage from './pages/ChatbotPage'

// Role groups used by route guards
const ALL_ROLES        = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const OPS_ROLES        = ['superadmin', 'tenant_superadmin', 'tenant_admin']
const TENANT_MGMT      = ['superadmin']
const USER_MGMT_ROLES  = ['superadmin', 'tenant_superadmin', 'tenant_admin']
const SETTINGS_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin']

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <ProtectedRoute><MainLayout /></ProtectedRoute>
      }>
        {/* OVERVIEW — all roles */}
        <Route index element={<DashboardPage />} />

        {/* ASSETS — all roles can view; write restricted on backend */}
        <Route path="assets"    element={<ProtectedRoute allowedRoles={ALL_ROLES}><AssetsPage /></ProtectedRoute>} />
        <Route path="my-assets" element={<ProtectedRoute allowedRoles={ALL_ROLES}><MyAssetsPage /></ProtectedRoute>} />

        {/* DISCOVERY / NETWORK — business_owner excluded */}
        <Route path="discovery" element={<ProtectedRoute allowedRoles={OPS_ROLES}><DiscoveryPage /></ProtectedRoute>} />
        <Route path="topology"  element={<ProtectedRoute allowedRoles={OPS_ROLES}><TopologyPage /></ProtectedRoute>} />

        {/* SECURITY — all roles */}
        <Route path="alerts"       element={<ProtectedRoute allowedRoles={ALL_ROLES}><AlertsPage /></ProtectedRoute>} />
        <Route path="advisories"   element={<ProtectedRoute allowedRoles={ALL_ROLES}><AdvisoriesPage /></ProtectedRoute>} />
        <Route path="threat-intel" element={<ProtectedRoute allowedRoles={ALL_ROLES}><ThreatIntelPage /></ProtectedRoute>} />
        <Route path="sbom"         element={<ProtectedRoute allowedRoles={ALL_ROLES}><SBOMPage /></ProtectedRoute>} />

        {/* REPORTS — all roles */}
        <Route path="reports" element={<ProtectedRoute allowedRoles={ALL_ROLES}><ReportsPage /></ProtectedRoute>} />

        {/* SYSTEM */}
        <Route path="agents"   element={<ProtectedRoute allowedRoles={ALL_ROLES}><AgentsPage /></ProtectedRoute>} />
        <Route path="chatbot"  element={<ProtectedRoute allowedRoles={ALL_ROLES}><ChatbotPage /></ProtectedRoute>} />
        <Route path="settings" element={<ProtectedRoute allowedRoles={SETTINGS_ROLES}><SettingsPage /></ProtectedRoute>} />

        {/* ADMIN */}
        <Route path="tenants" element={<ProtectedRoute allowedRoles={TENANT_MGMT}><TenantsPage /></ProtectedRoute>} />
        <Route path="users"   element={<ProtectedRoute allowedRoles={USER_MGMT_ROLES}><TenantSettingsPage /></ProtectedRoute>} />
      </Route>
    </Routes>
  )
}
