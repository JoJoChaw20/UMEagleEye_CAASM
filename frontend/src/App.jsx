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
import ChatbotPage from './pages/ChatbotPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <ProtectedRoute><MainLayout /></ProtectedRoute>
      }>
        <Route index element={<DashboardPage />} />
        {/* Assets */}
        <Route path="assets" element={<AssetsPage />} />
        <Route path="my-assets" element={<MyAssetsPage />} />
        <Route path="discovery" element={<DiscoveryPage />} />
        {/* Network */}
        <Route path="topology" element={<TopologyPage />} />
        {/* Security */}
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="advisories" element={<AdvisoriesPage />} />
        <Route path="threat-intel" element={<ThreatIntelPage />} />
        <Route path="sbom" element={<SBOMPage />} />
        {/* Reports */}
        <Route path="reports" element={<ReportsPage />} />
        {/* System */}
        <Route path="agents" element={<AgentsPage />} />
        <Route path="chatbot" element={<ChatbotPage />} />
        <Route path="tenants" element={<TenantsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}
