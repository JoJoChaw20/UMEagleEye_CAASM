import { Routes, Route } from 'react-router-dom'
import MainLayout from './components/layout/MainLayout'
import ProtectedRoute from './components/common/ProtectedRoute'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AssetsPage from './pages/AssetsPage'
import AlertsPage from './pages/AlertsPage'
import AdvisoriesPage from './pages/AdvisoriesPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <ProtectedRoute><MainLayout /></ProtectedRoute>
      }>
        <Route index element={<DashboardPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="advisories" element={<AdvisoriesPage />} />
        <Route path="threat-intel" element={<ThreatIntelPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}
