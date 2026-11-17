import { Navigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

// `action` needs that action; `check(user)` is for role-only pages (users, tenants).
export default function ProtectedRoute({ children, action, check }) {
  const { user, token, loading, can } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-dark-950">
        <div className="w-10 h-10 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
      </div>
    )
  }

  if (!token) return <Navigate to="/login" replace />

  const denied = user && ((action && !can(action)) || (check && !check(user)))
  if (denied) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="glass-card p-8 text-center max-w-md">
          <h2 className="text-xl font-bold text-accent-red mb-2">Access Denied</h2>
          <p className="text-dark-300">You do not have access to this page. Ask your Tenant Superadmin for access.</p>
        </div>
      </div>
    )
  }

  return children
}
