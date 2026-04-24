import { Navigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

export default function ProtectedRoute({ children, allowedRoles }) {
  const { user, token, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-dark-950">
        <div className="w-10 h-10 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
      </div>
    )
  }

  if (!token) return <Navigate to="/login" replace />

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="glass-card p-8 text-center max-w-md">
          <h2 className="text-xl font-bold text-accent-red mb-2">Access Denied</h2>
          <p className="text-dark-300">Your role does not have permission to access this page.</p>
        </div>
      </div>
    )
  }

  return children
}
