import { useAuth } from '../../context/AuthContext'

// Shown to a platform superadmin when the permissions catalog could not be loaded.
export default function PermissionsError() {
  const { retryCatalog } = useAuth()
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="glass-card p-8 text-center max-w-md">
        <h2 className="text-xl font-bold text-accent-red mb-2">Could not load your permissions.</h2>
        <button type="button" onClick={retryCatalog} className="btn-primary mt-4">Retry</button>
      </div>
    </div>
  )
}
