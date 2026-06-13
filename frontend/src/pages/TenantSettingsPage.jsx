import { useState, useEffect, useCallback } from 'react'
import {
  Building2, Users, Plus, Check, RefreshCw,
  ToggleLeft, ToggleRight, X, AlertTriangle,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// Roles a tenant_superadmin may assign to other users
const ASSIGNABLE_ROLES = [
  { value: 'tenant_admin',   label: 'Tenant Admin',   color: 'text-blue-400'  },
  { value: 'business_owner', label: 'Business Owner', color: 'text-green-400' },
]

const ROLE_COLORS = {
  tenant_superadmin: 'text-purple-400',
  tenant_admin:      'text-blue-400',
  business_owner:    'text-green-400',
}

const roleLabel = (r) => ({
  tenant_superadmin: 'Tenant Superadmin',
  tenant_admin:      'Tenant Admin',
  business_owner:    'Business Owner',
}[r] ?? (r?.replace(/_/g, ' ') ?? '—'))

// ── Invite / Assign Modal ─────────────────────────────────────────
function InviteModal({ tenantId, onClose, onInvite }) {
  const [mode, setMode] = useState('email')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [role, setRole] = useState('tenant_admin')
  const [assignUsername, setAssignUsername] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const payload = mode === 'email'
        ? { email, username: username || undefined, role }
        : { username: assignUsername }
      const res = await onInvite(payload)
      setResult(res)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to invite user')
    } finally { setSubmitting(false) }
  }

  if (result) {
    return (
      <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
        <div className="glass-card w-full max-w-sm p-5 space-y-4">
          <div className="flex items-center gap-2 text-green-400">
            <Check className="w-5 h-5" />
            <h3 className="font-semibold text-white text-sm">
              {result.action === 'created' ? 'User Created & Assigned' : 'User Assigned'}
            </h3>
          </div>
          <div className="bg-dark-800/60 rounded-xl p-3 text-xs space-y-1 border border-dark-700/40">
            <p className="text-dark-300"><span className="text-dark-500">Username:</span> {result.username}</p>
            <p className="text-dark-300"><span className="text-dark-500">Email:</span> {result.email}</p>
            <p className="text-dark-300"><span className="text-dark-500">Role:</span> {roleLabel(result.role)}</p>
            {result.action === 'created' && (
              <p className="text-yellow-400 pt-1">User must sign in via Google using this email address.</p>
            )}
          </div>
          <button onClick={onClose} className="btn-primary w-full text-sm">Done</button>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-sm p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white text-sm">Add User</h3>
          <button onClick={onClose} className="text-dark-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex gap-1 p-1 bg-dark-800/60 rounded-lg border border-dark-700/50">
          {['email', 'username'].map(m => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`flex-1 text-xs py-1.5 rounded-md transition-colors ${mode === m ? 'bg-eagle-500/20 text-eagle-400' : 'text-dark-400 hover:text-white'}`}
            >
              {m === 'email' ? 'Invite by Email' : 'Assign by Username'}
            </button>
          ))}
        </div>

        {error && <p className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded-lg p-2">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === 'email' ? (
            <>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Email *</label>
                <input
                  type="email" value={email} onChange={e => setEmail(e.target.value)}
                  placeholder="user@gmail.com" className="input-field w-full text-sm" required
                />
                <p className="text-xs text-dark-500 mt-1">If no account exists, one will be created. User must sign in via Google.</p>
              </div>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Username <span className="text-dark-600">(optional)</span></label>
                <input
                  type="text" value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="auto-generated" className="input-field w-full text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Role</label>
                <select value={role} onChange={e => setRole(e.target.value)} className="input-field w-full text-sm">
                  {ASSIGNABLE_ROLES.map(o => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
            </>
          ) : (
            <div>
              <label className="block text-xs text-dark-400 mb-1">Username</label>
              <input
                type="text" value={assignUsername} onChange={e => setAssignUsername(e.target.value)}
                placeholder="e.g. john_doe"
                className="input-field w-full text-sm" required
              />
              <p className="text-xs text-dark-500 mt-1">Must match an existing account username exactly.</p>
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-xs py-1.5">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-xs py-1.5 flex items-center justify-center gap-1">
              {submitting
                ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
                : <Check className="w-3 h-3" />}
              {mode === 'email' ? 'Invite' : 'Assign User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function TenantSettingsPage() {
  const { user } = useAuth()
  const isTenantSuperadmin = user?.role === 'tenant_superadmin'
  const tenantId = user?.tenantId

  const [tenant, setTenant]         = useState(null)
  const [users, setUsers]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [saving, setSaving]         = useState(false)
  const [saveError, setSaveError]   = useState(null)

  // Tenant edit fields
  const [tenantName, setTenantName] = useState('')
  const [isActive, setIsActive]     = useState(true)
  const [tenantDirty, setTenantDirty] = useState(false)

  // Per-user role edits
  const [pendingRoles, setPendingRoles] = useState({})
  const [savingRole, setSavingRole]     = useState({})
  const [roleError, setRoleError]       = useState({})

  // Per-user active toggle
  const [togglingActive, setTogglingActive] = useState({})
  const [activeError, setActiveError]       = useState({})

  const [showInvite, setShowInvite] = useState(false)

  const loadData = useCallback(async () => {
    if (!tenantId) return
    setLoading(true)
    const [tResult, uResult] = await Promise.allSettled([
      client.get(`/tenants/${tenantId}`),
      client.get(`/tenants/${tenantId}/users`),
    ])
    if (tResult.status === 'fulfilled') {
      const t = tResult.value.data
      setTenant(t)
      setTenantName(t.name)
      setIsActive(t.is_active)
      setTenantDirty(false)
    }
    if (uResult.status === 'fulfilled') {
      setUsers(uResult.value.data.users || [])
    }
    setLoading(false)
  }, [tenantId])

  useEffect(() => { loadData() }, [loadData])

  const saveTenantSettings = async () => {
    if (!tenantId) return
    setSaving(true)
    setSaveError(null)
    try {
      await client.patch(`/tenants/${tenantId}`, { name: tenantName, is_active: isActive })
      await loadData()
    } catch (err) {
      setSaveError(err?.response?.data?.detail || 'Failed to save settings')
    } finally { setSaving(false) }
  }

  const saveRole = async (userId) => {
    const newRole = pendingRoles[userId]
    if (!newRole || !tenantId) return
    setSavingRole(prev => ({ ...prev, [userId]: true }))
    setRoleError(prev => ({ ...prev, [userId]: null }))
    try {
      await client.patch(`/tenants/${tenantId}/users/${userId}/role`, { role: newRole })
      await loadData()
      setPendingRoles(prev => { const n = { ...prev }; delete n[userId]; return n })
    } catch (err) {
      setRoleError(prev => ({ ...prev, [userId]: err?.response?.data?.detail || 'Failed to save role' }))
    } finally { setSavingRole(prev => ({ ...prev, [userId]: false })) }
  }

  const toggleUserActive = async (userId, currentIsActive) => {
    if (!tenantId) return
    setTogglingActive(prev => ({ ...prev, [userId]: true }))
    setActiveError(prev => ({ ...prev, [userId]: null }))
    try {
      await client.patch(`/tenants/${tenantId}/users/${userId}/deactivate`, { is_active: !currentIsActive })
      await loadData()
    } catch (err) {
      setActiveError(prev => ({ ...prev, [userId]: err?.response?.data?.detail || 'Failed to update status' }))
    } finally {
      setTogglingActive(prev => ({ ...prev, [userId]: false }))
    }
  }

  const handleInvite = async (payload) => {
    if (!tenantId) return
    let result
    if (payload.username && !payload.email) {
      const r = await client.post(`/tenants/${tenantId}/users`, { username: payload.username })
      result = { action: 'assigned', username: r.data.username || payload.username, email: '', role: '' }
    } else {
      const r = await client.post(`/tenants/${tenantId}/users/invite`, payload)
      result = r.data
    }
    await loadData()
    return result
  }

  if (loading) {
    return (
      <div className="flex justify-center py-20">
        <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Tenant Management</h1>
        <p className="text-dark-400 text-sm mt-1">
          {tenant?.name} · {isTenantSuperadmin ? 'Manage settings and users' : 'View users'}
        </p>
      </div>

      {/* ── Tenant Settings (tenant_superadmin only) ── */}
      {isTenantSuperadmin && tenant && (
        <div className="glass-card p-6 space-y-5">
          <h2 className="font-semibold text-white flex items-center gap-2 text-base">
            <Building2 className="w-4 h-4 text-accent-cyan" />
            Tenant Settings
          </h2>

          {saveError && (
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {saveError}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-dark-400 mb-1">Tenant Name</label>
              <input
                type="text"
                value={tenantName}
                onChange={e => { setTenantName(e.target.value); setTenantDirty(true) }}
                className="input-field w-full text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-dark-400 mb-1">Slug</label>
              <input
                type="text" value={tenant.slug} disabled
                className="input-field w-full text-sm opacity-50 font-mono"
              />
            </div>
          </div>

          {tenantDirty && (
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => { setTenantName(tenant.name); setTenantDirty(false); setSaveError(null) }}
                className="btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={saveTenantSettings}
                disabled={saving || !tenantName.trim()}
                className="btn-primary flex items-center gap-2 text-sm"
              >
                {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                Save Changes
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Users ── */}
      <div className="glass-card overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-dark-700/50">
          <div>
            <h2 className="font-semibold text-white flex items-center gap-2 text-base">
              <Users className="w-4 h-4 text-accent-cyan" />
              Users
            </h2>
            <p className="text-xs text-dark-400 mt-0.5">
              {users.length} member{users.length !== 1 ? 's' : ''}
            </p>
          </div>
          {isTenantSuperadmin && (
            <button onClick={() => setShowInvite(true)} className="btn-primary text-sm flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Add User
            </button>
          )}
        </div>

        <div className="p-4 space-y-2">
          {users.length === 0 ? (
            <p className="text-dark-400 text-sm text-center py-8">No users assigned to this tenant.</p>
          ) : (
            users.map(u => {
              const isSelf          = u.user_id === user?.userId
              const isTsUser        = u.role === 'tenant_superadmin'
              const canEditRole     = isTenantSuperadmin && !isTsUser
              const canToggleActive = isTenantSuperadmin && !isSelf && !isTsUser
              const currentRole   = pendingRoles[u.user_id] ?? u.role
              const isDirty       = pendingRoles[u.user_id] !== undefined && pendingRoles[u.user_id] !== u.role

              return (
                <div key={u.user_id} className="bg-dark-800/60 rounded-xl p-3 border border-dark-700/40 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-medium text-white text-sm">
                        {u.username}
                        {isSelf && <span className="ml-2 text-[10px] text-dark-500 bg-dark-700 rounded px-1 py-0.5">you</span>}
                      </p>
                      <p className="text-xs text-dark-400 truncate">{u.email}</p>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${
                        u.is_active
                          ? 'text-green-400 border-green-500/30 bg-green-500/10'
                          : 'text-dark-400 border-dark-600 bg-dark-800'
                      }`}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                      {canToggleActive && (
                        <button
                          onClick={() => toggleUserActive(u.user_id, u.is_active)}
                          disabled={!!togglingActive[u.user_id]}
                          title={u.is_active ? 'Deactivate user' : 'Activate user'}
                          className="text-dark-400 hover:text-white transition-colors"
                        >
                          {togglingActive[u.user_id]
                            ? <RefreshCw className="w-4 h-4 animate-spin" />
                            : u.is_active
                              ? <ToggleRight className="w-5 h-5 text-eagle-400" />
                              : <ToggleLeft  className="w-5 h-5" />}
                        </button>
                      )}
                    </div>
                  </div>

                  {canEditRole ? (
                    <div className="flex items-center gap-2">
                      <select
                        value={currentRole}
                        onChange={e => setPendingRoles(prev => ({ ...prev, [u.user_id]: e.target.value }))}
                        className="flex-1 text-xs bg-dark-700 border border-dark-600 rounded-lg px-2 py-1.5 text-dark-200 focus:border-eagle-500 focus:outline-none"
                      >
                        {ASSIGNABLE_ROLES.map(o => (
                          <option key={o.value} value={o.value}>{o.label}</option>
                        ))}
                      </select>
                      {isDirty && (
                        <button
                          onClick={() => saveRole(u.user_id)}
                          disabled={savingRole[u.user_id]}
                          className="btn-primary text-xs py-1 px-3 flex items-center gap-1 flex-shrink-0"
                        >
                          {savingRole[u.user_id]
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <Check className="w-3 h-3" />}
                          Save
                        </button>
                      )}
                      {!isDirty && (
                        <span className={`text-xs font-medium flex-shrink-0 ${ROLE_COLORS[u.role] ?? 'text-dark-300'}`}>
                          {roleLabel(u.role)}
                        </span>
                      )}
                    </div>
                  ) : (
                    <p className={`text-xs font-medium ${ROLE_COLORS[u.role] ?? 'text-dark-300'}`}>
                      {roleLabel(u.role)}
                    </p>
                  )}

                  {roleError[u.user_id] && (
                    <p className="text-xs text-red-400">{roleError[u.user_id]}</p>
                  )}
                  {activeError[u.user_id] && (
                    <p className="text-xs text-red-400">{activeError[u.user_id]}</p>
                  )}
                </div>
              )
            })
          )}
        </div>
      </div>

      {showInvite && (
        <InviteModal
          tenantId={tenantId}
          onClose={() => setShowInvite(false)}
          onInvite={handleInvite}
        />
      )}
    </div>
  )
}
