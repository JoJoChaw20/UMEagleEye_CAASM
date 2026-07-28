import { useState, useEffect, useCallback } from 'react'
import { Plus, Edit2, Users, X, Check, Shield, ToggleLeft, ToggleRight, ChevronRight, RefreshCw, Building2 } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Status badge ──────────────────────────────────────────────────
function ActiveBadge({ active }) {
  return active
    ? <span className="text-xs px-2 py-0.5 rounded-full border bg-green-500/20 text-green-400 border-green-500/30">Active</span>
    : <span className="text-xs px-2 py-0.5 rounded-full border bg-red-500/20 text-red-400 border-red-500/30">Inactive</span>
}

// ── Auto-generate slug from name ──────────────────────────────────
function nameToSlug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
}

// ── Create Tenant Modal ───────────────────────────────────────────
function CreateTenantModal({ onClose, onSubmit }) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [autoSlug, setAutoSlug] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const handleNameChange = (v) => {
    setName(v)
    if (autoSlug) setSlug(nameToSlug(v))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await onSubmit({ name, slug })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to create tenant')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Create Tenant</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Tenant Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="Acme Corporation"
              className="input-field w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">
              Slug *
              <span className="ml-2 text-dark-500">(lowercase kebab-case)</span>
            </label>
            <input
              type="text"
              value={slug}
              onChange={(e) => { setAutoSlug(false); setSlug(e.target.value) }}
              placeholder="acme-corporation"
              className="input-field w-full text-sm font-mono"
              required
            />
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {submitting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-4 h-4" />}
              Create Tenant
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Edit Tenant Modal ─────────────────────────────────────────────
function EditTenantModal({ tenant, onClose, onSave }) {
  const [name, setName] = useState(tenant.name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      await onSave(tenant.tenant_id, { name })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to update tenant')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Edit Tenant</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <div className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="input-field w-full text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Slug</label>
            <input type="text" value={tenant.slug} disabled className="input-field w-full text-sm opacity-50 font-mono" />
          </div>
        </div>

        <div className="flex gap-3">
          <button onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
          <button onClick={handleSave} disabled={saving} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
            {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Check className="w-4 h-4" />}
            Save Changes
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Invite / Assign User Modal ────────────────────────────────────
function InviteUserModal({ tenantId, onClose, onInvite }) {
  const [mode, setMode] = useState('email') // 'email' | 'username'
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [role, setRole] = useState('business_owner')
  const [assignUsername, setAssignUsername] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    setResult(null)
    try {
      const res = await onInvite(tenantId, mode === 'email' ? { email, username: username || undefined, role } : { username: assignUsername })
      setResult(res)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to invite user')
    } finally {
      setSubmitting(false)
    }
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
            <p className="text-dark-300"><span className="text-dark-500">Role:</span> {result.role}</p>
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
          <h3 className="font-semibold text-white text-sm">Add User to Tenant</h3>
          <button onClick={onClose} className="text-dark-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode toggle */}
        <div className="flex gap-1 p-1 bg-dark-800/60 rounded-lg border border-dark-700/50">
          <button
            type="button"
            onClick={() => setMode('email')}
            className={`flex-1 text-xs py-1.5 rounded-md transition-colors ${mode === 'email' ? 'bg-eagle-500/20 text-eagle-400' : 'text-dark-400 hover:text-white'}`}
          >
            Invite by Email
          </button>
          <button
            type="button"
            onClick={() => setMode('username')}
            className={`flex-1 text-xs py-1.5 rounded-md transition-colors ${mode === 'username' ? 'bg-eagle-500/20 text-eagle-400' : 'text-dark-400 hover:text-white'}`}
          >
            Assign by Username
          </button>
        </div>

        {error && <p className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded-lg p-2">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === 'email' ? (
            <>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Email *</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@gmail.com"
                  className="input-field w-full text-sm"
                  required
                />
                <p className="text-xs text-dark-500 mt-1">If no account exists, one will be created. User must sign in via Google.</p>
              </div>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Username <span className="text-dark-600">(optional — auto-derived from email)</span></label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="auto-generated"
                  className="input-field w-full text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-dark-400 mb-1">Role</label>
                <select value={role} onChange={(e) => setRole(e.target.value)} className="input-field w-full text-sm">
                  <option value="tenant_superadmin">Tenant Superadmin</option>
                  <option value="tenant_admin">Tenant Admin</option>
                  <option value="business_owner">Business Owner</option>
                </select>
              </div>
            </>
          ) : (
            <div>
              <label className="block text-xs text-dark-400 mb-1">Username</label>
              <input
                type="text"
                value={assignUsername}
                onChange={(e) => setAssignUsername(e.target.value)}
                placeholder="e.g. john_doe"
                className="input-field w-full text-sm"
                required
              />
              <p className="text-xs text-dark-500 mt-1">Must match an existing account username exactly.</p>
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-xs py-1.5">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-xs py-1.5 flex items-center justify-center gap-1">
              {submitting ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" /> : <Check className="w-3 h-3" />}
              {mode === 'email' ? 'Invite' : 'Assign User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Users side panel ──────────────────────────────────────────────
const ROLE_OPTIONS = [
  { value: 'tenant_superadmin', label: 'Tenant Superadmin', color: 'text-purple-400' },
  { value: 'tenant_admin',      label: 'Tenant Admin',      color: 'text-blue-400'   },
  { value: 'business_owner',    label: 'Business Owner',    color: 'text-green-400'  },
]
const roleColor = (r) => ROLE_OPTIONS.find(o => o.value === r)?.color ?? 'text-dark-300'
const roleLabel = (r) => ROLE_OPTIONS.find(o => o.value === r)?.label ?? (r?.replace(/_/g, ' ') ?? '—')

function UsersPanel({ tenant, onClose, onAssigned }) {
  const { user: currentUser } = useAuth()
  const isSuperadmin = currentUser?.role === 'superadmin'

  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAssign, setShowAssign] = useState(false)
  const [pendingRoles, setPendingRoles] = useState({})   // userId → new role string
  const [savingRole, setSavingRole] = useState({})       // userId → bool
  const [roleError, setRoleError] = useState({})         // userId → error string

  const refreshUsers = () =>
    client.get(`/tenants/${tenant.tenant_id}/users`)
      .then(res => setUsers(res.data.users || []))
      .catch(() => setUsers([]))
      .finally(() => setLoading(false))

  useEffect(() => { refreshUsers() }, [tenant.tenant_id])

  const handleInvite = async (tenantId, payload) => {
    let result
    if (payload.username && !payload.email) {
      const r = await client.post(`/tenants/${tenantId}/users`, { username: payload.username })
      result = { action: 'assigned', username: r.data.username || payload.username, email: '', role: '' }
    } else {
      const r = await client.post(`/tenants/${tenantId}/users/invite`, payload)
      result = r.data
    }
    await refreshUsers()
    if (onAssigned) onAssigned()
    return result
  }

  const saveRole = async (userId) => {
    const newRole = pendingRoles[userId]
    if (!newRole) return
    setSavingRole(prev => ({ ...prev, [userId]: true }))
    setRoleError(prev => ({ ...prev, [userId]: null }))
    try {
      await client.patch(`/tenants/${tenant.tenant_id}/users/${userId}/role`, { role: newRole })
      await refreshUsers()
      setPendingRoles(prev => { const n = { ...prev }; delete n[userId]; return n })
    } catch (err) {
      setRoleError(prev => ({ ...prev, [userId]: err?.response?.data?.detail || 'Failed to change role' }))
    } finally {
      setSavingRole(prev => ({ ...prev, [userId]: false }))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end bg-black/40 backdrop-blur-sm">
      <div className="glass-card w-full sm:w-[460px] h-full sm:h-auto sm:max-h-[85vh] flex flex-col overflow-hidden sm:rounded-2xl sm:mr-4 sm:mb-4">
        <div className="flex items-center justify-between p-4 border-b border-dark-700/50">
          <div>
            <h3 className="font-semibold text-white">Users — {tenant.name}</h3>
            <p className="text-xs text-dark-400 mt-0.5">{users.length} member{users.length !== 1 ? 's' : ''}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAssign(true)}
              className="btn-secondary text-xs py-1 px-2 flex items-center gap-1"
            >
              <Plus className="w-3 h-3" />
              Add User
            </button>
            <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-6 h-6 border-2 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
            </div>
          ) : users.length === 0 ? (
            <p className="text-dark-400 text-sm text-center py-8">No users assigned to this tenant.</p>
          ) : (
            users.map((u) => {
              const currentRole = pendingRoles[u.user_id] ?? u.role
              const isDirty = pendingRoles[u.user_id] && pendingRoles[u.user_id] !== u.role
              return (
                <div key={u.user_id} className="bg-dark-800/60 rounded-xl p-3 border border-dark-700/40 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-medium text-white text-sm">{u.username}</p>
                      <p className="text-xs text-dark-400 truncate">{u.email}</p>
                      <p className="text-[11px] text-dark-400 font-mono mt-1 break-all bg-dark-900/70 border border-dark-700 rounded px-2 py-1">
                        <span className="text-dark-500 mr-1">User ID:</span>{u.user_id || '—'}
                      </p>
                    </div>
                    <span className="text-xs text-dark-500 flex-shrink-0">{u.is_active ? 'Active' : 'Inactive'}</span>
                  </div>

                  {isSuperadmin ? (
                    <div className="flex items-center gap-2">
                      <select
                        value={currentRole}
                        onChange={e => setPendingRoles(prev => ({ ...prev, [u.user_id]: e.target.value }))}
                        className="flex-1 text-xs bg-dark-700 border border-dark-600 rounded-lg px-2 py-1.5 text-dark-200 focus:border-eagle-500 focus:outline-none appearance-none"
                      >
                        {ROLE_OPTIONS.map(o => (
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
                        <span className={`text-xs font-medium flex-shrink-0 ${roleColor(u.role)}`}>
                          {roleLabel(u.role)}
                        </span>
                      )}
                    </div>
                  ) : (
                    <p className={`text-xs font-medium ${roleColor(u.role)}`}>{roleLabel(u.role)}</p>
                  )}

                  {roleError[u.user_id] && (
                    <p className="text-xs text-red-400">{roleError[u.user_id]}</p>
                  )}
                </div>
              )
            })
          )}
        </div>
      </div>

      {showAssign && (
        <InviteUserModal
          tenantId={tenant.tenant_id}
          onClose={() => setShowAssign(false)}
          onInvite={handleInvite}
        />
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function TenantsPage() {
  const { user } = useAuth()
  const [tenants, setTenants] = useState([])
  const [tenantDetails, setTenantDetails] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editTenant, setEditTenant] = useState(null)
  const [usersTenant, setUsersTenant] = useState(null)

  const loadTenants = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await client.get('/tenants')
      const rows = res.data.tenants || []
      setTenants(rows)
      const details = {}
      await Promise.allSettled(rows.map(async (t) => {
        try {
          const d = await client.get(`/tenants/${t.tenant_id}`)
          details[t.tenant_id] = d.data
        } catch { /* skip */ }
      }))
      setTenantDetails(details)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load tenants')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadTenants() }, [loadTenants])

  // Redirect non-superadmin (after all hooks)
  if (user && user.role !== 'superadmin') {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center text-dark-400">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>Access denied. SuperAdmin only.</p>
        </div>
      </div>
    )
  }

  const handleCreate = async ({ name, slug }) => {
    await client.post('/tenants', { name, slug })
    await loadTenants()
  }

  const handleEdit = async (tenantId, updates) => {
    await client.patch(`/tenants/${tenantId}`, updates)
    setTenants(prev => prev.map(t => t.tenant_id === tenantId ? { ...t, ...updates } : t))
  }

  const handleDeactivate = async (tenantId, currentActive) => {
    const action = currentActive ? 'deactivate' : 'activate'
    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} this tenant?`)) return
    try {
      await client.patch(`/tenants/${tenantId}`, { is_active: !currentActive })
      setTenants(prev => prev.map(t => t.tenant_id === tenantId ? { ...t, is_active: !currentActive } : t))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to update tenant')
    }
  }

  return (
    <div className="space-y-6">
      {/* SuperAdmin banner */}
      <div className="flex items-center gap-3 p-3 bg-purple-500/10 border border-purple-500/30 rounded-xl">
        <Shield className="w-5 h-5 text-purple-400 flex-shrink-0" />
        <p className="text-sm text-purple-300">You are managing as <strong>SuperAdmin</strong> — all tenants are visible.</p>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Tenant Management</h1>
          <p className="text-dark-400 text-sm mt-1">{tenants.length} tenant{tenants.length !== 1 ? 's' : ''} registered</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadTenants} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Create Tenant
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadTenants} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Tenants table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : tenants.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Status</th>
                <th>Users</th>
                <th>Assets</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((t) => {
                const detail = tenantDetails[t.tenant_id]
                return (
                  <tr key={t.tenant_id}>
                    <td>
                      <p className="font-medium text-white">{t.name}</p>
                      <p className="text-xs text-dark-500 font-mono break-all">{t.tenant_id || '—'}</p>
                    </td>
                    <td className="font-mono text-sm text-accent-cyan">{t.slug}</td>
                    <td><ActiveBadge active={t.is_active} /></td>
                    <td className="text-dark-300 text-sm">{detail?.user_count ?? '—'}</td>
                    <td className="text-dark-300 text-sm">{detail?.asset_count ?? '—'}</td>
                    <td className="text-dark-400 text-xs">
                      {t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setUsersTenant(t)}
                          className="p-1.5 hover:bg-blue-500/10 rounded text-dark-400 hover:text-blue-400 transition-colors"
                          title="View Users"
                        >
                          <Users className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setEditTenant(t)}
                          className="p-1.5 hover:bg-dark-700 rounded text-dark-400 hover:text-white transition-colors"
                          title="Edit Tenant"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeactivate(t.tenant_id, t.is_active)}
                          className={`p-1.5 rounded transition-colors ${t.is_active ? 'text-dark-400 hover:text-yellow-400 hover:bg-yellow-500/10' : 'text-dark-400 hover:text-green-400 hover:bg-green-500/10'}`}
                          title={t.is_active ? 'Deactivate' : 'Activate'}
                        >
                          {t.is_active ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Building2 className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No tenants yet</p>
            <p className="text-sm mb-4">Create your first tenant to get started.</p>
            <button onClick={() => setShowCreate(true)} className="btn-primary">
              <Plus className="w-4 h-4 mr-2" />
              Create Tenant
            </button>
          </div>
        )}
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateTenantModal
          onClose={() => setShowCreate(false)}
          onSubmit={handleCreate}
        />
      )}

      {editTenant && (
        <EditTenantModal
          tenant={editTenant}
          onClose={() => setEditTenant(null)}
          onSave={handleEdit}
        />
      )}

      {usersTenant && (
        <UsersPanel
          tenant={usersTenant}
          onClose={() => setUsersTenant(null)}
          onAssigned={loadTenants}
        />
      )}
    </div>
  )
}
