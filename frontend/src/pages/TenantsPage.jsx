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
  const [isActive, setIsActive] = useState(tenant.is_active)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      await onSave(tenant.tenant_id, { name, is_active: isActive })
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

          <div className="flex items-center justify-between py-2">
            <label className="text-sm text-dark-300">Active</label>
            <button type="button" onClick={() => setIsActive(v => !v)} className="text-dark-400 hover:text-white transition-colors">
              {isActive
                ? <ToggleRight className="w-7 h-7 text-eagle-400" />
                : <ToggleLeft className="w-7 h-7" />
              }
            </button>
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

// ── Assign User Modal ─────────────────────────────────────────────
function AssignUserModal({ tenantId, onClose, onAssign }) {
  const [userId, setUserId] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await onAssign(tenantId, userId)
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to assign user')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-sm p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white text-sm">Assign User to Tenant</h3>
          <button onClick={onClose} className="text-dark-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
        {error && <p className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded-lg p-2">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">User ID (UUID)</label>
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="input-field w-full text-sm font-mono"
              required
            />
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-xs py-1.5">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-xs py-1.5 flex items-center justify-center gap-1">
              {submitting ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" /> : <Check className="w-3 h-3" />}
              Assign
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Users side panel ──────────────────────────────────────────────
function UsersPanel({ tenant, onClose, onAssigned }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAssign, setShowAssign] = useState(false)

  useEffect(() => {
    client.get(`/tenants/${tenant.tenant_id}/users`)
      .then(res => setUsers(res.data.users || []))
      .catch(() => setUsers([]))
      .finally(() => setLoading(false))
  }, [tenant.tenant_id])

  const handleAssign = async (tenantId, userId) => {
    await client.post(`/tenants/${tenantId}/users`, { user_id: userId })
    // Reload users
    const res = await client.get(`/tenants/${tenantId}/users`)
    setUsers(res.data.users || [])
    if (onAssigned) onAssigned()
  }

  const ROLE_COLORS = {
    superadmin: 'text-purple-400',
    ops_lead: 'text-blue-400',
    security_engineer: 'text-cyan-400',
    mssp_analyst: 'text-yellow-400',
    business_owner: 'text-green-400',
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end bg-black/40 backdrop-blur-sm">
      <div className="glass-card w-full sm:w-[420px] h-full sm:h-auto sm:max-h-[85vh] flex flex-col overflow-hidden sm:rounded-2xl sm:mr-4 sm:mb-4">
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
              Assign
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
            users.map((u) => (
              <div key={u.user_id} className="bg-dark-800/60 rounded-xl p-3 border border-dark-700/40 flex items-center justify-between">
                <div>
                  <p className="font-medium text-white text-sm">{u.username}</p>
                  <p className="text-xs text-dark-400">{u.email}</p>
                  <p className="text-xs text-dark-500 font-mono mt-0.5">{u.user_id?.slice(0, 16)}...</p>
                </div>
                <div className="text-right">
                  <p className={`text-xs font-medium capitalize ${ROLE_COLORS[u.role] || 'text-dark-300'}`}>
                    {u.role?.replace('_', ' ')}
                  </p>
                  <p className="text-xs text-dark-500 mt-0.5">
                    {u.is_active ? 'Active' : 'Inactive'}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {showAssign && (
        <AssignUserModal
          tenantId={tenant.tenant_id}
          onClose={() => setShowAssign(false)}
          onAssign={handleAssign}
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

  // Redirect non-superadmin
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

  const loadTenants = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await client.get('/tenants')
      const rows = res.data.tenants || []
      setTenants(rows)
      // Load detail (user count, asset count) for each tenant
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
                      <p className="text-xs text-dark-500 font-mono">{t.tenant_id?.slice(0, 12)}...</p>
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
