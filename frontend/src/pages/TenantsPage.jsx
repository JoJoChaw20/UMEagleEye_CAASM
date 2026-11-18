import { useState, useEffect, useCallback } from 'react'
import { Plus, Users, KeyRound, X, Check, Shield, ToggleLeft, ToggleRight, RefreshCw, Building2, UserPlus } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import { SidePanel, Toast, useToast, Spinner } from '../components/common/PageParts'
import { accessSummary, countActions } from '../utils/actions'
import StepUpDialog from '../components/auth/StepUpDialog'
import { stepUpReady } from '../utils/mfa.js'
import { RESTORE_VERIFICATION, restoreReady, restoreBody } from '../utils/notices'

// ── Status badge ──────────────────────────────────────────────────
function ActiveBadge({ active }) {
  return active
    ? <span className="text-xs px-2 py-0.5 rounded-md border bg-green-500/20 text-green-400 border-green-500/30">Active</span>
    : <span className="text-xs px-2 py-0.5 rounded-md border bg-red-500/20 text-red-400 border-red-500/30">Inactive</span>
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-dark-950/70 p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-dark-50">Create Tenant</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-50 transition-colors">
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

// ── Users side panel (read-only) ──────────────────────────────────
// The Platform Superadmin sees who is in a tenant and what each person may do, but does not grant
// actions: that is the Tenant Superadmin's job. Until the provisioning flow exists, it may invite a
// tenant's first Tenant Superadmin (POST .../users/invite with as_tenant_superadmin).
function InviteOwner({ tenantId, onInvited }) {
  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const res = await client.post(`/tenants/${tenantId}/users/invite`, { email: email.trim(), as_tenant_superadmin: true })
      await onInvited(res.data)
    } catch (err) {
      const d = err?.response?.data?.detail
      setError(typeof d === 'string' && d ? d : 'Could not invite this user.')
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3 rounded-xl border border-accent-purple/30 bg-accent-purple/5 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <div className="flex min-w-0 flex-1 items-start gap-3">
          <UserPlus className="mt-0.5 h-4 w-4 shrink-0 text-accent-purple" />
          <div className="min-w-0">
            <p className="text-sm font-medium text-dark-50">This tenant has no Tenant Superadmin.</p>
            <p className="mt-0.5 text-xs text-dark-400">The Tenant Superadmin adds the tenant&apos;s users and chooses what each person can do.</p>
          </div>
        </div>
        {!open && (
          <button type="button" onClick={() => setOpen(true)} className="btn-primary shrink-0 text-xs py-1.5">
            Invite Tenant Superadmin
          </button>
        )}
      </div>
      {open && (
        <form onSubmit={submit} className="space-y-2">
          {error && <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-400">{error}</p>}
          <label htmlFor="owner-email" className="block text-xs text-dark-400">Email</label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input id="owner-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              placeholder="name@example.com" className="input-field flex-1 text-sm" required autoFocus />
            <div className="flex gap-2">
              <button type="button" onClick={() => { setOpen(false); setError(null) }} className="btn-secondary text-xs py-1.5">Cancel</button>
              <button type="submit" disabled={submitting} className="btn-primary flex items-center gap-1 text-xs py-1.5">
                {submitting ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                Invite Tenant Superadmin
              </button>
            </div>
          </div>
          <p className="text-xs text-dark-500">They sign in with Google using this email.</p>
        </form>
      )}
    </div>
  )
}

// ── Restore tenant ownership (Platform Superadmin, step-up) ───────
// Suspends the former Tenant Superadmin and invites the named person as the new one. The Platform
// Superadmin gains no access to the tenant.
function RestoreOwnershipDialog({ tenant, onClose, onDone }) {
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const submit = async (stepUp) => {
    const res = await client.post(`/tenants/${tenant.tenant_id}/ownership/restore`, restoreBody({ email, username, stepUp }))
    await onDone(res.data)
  }
  return (
    <StepUpDialog title={`Restore tenant ownership: ${tenant.name}`} confirmLabel="Restore ownership" danger idPrefix="restore"
      onSubmit={submit} onCancel={onClose} isReady={(s) => restoreReady(email, username) && stepUpReady(s)}>
      <p className="text-sm text-dark-300">{RESTORE_VERIFICATION}</p>
      <p className="mt-2 text-sm text-dark-300">The current Tenant Superadmin will be suspended and signed out.</p>
      <div className="mt-4 space-y-3">
        <div>
          <label htmlFor="restore-email" className="mb-1.5 block text-sm font-medium text-dark-200">New owner email</label>
          <input id="restore-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="input-field w-full" autoComplete="off" required />
        </div>
        <div>
          <label htmlFor="restore-username" className="mb-1.5 block text-sm font-medium text-dark-200">Username (optional)</label>
          <input id="restore-username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="input-field w-full" autoComplete="off" />
        </div>
      </div>
    </StepUpDialog>
  )
}

function UsersPanel({ tenant, onClose, onAssigned }) {
  const { catalog } = useAuth()
  const { toast, show: showToast } = useToast()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  const refreshUsers = useCallback(() =>
    client.get(`/tenants/${tenant.tenant_id}/users`)
      .then((res) => { setUsers(res.data.users || []); setLoadError(false) })
      .catch(() => { setUsers([]); setLoadError(true) })
      .finally(() => setLoading(false)), [tenant.tenant_id])

  useEffect(() => { refreshUsers() }, [refreshUsers])

  const hasOwner = users.some((u) => u.role === 'tenant_superadmin')

  const onInvited = async (data) => {
    showToast(`Invited ${data.email} as Tenant Superadmin.`)
    await refreshUsers()
    if (onAssigned) onAssigned()
  }

  return (
    <SidePanel
      title={`Users — ${tenant.name}`}
      subtitle={`${users.length} member${users.length !== 1 ? 's' : ''} · read-only`}
      onClose={onClose}
      width="sm:w-[640px]"
    >
      <Toast toast={toast} />
      {loading ? (
        <Spinner className="py-8" />
      ) : loadError ? (
        <div className="space-y-2 py-8 text-center">
          <p className="text-sm text-red-400">Could not load users.</p>
          <button type="button" onClick={refreshUsers} className="btn-secondary text-xs py-1.5">Try again</button>
        </div>
      ) : (
        <>
          {!hasOwner && <InviteOwner tenantId={tenant.tenant_id} onInvited={onInvited} />}
          {users.length === 0 ? (
            <p className="py-8 text-center text-sm text-dark-400">No users assigned to this tenant.</p>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-dark-700">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Access</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => {
                    const isOwner = u.role === 'tenant_superadmin'
                    const tone = isOwner ? 'text-accent-purple' : u.actions?.length ? 'text-dark-100' : 'text-dark-500'
                    return (
                      <tr key={u.user_id}>
                        <td>
                          <p className="text-sm font-medium text-dark-50">{u.username}</p>
                          <p className="break-all text-xs text-dark-400">{u.email}</p>
                          <p className="mt-0.5 break-all font-mono text-[11px] text-dark-500" title="User ID">{u.user_id}</p>
                        </td>
                        <td className={`text-sm ${tone}`}>
                          {isOwner ? 'Tenant Superadmin · all actions' : catalog ? accessSummary(u.actions, catalog) : (u.actions?.length ? countActions(u.actions.length) : 'No access')}
                        </td>
                        <td><ActiveBadge active={u.is_active} /></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-xs text-dark-500">Each tenant&apos;s Tenant Superadmin chooses what its users can do.</p>
        </>
      )}
    </SidePanel>
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
  const [usersTenant, setUsersTenant] = useState(null)
  const [restoreTenant, setRestoreTenant] = useState(null)
  const { toast, show: showToast } = useToast()

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
      <div className="flex items-center gap-3 p-3 bg-accent-purple/10 border border-accent-purple/30 rounded-xl">
        <Shield className="w-5 h-5 text-accent-purple flex-shrink-0" />
        <p className="text-sm text-accent-purple">You are managing as <strong>SuperAdmin</strong> — all tenants are visible.</p>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Tenant Management</h1>
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
                      <p className="font-medium text-dark-50">{t.name}</p>
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
                          className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors"
                          title="View Users"
                        >
                          <Users className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setRestoreTenant(t)}
                          className="p-1.5 hover:bg-accent-purple/10 rounded text-dark-400 hover:text-accent-purple transition-colors"
                          title="Restore tenant ownership" aria-label={`Restore tenant ownership: ${t.name}`}
                        >
                          <KeyRound className="w-4 h-4" />
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

      <Toast toast={toast} />
      {restoreTenant && (
        <RestoreOwnershipDialog
          tenant={restoreTenant}
          onClose={() => setRestoreTenant(null)}
          onDone={async (d) => {
            setRestoreTenant(null)
            showToast(`Ownership restored. ${d?.email || 'The new owner'} is the Tenant Superadmin.`)
            await loadTenants()
          }}
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
