import { useState, useEffect, useCallback } from 'react'
import {
  Building2, Users, Plus, Check, RefreshCw, AlertTriangle, SlidersHorizontal, UserX, UserCheck, KeyRound, Trash2,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import ActionPicker from '../components/users/ActionPicker'
import { SidePanel, RowMenu, Toast, useToast, Spinner } from '../components/common/PageParts'
import StepUpDialog from '../components/auth/StepUpDialog'
import { MFA_RESET_GUIDANCE, mfaResetToast } from '../utils/mfa'
import { canConfirmDelete } from '../utils/users'
import { accessSummary, actionLabels } from '../utils/actions'

// Users page for the Tenant Superadmin: the tenant's name, and who may do what. Each tenant user
// holds a list of actions, chosen in the ActionPicker (PUT /tenants/:id/users/:userId/actions).

const errorDetail = (err, fallback) => {
  const d = err?.response?.data?.detail
  return typeof d === 'string' && d ? d : fallback
}

function ErrorNote({ children }) {
  if (!children) return null
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{children}</span>
    </div>
  )
}

// The picker needs the catalog; it is fetched once per sign-in and may still be on its way.
function CatalogGate({ children }) {
  const { catalog, catalogError, retryCatalog } = useAuth()
  if (catalog) return children
  if (catalogError) {
    return (
      <div className="space-y-2 rounded-lg border border-dark-700 p-4 text-sm text-dark-300">
        <p>The list of actions could not be loaded.</p>
        <button type="button" onClick={retryCatalog} className="btn-secondary text-xs py-1.5">Try again</button>
      </div>
    )
  }
  return <Spinner className="py-10" />
}

// Pinned under the panel body, so a save error is always in view next to the button.
function PanelButtons({ onCancel, submitting, disabled, label, form, error }) {
  return (
    <div className="space-y-3">
      <ErrorNote>{error}</ErrorNote>
      <div className="flex justify-end gap-2">
        <button type="button" onClick={onCancel} className="btn-secondary text-sm py-1.5">Cancel</button>
        <button type="submit" form={form} disabled={submitting || disabled}
          className="btn-primary text-sm py-1.5 flex items-center gap-1.5 disabled:opacity-40">
          {submitting ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          {label}
        </button>
      </div>
    </div>
  )
}

// ── Edit access ───────────────────────────────────────────────────
function EditAccessPanel({ tenantId, target, onClose, onSaved }) {
  const { catalog } = useAuth()
  const [actions, setActions] = useState(target.actions || [])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const initial = target.actions || []
  const dirty = actions.length !== initial.length || actions.some((k) => !initial.includes(k))

  const save = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const res = await client.put(`/tenants/${tenantId}/users/${target.user_id}/actions`, { actions })
      onSaved(target, res.data)
    } catch (err) {
      setError(errorDetail(err, 'Could not update access. Try again.'))
      setSubmitting(false)
    }
  }

  return (
    <SidePanel
      title={`Edit access for ${target.username}`}
      subtitle={target.email}
      onClose={onClose}
      width="sm:w-[640px]"
      dirty={dirty}
      footer={(requestClose) => (
        <PanelButtons form="edit-access" onCancel={requestClose} submitting={submitting} disabled={!dirty || !catalog} label="Save" error={error} />
      )}
    >
      <form id="edit-access" onSubmit={save} className="space-y-4">
        <p className="text-xs text-dark-400">Changes apply from the person&apos;s next action in the app.</p>
        <CatalogGate>
          <ActionPicker value={actions} onChange={setActions} catalog={catalog} disabled={submitting} />
        </CatalogGate>
      </form>
    </SidePanel>
  )
}

// ── Invite (new or existing account by email) or add an existing account by username ──
function InvitePanel({ tenantId, onClose, onDone }) {
  const { catalog } = useAuth()
  const [mode, setMode] = useState('email')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [actions, setActions] = useState([])
  const [assignUsername, setAssignUsername] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const dirty = !!(email || username || actions.length || assignUsername)

  const submit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      if (mode === 'email') {
        const res = await client.post(`/tenants/${tenantId}/users/invite`, {
          email: email.trim(), username: username.trim() || undefined, actions,
        })
        const d = res.data
        onDone(d.action === 'created'
          ? `Invited ${d.email}. They sign in with Google using this email.`
          : `${d.username} added to this tenant.`)
      } else {
        const res = await client.post(`/tenants/${tenantId}/users`, { username: assignUsername.trim() })
        onDone(`${res.data.username || assignUsername.trim()} added to this tenant with no access.`)
      }
    } catch (err) {
      setError(errorDetail(err, mode === 'email' ? 'Could not invite this user.' : 'Could not add this user.'))
      setSubmitting(false)
    }
  }

  return (
    <SidePanel
      title="Add user"
      onClose={onClose}
      width="sm:w-[640px]"
      dirty={dirty}
      footer={(requestClose) => (
        <PanelButtons form="invite-user" onCancel={requestClose} submitting={submitting} label={mode === 'email' ? 'Invite' : 'Add user'} error={error} />
      )}
    >
      <div className="flex gap-1 rounded-lg border border-dark-700/50 bg-dark-800/60 p-1" role="tablist" aria-label="How to add">
        {[['email', 'Invite by email'], ['username', 'Existing account']].map(([m, label]) => (
          <button key={m} type="button" role="tab" aria-selected={mode === m}
            onClick={() => { setMode(m); setError(null) }}
            className={`flex-1 rounded-md py-1.5 text-xs transition-colors ${mode === m ? 'bg-eagle-500/20 text-eagle-400' : 'text-dark-400 hover:text-dark-50'}`}>
            {label}
          </button>
        ))}
      </div>

      <form id="invite-user" onSubmit={submit} className="space-y-4">
        {mode === 'email' ? (
          <>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="invite-email" className="mb-1 block text-xs text-dark-400">Email</label>
                <input id="invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@example.com" className="input-field w-full text-sm" required autoFocus />
              </div>
              <div>
                <label htmlFor="invite-username" className="mb-1 block text-xs text-dark-400">
                  Username <span className="text-dark-600">(optional)</span>
                </label>
                <input id="invite-username" type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                  placeholder="From the email" className="input-field w-full text-sm" minLength={3} maxLength={100} />
              </div>
            </div>
            <p className="text-xs text-dark-500">They sign in with Google using this email.</p>
            <div className="space-y-3 border-t border-dark-700/60 pt-4">
              <div>
                <h3 className="text-sm font-semibold text-dark-100">Access</h3>
                <p className="mt-0.5 text-xs text-dark-400">New users start with no access until you grant actions.</p>
              </div>
              <CatalogGate>
                <ActionPicker value={actions} onChange={setActions} catalog={catalog} disabled={submitting} />
              </CatalogGate>
            </div>
          </>
        ) : (
          <div>
            <label htmlFor="assign-username" className="mb-1 block text-xs text-dark-400">Username</label>
            <input id="assign-username" type="text" value={assignUsername} onChange={(e) => setAssignUsername(e.target.value)}
              placeholder="e.g. john_doe" className="input-field w-full text-sm" required autoFocus />
            <p className="mt-1 text-xs text-dark-500">
              Must match an existing account that is not in a tenant. New users start with no access until you grant actions.
            </p>
          </div>
        )}
      </form>
    </SidePanel>
  )
}

function StatusBadge({ active }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs ${
      active ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-dark-600 bg-dark-800 text-dark-400'
    }`}>
      {active ? 'Active' : 'Inactive'}
    </span>
  )
}

// ── Main page ─────────────────────────────────────────────────────
function DeleteUserDialog({ target, onSubmit, onCancel }) {
  const [typed, setTyped] = useState('')
  const isReady = ({ hasPassword, password, code }) =>
    canConfirmDelete({ typed, username: target.username, code, needsPassword: hasPassword, password })
  return (
    <StepUpDialog title="Delete user" idPrefix="delete" confirmLabel="Delete user" danger
      isReady={isReady} onSubmit={(body) => onSubmit(body, typed)} onCancel={onCancel}>
      <p>Delete {target.username}? This removes the account permanently and cannot be undone. Their past actions stay in the audit log. To keep the account, deactivate it instead.</p>
      <div className="mt-4">
        <label htmlFor="delete-username" className="mb-1.5 block text-sm font-medium text-dark-200">Type the username to confirm</label>
        <input id="delete-username" type="text" autoComplete="off" autoCapitalize="off" spellCheck={false}
          value={typed} onChange={(e) => setTyped(e.target.value)} className="input-field w-full" />
      </div>
    </StepUpDialog>
  )
}

export default function TenantSettingsPage() {
  const { user, catalog, catalogError, retryCatalog } = useAuth()
  const isTenantSuperadmin = user?.role === 'tenant_superadmin'
  const tenantId = user?.tenantId
  const { toast, show: showToast } = useToast()

  const [tenant, setTenant]         = useState(null)
  const [users, setUsers]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [saving, setSaving]         = useState(false)
  const [saveError, setSaveError]   = useState(null)

  // Tenant edit fields
  const [tenantName, setTenantName] = useState('')
  const [tenantDirty, setTenantDirty] = useState(false)

  const [togglingActive, setTogglingActive] = useState({})
  const [editing, setEditing] = useState(null)   // user row whose access is open
  const [showInvite, setShowInvite] = useState(false)
  const [resetting, setResetting] = useState(null)  // user row whose MFA reset is being confirmed
  const [deleting, setDeleting] = useState(null)    // user row whose deletion is being confirmed

  const loadUsers = useCallback(async () => {
    if (!tenantId) return
    try {
      const res = await client.get(`/tenants/${tenantId}/users`)
      setUsers(res.data.users || [])
    } catch (err) {
      showToast(errorDetail(err, 'Could not load users.'), 'error')
    }
  }, [tenantId, showToast])

  const loadData = useCallback(async () => {
    if (!tenantId) return
    setLoading(true)
    const [tResult] = await Promise.allSettled([client.get(`/tenants/${tenantId}`), loadUsers()])
    if (tResult.status === 'fulfilled') {
      const t = tResult.value.data
      setTenant(t)
      setTenantName(t.name)
      setTenantDirty(false)
    }
    setLoading(false)
  }, [tenantId, loadUsers])

  useEffect(() => { loadData() }, [loadData])

  const saveTenantSettings = async () => {
    if (!tenantId) return
    setSaving(true)
    setSaveError(null)
    try {
      const res = await client.patch(`/tenants/${tenantId}`, { name: tenantName })
      const name = res.data?.name ?? tenantName
      setTenant((t) => ({ ...t, name }))
      setTenantName(name)
      setTenantDirty(false)
    } catch (err) {
      setSaveError(errorDetail(err, 'Failed to save settings'))
    } finally { setSaving(false) }
  }

  const toggleUserActive = async (u) => {
    if (!tenantId) return
    setTogglingActive((prev) => ({ ...prev, [u.user_id]: true }))
    try {
      await client.patch(`/tenants/${tenantId}/users/${u.user_id}/deactivate`, { is_active: !u.is_active })
      setUsers((rows) => rows.map((r) => (r.user_id === u.user_id ? { ...r, is_active: !u.is_active } : r)))
      showToast(`${u.username} ${u.is_active ? 'deactivated' : 'activated'}.`)
    } catch (err) {
      showToast(errorDetail(err, 'Failed to update status'), 'error')
    } finally {
      setTogglingActive((prev) => ({ ...prev, [u.user_id]: false }))
    }
  }

  const resetMfa = async (body) => {
    const target = resetting
    await client.post(`/tenants/${tenantId}/users/${target.user_id}/mfa-reset`, body)
    setResetting(null)
    showToast(mfaResetToast(target.username))
  }

  const deleteUser = async (body, typed) => {
    const target = deleting
    await client.delete(`/tenants/${tenantId}/users/${target.user_id}`, { data: { ...body, confirm_username: typed } })
    setUsers((rows) => rows.filter((r) => r.user_id !== target.user_id))
    setDeleting(null)
    showToast(`${target.username} was deleted.`)
  }

  const onAccessSaved = (target, data) => {
    setUsers((rows) => rows.map((r) => (r.user_id === target.user_id ? { ...r, actions: data.actions } : r)))
    setEditing(null)
    const added = data.added_requirements || []
    showToast(`Access updated for ${target.username}.${added.length ? ` Also granted: ${actionLabels(added, catalog)}.` : ''}`)
  }

  const onInvited = async (message) => {
    setShowInvite(false)
    showToast(message)
    await loadUsers()
  }

  if (loading) return <Spinner className="py-20" />

  return (
    <div className="space-y-6">
      <Toast toast={toast} />

      {/* Header */}
      <div>
        <h1 className="page-title">Tenant Management</h1>
        <p className="text-dark-400 text-sm mt-1">
          {tenant?.name} · Manage settings and who can do what
        </p>
      </div>

      {/* ── Tenant Settings ── */}
      {isTenantSuperadmin && tenant && (
        <div className="glass-card p-6 space-y-5">
          <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
            <Building2 className="w-4 h-4 text-accent-cyan" />
            Tenant Settings
          </h2>

          <ErrorNote>{saveError}</ErrorNote>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="tenant-name" className="block text-xs text-dark-400 mb-1">Tenant Name</label>
              <input
                id="tenant-name"
                type="text"
                value={tenantName}
                onChange={e => { setTenantName(e.target.value); setTenantDirty(true) }}
                className="input-field w-full text-sm"
              />
            </div>
            <div>
              <label htmlFor="tenant-slug" className="block text-xs text-dark-400 mb-1">Slug</label>
              <input
                id="tenant-slug" type="text" value={tenant.slug} disabled
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
        <div className="flex items-center justify-between gap-3 p-4 border-b border-dark-700/50">
          <div>
            <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
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

        {users.length === 0 ? (
          <p className="text-dark-400 text-sm text-center py-8">No users assigned to this tenant.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Access</th>
                  <th>Status</th>
                  <th className="w-12"><span className="sr-only">Menu</span></th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = u.user_id === user?.userId
                  const isOwner = u.role === 'tenant_superadmin'
                  const canEdit = isTenantSuperadmin && u.role === 'tenant_user'
                  const canToggle = isTenantSuperadmin && !isSelf && !isOwner
                  const canResetMfa = isTenantSuperadmin && !isSelf && u.role === 'tenant_user'
                  const catalogFailed = !isOwner && !catalog && catalogError
                  const access = isOwner
                    ? 'Tenant Superadmin · all actions'
                    : catalog ? accessSummary(u.actions, catalog) : '…'
                  const accessTone = isOwner ? 'text-accent-purple' : (u.actions?.length ? 'text-dark-100' : 'text-dark-500')
                  return (
                    <tr key={u.user_id}>
                      <td>
                        <span className="font-medium text-dark-50">{u.username}</span>
                        {isSelf && <span className="ml-2 rounded bg-dark-700 px-1 py-0.5 text-[11px] text-dark-400">you</span>}
                      </td>
                      <td className="text-sm text-dark-300">{u.email}</td>
                      <td>
                        {catalogFailed ? (
                          <span className="flex items-center gap-2 text-sm text-dark-500">
                            Could not load
                            <button type="button" onClick={retryCatalog} className="text-xs text-eagle-400 hover:underline">Retry</button>
                          </span>
                        ) : canEdit ? (
                          <button type="button" onClick={() => setEditing(u)} title="Edit access"
                            className={`rounded text-left text-sm underline decoration-dark-600 decoration-dotted underline-offset-4 hover:text-eagle-400 hover:decoration-eagle-500 ${accessTone}`}>
                            {access}
                          </button>
                        ) : (
                          <span className={`text-sm ${accessTone}`}>{access}</span>
                        )}
                      </td>
                      <td><StatusBadge active={u.is_active} /></td>
                      <td>
                        {togglingActive[u.user_id]
                          ? <RefreshCw className="m-1.5 h-4 w-4 animate-spin text-dark-400" />
                          : (
                            <RowMenu items={[
                              canEdit && { label: 'Edit access', icon: SlidersHorizontal, onClick: () => setEditing(u) },
                              canToggle && (u.is_active
                                ? { label: 'Deactivate', icon: UserX, danger: true, onClick: () => toggleUserActive(u) }
                                : { label: 'Activate', icon: UserCheck, onClick: () => toggleUserActive(u) }),
                              canResetMfa && { label: 'Reset MFA', icon: KeyRound, danger: true, onClick: () => setResetting(u) },
                              canResetMfa && { label: 'Delete user', icon: Trash2, danger: true, onClick: () => setDeleting(u) },
                            ]} />
                          )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {resetting && (
        <StepUpDialog title="Reset MFA" idPrefix="reset" confirmLabel="Reset MFA" danger
          onSubmit={resetMfa} onCancel={() => setResetting(null)}>
          <p>{MFA_RESET_GUIDANCE}</p>
          <p className="mt-2">Reset MFA for <span className="font-medium text-dark-50">{resetting.username}</span>.</p>
        </StepUpDialog>
      )}

      {deleting && (
        <DeleteUserDialog target={deleting} onSubmit={deleteUser} onCancel={() => setDeleting(null)} />
      )}

      {editing && (
        <EditAccessPanel
          tenantId={tenantId}
          target={editing}
          onClose={() => setEditing(null)}
          onSaved={onAccessSaved}
        />
      )}

      {showInvite && (
        <InvitePanel
          tenantId={tenantId}
          onClose={() => setShowInvite(false)}
          onDone={onInvited}
        />
      )}
    </div>
  )
}
