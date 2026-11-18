import { useState, useEffect, useCallback } from 'react'
import { Crown, AlertTriangle } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import ActionPicker from '../users/ActionPicker'
import StepUpDialog from '../auth/StepUpDialog'
import { useSingleFlight } from '../auth/AuthParts'
import { Spinner } from '../common/PageParts'
import { cleanTotpInput } from '../../utils/mfa.js'
import {
  viewFor, afterModeLabel, AFTER_MODES, REASONS, reasonLabel, PLAN_BANNER, plan3Ready, transferBodyReady, localDate, dateAfterToday, deadlineISO,
} from '../../utils/ownership'

const errText = (err, fallback) => {
  const d = err?.response?.data?.detail
  return typeof d === 'string' && d ? d : fallback
}

function Note({ children, tone = 'error' }) {
  if (!children) return null
  const cls = tone === 'warn' ? 'border-amber-500/30 bg-amber-500/10 text-amber-400' : 'border-red-500/30 bg-red-500/10 text-red-400'
  return (
    <div role="alert" className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${cls}`}>
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{children}</span>
    </div>
  )
}

function UserSelect({ id, label, value, onChange, users, exclude = [] }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs text-dark-400">{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className="input-field w-full text-sm">
        <option value="">Choose a user</option>
        {users.filter((u) => !exclude.includes(u.user_id) || u.user_id === value).map((u) => (
          <option key={u.user_id} value={u.user_id}>{u.email ? `${u.username} (${u.email})` : u.username}</option>
        ))}
      </select>
    </div>
  )
}

// A plain button that runs one request at a time and shows the server's error.
function ActionButton({ children, onRun, className = 'btn-secondary text-sm py-1.5', failText }) {
  const [busy, run] = useSingleFlight()
  const [error, setError] = useState('')
  const go = () => run(async () => {
    setError('')
    try { await onRun() } catch (err) { setError(errText(err, failText)); return false }
    return true
  })
  return (
    <span className="inline-flex flex-col gap-2">
      <button type="button" disabled={busy} onClick={go} className={`${className} disabled:opacity-40`}>{busy ? 'Working…' : children}</button>
      {error && <span role="alert" className="text-xs text-red-400">{error}</span>}
    </span>
  )
}

export default function OwnershipSection({ tenantId, users, onChanged }) {
  const { user, catalog, refreshUser } = useAuth()
  const [res, setRes] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [dialog, setDialog] = useState(null) // { kind, body? }
  const [flash, setFlash] = useState('')
  const { hash } = useLocation()

  // The checklist links here (/users#ownership): scroll once the section has loaded
  useEffect(() => {
    if (res && hash === '#ownership') document.getElementById('ownership')?.scrollIntoView?.({ block: 'start' })
  }, [res !== null, hash]) // eslint-disable-line react-hooks/exhaustive-deps

  const base = `/tenants/${tenantId}/ownership`
  const load = useCallback(async () => {
    try {
      const r = await client.get(base)
      setRes(r.data)
      setLoadError('')
    } catch (err) {
      setLoadError(errText(err, 'Could not load ownership.'))
    }
  }, [base])
  useEffect(() => { load() }, [load])

  // After any action: re-read ownership and the caller (the role may have changed).
  const after = async (message) => {
    setDialog(null)
    if (message) setFlash(message)
    await load()
    try { await refreshUser() } catch { /* the next focus refresh retries */ }
    if (onChanged) onChanged()
  }

  const v = viewFor(res, user)
  const active = (users || []).filter((u) => u.is_active && u.role === 'tenant_user' && u.user_id !== user?.userId)

  if (!res) return loadError ? <div className="glass-card p-6"><Note>{loadError}</Note></div> : <Spinner className="py-10" />

  const t = v.pendingTransfer
  const r = v.recovery

  return (
    <div id="ownership" className="glass-card p-6 space-y-5">
      <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
        <Crown className="w-4 h-4 text-accent-cyan" />
        Tenant ownership
      </h2>
      <p className="text-sm text-dark-300">Current owner: <span className="font-medium text-dark-50">{v.owner?.username}</span></p>
      {flash && <p role="status" className="text-sm text-green-400">{flash}</p>}
      {loadError && <Note>{loadError}</Note>}

      {v.showPlanBanner && <Note tone="warn">{PLAN_BANNER}</Note>}

      {v.pendingAsRecipient && (
        <div className="space-y-3 rounded-lg border border-eagle-500/30 bg-eagle-500/5 p-4">
          <p className="text-sm text-dark-100">{t.message}</p>
          <div className="flex gap-2">
            <button type="button" className="btn-primary text-sm py-1.5" onClick={() => setDialog({ kind: 'accept' })}>Accept</button>
            <ActionButton failText="Could not decline." onRun={async () => { await client.post(`${base}/transfer/decline`); await after('Transfer declined.') }}>Decline</ActionButton>
          </div>
        </div>
      )}

      {v.pendingAsOwner && (
        <div className="space-y-2 rounded-lg border border-dark-700 p-4 text-sm text-dark-200">
          <p>Transfer to <span className="font-medium text-dark-50">{t.to_user.username}</span> is waiting for their answer until {new Date(t.expires_at).toLocaleString()}. After: {afterModeLabel(t.after.mode)}.</p>
          <ActionButton failText="Could not cancel." onRun={async () => { await client.delete(`${base}/transfer`); await after('Transfer cancelled.') }}>Cancel transfer</ActionButton>
        </div>
      )}

      {v.canTransfer && <TransferForm users={active} catalog={catalog} onSubmit={(body) => setDialog({ kind: 'transfer', body })} />}

      {v.isOwner && (
        <PlanForm users={active} plan={v.plan} onSubmit={(body) => setDialog({ kind: 'plan', body })} />
      )}

      {r && (
        <div className="space-y-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm text-dark-200">
          <p className="font-medium text-dark-50">Emergency recovery open</p>
          <p>Reason: {reasonLabel(r.reason)}. Status: {r.status.replace('_', ' ')}. Successor: {r.successor?.username}.</p>
          <p>Approvals: {Number(r.approver1_approved) + Number(r.approver2_approved)} of 2. Expires {new Date(r.expires_at).toLocaleString()}.{r.hold_until ? ` Hold ends ${new Date(r.hold_until).toLocaleString()}.` : ''}</p>
          {v.canApprove && <button type="button" className="btn-primary text-sm py-1.5" onClick={() => setDialog({ kind: 'approve' })}>Approve</button>}
          {v.canCancelRecovery && <button type="button" className="btn-secondary text-sm py-1.5" onClick={() => setDialog({ kind: 'cancel' })}>Cancel this recovery</button>}
        </div>
      )}

      {v.recoveryInProgress && <p className="text-sm text-dark-300">An ownership recovery is in progress.</p>}

      {v.canStartRecovery && (
        <div className="space-y-2 border-t border-dark-700/60 pt-4">
          <button type="button" className="btn-secondary text-sm py-1.5" onClick={() => setDialog({ kind: 'start' })}>Start emergency recovery</button>
        </div>
      )}

      {dialog?.kind === 'accept' && t && (
        <StepUpDialog title="Accept ownership" idPrefix="own-accept" confirmLabel="Accept" onCancel={() => setDialog(null)}
          onSubmit={async (b) => { await client.post(`${base}/transfer/accept`, b); await after('You are now the Tenant Superadmin.') }}>
          <p>{t.message}</p>
        </StepUpDialog>
      )}
      {dialog?.kind === 'transfer' && (
        <StepUpDialog title="Transfer ownership" idPrefix="own-transfer" confirmLabel="Send request" danger onCancel={() => setDialog(null)}
          onSubmit={async (b) => { await client.post(`${base}/transfer`, { ...dialog.body, ...b }); await after('Transfer request sent. They have 72 hours to answer.') }}>
          <p>Send this transfer request? You can cancel until it is accepted.</p>
        </StepUpDialog>
      )}
      {dialog?.kind === 'plan' && (
        <StepUpDialog title="Save recovery plan" idPrefix="own-plan" confirmLabel="Save plan" onCancel={() => setDialog(null)}
          onSubmit={async (b) => { await client.put(`${base}/recovery-plan`, { ...dialog.body, ...b }); await after('Recovery plan saved.') }}>
          <p>Save the successor and the two approvers.</p>
        </StepUpDialog>
      )}
      {dialog?.kind === 'approve' && (
        <StepUpDialog title="Approve recovery" idPrefix="own-approve" confirmLabel="Approve" onCancel={() => setDialog(null)}
          onSubmit={async (b) => { await client.post(`${base}/recovery/approve`, b); await after('Approval recorded.') }}>
          <p>Approve this emergency recovery ({reasonLabel(r?.reason)}).</p>
        </StepUpDialog>
      )}
      {dialog?.kind === 'cancel' && (
        <StepUpDialog title="Cancel this recovery" idPrefix="own-cancel" confirmLabel="Cancel this recovery" danger onCancel={() => setDialog(null)}
          onSubmit={async (b) => { await client.post(`${base}/recovery/cancel`, b); await after('Recovery disputed. Contact platform support for verification.') }}>
          <p>Cancel this recovery? The case then goes to platform verification.</p>
        </StepUpDialog>
      )}
      {dialog?.kind === 'start' && <StartDialog base={base} onCancel={() => setDialog(null)} onDone={after} />}
    </div>
  )
}

function StartDialog({ base, onCancel, onDone }) {
  const [reason, setReason] = useState('')
  return (
    <StepUpDialog title="Start emergency recovery" idPrefix="own-start" confirmLabel="Start recovery" danger onCancel={onCancel}
      isReady={({ hasPassword, password, code }) => !!reason && cleanTotpInput(code).length === 6 && (!hasPassword || !!password)}
      onSubmit={async (b) => { await client.post(`${base}/recovery`, { reason, ...b }); await onDone('Recovery started. Both approvers must approve within 72 hours.') }}>
      <label htmlFor="own-reason" className="mb-1 block text-sm font-medium text-dark-200">Why is the owner unavailable?</label>
      <select id="own-reason" value={reason} onChange={(e) => setReason(e.target.value)} className="input-field w-full text-sm">
        <option value="">Choose a reason</option>
        {REASONS.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
      </select>
    </StepUpDialog>
  )
}

function TransferForm({ users, catalog, onSubmit }) {
  const [to, setTo] = useState('')
  const [mode, setMode] = useState('stay')
  const [actions, setActions] = useState([])
  const [date, setDate] = useState('')
  const ready = transferBodyReady({ to, mode, date })
  const submit = (e) => {
    e.preventDefault()
    if (!ready) return
    const after = { mode }
    if (mode !== 'deactivate_now') after.actions = actions
    if (mode === 'deactivate_on') after.deactivate_on = deadlineISO(date)
    onSubmit({ to_user_id: to, after })
  }
  return (
    <form onSubmit={submit} className="space-y-4 border-t border-dark-700/60 pt-4">
      <h3 className="text-sm font-semibold text-dark-100">Transfer ownership</h3>
      <UserSelect id="own-to" label="New owner" value={to} onChange={setTo} users={users} />
      <fieldset className="space-y-2">
        <legend className="mb-1 text-xs text-dark-400">What happens to your account afterwards</legend>
        {AFTER_MODES.map((m) => (
          <label key={m} className="flex items-center gap-2 text-sm text-dark-100">
            <input type="radio" name="own-after" value={m} checked={mode === m} onChange={() => setMode(m)} className="accent-eagle-500" />
            {afterModeLabel(m)}
          </label>
        ))}
      </fieldset>
      {mode === 'deactivate_on' && (
        <div>
          <label htmlFor="own-date" className="mb-1 block text-xs text-dark-400">Deactivate on</label>
          <input id="own-date" type="date" value={date} min={localDate(1)}
            onChange={(e) => setDate(e.target.value)} className="input-field text-sm" />
        </div>
      )}
      {mode === 'deactivate_on' && date && !dateAfterToday(date) && (
        <p role="alert" className="text-xs text-red-400">Choose a date after today.</p>
      )}
      {mode !== 'deactivate_now' && catalog && (
        <div className="space-y-2">
          <p className="text-xs text-dark-400">Your access as a Tenant user{mode === 'deactivate_on' ? ' until then' : ''}</p>
          <ActionPicker value={actions} onChange={setActions} catalog={catalog} />
        </div>
      )}
      <button type="submit" disabled={!ready} className="btn-primary text-sm py-1.5 disabled:opacity-40">Transfer ownership</button>
    </form>
  )
}

function PlanForm({ users, plan, onSubmit }) {
  const saved = [plan?.successor, plan?.approver1, plan?.approver2].map((p) => p?.user_id || '')
  const key = saved.join('|')
  const [s, setS] = useState(saved[0])
  const [a1, setA1] = useState(saved[1])
  const [a2, setA2] = useState(saved[2])
  // Re-sync when the loaded plan changes (after a save or a reload).
  useEffect(() => { setS(saved[0]); setA1(saved[1]); setA2(saved[2]) }, [key]) // eslint-disable-line react-hooks/exhaustive-deps
  const activeIds = users.map((u) => u.user_id)
  // A saved member who is no longer active is shown as such and must be replaced.
  const gone = (id, p) => (id && !activeIds.includes(id) ? [{ user_id: id, username: `${p?.username || 'Unknown'} (no longer active)`, email: '', stale: true }] : [])
  const opts = (id, p) => [...gone(id, p), ...users]
  const ready = plan3Ready(s, a1, a2) && [s, a1, a2].every((id) => activeIds.includes(id))
  return (
    <form onSubmit={(e) => { e.preventDefault(); if (ready) onSubmit({ successor_id: s, approver_ids: [a1, a2] }) }}
      className="space-y-3 border-t border-dark-700/60 pt-4">
      <h3 className="text-sm font-semibold text-dark-100">Recovery plan</h3>
      <p className="text-xs text-dark-400">Choose a successor and two approvers: three different active users.</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <UserSelect id="own-succ" label="Successor" value={s} onChange={setS} users={opts(s, plan?.successor)} exclude={[a1, a2]} />
        <UserSelect id="own-a1" label="Approver 1" value={a1} onChange={setA1} users={opts(a1, plan?.approver1)} exclude={[s, a2]} />
        <UserSelect id="own-a2" label="Approver 2" value={a2} onChange={setA2} users={opts(a2, plan?.approver2)} exclude={[s, a1]} />
      </div>
      {[s, a1, a2].some((id) => id && !activeIds.includes(id)) && (
        <p role="alert" className="text-xs text-amber-400">A saved member is no longer active. Pick a replacement.</p>
      )}
      <button type="submit" disabled={!ready} className="btn-secondary text-sm py-1.5 disabled:opacity-40">Save plan</button>
    </form>
  )
}
