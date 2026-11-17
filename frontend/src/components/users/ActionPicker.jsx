import { useState, useEffect, useMemo, useRef } from 'react'
import { createPortal } from 'react-dom'
import { ChevronRight, Check, ShieldOff, ShieldCheck, AlertTriangle, Info } from 'lucide-react'
import {
  matchPreset, addAction, removeAction, presetActions, accessSummary, actionLabel, actionLabels,
} from '../../utils/actions'

// Chooses a person's actions. Controlled: `value` is the selected action keys, `onChange` gets the
// next list (always closed over requirements, in catalog order). No requests of its own.

const IMPACT = {
  low:    { label: 'Low',    cls: 'bg-dark-700/50 text-dark-300 border-dark-600' },
  medium: { label: 'Medium', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  high:   { label: 'High',   cls: 'bg-red-500/10 text-red-400 border-red-500/30' },
}

const NOTE_MS = 6000

function ImpactBadge({ impact }) {
  const it = IMPACT[impact] || IMPACT.low
  return <span className={`shrink-0 rounded-md border px-1.5 py-px text-[11px] font-medium ${it.cls}`}>{it.label}</span>
}

// "Removing … also removes … Remove all n?" Esc and the backdrop cancel; Esc stops here so a
// surrounding side panel stays open.
function RemoveConfirm({ label, removedLabels, count, onConfirm, onCancel }) {
  const cancelRef = useRef(null)
  const onCancelRef = useRef(onCancel)
  onCancelRef.current = onCancel
  useEffect(() => {
    cancelRef.current?.focus()
    const onKey = (e) => {
      if (e.key !== 'Escape') return
      e.stopPropagation()
      onCancelRef.current()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [])
  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-dark-950/70 p-4 animate-[palette-fade_160ms_ease-out]" onClick={onCancel}>
      <div role="alertdialog" aria-modal="true" aria-labelledby="remove-action-title" aria-describedby="remove-action-body"
        className="glass-card w-full max-w-md bg-dark-800 p-5 animate-[palette-rise_220ms_cubic-bezier(0.16,1,0.3,1)]"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-amber-500/10">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </span>
          <div className="min-w-0">
            <h3 id="remove-action-title" className="font-semibold text-dark-50">Remove access</h3>
            <p id="remove-action-body" className="mt-1 text-sm text-dark-300">
              Removing &quot;{label}&quot; also removes: {removedLabels}. Remove all {count}?
            </p>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button ref={cancelRef} type="button" onClick={onCancel} className="btn-secondary text-sm py-1.5">Cancel</button>
          <button type="button" onClick={onConfirm}
            className="rounded-lg border border-red-500/40 bg-red-500/15 px-3 py-1.5 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/25">
            Remove all
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

function ActionRow({ action, checked, note, onToggle, disabled }) {
  const id = `action-${action.key}`
  return (
    <div className={`rounded-lg px-3 py-2.5 transition-colors ${checked ? 'bg-eagle-500/[0.06]' : 'hover:bg-dark-700/30'}`}>
      <label htmlFor={id} className={`flex items-start gap-3 ${disabled ? 'cursor-default' : 'cursor-pointer'}`}>
        <input id={id} type="checkbox" checked={checked} disabled={disabled} onChange={onToggle}
          className="mt-0.5 h-4 w-4 shrink-0 accent-eagle-500" />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-dark-100">{action.label}</span>
            <ImpactBadge impact={action.impact} />
          </span>
          {action.description && <span className="mt-0.5 block text-xs text-dark-400">{action.description}</span>}
          {action.impact === 'high' && (
            <span className="mt-1 flex items-center gap-1 text-xs text-red-400">
              <AlertTriangle className="h-3 w-3 shrink-0" />
              Not in any preset. Review before granting.
            </span>
          )}
        </span>
      </label>
      {note && (
        <p role="status" className="ml-7 mt-1.5 flex items-start gap-1.5 text-xs text-eagle-400 animate-[palette-fade_160ms_ease-out]">
          <Info className="mt-px h-3 w-3 shrink-0" />
          Also added: {note}
        </p>
      )}
    </div>
  )
}

export default function ActionPicker({ value, onChange, catalog, disabled = false }) {
  const selected = useMemo(() => new Set(value || []), [value])
  const [openGroups, setOpenGroups] = useState(() => new Set())
  const [note, setNote] = useState(null)       // { key, text } under the row just ticked
  const [confirm, setConfirm] = useState(null) // { key, next, removed } while asking

  useEffect(() => {
    if (!note) return undefined
    const t = setTimeout(() => setNote(null), NOTE_MS)
    return () => clearTimeout(t)
  }, [note])

  const groups = useMemo(() => (catalog?.groups || [])
    .map((g) => ({ ...g, actions: (catalog.actions || []).filter((a) => a.group === g.key) }))
    .filter((g) => g.actions.length), [catalog])

  if (!catalog) return null

  const list = value || []
  const preset = matchPreset(list, catalog)
  const allOpen = groups.length > 0 && groups.every((g) => openGroups.has(g.key))

  const toggleGroup = (key) => setOpenGroups((cur) => {
    const next = new Set(cur)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  })

  const tick = (key) => {
    const { next, added } = addAction(list, key, catalog)
    onChange(next)
    setNote(added.length ? { key, text: actionLabels(added, catalog) } : null)
  }

  const untick = (key) => {
    const { next, removed } = removeAction(list, key, catalog)
    if (removed.length) setConfirm({ key, next, removed })
    else { onChange(next); setNote(null) }
  }

  const choosePreset = (key) => {
    onChange(presetActions(key, catalog))
    setNote(null)
  }

  const SummaryIcon = list.length ? ShieldCheck : ShieldOff

  return (
    <div className="space-y-4">
      {/* Presets */}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" role="group" aria-label="Presets">
        {(catalog.presets || []).map((p) => {
          const active = preset === p.key
          return (
            <button key={p.key} type="button" disabled={disabled} onClick={() => choosePreset(p.key)} aria-pressed={active}
              className={`rounded-lg border px-3 py-2.5 text-left transition-colors disabled:opacity-50 ${
                active
                  ? 'border-eagle-500/60 bg-eagle-500/10'
                  : 'border-dark-700 bg-dark-800/60 hover:border-dark-500 hover:bg-dark-700/40'
              }`}>
              <span className="flex items-center justify-between gap-2">
                <span className={`text-sm font-semibold ${active ? 'text-eagle-400' : 'text-dark-100'}`}>{p.label}</span>
                {active && <Check className="h-4 w-4 text-eagle-400" />}
              </span>
              <span className="mt-0.5 block text-xs text-dark-400">{p.description}</span>
            </button>
          )
        })}
      </div>

      {/* Summary */}
      <div className="flex items-center justify-between gap-3">
        <p className={`flex items-center gap-2 text-sm font-medium ${list.length ? 'text-dark-100' : 'text-dark-400'}`} aria-live="polite">
          <SummaryIcon className={`h-4 w-4 ${list.length ? 'text-eagle-400' : 'text-dark-500'}`} />
          {accessSummary(list, catalog, { withCount: true })}
        </p>
        {groups.length > 1 && (
          <button type="button" className="shrink-0 text-xs text-dark-400 hover:text-dark-100"
            onClick={() => setOpenGroups(allOpen ? new Set() : new Set(groups.map((g) => g.key)))}>
            {allOpen ? 'Collapse all' : 'Expand all'}
          </button>
        )}
      </div>

      {/* Groups */}
      <div className="divide-y divide-dark-700/60 overflow-hidden rounded-xl border border-dark-700">
        {groups.map((g) => {
          const open = openGroups.has(g.key)
          const n = g.actions.filter((a) => selected.has(a.key)).length
          return (
            <section key={g.key}>
              <button type="button" onClick={() => toggleGroup(g.key)} aria-expanded={open} aria-controls={`group-${g.key}`}
                className="flex w-full items-center gap-2 bg-dark-800/60 px-3 py-2.5 text-left transition-colors hover:bg-dark-700/40">
                <ChevronRight className={`h-4 w-4 shrink-0 text-dark-400 transition-transform duration-150 ${open ? 'rotate-90' : ''}`} />
                <span className="flex-1 text-sm font-medium text-dark-100">{g.label}</span>
                <span className={`text-xs tabular-nums ${n ? 'text-eagle-400' : 'text-dark-500'}`}>{n} of {g.actions.length}</span>
              </button>
              {open && (
                <div id={`group-${g.key}`} className="space-y-0.5 p-1.5">
                  {g.actions.map((a) => (
                    <ActionRow key={a.key} action={a} disabled={disabled}
                      checked={selected.has(a.key)}
                      note={note?.key === a.key ? note.text : null}
                      onToggle={() => (selected.has(a.key) ? untick(a.key) : tick(a.key))} />
                  ))}
                </div>
              )}
            </section>
          )
        })}
      </div>

      {confirm && (
        <RemoveConfirm
          label={actionLabel(confirm.key, catalog)}
          removedLabels={actionLabels(confirm.removed, catalog)}
          count={confirm.removed.length + 1}
          onCancel={() => setConfirm(null)}
          onConfirm={() => { onChange(confirm.next); setConfirm(null); setNote(null) }}
        />
      )}
    </div>
  )
}
