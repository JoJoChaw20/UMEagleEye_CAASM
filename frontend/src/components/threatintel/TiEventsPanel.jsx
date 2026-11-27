// Threat-intel events (MISP-style): a tenant's own IOC collections and the ones other tenants share with it.
// API: /cti/events (workers/src/routes/tiEvents.ts). MyCERT's advisories are platform events too, listed on
// their own tab (MycertPanel.jsx), but they open here: EventView shows any event, with MyCERT's facts.
// Every detail opens in the Threat Intelligence panel (TiPanel.jsx): an event (EventView), and the form to
// create or edit one (EventForm); the list below has one filter bar and pages of 20.
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Plus, Pencil, Trash2, Send, Undo2, Shield, AlertTriangle, X, Bug, ExternalLink, BookOpen } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { softwareFor, softwareUrl, techniqueUrl, useAttackCatalog } from './attackCatalog'
import { alertLabel, SevBadge } from '../common/alertMeta'
import { alertChangeText } from '../../utils/alertChange'
import { ConfirmDialog, Spinner } from '../common/PageParts'
import { ClearFilters, EmptyState, FilterBar, FilterChip, ListPager, ListTotal, PanelList, pageWithin } from '../common/ListParts'
import { Badge, LevelBadge, SearchBox, day } from './tiParts'
import { useTiPanel } from './tiPanelContext'
import { TypeLabel } from './IndicatorPanel'

const PAGE = 20
const SHARING = {
  organisation: { label: 'Only our organisation', short: 'Our organisation' },
  all_tenants:  { label: 'All tenants',            short: 'All tenants' },
  platform:     { label: 'Platform (every tenant)', short: 'Every organisation' },
}
const TYPE_LABELS = { ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash', email: 'Email', cve: 'CVE', software: 'Software' }
const KIND_LABEL = { advisory: 'Advisory', alert: 'Alert', report: 'Report' }

// Does a tag look like an indicator? (Tags are labels; they never match anything.)
// A rough mirror of workers/src/lib/iocParse.ts detectType, defanged values included.
const IOC_LIKE = [
  /^cve-\d{4}-\d{4,}$/i,
  /^\d{1,3}(\.|\[\.\])\d{1,3}(\.|\[\.\])\d{1,3}(\.|\[\.\])\d{1,3}$/,
  /^(hxxps?|https?|ftp|fxp):\/\/?/i,
  /\[\.\]|\(\.\)|\[dot\]/i,
  /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i,
  /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i,
  /^([a-z0-9-]+\.)+[a-z]{2,}$/i,
]
const looksLikeIoc = (tag) => IOC_LIKE.some(re => re.test(tag.trim()))

const StatusBadge = ({ status }) => status === 'published'
  ? <Badge cls="border-green-500/40 bg-green-500/15 text-green-300">Published</Badge>
  : <Badge>Draft</Badge>

function errorText(err, fallback) {
  return err?.response?.data?.detail || fallback
}

// ── ATT&CK techniques picker (from MITRE's catalogue) ─────────
const PICK_RESULTS = 10

function TechniquePicker({ cat, value, onChange }) {
  const [q, setQ] = useState('')
  const query = q.trim().toLowerCase()
  const chosen = new Set(value)
  const results = !cat || !query ? [] : cat.techniques
    .filter(t => !chosen.has(t.id) && (t.id.toLowerCase().startsWith(query) || t.name.toLowerCase().includes(query)))
    .slice(0, PICK_RESULTS)
  const nameOf = (id) => cat?.techniques.find(t => t.id === id)?.name ?? ''
  const add = (id) => { onChange([...value, id]); setQ('') }

  return (
    <div className="space-y-1.5">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {value.map(id => (
            <span key={id} className="text-xs px-1.5 py-0.5 rounded bg-dark-700/70 text-dark-200 flex items-center gap-1">
              <span className="font-mono">{id}</span> {nameOf(id)}
              <button type="button" onClick={() => onChange(value.filter(v => v !== id))} className="text-dark-400 hover:text-red-400" aria-label={`Remove ${id}`}><X className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
      )}
      <div className="relative">
        <input value={q} onChange={e => setQ(e.target.value)} disabled={!cat}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); if (results[0]) add(results[0].id) } }}
          className="input-field w-full text-sm" placeholder={cat ? 'Search by ID or name, e.g. T1566 or phishing' : 'Loading ATT&CK…'} />
        {results.length > 0 && (
          <div className="absolute z-20 left-0 right-0 mt-1 max-h-56 overflow-y-auto rounded-lg border border-dark-600 bg-dark-800 shadow-float">
            {results.map(t => (
              <button key={t.id} type="button" onClick={() => add(t.id)}
                className="w-full text-left px-2.5 py-1.5 text-xs hover:bg-dark-700 flex gap-2">
                <span className="font-mono text-dark-400 w-16 shrink-0">{t.id}</span>
                <span className="flex-1 text-dark-100 truncate">{t.name}</span>
                <span className="text-dark-500 truncate max-w-[40%]">{t.tactics.map(sh => cat.tactics.find(x => x.short === sh)?.name).join(', ')}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Create / edit form (a view in the panel) ──────────────────
// view.initial: the event being edited (opened from its own view, so Cancel goes back to it); none: a new
// draft, which becomes its own view once saved.
export function EventForm({ view, setHead, panel, showToast }) {
  const initial = view.initial ?? null
  const { can } = useAuth()
  const canIndicators = can('ti_event.edit')   // indicators are added through the attributes endpoint
  const startForm = useMemo(() => ({
    title: initial?.title ?? '',
    description: initial?.description ?? '',
    threat_level: initial?.threat_level ?? 'medium',
    distribution: initial?.distribution ?? 'organisation',
    tags: (initial?.tags ?? []).join(', '),
    malware_family: initial?.malware_family ?? '',
  }), [initial])
  const startTechniques = useMemo(() => (initial?.attack_techniques ?? []).map(t => t.id), [initial])
  const [form, setForm] = useState(startForm)
  const [techniques, setTechniques] = useState(startTechniques)
  const cat = useAttackCatalog()
  const famSoftware = form.malware_family.trim() ? softwareFor(cat, form.malware_family) : null
  const [indicators, setIndicators] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))
  const tagList = form.tags.split(',').map(t => t.trim()).filter(Boolean)
  const iocTags = tagList.filter(looksLikeIoc)
  const moveTagsToIndicators = () => {
    setIndicators(v => [v.trim(), ...iocTags].filter(Boolean).join('\n'))
    setForm(f => ({ ...f, tags: tagList.filter(t => !looksLikeIoc(t)).join(', ') }))
  }
  const dirty = JSON.stringify(form) !== JSON.stringify(startForm) || techniques.join() !== startTechniques.join() || !!indicators.trim()

  const save = useCallback(async () => {
    setSaving(true)
    setError('')
    const body = {
      title: form.title.trim(),
      description: form.description.trim() || null,
      threat_level: form.threat_level,
      distribution: form.distribution,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
      malware_family: form.malware_family.trim() || null,
      attack_techniques: techniques,
    }
    let saved
    try {
      const res = initial
        ? await client.patch(`/cti/events/${initial.event_id}`, body)
        : await client.post('/cti/events', body)
      saved = res.data
    } catch (err) {
      setError(errorText(err, 'Failed to save the event'))
      setSaving(false)
      return
    }
    // Indicators typed here are added right after the event is saved.
    let added = null
    if (canIndicators && indicators.trim()) {
      try {
        added = (await client.post(`/cti/events/${saved.event_id}/attributes`, { text: indicators })).data
      } catch (err) {
        added = { error: errorText(err, 'the indicators could not be added') }
      }
    }
    setSaving(false)
    if (initial) showToast(added?.error ? `Saved, but ${added.error}.` : added ? `Saved. ${added.added} indicator(s) added.` : `Saved. ${alertChangeText(saved)}`.trim(), added?.error ? 'error' : 'success')
    else showToast(added?.error ? `Draft created, but ${added.error}.` : added ? `Draft created with ${added.added} indicator(s). Publish it to use them.` : 'Draft created. Add indicators, then publish.', added?.error ? 'error' : 'success')
    panel.changed()
    if (initial) panel.back()
    else panel.replace({ kind: 'event', id: saved.event_id, label: saved.title })
  }, [form, techniques, indicators, initial, canIndicators, panel, showToast])

  useEffect(() => {
    setHead({
      title: initial ? 'Edit event' : 'New threat-intel event',
      subtitle: initial?.title,
      dirty,
      footer: (requestClose) => (
        <div className="flex justify-end gap-2">
          <button type="button" onClick={initial ? panel.back : requestClose} className="btn-secondary text-sm">Cancel</button>
          <button type="button" onClick={save} disabled={saving || form.title.trim().length < 3} className="btn-primary text-sm disabled:opacity-50">
            {saving ? 'Saving…' : initial ? 'Save' : 'Create draft'}
          </button>
        </div>
      ),
    })
  }, [initial, dirty, saving, form.title, save, panel, setHead])

  return (
    <div className="space-y-4">
      <label className="block text-sm text-dark-300">Title
        <input value={form.title} onChange={set('title')} maxLength={200} className="input-field w-full mt-1"
          placeholder="e.g. Phishing campaign against Malaysian universities" />
      </label>
      <label className="block text-sm text-dark-300">Description
        <textarea value={form.description} onChange={set('description')} rows={3} className="input-field w-full mt-1"
          placeholder="What it is, where it came from, what to do" />
      </label>
      <div className="grid grid-cols-2 gap-3">
        <label className="block text-sm text-dark-300">Threat level
          <select value={form.threat_level} onChange={set('threat_level')} className="input-field w-full mt-1">
            <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </select>
        </label>
        <label className="block text-sm text-dark-300">Shared with
          <select value={form.distribution} onChange={set('distribution')} className="input-field w-full mt-1">
            <option value="organisation">Only our organisation</option>
            <option value="all_tenants">All tenants</option>
          </select>
          {form.distribution === 'all_tenants' && (
            <span className="block text-xs text-dark-500 mt-1">Other tenants can read it; it raises alerts in theirs only if they turn that on.</span>
          )}
        </label>
      </div>
      <label className="block text-sm text-dark-300">Tags <span className="text-dark-500">(labels for finding the event, comma separated)</span>
        <input value={form.tags} onChange={set('tags')} className="input-field w-full mt-1" placeholder="phishing, malaysia" />
      </label>
      {iocTags.length > 0 && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-200 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="flex-1">
            <p>{iocTags.length === 1 ? 'This tag looks' : 'These tags look'} like {iocTags.length === 1 ? 'an indicator' : 'indicators'}: <span className="font-mono">{iocTags.join(', ')}</span>. Tags are only labels and never match anything.</p>
            {canIndicators && <button type="button" onClick={moveTagsToIndicators} className="mt-1 underline hover:text-amber-100">Move to indicators</button>}
          </div>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <label className="block text-sm text-dark-300">Malware family <span className="text-dark-500">(optional)</span>
          <input value={form.malware_family} onChange={set('malware_family')} maxLength={120} className="input-field w-full mt-1" placeholder="e.g. Cobalt Strike" />
          {form.malware_family.trim() && cat && (
            <span className={`block text-xs mt-1 ${famSoftware ? 'text-green-400' : 'text-dark-500'}`}>
              {famSoftware
                ? `In ATT&CK: ${famSoftware.name} (${famSoftware.id}), ${famSoftware.count} techniques`
                : 'Not in ATT&CK: no techniques from the family'}
            </span>
          )}
        </label>
        <div className="text-sm text-dark-300">ATT&CK techniques <span className="text-dark-500">(optional)</span>
          <div className="mt-1"><TechniquePicker cat={cat} value={techniques} onChange={setTechniques} /></div>
        </div>
      </div>
      {canIndicators && <label className="block text-sm text-dark-300">Indicators <span className="text-dark-500">(optional: one per line, added when you save)</span>
        <textarea value={indicators} onChange={e => setIndicators(e.target.value)} rows={3} className="input-field w-full mt-1 font-mono text-xs"
          placeholder={'IPs, domains, URLs, hashes, emails or CVE IDs, e.g.\n203.0.113.5\nhxxp://evil[.]example[.]my'} />
      </label>}
      <p className="text-xs text-dark-500">
        {initial ? 'Changes to a published event update its alerts when you save.' : 'A new event is a draft. Its indicators count for alerts once you publish it'}
        {!initial && (form.distribution === 'organisation' ? ', for your organisation only.' : ': in your organisation, and in other tenants that choose to use it.')}
      </p>
      {error && <p className="text-sm text-red-400">{error}</p>}
    </div>
  )
}

// ── Add attributes box ────────────────────────────────────────
function AddAttributes({ eventId, onAdded, showToast }) {
  const [text, setText] = useState('')
  const [type, setType] = useState('')
  const [toIds, setToIds] = useState(true)
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)

  const add = async () => {
    setBusy(true)
    setResult(null)
    try {
      const res = await client.post(`/cti/events/${eventId}/attributes`, {
        text, ...(type ? { type } : {}), to_ids: toIds, comment: comment.trim() || null,
      })
      setResult(res.data)
      if (res.data.added > 0) setText('')
      onAdded(res.data)
    } catch (err) {
      showToast(errorText(err, 'Failed to add indicators'), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-3 rounded-lg border border-dark-700/60 p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-dark-400">Add indicators</h3>
      <textarea value={text} onChange={e => setText(e.target.value)} rows={4} className="input-field w-full font-mono text-xs"
        placeholder={type === 'software'
          ? 'One per line: a program or package name, optionally @version, e.g.\nMOVEit Transfer\nlog4j-core@2.14.1'
          : 'One per line: IPs, domains, URLs, hashes, emails or CVE IDs.\nDefanged values work too, e.g. hxxp://evil[.]com or 203.0.113[.]5'} />
      <div className="flex items-center gap-3 flex-wrap text-sm">
        <select value={type} onChange={e => setType(e.target.value)} className="input-field text-sm py-1.5 w-48">
          <option value="">Detect type automatically</option>
          {Object.entries(TYPE_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{k === 'software' ? 'All are: Software to watch (name or name@version)' : `All are: ${v}`}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-dark-300" title="Off = context only: never raises or ranks an alert">
          <input type="checkbox" checked={toIds} onChange={e => setToIds(e.target.checked)} /> Use for alerts
        </label>
        <input value={comment} onChange={e => setComment(e.target.value)} className="input-field text-sm py-1.5 flex-1 min-w-[12rem]"
          placeholder="Comment (optional, applies to all)" />
        <button onClick={add} disabled={busy || !text.trim()} className="btn-primary text-sm disabled:opacity-50">
          {busy ? 'Adding…' : 'Add'}
        </button>
      </div>
      {result && (
        <div className="text-xs text-dark-300 space-y-1">
          <p>
            Added {result.added}
            {result.already_present > 0 && ` · ${result.already_present} already in this event`}
            {result.on_warninglist > 0 && ` · ${result.on_warninglist} on a warninglist (kept, never alert)`}
            {result.rejected_count > 0 && ` · ${result.rejected_count} not recognised`}
            {result.alerts_updated > 0 && ` · ${alertChangeText(result).replace(/\.$/, '')}`}
          </p>
          {result.rejected?.length > 0 && (
            <p className="text-red-300 font-mono break-all">
              {result.rejected.slice(0, 8).map(r => r.input).join(', ')}{result.rejected_count > 8 ? ', …' : ''}
            </p>
          )}
        </div>
      )}
    </section>
  )
}

// ── Alerts from another tenant's shared event: off unless this tenant turns them on ──
// (workers/src/lib/sharedEvents.ts). A choice for this event wins over the tenant's default.
function SharedAlertChoice({ ev, busy, act }) {
  const { can } = useAuth()
  const canChoose = can('ti_event.publish')
  const set = (alerts) => act(() => client.put(`/cti/events/${ev.event_id}/alerts`, { alerts }),
    alerts === null ? 'Back to your default.' : alerts ? 'Alerts from this event are on.' : 'Alerts from this event are off.')
  const why = ev.alerts_choice === null
    ? `your default for shared events (${ev.shared_event_alerts ? 'on' : 'off'})`
    : 'chosen for this event'
  return (
    <section className={`flex flex-wrap items-start justify-between gap-4 rounded-lg border p-4 ${ev.alerts_here ? 'border-amber-500/40' : 'border-dark-700/60'}`}>
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-dark-200">
          Alerts in your organisation: <span className={ev.alerts_here ? 'text-amber-300' : 'text-dark-400'}>{ev.alerts_here ? 'On' : 'Off'}</span>
        </h3>
        <p className="text-xs text-dark-400 mt-1">
          {ev.status !== 'published' ? 'Unpublished by its owner: not used for alerts. ' : ''}
          {ev.alerts_here
            ? `Its indicators are matched against your assets and agents, and its alerts say "Shared by ${ev.tenant_name ?? 'another tenant'}" (${why}).`
            : `It is for reading only: its indicators raise no alerts here (${why}).`}
        </p>
      </div>
      {canChoose && ev.status === 'published' && (
        <div className="flex items-center gap-2 flex-wrap">
          {ev.alerts_here
            ? <button onClick={() => set(false)} disabled={busy} className="btn-secondary text-sm">Turn off for this event</button>
            : <button onClick={() => set(true)} disabled={busy} className="btn-primary text-sm">Raise alerts from this event</button>}
          {ev.alerts_choice !== null && (
            <button onClick={() => set(null)} disabled={busy} className="text-xs text-dark-400 hover:text-dark-100 underline">Use our default</button>
          )}
        </div>
      )}
    </section>
  )
}

// What a MyCERT advisory says beyond the event's own fields (workers/src/services/mycert.ts source_meta):
// MyCERT's rating, the affected products, and the sentence behind each exploited CVE.
function MycertFacts({ ev }) {
  const meta = ev.source_meta || {}
  const evidence = Object.entries(meta.exploited_evidence || {})
  return (
    <div className="rounded-lg border border-eagle-500/30 bg-eagle-500/5 p-3 space-y-2 text-xs">
      <p className="flex items-center gap-2 flex-wrap text-dark-200">
        <Shield className="w-3.5 h-3.5 text-eagle-400" />
        <span className="font-semibold">MyCERT {KIND_LABEL[meta.kind] ?? 'advisory'} {ev.external_id}</span>
        {meta.rating && <span>· MyCERT rates it <span className="font-semibold uppercase">{meta.rating}</span></span>}
      </p>
      {meta.products?.length > 0 && (
        <p className="text-dark-300"><span className="text-dark-400">Affected: </span>{meta.products.join(' · ')}</p>
      )}
      {evidence.length > 0 && (
        <div className="space-y-1">
          <p className="text-red-300 font-medium">Exploited in the wild, per MyCERT: these rank like CISA KEV CVEs on your alerts</p>
          {evidence.map(([cve, why]) => (
            <p key={cve} className="text-dark-300"><span className="font-mono text-dark-100">{cve}</span> <span className="text-dark-500">“{why}”</span></p>
          ))}
        </div>
      )}
      <p className="text-dark-500">Loaded from MyCERT automatically, for every organisation; it cannot be edited here.</p>
    </div>
  )
}

// ── One event (a view in the panel): MyCERT advisories open here too ──
export function EventView({ view, setHead, panel, showToast }) {
  const { can } = useAuth()
  const [ev, setEv] = useState(null)
  const [busy, setBusy] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await client.get(`/cti/events/${view.id}`)
      setEv(res.data)
    } catch (err) {
      showToast(errorText(err, 'Failed to load the event'), 'error')
      panel.close()
    }
  }, [view.id]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { load() }, [load, panel.version])

  const act = useCallback(async (fn, okMsg) => {
    setBusy(true)
    try {
      const res = await fn()
      showToast(`${okMsg} ${alertChangeText(res?.data)}`.trim())
      panel.changed()
    } catch (err) {
      showToast(errorText(err, 'The change failed'), 'error')
    } finally {
      setBusy(false)
    }
  }, [panel, showToast])

  const mycert = ev?.origin === 'mycert'
  const editable = !!ev?.can_edit
  useEffect(() => {
    if (!ev) return
    const meta = ev.source_meta || {}
    setHead({
      title: ev.title,
      subtitle: mycert ? `MyCERT ${(KIND_LABEL[meta.kind] ?? 'advisory').toLowerCase()} · published ${day(ev.published_at)}` : `Threat-intel event · ${ev.status === 'published' ? 'published' : 'draft'}`,
      footer: mycert ? (meta.url ? (
        <a href={meta.url} target="_blank" rel="noreferrer" className="btn-secondary inline-flex items-center gap-1.5 text-sm">Read it on MyCERT <ExternalLink className="h-3.5 w-3.5" /></a>
      ) : null) : editable && (can('ti_event.edit') || can('ti_event.publish') || can('ti_event.delete')) ? (
        <div className="flex flex-wrap items-center gap-2">
          {can('ti_event.edit') && <button onClick={() => panel.push({ kind: 'eventForm', initial: ev, label: ev.title })} disabled={busy} className="btn-secondary flex items-center gap-2 text-sm"><Pencil className="h-4 w-4" /> Edit</button>}
          {can('ti_event.publish') && (
            <button onClick={() => act(() => client.post(`/cti/events/${ev.event_id}/${ev.status === 'published' ? 'unpublish' : 'publish'}`), ev.status === 'published' ? 'Unpublished.' : 'Published.')}
              disabled={busy} className={`${ev.status === 'published' ? 'btn-secondary' : 'btn-primary'} flex items-center gap-2 text-sm`}>
              {ev.status === 'published' ? <><Undo2 className="h-4 w-4" /> Unpublish</> : <><Send className="h-4 w-4" /> Publish</>}
            </button>
          )}
          {can('ti_event.delete') && <button onClick={() => setConfirmDelete(true)} disabled={busy} className="btn-secondary ml-auto flex items-center gap-2 text-sm hover:text-red-400"><Trash2 className="h-4 w-4" /> Delete</button>}
        </div>
      ) : null,
    })
  }, [ev, mycert, editable, busy, can, act, panel, setHead])

  if (!ev) return <Spinner />

  const remove = async () => {
    setConfirmDelete(false)
    setBusy(true)
    try {
      const res = await client.delete(`/cti/events/${ev.event_id}`)
      showToast(`Event deleted. ${alertChangeText(res.data)}`.trim())
      panel.changed()
      panel.close()
    } catch (err) {
      showToast(errorText(err, 'Failed to delete the event'), 'error')
      setBusy(false)
    }
  }
  const toggleIds = (a) => act(() => client.patch(`/cti/events/${ev.event_id}/attributes/${a.attribute_id}`, { to_ids: !a.to_ids }),
    a.to_ids ? 'Indicator set to context only.' : 'Indicator used for alerts.')
  const removeAttr = (a) => act(() => client.delete(`/cti/events/${ev.event_id}/attributes/${a.attribute_id}`), 'Indicator removed.')
  const openIndicator = (a) => panel.push({ kind: 'indicator', value: a.value, label: mycert ? `${ev.external_id?.replace(/\.\d{6}$/, '')}` : ev.title })
  const tags = (ev.tags || []).filter((t) => !(mycert && (t === 'MyCERT' || KIND_LABEL[t.toLowerCase()])))
  const alerts = ev.matching_alerts ?? []

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-1.5">
        <LevelBadge level={ev.threat_level} suffix=" threat" />
        {!mycert && <StatusBadge status={ev.status} />}
        <Badge>{SHARING[ev.distribution]?.label}</Badge>
        {ev.shared_in && <Badge cls="border-sky-500/30 bg-sky-500/10 text-sky-300">Shared by {ev.tenant_name ?? 'another tenant'}</Badge>}
        {tags.slice(0, 8).map(t => <Badge key={t} cls="border-eagle-500/30 bg-eagle-500/10 text-eagle-300">{t}</Badge>)}
        {tags.length > 8 && <span className="text-xs text-dark-500">+{tags.length - 8} tags</span>}
      </div>
      {ev.description && <p className="whitespace-pre-wrap text-sm text-dark-300">{mycert ? ev.description.split('\n\nSource:')[0] : ev.description}</p>}
      {mycert && <MycertFacts ev={ev} />}
      {(ev.malware_family || ev.attack_techniques?.length > 0) && (
        <div className="space-y-1.5 text-xs">
          {ev.malware_family && (
            <p className="flex flex-wrap items-center gap-1.5 text-dark-300">
              <Bug className="h-3.5 w-3.5 text-dark-400" /> Malware family: <span className="text-dark-100">{ev.malware_family}</span>
              {ev.attack_software
                ? <a href={softwareUrl(ev.attack_software)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-eagle-400 hover:underline">ATT&CK {ev.attack_software_name} ({ev.attack_software}) <ExternalLink className="h-3 w-3" /></a>
                : <span className="text-dark-500">(not in ATT&CK)</span>}
            </p>
          )}
          {ev.attack_techniques?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {ev.attack_techniques.map(t => (
                <a key={t.id} href={techniqueUrl(t.id)} target="_blank" rel="noreferrer" title={t.name} className="rounded bg-dark-700/60 px-1.5 py-0.5 text-dark-200 hover:text-eagle-400">
                  <span className="font-mono">{t.id}</span> {t.name}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
      <p className="text-xs text-dark-400">
        {mycert ? `Loaded ${day(ev.created_at)}. ` : `Created ${day(ev.created_at)} · updated ${day(ev.updated_at)}. `}
        {ev.shared_in
          ? `Shared by ${ev.tenant_name ?? 'another tenant'}. `
          : ev.status === 'published'
            ? 'Published: its indicators are used for alerts' + (ev.distribution === 'organisation' ? ' in your organisation. '
              : ev.distribution === 'platform' ? ' in every organisation. ' : ' in your organisation, and in other tenants that turn it on. ')
            : 'Draft: not used for alerts until you publish it. '}
        IPs, domains, URLs and software are matched against {ev.shared_in ? 'devices' : 'your devices'}; hashes are checked by the agents; emails are kept for reference.
      </p>

      {ev.shared_in && <SharedAlertChoice ev={ev} busy={busy} act={act} />}

      {ev.status === 'published' && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">
            On your devices · {alerts.length}{alerts.length === 50 ? '+' : ''} open {alerts.length === 1 ? 'alert' : 'alerts'}
          </h3>
          {alerts.length === 0 ? (
            <p className="text-sm text-dark-500">{ev.shared_in && !ev.alerts_here ? 'None: alerts from this event are off in your organisation.' : 'None of your devices has what it names.'}</p>
          ) : (
            <ul className="space-y-1">
              {alerts.map(m => (
                <li key={m.event_id} className="flex items-center gap-2 text-xs text-dark-300">
                  <SevBadge sev={m.severity} />
                  <span className="text-dark-200">{m.event_type === 'cve_detected' ? `${m.package_name ? `${m.package_name}: ` : ''}${m.cve_id}` : alertLabel({ event_type: m.event_type, details: { match_kind: m.match_kind } })}</span>
                  <span className="truncate font-mono text-dark-400">{m.event_type === 'cti_match' ? `${m.observed} ↔ ${m.indicator_value}` : ''}</span>
                  <Link to={`/inventory/${m.asset_id}`} className="ml-auto text-eagle-400 hover:underline">{m.asset_name}</Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {editable && can('ti_event.edit') && <AddAttributes eventId={ev.event_id} showToast={showToast} onAdded={() => panel.changed()} />}

      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-dark-400">
          {mycert ? 'CVEs and indicators' : 'Indicators'} · {ev.attribute_count.toLocaleString()}
        </h3>
        <PanelList rows={ev.attributes} one="indicator" empty={editable ? 'No indicators yet. Add some above.' : 'None.'}
          head={editable ? ['Type', 'Value', 'Used for alerts', 'Comment', ''] : ['Type', 'Value', 'Used for alerts', 'Comment']}
          row={(a) => (
            <tr key={a.attribute_id} tabIndex={0} className="cursor-pointer hover:bg-dark-700/30" onClick={() => openIndicator(a)}
              onKeyDown={(e) => { if (e.key === 'Enter') openIndicator(a) }}>
              <td><TypeLabel type={a.type} /></td>
              <td className="max-w-[16rem] break-all font-mono text-xs text-dark-100">{a.value}</td>
              <td className="text-xs">
                {a.warning ? (
                  <span className="inline-flex items-center gap-1 text-amber-300" title="On a warninglist: kept for reference, never raises an alert"><AlertTriangle className="h-3.5 w-3.5" /> {a.warning_label}</span>
                ) : editable ? (
                  <button onClick={(e) => { e.stopPropagation(); toggleIds(a) }} disabled={busy} className={a.to_ids ? 'text-green-300 hover:underline' : 'text-dark-500 hover:underline'}>
                    {a.to_ids ? 'Yes' : 'No (context only)'}
                  </button>
                ) : <span className={a.to_ids ? 'text-dark-200' : 'text-dark-500'}>{a.to_ids ? 'Yes' : 'No (context only)'}</span>}
              </td>
              <td className="max-w-[14rem] truncate text-xs text-dark-400" title={a.comment || ''}>{a.comment || '—'}</td>
              {editable && (
                <td className="text-right">
                  <button onClick={(e) => { e.stopPropagation(); removeAttr(a) }} disabled={busy} className="text-dark-500 hover:text-red-400" title="Remove" aria-label={`Remove ${a.value}`}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              )}
            </tr>
          )} />
      </section>

      {confirmDelete && (
        <ConfirmDialog title="Delete this event?" confirmLabel="Delete" danger onCancel={() => setConfirmDelete(false)} onConfirm={remove}>
          “{ev.title}” and its {ev.attribute_count} indicator(s) are deleted, and the alerts they raised are checked again. This cannot be undone.
        </ConfirmDialog>
      )}
    </div>
  )
}

// ── The list ──────────────────────────────────────────────────
export default function TiEventsPanel({ showToast }) {
  const panel = useTiPanel()
  const { can, isPlatformSuperadmin, user } = useAuth()
  const canCreate = can('ti_event.create')
  const [events, setEvents] = useState(null)
  const [shared, setShared] = useState({ on: null, canSet: false })   // the tenant's default for shared events
  const [savingShared, setSavingShared] = useState(false)
  const [q, setQ] = useState('')
  const [owner, setOwner] = useState('')          // '' | ours | shared
  const [drafts, setDrafts] = useState(false)
  const [page, setPage] = useState(1)

  const load = useCallback(async () => {
    try {
      const res = await client.get('/cti/events')
      setEvents(res.data.items || [])
      setShared({ on: res.data.shared_event_alerts ?? null, canSet: !!res.data.can_set_shared_default })
    } catch (err) {
      showToast(errorText(err, 'Failed to load threat-intel events'), 'error')
      setEvents([])
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { load() }, [load, panel.version])
  useEffect(() => { setPage(1) }, [q, owner, drafts])

  const isMine = (e) => e.own || (isPlatformSuperadmin && !e.tenant_id)
  const query = q.trim().toLowerCase()
  const base = (events || []).filter((e) => (!query || e.title.toLowerCase().includes(query) || (e.tags || []).some((t) => t.toLowerCase().includes(query)))
    && (!drafts || e.status === 'draft'))
  const shown = base.filter((e) => (owner === 'ours' ? isMine(e) : owner === 'shared' ? !isMine(e) : true))
  const filtered = !!(query || owner || drafts)
  const clear = () => { setQ(''); setOwner(''); setDrafts(false) }
  const current = pageWithin(page, PAGE, shown.length)
  const open = (e) => panel.open({ kind: 'event', id: e.event_id, label: e.title })

  const setSharedDefault = async (on) => {
    setSavingShared(true)
    try {
      const { data } = await client.put(`/tenants/${user?.tenantId}/shared-event-alerts`, { alerts: on })
      showToast(`Alerts from shared events are ${on ? 'on' : 'off'} by default. ${alertChangeText(data)}`.trim())
      await load()
    } catch (err) {
      showToast(errorText(err, 'Failed to save the setting'), 'error')
    } finally {
      setSavingShared(false)
    }
  }

  return (
    <div className="space-y-3">
      <FilterBar>
        <SearchBox value={q} onChange={setQ} placeholder="Search events" />
        <FilterChip pressed={!owner} onClick={() => setOwner('')} count={base.length}>All</FilterChip>
        <FilterChip pressed={owner === 'ours'} onClick={() => setOwner('ours')} count={base.filter(isMine).length}>Ours</FilterChip>
        <FilterChip pressed={owner === 'shared'} onClick={() => setOwner('shared')} count={base.filter((e) => !isMine(e)).length}>Shared with us</FilterChip>
        <label className="ml-1 inline-flex items-center gap-1.5 text-xs text-dark-300">
          <input type="checkbox" checked={drafts} onChange={(e) => setDrafts(e.target.checked)} className="accent-eagle-500" /> Drafts only
        </label>
        {filtered && <ClearFilters onClick={clear} />}
        <ListTotal><b>{shown.length.toLocaleString()}</b> {shown.length === 1 ? 'event' : 'events'}</ListTotal>
        {canCreate && (
          <button onClick={() => panel.open({ kind: 'eventForm', label: 'New threat-intel event' })} className="btn-primary flex items-center gap-2 text-sm">
            <Plus className="h-4 w-4" /> New event
          </button>
        )}
      </FilterBar>

      {owner === 'shared' && shared.on !== null && (
        <div className="glass-card flex flex-wrap items-start justify-between gap-4 p-4">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-dark-200">
              Alerts from events other tenants share: <span className={shared.on ? 'text-amber-300' : 'text-dark-400'}>{shared.on ? 'On' : 'Off'} by default</span>
            </h3>
            <p className="mt-1 text-xs text-dark-400">
              {shared.on
                ? 'Every event another tenant shares with all tenants is matched against your assets and agents, unless you turn it off for that event.'
                : 'Shared events are for reading only, unless you turn alerts on for an event (open it).'}
              {' '}Their alerts say which tenant shared them.
            </p>
          </div>
          {shared.canSet && (
            <button onClick={() => setSharedDefault(!shared.on)} disabled={savingShared} className="btn-secondary text-sm">
              {savingShared ? 'Saving…' : shared.on ? 'Turn off by default' : 'Turn on for all shared events'}
            </button>
          )}
        </div>
      )}

      <div className="glass-card overflow-hidden">
        {events === null ? <Spinner className="py-20" /> : shown.length === 0 ? (
          <EmptyState icon={BookOpen} title="No events" filtered={filtered} onClear={clear}>
            {canCreate ? 'Create one to record a campaign’s indicators (IPs, domains, hashes, CVEs) and share it.' : 'Your analysts have not published any yet.'}
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>Event</th><th>Threat</th><th>Status</th><th>Shared with</th><th>Alerts here</th><th>Indicators</th><th>Updated</th></tr>
                </thead>
                <tbody>
                  {shown.slice((current - 1) * PAGE, current * PAGE).map(e => (
                    <tr key={e.event_id} tabIndex={0} className="cursor-pointer hover:bg-dark-700/30" onClick={() => open(e)}
                      onKeyDown={(ev) => { if (ev.key === 'Enter') open(e) }}>
                      <td className="max-w-xs">
                        <p className="truncate text-sm font-medium text-dark-100" title={e.title}>{e.title}</p>
                        <p className="truncate text-xs text-dark-500">{!isMine(e) ? `Shared by ${e.tenant_id ? e.tenant_name : 'the platform'}` : (e.tags || []).join(', ')}</p>
                      </td>
                      <td><LevelBadge level={e.threat_level} /></td>
                      <td><StatusBadge status={e.status} /></td>
                      <td className="text-xs text-dark-300">{SHARING[e.distribution]?.short}</td>
                      <td className="text-xs" title={e.shared_in ? (e.alerts_choice === null ? 'Your default for shared events' : 'Chosen for this event') : undefined}>
                        {e.alerts_here === undefined ? <span className="text-dark-500">—</span>
                          : e.alerts_here ? <span className="text-amber-300">Yes</span>
                          : <span className="text-dark-500">{e.status === 'draft' ? 'Not yet' : 'No'}</span>}
                      </td>
                      <td className="text-xs tabular-nums text-dark-300">{e.attribute_count.toLocaleString()}{e.cve_count > 0 && <span className="text-dark-500"> ({e.cve_count} CVE)</span>}</td>
                      <td className="whitespace-nowrap text-xs text-dark-400">{day(e.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ListPager page={current} pageSize={PAGE} total={shown.length} one="event" onChange={setPage} />
          </>
        )}
      </div>
    </div>
  )
}
