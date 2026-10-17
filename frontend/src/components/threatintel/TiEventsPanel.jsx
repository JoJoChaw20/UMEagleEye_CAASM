// Threat-intel events (MISP-style): a tenant's own IOC collections, plus the ones other
// tenants shared and the platform's. API: /cti/events (workers/src/routes/tiEvents.ts).
import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  Plus, ArrowLeft, Pencil, Trash2, Send, Undo2, Shield, AlertTriangle, X, Tag, Crosshair,
} from 'lucide-react'
import client from '../../api/client'
import { alertLabel, renderDetail, SevBadge, timeAgo } from '../common/alertMeta'

const LEVELS = {
  high:   { label: 'High',   cls: 'bg-red-500/15 text-red-300 border-red-500/40' },
  medium: { label: 'Medium', cls: 'bg-orange-500/15 text-orange-300 border-orange-500/40' },
  low:    { label: 'Low',    cls: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' },
}
const SHARING = {
  organisation: { label: 'Only our organisation', short: 'Private' },
  all_tenants:  { label: 'All tenants',            short: 'Shared' },
  platform:     { label: 'Platform (every tenant)', short: 'Platform' },
}
const TYPE_LABELS = { ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash', email: 'Email', cve: 'CVE', software: 'Software' }

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
const WRITE_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin']

const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : '—')
const Badge = ({ cls, children, title }) => (
  <span title={title} className={`text-xs px-2 py-0.5 rounded-full border font-medium whitespace-nowrap ${cls}`}>{children}</span>
)
const StatusBadge = ({ status }) => status === 'published'
  ? <Badge cls="bg-green-500/15 text-green-300 border-green-500/40">Published</Badge>
  : <Badge cls="bg-dark-700 text-dark-300 border-dark-600">Draft</Badge>

function errorText(err, fallback) {
  return err?.response?.data?.detail || fallback
}

// ── Create / edit dialog ──────────────────────────────────────
function EventDialog({ user, initial, onClose, onSaved }) {
  const isSuperadmin = user?.role === 'superadmin'
  const [form, setForm] = useState({
    title: initial?.title ?? '',
    description: initial?.description ?? '',
    threat_level: initial?.threat_level ?? 'medium',
    distribution: initial?.distribution ?? (isSuperadmin ? 'platform' : 'organisation'),
    tags: (initial?.tags ?? []).join(', '),
  })
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

  const save = async () => {
    setSaving(true)
    setError('')
    const body = {
      title: form.title.trim(),
      description: form.description.trim() || null,
      threat_level: form.threat_level,
      distribution: form.distribution,
      tags: tagList,
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
    if (indicators.trim()) {
      try {
        added = (await client.post(`/cti/events/${saved.event_id}/attributes`, { text: indicators })).data
      } catch (err) {
        added = { error: errorText(err, 'the indicators could not be added') }
      }
    }
    setSaving(false)
    onSaved(saved, added)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="glass-card w-full max-w-lg p-6 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">{initial ? 'Edit event' : 'New threat-intel event'}</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-100"><X className="w-5 h-5" /></button>
        </div>
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
            {isSuperadmin ? (
              <p className="input-field w-full mt-1 text-dark-200">Every tenant (platform event)</p>
            ) : (
              <select value={form.distribution} onChange={set('distribution')} className="input-field w-full mt-1">
                <option value="organisation">Only our organisation</option>
                <option value="all_tenants">All tenants</option>
              </select>
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
              <button type="button" onClick={moveTagsToIndicators} className="mt-1 underline hover:text-amber-100">Move to indicators</button>
            </div>
          </div>
        )}
        <label className="block text-sm text-dark-300">Indicators <span className="text-dark-500">(optional: one per line, added when you save)</span>
          <textarea value={indicators} onChange={e => setIndicators(e.target.value)} rows={3} className="input-field w-full mt-1 font-mono text-xs"
            placeholder={'IPs, domains, URLs, hashes, emails or CVE IDs, e.g.\n203.0.113.5\nhxxp://evil[.]example[.]my'} />
        </label>
        <p className="text-xs text-dark-500">
          A new event is a draft. Its indicators count for alerts once you publish it
          {form.distribution === 'organisation' ? ', for your organisation only.' : ', for every tenant that can see it.'}
        </p>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="btn-secondary text-sm">Cancel</button>
          <button onClick={save} disabled={saving || form.title.trim().length < 3} className="btn-primary text-sm disabled:opacity-50">
            {saving ? 'Saving…' : initial ? 'Save' : 'Create draft'}
          </button>
        </div>
      </div>
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
    <div className="glass-card p-4 space-y-3">
      <h3 className="text-sm font-semibold text-dark-200">Add indicators</h3>
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
            {result.alerts_updated > 0 && ` · ${result.alerts_updated} alert(s) updated`}
          </p>
          {result.rejected?.length > 0 && (
            <p className="text-red-300 font-mono break-all">
              {result.rejected.slice(0, 8).map(r => r.input).join(', ')}{result.rejected_count > 8 ? ', …' : ''}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ── One event ─────────────────────────────────────────────────
function EventDetail({ user, eventId, onBack, onChanged, showToast }) {
  const [ev, setEv] = useState(null)
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await client.get(`/cti/events/${eventId}`)
      setEv(res.data)
    } catch (err) {
      showToast(errorText(err, 'Failed to load the event'), 'error')
      onBack()
    }
  }, [eventId]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  const act = async (fn, okMsg) => {
    setBusy(true)
    try {
      const res = await fn()
      const n = res?.data?.alerts_updated
      showToast(n ? `${okMsg} ${n} alert(s) updated.` : okMsg)
      await load()
      onChanged()
    } catch (err) {
      showToast(errorText(err, 'The change failed'), 'error')
    } finally {
      setBusy(false)
    }
  }

  if (!ev) {
    return <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
  }

  const publish = () => act(() => client.post(`/cti/events/${ev.event_id}/${ev.status === 'published' ? 'unpublish' : 'publish'}`),
    ev.status === 'published' ? 'Unpublished.' : 'Published.')
  const remove = async () => {
    if (!confirm(`Delete "${ev.title}" and its ${ev.attribute_count} indicator(s)? This cannot be undone.`)) return
    setBusy(true)
    try {
      const res = await client.delete(`/cti/events/${ev.event_id}`)
      const n = res.data?.alerts_updated
      showToast(n ? `Event deleted. ${n} alert(s) updated.` : 'Event deleted.')
      onChanged()
      onBack()
    } catch (err) {
      showToast(errorText(err, 'Failed to delete the event'), 'error')
      setBusy(false)
    }
  }
  const toggleIds = (a) => act(() => client.patch(`/cti/events/${ev.event_id}/attributes/${a.attribute_id}`, { to_ids: !a.to_ids }),
    a.to_ids ? 'Indicator set to context only.' : 'Indicator used for alerts.')
  const removeAttr = (a) => act(() => client.delete(`/cti/events/${ev.event_id}/attributes/${a.attribute_id}`), 'Indicator removed.')

  return (
    <div className="space-y-4">
      <button onClick={onBack} className="inline-flex items-center gap-1.5 text-sm text-dark-400 hover:text-dark-100">
        <ArrowLeft className="w-4 h-4" /> All events
      </button>

      <div className="glass-card p-5 space-y-3">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <h2 className="text-xl font-semibold text-white break-words">{ev.title}</h2>
            <div className="flex items-center gap-1.5 flex-wrap mt-2">
              <StatusBadge status={ev.status} />
              <Badge cls={LEVELS[ev.threat_level]?.cls}>{LEVELS[ev.threat_level]?.label} threat</Badge>
              <Badge cls="bg-dark-700/60 text-dark-200 border-dark-600">{SHARING[ev.distribution]?.label}</Badge>
              {(ev.tags || []).map(t => (
                <Badge key={t} cls="bg-eagle-500/10 text-eagle-300 border-eagle-500/30"><Tag className="w-3 h-3 inline mr-1" />{t}</Badge>
              ))}
            </div>
          </div>
          {ev.can_edit && (
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => setEditing(true)} disabled={busy} className="btn-secondary text-sm flex items-center gap-2"><Pencil className="w-4 h-4" /> Edit</button>
              <button onClick={publish} disabled={busy} className={`${ev.status === 'published' ? 'btn-secondary' : 'btn-primary'} text-sm flex items-center gap-2`}>
                {ev.status === 'published' ? <><Undo2 className="w-4 h-4" /> Unpublish</> : <><Send className="w-4 h-4" /> Publish</>}
              </button>
              <button onClick={remove} disabled={busy} className="btn-secondary text-sm flex items-center gap-2 hover:text-red-400"><Trash2 className="w-4 h-4" /> Delete</button>
            </div>
          )}
        </div>
        {ev.description && <p className="text-sm text-dark-300 whitespace-pre-wrap">{ev.description}</p>}
        <p className="text-xs text-dark-500">
          Created {fmt(ev.created_at)} · updated {fmt(ev.updated_at)}{ev.published_at && ` · published ${fmt(ev.published_at)}`}
        </p>
        <p className="text-xs text-dark-400">
          {ev.status === 'published'
            ? 'Published: its indicators are used for alerts' + (ev.distribution === 'organisation' ? ' in your organisation.' : ' in every tenant that can see it.')
            : 'Draft: not used for alerts until you publish it.'}
          {' '}IPs, domains, URLs and software are matched against your assets; hashes and emails are kept for reference.
        </p>
      </div>

      {ev.status === 'published' && (
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-2">
            <Crosshair className="w-4 h-4 text-accent-red" /> Open alerts this event drives ({ev.matching_alerts?.length ?? 0}{ev.matching_alerts?.length === 50 ? '+' : ''})
          </h3>
          {(ev.matching_alerts ?? []).length === 0 ? (
            <p className="text-xs text-dark-500">None of your assets match it right now.</p>
          ) : (
            <ul className="space-y-1">
              {ev.matching_alerts.map(m => (
                <li key={m.event_id} className="text-xs text-dark-300 flex items-center gap-2">
                  <SevBadge sev={m.severity} />
                  <span className="text-dark-200">{m.event_type === 'cve_detected' ? m.cve_id : alertLabel({ event_type: m.event_type, details: { match_kind: m.match_kind } })}</span>
                  <span className="font-mono text-dark-400 truncate">{m.event_type === 'cti_match' ? `${m.observed} ↔ ${m.indicator_value}` : ''}</span>
                  <Link to={`/inventory/${m.asset_id}`} className="ml-auto text-eagle-400 hover:underline">{m.asset_name}</Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {ev.can_edit && <AddAttributes eventId={ev.event_id} showToast={showToast} onAdded={() => { load(); onChanged() }} />}

      <div className="glass-card overflow-hidden">
        <div className="p-4 border-b border-dark-700/50">
          <h3 className="text-sm font-semibold text-dark-200">{ev.attribute_count} indicator(s)</h3>
        </div>
        {ev.attributes.length === 0 ? (
          <p className="text-center py-10 text-dark-500 text-sm">No indicators yet{ev.can_edit ? '. Paste some above.' : '.'}</p>
        ) : (
          <div className="max-h-[28rem] overflow-y-auto">
            <table className="w-full text-xs table-fixed">
              <colgroup><col className="w-[10%]" /><col className="w-[40%]" /><col className="w-[16%]" /><col className="w-[26%]" /><col className="w-[8%]" /></colgroup>
              <thead className="sticky top-0 z-10 bg-dark-800">
                <tr className="text-dark-400 border-b border-dark-700">
                  <th className="text-left py-2 px-3 font-medium">Type</th>
                  <th className="text-left py-2 px-3 font-medium">Value</th>
                  <th className="text-left py-2 px-3 font-medium">Used for alerts</th>
                  <th className="text-left py-2 px-3 font-medium">Comment</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {ev.attributes.map(a => (
                  <tr key={a.attribute_id} className="border-b border-dark-700/30 hover:bg-dark-700/20">
                    <td className="py-1.5 px-3 text-dark-300">{TYPE_LABELS[a.type] ?? a.type}</td>
                    <td className="py-1.5 px-3 font-mono text-dark-100 truncate" title={a.value}>{a.value}</td>
                    <td className="py-1.5 px-3">
                      {a.warning ? (
                        <span className="inline-flex items-center gap-1 text-amber-300" title="On a warninglist: kept for reference, never raises an alert">
                          <AlertTriangle className="w-3.5 h-3.5" /> {a.warning_label}
                        </span>
                      ) : ev.can_edit ? (
                        <button onClick={() => toggleIds(a)} disabled={busy}
                          className={a.to_ids ? 'text-green-300 hover:underline' : 'text-dark-500 hover:underline'}>
                          {a.to_ids ? 'Yes' : 'No (context only)'}
                        </button>
                      ) : (a.to_ids ? 'Yes' : 'No (context only)')}
                    </td>
                    <td className="py-1.5 px-3 text-dark-400 truncate" title={a.comment || ''}>{a.comment || '—'}</td>
                    <td className="py-1.5 px-3 text-right">
                      {ev.can_edit && (
                        <button onClick={() => removeAttr(a)} disabled={busy} className="text-dark-500 hover:text-red-400" title="Remove">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <EventDialog user={user} initial={ev} onClose={() => setEditing(false)}
          onSaved={(saved, added) => {
            setEditing(false)
            showToast(added?.error ? `Saved, but ${added.error}.` : added ? `Saved. ${added.added} indicator(s) added.` : saved.alerts_updated ? `Saved. ${saved.alerts_updated} alert(s) updated.` : 'Saved.',
              added?.error ? 'error' : 'success')
            load(); onChanged()
          }} />
      )}
    </div>
  )
}

// ── Matches: open threat-intel match alerts on this organisation's assets ──
export function TiMatchesPanel({ showToast }) {
  const [items, setItems] = useState(null)
  useEffect(() => {
    client.get('/events', { params: { event_type: 'cti_match', status: 'open', page_size: 200, sort: 'priority' } })
      .then(r => setItems(r.data.items || []))
      .catch(err => { showToast(errorText(err, 'Failed to load matches'), 'error'); setItems([]) })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (items === null) {
    return <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
  }
  return (
    <div className="space-y-3">
      <p className="text-sm text-dark-400">
        Your assets that threat intelligence names: a public IP or hostname listed by a feed or event (possible compromise),
        or software an event watches. Checked after every scan, inventory and SBOM, nightly against the feeds, and whenever an event changes.
      </p>
      <div className="glass-card overflow-hidden">
        {items.length === 0 ? (
          <div className="text-center py-16 text-dark-400">
            <Crosshair className="w-12 h-12 mx-auto mb-3 opacity-20" />
            <p className="font-medium">No matches</p>
            <p className="text-sm mt-1">None of your assets' public IPs, hostnames or software appear in threat intel right now.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead><tr><th>Severity</th><th>Match</th><th>Asset</th><th>Matched</th><th>Listed by</th><th>Since</th></tr></thead>
            <tbody>
              {items.map(e => (
                <tr key={e.event_id}>
                  <td><SevBadge sev={e.severity} /></td>
                  <td className="text-sm text-dark-100">{alertLabel(e)}<p className="font-mono text-xs text-accent-cyan">{renderDetail(e)}</p></td>
                  <td><Link to={`/inventory/${e.asset_id}`} className="text-sm text-eagle-400 hover:underline">{e.asset_hostname || e.asset_ip}</Link></td>
                  <td className="font-mono text-xs text-dark-300">{e.details?.observed}</td>
                  <td className="text-xs text-dark-300">{(e.details?.sources ?? []).join(', ')}</td>
                  <td className="text-xs text-dark-400">{timeAgo(e.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {items.length > 0 && <Link to="/alerts?view=threat_intel" className="text-sm text-eagle-400 hover:underline">Work them on the Alerts page →</Link>}
    </div>
  )
}

// ── Panel: list ↔ detail ──────────────────────────────────────
export default function TiEventsPanel({ user, showToast }) {
  const canWrite = WRITE_ROLES.includes(user?.role)
  const [events, setEvents] = useState(null)
  const [filter, setFilter] = useState('all')       // all | ours | shared | drafts
  const [openId, setOpenId] = useState(null)
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await client.get('/cti/events')
      setEvents(res.data.items || [])
    } catch (err) {
      showToast(errorText(err, 'Failed to load threat-intel events'), 'error')
      setEvents([])
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  if (openId) {
    return <EventDetail user={user} eventId={openId} onBack={() => setOpenId(null)} onChanged={load} showToast={showToast} />
  }

  const isMine = (e) => e.own || (user?.role === 'superadmin' && !e.tenant_id)
  const shown = (events || []).filter(e =>
    filter === 'ours' ? isMine(e) : filter === 'shared' ? !isMine(e) : filter === 'drafts' ? e.status === 'draft' : true)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex gap-1 bg-dark-800 rounded-lg p-1">
          {[['all', 'All'], ['ours', 'Ours'], ['shared', 'Shared with us'], ['drafts', 'Drafts']].map(([id, label]) => (
            <button key={id} onClick={() => setFilter(id)}
              className={`px-3 py-1.5 rounded-md text-sm ${filter === id ? 'bg-eagle-600 text-white' : 'text-dark-400 hover:text-dark-100'}`}>
              {label}
            </button>
          ))}
        </div>
        {canWrite && (
          <button onClick={() => setCreating(true)} className="btn-primary text-sm flex items-center gap-2">
            <Plus className="w-4 h-4" /> New event
          </button>
        )}
      </div>

      <div className="glass-card overflow-hidden">
        {events === null ? (
          <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
        ) : shown.length === 0 ? (
          <div className="text-center py-16 text-dark-400">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-20" />
            <p className="font-medium">No events here yet</p>
            <p className="text-sm mt-1">
              {canWrite ? 'Create one to record a campaign’s indicators (IPs, domains, hashes, CVEs) and share it.' : 'Your analysts have not published any yet.'}
            </p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr><th>Event</th><th>Level</th><th>Status</th><th>Shared with</th><th>From</th><th>Indicators</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {shown.map(e => (
                <tr key={e.event_id} className="cursor-pointer hover:bg-dark-700/30" onClick={() => setOpenId(e.event_id)}>
                  <td className="max-w-xs">
                    <p className="text-sm text-dark-100 font-medium truncate" title={e.title}>{e.title}</p>
                    {(e.tags || []).length > 0 && <p className="text-xs text-dark-500 truncate">{e.tags.join(', ')}</p>}
                  </td>
                  <td><Badge cls={LEVELS[e.threat_level]?.cls}>{LEVELS[e.threat_level]?.label}</Badge></td>
                  <td><StatusBadge status={e.status} /></td>
                  <td className="text-xs text-dark-300">{SHARING[e.distribution]?.short}</td>
                  <td className="text-xs text-dark-300">{!e.tenant_id ? 'Platform' : e.own ? 'Us' : e.tenant_name}</td>
                  <td className="text-xs text-dark-300">{e.attribute_count}{e.cve_count > 0 && <span className="text-dark-500"> ({e.cve_count} CVE)</span>}</td>
                  <td className="text-xs text-dark-400">{fmt(e.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {creating && (
        <EventDialog user={user} onClose={() => setCreating(false)}
          onSaved={(saved, added) => {
            setCreating(false)
            showToast(added?.error ? `Draft created, but ${added.error}.` : added ? `Draft created with ${added.added} indicator(s). Publish it to use them.` : 'Draft created. Add indicators, then publish.',
              added?.error ? 'error' : 'success')
            load(); setOpenId(saved.event_id)
          }} />
      )}
    </div>
  )
}
