// The organisation's public addresses (GET /network/public-addresses, D4): the addresses its agents reach
// the internet from, and ones added by hand. An address agents report is only "unconfirmed" until someone
// marks it the organisation's own: a laptop at home or a shared campus network reports addresses that
// are not. Shown on the Network page's overview, under the networks.
import { useCallback, useEffect, useState } from 'react'
import { Globe, Plus, Trash2 } from 'lucide-react'
import client from '../../api/client'
import { Toast, ago, useToast } from '../common/PageParts'
import { plural } from './NetworkBands'

const STATUS = {
  ours: { label: 'Ours', chip: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
  unconfirmed: { label: 'Unconfirmed', chip: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  not_ours: { label: 'Not ours', chip: 'bg-dark-700/60 text-dark-300 border-dark-600' },
}

const errorOf = (err, fallback) => err?.response?.data?.detail || fallback

const LIST_KIND = { c2: 'command-and-control or malware server', malware: 'malware download on it', range: 'criminal network range', event: 'named by a threat event' }

/** What the blocklists say about the address (workers/src/services/publicAddresses.ts, rule R11). */
function Listings({ row }) {
  const listings = row.blocklists?.listings ?? []
  if (!row.checked_at) return <span className="text-dark-400">not checked yet</span>
  if (listings.length === 0) {
    return <span className="text-emerald-400" title={`Checked ${new Date(row.checked_at).toLocaleString()}`}>on none</span>
  }
  const bySource = new Map()
  for (const l of listings) if (!bySource.has(l.source)) bySource.set(l.source, l)
  return (
    <ul className="space-y-0.5">
      {[...bySource.values()].slice(0, 3).map((l) => (
        <li key={l.source} className={l.kind === 'c2' ? 'text-red-400' : 'text-amber-400'} title={`${l.value}${l.ref ? ` (${l.ref})` : ''}`}>
          {l.source}<span className="text-dark-400"> · {LIST_KIND[l.kind] ?? l.kind}</span>
        </li>
      ))}
      {bySource.size > 3 && <li className="text-dark-400">and {bySource.size - 3} more</li>}
    </ul>
  )
}

/** What Shodan InternetDB sees on the address: open ports (those that alert on an address marked ours,
 *  workers/src/lib/internetView.ts, in red), its tags and the CVEs it guesses. */
function InternetView({ row, lookup, alertPorts }) {
  if (!lookup) return <span className="text-dark-500">check off</span>
  if (row.ip.includes(':')) return <span className="text-dark-500">IPv4 only</span>
  if (row.status === 'not_ours') return <span className="text-dark-500">—</span>
  const v = row.internetdb
  if (!v || !row.internetdb_at) return <span className="text-dark-400">not asked yet</span>
  const when = `Shodan InternetDB, asked ${new Date(row.internetdb_at).toLocaleString()}`
  if (!v.found || v.ports.length === 0) return <span className="text-emerald-400" title={when}>no open port known</span>
  return (
    <div className="space-y-0.5" title={when}>
      <p className="font-mono">
        {v.ports.map((p, i) => (
          <span key={p} className={alertPorts.has(p) ?'text-red-400 font-semibold' : 'text-dark-200'}>{i > 0 && ', '}{p}</span>
        ))}
      </p>
      {v.tags?.length > 0 && <p className="text-dark-400">{v.tags.slice(0, 4).join(', ')}</p>}
      {v.vulns?.length > 0 && (
        <p className="text-dark-400" title={v.vulns.slice(0, 20).join(', ')}>
          {plural(v.vulns.length, 'CVE')} reported by Shodan, unverified
        </p>
      )}
    </div>
  )
}

export default function PublicAddresses({ tenantId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [ip, setIp] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const { toast, show } = useToast()

  const load = useCallback(async () => {
    try {
      const { data: d } = await client.get('/network/public-addresses', { params: tenantId ? { tenant_id: tenantId } : {} })
      setData(d); setError(null)
    } catch (err) {
      setError(errorOf(err, 'Could not load the public addresses'))
    }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  const add = async (e) => {
    e.preventDefault()
    if (!ip.trim()) return
    setBusy(true)
    try {
      await client.post('/network/public-addresses', { ip: ip.trim(), note: note.trim() || null })
      setIp(''); setNote('')
      show(`${ip.trim()} added as the organisation's own`)
      await load()
    } catch (err) {
      show(errorOf(err, 'Could not add the address'), 'error')
    } finally { setBusy(false) }
  }

  const setStatus = async (row, status) => {
    try {
      await client.patch(`/network/public-addresses/${row.public_address_id}`, { status })
      show(`${row.ip}: ${STATUS[status].label.toLowerCase()}`)
      await load()
    } catch (err) {
      show(errorOf(err, 'Could not change the address'), 'error')
    }
  }

  const remove = async (row) => {
    const agentsNote = row.agents_now.length ? '\n\nAgents still connect from it, so it comes back as unconfirmed within an hour.' : ''
    if (!confirm(`Remove ${row.ip} from the list?${agentsNote}`)) return
    try {
      await client.delete(`/network/public-addresses/${row.public_address_id}`)
      await load()
    } catch (err) {
      show(errorOf(err, 'Could not remove the address'), 'error')
    }
  }

  const items = data?.items ?? []
  const canEdit = !!data?.can_edit
  const alertPorts = new Set(data?.alert_ports ?? [])

  const setLookup = async (enabled) => {
    if (!enabled && !confirm("Stop asking Shodan InternetDB about the organisation's addresses?\n\nWhat it said is deleted and its alerts close.")) return
    setBusy(true)
    try {
      await client.put('/network/public-addresses/lookup', { enabled })
      show(enabled ? 'Asking Shodan InternetDB about the addresses' : 'Shodan InternetDB check turned off')
      await load()
    } catch (err) {
      show(errorOf(err, 'Could not change the setting'), 'error')
    } finally { setBusy(false) }
  }
  const unconfirmed = items.filter((r) => r.status === 'unconfirmed').length

  return (
    <section className="glass-card p-4 space-y-3" aria-labelledby="public-addresses-title">
      <Toast toast={toast} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-3xl">
          <h2 id="public-addresses-title" className="text-base font-semibold text-dark-50 inline-flex items-center gap-2">
            <Globe className="w-4 h-4 text-eagle-400" aria-hidden="true" />Public addresses
          </h2>
          <p className="text-xs text-dark-400 mt-1">
            The addresses your agents reach the internet from, and any you add, such as a server's or the office's fixed address.
            Mark the ones that belong to the organisation: laptops at home and shared networks (a campus) also report addresses that are not yours.
            Each is checked against ThreatFox, Feodo Tracker, URLhaus, your threat events and Spamhaus DROP after every feed update:
            one of yours on a list raises an alert, an unconfirmed one a review item.
          </p>
        </div>
        {unconfirmed > 0 && canEdit && (
          <span className="text-xs text-amber-400">{plural(unconfirmed, 'address', 'addresses')} to confirm</span>
        )}
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {canEdit && (
        <form onSubmit={add} className="flex flex-wrap items-center gap-2">
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="Public IP address" aria-label="Public IP address"
            className="input-field text-sm w-56 font-mono" maxLength={64} />
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional), e.g. mail server" aria-label="Note"
            className="input-field text-sm w-72" maxLength={200} />
          <button type="submit" className="btn-secondary text-sm inline-flex items-center gap-1.5" disabled={busy || !ip.trim()}>
            <Plus className="w-4 h-4" />Add as ours
          </button>
        </form>
      )}

      {data && items.length === 0 && (
        <p className="text-sm text-dark-400">
          No public address yet. Agents report theirs with their next check-in (phones are left out: on mobile data they show the carrier's address).
        </p>
      )}

      {items.length > 0 && (
        <div className="overflow-x-auto -mx-1">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-dark-400">
                <th className="px-2 py-2 font-semibold">Address</th>
                <th className="px-2 py-2 font-semibold">Status</th>
                <th className="px-2 py-2 font-semibold">Blocklists</th>
                <th className="px-2 py-2 font-semibold">Seen from the internet</th>
                <th className="px-2 py-2 font-semibold">Agents connecting from it</th>
                <th className="px-2 py-2 font-semibold">Seen</th>
                <th className="px-2 py-2 font-semibold">Note</th>
                {canEdit && <th className="px-2 py-2"><span className="sr-only">Remove</span></th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/60">
              {items.map((row) => (
                <tr key={row.public_address_id} className={row.status === 'not_ours' ? 'opacity-70' : ''}>
                  <td className="px-2 py-2 align-top">
                    <span className="font-mono text-dark-50 break-all">{row.ip}</span>
                    <span className="flex flex-wrap gap-1 mt-1">
                      {row.source === 'manual' && <span className="text-[11px] text-dark-400">added by hand</span>}
                      {row.shared && (
                        <span className="text-[11px] text-amber-400" title="Agents of another organisation reported this address in the last 30 days: probably a shared network">
                          shared with other organisations
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-2 py-2 align-top">
                    {canEdit ? (
                      <select value={row.status} onChange={(e) => setStatus(row, e.target.value)} aria-label={`Status of ${row.ip}`}
                        className="input-field text-xs py-1 w-36">
                        {Object.entries(STATUS).map(([k, s]) => <option key={k} value={k}>{s.label}</option>)}
                      </select>
                    ) : (
                      <span className={`inline-block text-xs px-2 py-0.5 rounded-md border ${STATUS[row.status]?.chip ?? STATUS.unconfirmed.chip}`}>
                        {STATUS[row.status]?.label ?? row.status}
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-2 align-top text-xs"><Listings row={row} /></td>
                  <td className="px-2 py-2 align-top text-xs"><InternetView row={row} lookup={data.lookup} alertPorts={alertPorts} /></td>
                  <td className="px-2 py-2 align-top text-dark-200">
                    {row.agents_now.length > 0
                      ? row.agents_now.slice(0, 4).map((a) => a.name).join(', ') + (row.agents_now.length > 4 ? ` and ${row.agents_now.length - 4} more` : '')
                      : row.last_agent ? <span className="text-dark-400">none now · last {row.last_agent.name}</span>
                        : <span className="text-dark-400">none</span>}
                  </td>
                  <td className="px-2 py-2 align-top text-xs text-dark-300 whitespace-nowrap">
                    {row.last_seen ? <span title={`First seen ${new Date(row.first_seen).toLocaleString()}`}>{ago(row.last_seen)}</span>
                      : <span className="text-dark-400">not by an agent</span>}
                  </td>
                  <td className="px-2 py-2 align-top text-xs text-dark-300 max-w-[16rem] break-words">{row.note ?? ''}</td>
                  {canEdit && (
                    <td className="px-2 py-2 align-top text-right">
                      <button type="button" onClick={() => remove(row)} className="p-1.5 rounded-md text-dark-400 hover:text-red-400 hover:bg-red-500/10"
                        aria-label={`Remove ${row.ip}`} title="Remove">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-dark-700/60 pt-3 text-xs text-dark-400">
          <label className={`inline-flex items-center gap-2 ${data.can_switch ? 'cursor-pointer text-dark-200' : ''}`}>
            <input type="checkbox" checked={!!data.lookup} disabled={!data.can_switch || busy}
              onChange={(e) => setLookup(e.target.checked)} className="accent-eagle-500" />
            Check what the internet sees (Shodan InternetDB, weekly)
          </label>
          <span>
            Sends these addresses to Shodan, the only place they go. An open management port on an address marked ours raises an alert.
            {!data.can_switch && ' Only the Tenant Superadmin can change this.'}
          </span>
        </div>
      )}
      <p className="text-[11px] text-dark-500">
        Open ports from <a href="https://internetdb.shodan.io/" target="_blank" rel="noreferrer" className="hover:text-dark-300 underline">Shodan InternetDB</a>.
        Network ranges from <a href="https://www.spamhaus.org/drop/" target="_blank" rel="noreferrer" className="hover:text-dark-300 underline">Spamhaus DROP</a>, © The Spamhaus Project.
      </p>
    </section>
  )
}
