import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus, ExternalLink } from 'lucide-react'
import client from '../../api/client'
import AdoptMatchModal from '../assets/AdoptMatchModal'
import { buildMatchIndex } from '../assets/assetMeta'
import { SidePanel, Spinner } from '../common/PageParts'
import { KIND_LABEL } from './discoveryMeta'

function formatOs(os) {
  if (!os) return null
  if (typeof os === 'string') return os
  return os.name ? `${os.name}${os.accuracy ? ` (${os.accuracy}%)` : ''}` : null
}

function formatPorts(ports) {
  if (!Array.isArray(ports) || ports.length === 0) return null
  const list = ports.slice(0, 10).map((p) => (typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : String(p)))
  return list.join('  ') + (ports.length > 10 ? `  +${ports.length - 10} more` : '')
}

const STATUS = {
  mine:       { label: 'In My Assets', cls: 'bg-green-500/15 text-green-500 border-green-500/40' },
  discovered: { label: 'Discovered',   cls: 'bg-blue-500/15 text-blue-400 border-blue-500/40' },
  gone:       { label: 'Not in assets', cls: 'bg-dark-600/40 text-dark-400 border-dark-500/30' },
}

// The hosts of one Discovery record. Every host a scan finds is already an asset
// (in Discovered); adopting moves it to My Assets, with the same "may already be in
// My Assets" check as the Inventory page.
export default function HostsPanel({ scanId, agentName, canAdopt, onClose }) {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [adopted, setAdopted] = useState(() => new Set())
  const [busy, setBusy] = useState(null)
  const [matchIndex, setMatchIndex] = useState(null)
  const [adoptTarget, setAdoptTarget] = useState(null)

  useEffect(() => {
    client.get(`/scans/${scanId}/hosts`)
      .then((r) => setData(r.data))
      .catch((err) => setError(err?.response?.data?.detail || 'Failed to load hosts'))
  }, [scanId])

  const setMine = async (assetId) => {
    await client.patch(`/assets/${assetId}`, { in_my_assets: true })
    setAdopted((cur) => new Set([...cur, assetId]))
  }

  const adopt = async (host) => {
    const a = host.asset
    setBusy(a.asset_id)
    try {
      let index = matchIndex
      if (!index) {
        const res = await client.get('/assets/duplicates', { params: data.scan.tenant_id ? { tenant_id: data.scan.tenant_id } : {} })
        index = buildMatchIndex(res.data.groups || [])
        setMatchIndex(index)
      }
      const hit = index.get(a.asset_id)
      const matches = (hit?.others || []).filter((o) => o.inMyAssets)
      if (matches.length > 0) {
        setAdoptTarget({ asset: { assetId: a.asset_id, hostname: a.hostname, ipAddress: host.ip }, matches, reasons: hit.reasons || [] })
      } else {
        await setMine(a.asset_id)
      }
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to add the asset to My Assets')
    } finally {
      setBusy(null)
    }
  }

  const scan = data?.scan
  const hosts = data?.hosts ?? []
  return (
    <SidePanel onClose={onClose}
      title={scan ? `${KIND_LABEL[scan.kind] ?? 'Scan'} · ${scan.kind === 'passive' || scan.kind === 'investigation' ? (scan.network ?? scan.subnet) : scan.subnet}` : 'Hosts'}
      subtitle={scan && <>
        {hosts.length} host{hosts.length === 1 ? '' : 's'}{agentName ? ` · ${agentName}` : ''}
        {scan.completed_at && ` · ${new Date(scan.completed_at).toLocaleString()}`}
      </>}>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {!data && !error && <Spinner />}
      {data && hosts.length === 0 && <p className="text-sm text-dark-400 text-center py-8">No hosts in this record.</p>}
      {data && hosts.length > 0 && (
        <>
          <p className="text-xs text-dark-400">
            Every host found is already in the asset list (Discovered). Add the ones your organisation manages to My Assets;
            leave personal phones, TVs and guest devices in Discovered.
          </p>
          <ul className="space-y-2">
            {hosts.map((h, i) => {
              const a = h.asset
              const mine = a && (a.in_my_assets || adopted.has(a.asset_id))
              const status = !a ? STATUS.gone : mine ? STATUS.mine : STATUS.discovered
              const os = formatOs(h.os)
              const ports = formatPorts(h.ports)
              return (
                <li key={`${h.ip}-${h.mac ?? i}`} className="rounded-xl p-3 border bg-dark-850 border-dark-700">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        {a ? (
                          <Link to={`/inventory/${a.asset_id}`} className="font-mono text-sm text-accent-cyan hover:underline">{h.ip}</Link>
                        ) : <span className="font-mono text-sm text-accent-cyan">{h.ip}</span>}
                        <span className={`text-[11px] px-1.5 py-0.5 border rounded-full ${status.cls}`}>{status.label}</span>
                      </div>
                      {(h.hostname || a?.hostname) && <p className="text-xs text-dark-200">{h.hostname || a.hostname}</p>}
                      {h.mac && <p className="text-xs text-dark-400 font-mono">{h.mac}{h.vendor ? ` · ${h.vendor}` : ''}</p>}
                      {os && <p className="text-xs text-dark-300"><span className="text-dark-400">OS:</span> {os}</p>}
                      {ports && <p className="text-xs text-dark-400">Ports: <span className="font-mono text-dark-300">{ports}</span></p>}
                      {h.description && <p className="text-xs text-dark-400 pt-1">{h.description}</p>}
                    </div>
                    <div className="shrink-0 flex flex-col items-end gap-1.5">
                      {canAdopt && a && !mine && (
                        <button onClick={() => adopt(h)} disabled={busy === a.asset_id} className="btn-primary text-xs py-1.5 px-3 inline-flex items-center gap-1.5 disabled:opacity-50">
                          {busy === a.asset_id ? <span className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-3 h-3" />}
                          Add to My Assets
                        </button>
                      )}
                      {a && (
                        <Link to={`/inventory/${a.asset_id}`} className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-1">
                          Asset <ExternalLink className="w-3 h-3" />
                        </Link>
                      )}
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        </>
      )}

      {adoptTarget && (
        <AdoptMatchModal
          asset={adoptTarget.asset}
          matches={adoptTarget.matches}
          reasons={adoptTarget.reasons}
          onClose={() => setAdoptTarget(null)}
          reviewLabel="Review on asset page"
          onReviewDuplicates={() => navigate(`/inventory/${adoptTarget.asset.assetId}`)}
          onAdopt={async () => {
            try { await setMine(adoptTarget.asset.assetId); setAdoptTarget(null) } catch (err) {
              alert(err?.response?.data?.detail || 'Failed to add the asset to My Assets')
            }
          }}
        />
      )}
    </SidePanel>
  )
}
