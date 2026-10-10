import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  ArrowLeft, Pencil, RefreshCw, Bookmark, MinusCircle, CheckCircle, Trash2, Zap,
  Server, Cpu, Network, Bell, GitBranch, History, Link2, ShieldAlert, Eraser,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import CriticalityBadge from '../components/common/CriticalityBadge'
import BlastRadiusModal from '../components/common/BlastRadiusModal'
import DuplicatesPanel from '../components/common/DuplicatesPanel'
import { EditAssetModal } from '../components/assets/AssetModals'
import AdoptMatchModal from '../components/assets/AdoptMatchModal'
import { DEVICE_TYPE_META, SOURCE_META, assetName, buildMatchIndex } from '../components/assets/assetMeta'
import { Section, Field, Empty, fmtDateTime } from '../components/assets/DetailParts'
import {
  AgentOsFields, HardwareSection, InterfacesSection, ListeningSection, PatchesSection, SecuritySection, SoftwareSection,
} from '../components/assets/EndpointSections'
import { RISKY_PORTS, SevBadge, StatusBadge, alertLabel, renderDetail, timeAgo } from '../components/common/alertMeta'
import { formatSeen } from '../utils/time'
import { isLocallyAdministeredMac } from '../utils/mac'

// Human labels for the os_info keys written by scan ingest (active, passive, SNMP).
const OS_FIELDS = [
  ['name', 'Operating system'],
  ['accuracy', 'OS match accuracy', (v) => `${v}%`],
  ['smb_computer_name', 'SMB computer name'],
  ['smb_domain', 'SMB domain'],
  ['smb_fqdn', 'SMB FQDN'],
  ['dhcp_device_hint', 'DHCP device hint'],
  ['dhcp_vendor_class', 'DHCP vendor class'],
  ['fingerbank_device', 'Fingerbank device', (v, os) => (os.fingerbank_score ? `${v} (score ${os.fingerbank_score})` : v)],
  ['snmp_sysdescr', 'SNMP description'],
  ['snmp_sysobjectid', 'SNMP object ID'],
  ['snmp_interfaces', 'SNMP interfaces', (v) => (Array.isArray(v) ? `${v.length} interface${v.length === 1 ? '' : 's'}` : String(v))],
]

export default function AssetDetailPage() {
  const { assetId } = useParams()
  const navigate = useNavigate()
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const isReadOnly = isSuperadmin || isBusinessOwner
  const canDelete = user?.role === 'tenant_superadmin'

  const [asset, setAsset] = useState(null)
  const [status, setStatus] = useState('loading')   // loading | ready | notfound | error
  const [score, setScore] = useState(null)
  const [addresses, setAddresses] = useState(null)
  const [alerts, setAlerts] = useState(null)        // { items, total }
  const [sbom, setSbom] = useState(undefined)       // undefined = loading, null = none
  const [software, setSoftware] = useState(undefined) // { items, total } from the agent inventory
  const [graph, setGraph] = useState(null)
  const [dupGroups, setDupGroups] = useState([])
  const [notice, setNotice] = useState(null)

  const [editing, setEditing] = useState(false)
  const [rescoring, setRescoring] = useState(false)
  const [showBlast, setShowBlast] = useState(false)
  const [showDuplicates, setShowDuplicates] = useState(false)
  const [adoptTarget, setAdoptTarget] = useState(null)

  const loadAsset = useCallback(async () => {
    try {
      const res = await client.get(`/assets/${assetId}`)
      setAsset(res.data)
      setStatus('ready')
    } catch (err) {
      setStatus(err?.response?.status === 404 ? 'notfound' : 'error')
    }
  }, [assetId])

  // Secondary panels load independently, so one failing never blanks the page.
  const loadPanels = useCallback(() => {
    client.get(`/assets/${assetId}/score`).then((r) => setScore(r.data)).catch(() => setScore(null))
    client.get(`/assets/${assetId}/addresses`).then((r) => setAddresses(r.data.addresses || [])).catch(() => setAddresses([]))
    client.get('/events', { params: { asset_id: assetId, status: 'open', page_size: 10, sort: 'priority' } })
      .then((r) => setAlerts({ items: r.data.items || [], total: r.data.total ?? (r.data.items || []).length }))
      .catch(() => setAlerts({ items: [], total: 0 }))
    client.get(`/assets/${assetId}/software`).then((r) => setSoftware(r.data)).catch(() => setSoftware({ items: [], total: 0 }))
    client.get('/sboms', { params: { asset_id: assetId, page_size: 1 } })
      .then((r) => setSbom(r.data.items?.[0] ?? null)).catch(() => setSbom(null))
    if (!isBusinessOwner) {
      client.get(`/relationships/graph/${assetId}`).then((r) => setGraph(r.data)).catch(() => setGraph({ nodes: [], edges: [] }))
    }
  }, [assetId, isBusinessOwner])

  // Duplicates are tenant-wide; scope to the asset's tenant (matters for superadmin).
  const tenantId = asset?.tenantId
  useEffect(() => {
    if (isBusinessOwner || !tenantId) return
    client.get('/assets/duplicates', { params: { tenant_id: tenantId } })
      .then((r) => setDupGroups(r.data.groups || [])).catch(() => setDupGroups([]))
  }, [tenantId, isBusinessOwner, asset?.updatedAt])

  useEffect(() => {
    // Same component is reused when navigating between assets, so close any open
    // dialogs from the previous asset as well.
    setEditing(false); setShowBlast(false); setShowDuplicates(false); setAdoptTarget(null); setNotice(null)
    setStatus('loading'); setAsset(null); setScore(null); setAddresses(null); setAlerts(null)
    setSbom(undefined); setSoftware(undefined); setGraph(null); setDupGroups([])
    loadAsset()
    loadPanels()
  }, [loadAsset, loadPanels])

  useEffect(() => {
    if (!notice) return
    const t = setTimeout(() => setNotice(null), 6000)
    return () => clearTimeout(t)
  }, [notice])

  const match = useMemo(() => buildMatchIndex(dupGroups).get(assetId) ?? null, [dupGroups, assetId])

  // ── Actions ──
  const refresh = async () => { await loadAsset(); loadPanels() }

  const setMembership = async (inMyAssets) => {
    await client.patch(`/assets/${assetId}`, { in_my_assets: inMyAssets })
    setNotice(inMyAssets ? 'Added to My Assets.' : 'Moved to Discovered.')
    await refresh()
  }

  const handleAdopt = async () => {
    const mine = (match?.others || []).filter((o) => o.inMyAssets)
    if (mine.length > 0) { setAdoptTarget({ matches: mine, reasons: match.reasons }); return }
    try { await setMembership(true) } catch (err) { alert(err?.response?.data?.detail || 'Failed to add asset to My Assets') }
  }

  const handleRemove = async () => {
    if (!confirm(
      `Move ${assetName(asset)} to Discovered?\n\n` +
      '• It keeps its history, owner and criticality.\n' +
      '• It will be hidden from the relationship graph.\n' +
      '• You can adopt it again at any time.'
    )) return
    try { await setMembership(false) } catch (err) { alert(err?.response?.data?.detail || 'Failed to remove asset from My Assets') }
  }

  const handleRescore = async () => {
    setRescoring(true)
    try {
      const res = await client.post(`/assets/${assetId}/rescore`)
      const { changed, previous, current } = res.data
      setNotice(changed ? `Criticality ${previous}/10 → ${current}/10.` : 'Criticality already up to date.')
      if (changed) await refresh()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Rescore failed')
    } finally {
      setRescoring(false)
    }
  }

  const handleBaseline = async () => {
    if (!confirm('Set the baseline to this asset\'s current state?\n\nThis replaces the current baseline (ports, packages, hostname, MAC, exposure and device type).')) return
    try {
      await client.post(`/assets/${assetId}/baseline`, { confirm: true })
      setNotice('Baseline set.')
      await loadAsset()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to set baseline')
    }
  }

  const handleClearInventory = async () => {
    if (!confirm(
      `Clear the agent inventory of ${assetName(asset)}?\n\n` +
      '• Removes the hardware, OS, patch, security and network details and the installed-software list.\n' +
      '• The asset, its scans and alerts are kept.\n' +
      '• The agent on this machine sends a new inventory at its next run unless it is stopped or started with --no-inventory.'
    )) return
    try {
      const res = await client.delete(`/assets/${assetId}/inventory`)
      setNotice(`Inventory cleared (${res.data.software_removed} software entr${res.data.software_removed === 1 ? 'y' : 'ies'} removed).`)
      await refresh()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to clear inventory')
    }
  }

  const handleDelete = async () => {
    if (!confirm(
      `Delete ${assetName(asset)} permanently?\n\n` +
      'This permanently deletes the asset and its events, SBOMs, dependencies and relationships. This cannot be undone.'
    )) return
    try {
      await client.delete(`/assets/${assetId}`)
      navigate(asset.inMyAssets ? '/inventory' : '/inventory?scope=discovered', { replace: true })
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete asset')
    }
  }

  // ── States ──
  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center py-32">
        <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
      </div>
    )
  }
  if (status !== 'ready') {
    return (
      <div className="glass-card p-10 text-center space-y-3">
        <Server className="w-12 h-12 mx-auto opacity-20" />
        <p className="text-white font-medium">{status === 'notfound' ? 'Asset not found' : 'Could not load this asset'}</p>
        <p className="text-sm text-dark-400">
          {status === 'notfound' ? 'It may have been deleted or merged into another asset.' : 'Check your connection and try again.'}
        </p>
        <div className="flex justify-center gap-2">
          {status === 'error' && <button onClick={loadAsset} className="btn-secondary text-sm">Retry</button>}
          <Link to="/inventory" className="btn-primary text-sm">Back to inventory</Link>
        </div>
      </div>
    )
  }

  const os = (asset.osInfo ?? {})
  const deviceMeta = DEVICE_TYPE_META[asset.deviceType] ?? DEVICE_TYPE_META.unknown
  const srcMeta = SOURCE_META[asset.source] ?? SOURCE_META.scan_passive
  const lastSeen = formatSeen(asset.lastScanned, { nullText: 'Never scanned' })
  const services = Array.isArray(os.services) && os.services.length
    ? os.services
    : (Array.isArray(os.ports) ? os.ports.map((p) => {
        const [port, protocol] = String(p).split('/')
        return { port: Number(port), protocol: protocol || 'tcp' }
      }) : [])
  const osRows = OS_FIELDS.filter(([k]) => os[k] != null && os[k] !== '' && !(Array.isArray(os[k]) && os[k].length === 0))
  const inv = asset.endpointInventory || null
  const baseline = asset.baselineState
  const backHref = asset.inMyAssets ? '/inventory' : '/inventory?scope=discovered'
  const neighbors = graph ? graph.nodes.filter((n) => n.asset_id !== assetId) : []
  const neighborEdges = (id) => (graph?.edges || []).filter((e) => e.source === id || e.target === id)

  return (
    <div className="space-y-6">
      {/* Breadcrumb + header */}
      <div className="space-y-3">
        <Link to={backHref} className="inline-flex items-center gap-1.5 text-sm text-dark-400 hover:text-dark-100">
          <ArrowLeft className="w-4 h-4" /> {asset.inMyAssets ? 'My Assets' : 'Discovered'}
        </Link>

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-3">
            <span className="text-3xl leading-none mt-1" aria-hidden="true">{deviceMeta.icon}</span>
            <div>
              <h1 className="text-2xl font-bold text-white break-all">{assetName(asset)}</h1>
              <div className="font-mono text-sm text-accent-cyan mt-0.5">{asset.ipAddress}</div>
              <div className="flex items-center gap-1.5 flex-wrap mt-2">
                <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${asset.inMyAssets
                  ? 'bg-green-500/20 text-green-400 border-green-500/30'
                  : 'bg-dark-600/40 text-dark-300 border-dark-500/30'}`}>
                  {asset.inMyAssets ? 'My Assets' : 'Discovered'}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-dark-700/40 text-dark-200 border-dark-600/40">{deviceMeta.label}</span>
                <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${srcMeta.cls}`}>{srcMeta.label}</span>
                {asset.isInternetFacing && (
                  <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-yellow-500/10 text-yellow-400 border-yellow-500/30">Internet-facing</span>
                )}
                {inv && (
                  <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-eagle-500/10 text-eagle-400 border-eagle-500/30"
                    title={`Inventory reported by the EagleEye agent on ${fmtDateTime(asset.inventoryCollectedAt)}`}>
                    Agent installed
                  </span>
                )}
                <span className={`text-xs ${lastSeen.stale ? 'text-amber-400' : 'text-dark-400'}`} title={lastSeen.title || ''}>Last seen {lastSeen.text}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {!isBusinessOwner && (
              <button onClick={() => setShowBlast(true)} className="btn-secondary text-sm flex items-center gap-2">
                <Zap className="w-4 h-4 text-yellow-400" /> Blast radius
              </button>
            )}
            {!isReadOnly && asset.inMyAssets && (
              <>
                <button onClick={() => setEditing(true)} className="btn-secondary text-sm flex items-center gap-2"><Pencil className="w-4 h-4" /> Edit</button>
                <button onClick={handleRescore} disabled={rescoring} className="btn-secondary text-sm flex items-center gap-2">
                  <RefreshCw className={`w-4 h-4 ${rescoring ? 'animate-spin' : ''}`} /> Rescore
                </button>
                <button onClick={handleBaseline} className="btn-secondary text-sm flex items-center gap-2"><Bookmark className="w-4 h-4" /> Set baseline</button>
                <button onClick={handleRemove} className="btn-secondary text-sm flex items-center gap-2"><MinusCircle className="w-4 h-4" /> Move to Discovered</button>
              </>
            )}
            {!isReadOnly && !asset.inMyAssets && (
              <button onClick={handleAdopt} className="btn-primary text-sm flex items-center gap-2"><CheckCircle className="w-4 h-4" /> Adopt into My Assets</button>
            )}
            {!isReadOnly && (asset.endpointInventory || software?.items?.length > 0) && (
              <button onClick={handleClearInventory} className="btn-secondary text-sm flex items-center gap-2" title="Remove the inventory the agent reported for this machine">
                <Eraser className="w-4 h-4" /> Clear inventory
              </button>
            )}
            {canDelete && (
              <button onClick={handleDelete} className="btn-secondary text-sm flex items-center gap-2 hover:text-red-400" title="Delete permanently">
                <Trash2 className="w-4 h-4" /> Delete
              </button>
            )}
          </div>
        </div>
      </div>

      {notice && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 text-sm border-green-500/30" role="status">
          <CheckCircle className="w-4 h-4 text-green-400" /> <span className="text-dark-100">{notice}</span>
        </div>
      )}

      {match && (
        <div className="glass-card px-4 py-3 border-yellow-500/30 space-y-1.5">
          <div className="flex items-center gap-2 text-sm">
            <Link2 className="w-4 h-4 text-yellow-400" />
            <span className="text-dark-100">
              Possible duplicate of {match.others.map((o, i) => (
                <span key={o.assetId}>
                  {i > 0 && ', '}
                  <Link to={`/inventory/${o.assetId}`} className="text-eagle-400 hover:underline">{assetName(o)}</Link>
                  {o.inMyAssets && <span className="text-dark-400"> (My Assets)</span>}
                </span>
              ))}
            </span>
            <button onClick={() => setShowDuplicates(true)} className="ml-auto text-xs text-eagle-400 hover:underline">Review duplicates</button>
          </div>
          <p className="text-xs text-dark-400 pl-6">{match.reasons.join(' · ')}{match.confidence === 'safe' ? ' · safe to merge' : ' · needs review'}</p>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Identity */}
        <Section icon={Server} title="Identity" className="xl:col-span-1">
          <dl>
            <Field label="Hostname">{asset.hostname}</Field>
            <Field label="IP address"><span className="font-mono">{asset.ipAddress}</span></Field>
            <Field label="MAC address">
              {asset.macAddress
                ? <span className="font-mono lowercase">{asset.macAddress}{isLocallyAdministeredMac(asset.macAddress) && <span className="block text-[11px] text-dark-400 normal-case">Private (randomized)</span>}</span>
                : null}
            </Field>
            <Field label="Vendor">{asset.hardwareVendor}</Field>
            <Field label="Device type">
              {deviceMeta.label}
              <span className="block text-[11px] text-dark-400">{asset.deviceTypeSource === 'manual' ? 'Set by hand' : 'Inferred from scans'}</span>
            </Field>
            <Field label="Owner">{asset.owner}</Field>
            <Field label="Host key">{asset.hostKey}</Field>
            <Field label="Internet-facing">
              {asset.isInternetFacing ? 'Yes' : 'No'}
              {asset.internetFacingOverride != null && <span className="block text-[11px] text-dark-400">Confirmed by an analyst</span>}
            </Field>
            <Field label="First seen">{fmtDateTime(asset.createdAt)}</Field>
            <Field label="Last scanned">{asset.lastScanned ? fmtDateTime(asset.lastScanned) : 'Never'}</Field>
          </dl>
          {os.ai_description && (
            <p className="mt-3 text-xs text-dark-300"><span className="text-eagle-400/80 font-medium mr-1">AI:</span>{os.ai_description}</p>
          )}
        </Section>

        {/* Criticality */}
        <Section icon={ShieldAlert} title="Criticality" right={<CriticalityBadge score={asset.criticalityScore} assetId={asset.assetId} footer="computed" />}>
          {score ? (
            <>
              <p className="text-xs text-dark-400 mb-2">Computed from this asset's own facts. Each line adds to or subtracts from the score.</p>
              <ul className="space-y-1">
                {score.factors.map((f) => (
                  <li key={f} className="text-sm text-dark-100 flex items-start gap-2"><span className="text-eagle-400 mt-0.5">•</span>{f}</li>
                ))}
              </ul>
              {score.score !== asset.criticalityScore && (
                <p className="mt-3 text-xs text-amber-400">The stored score ({asset.criticalityScore}) differs from the current formula ({score.score}). Rescore to update it.</p>
              )}
            </>
          ) : <Empty>Score breakdown unavailable.</Empty>}
        </Section>

        {/* Operating system */}
        <Section icon={Cpu} title="Operating system">
          {inv || osRows.length ? (
            <dl>
              {inv && <AgentOsFields inv={inv} />}
              {osRows.length > 0 && inv && <p className="pt-3 pb-1 text-[11px] uppercase tracking-wide text-dark-500">Seen by network scans</p>}
              {osRows.map(([k, label, fmt]) => (
                <Field key={k} label={label}>{fmt ? fmt(os[k], os) : String(os[k])}</Field>
              ))}
            </dl>
          ) : <Empty>No OS details collected yet. An active scan, SNMP poll or the EagleEye agent fills this in.</Empty>}
        </Section>

        {inv && <HardwareSection inv={inv} />}
        {inv && <SecuritySection inv={inv} />}
        {inv && <PatchesSection inv={inv} />}

        {/* Services */}
        <Section icon={Network} title="Open ports & services" className="xl:col-span-2"
          right={<span className="text-xs text-dark-400">{services.length} open</span>}>
          {services.length ? (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={`${s.port}/${s.protocol}`}>
                      <td className="font-mono text-sm whitespace-nowrap">
                        {s.port}/{s.protocol}
                        {RISKY_PORTS[s.port] && <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded border bg-red-500/10 text-red-400 border-red-500/30">Risky</span>}
                      </td>
                      <td className="text-sm">{s.service || RISKY_PORTS[s.port] || '—'}</td>
                      <td className="text-sm text-dark-300">{s.product || '—'}</td>
                      <td className="text-sm text-dark-300">{s.version || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>{asset.source === 'scan_passive' ? 'Passive scans cannot see ports. Run an active scan to list services.' : 'No open ports recorded.'}</Empty>
          )}
        </Section>

        {/* Software */}
        <SoftwareSection software={software} sbom={sbom} inventoryAt={asset.inventoryCollectedAt} />

        {inv && <ListeningSection inv={inv} className="xl:col-span-2" />}
        {inv && <InterfacesSection inv={inv} />}

        {/* Alerts */}
        <Section icon={Bell} title="Open alerts" className="xl:col-span-2"
          right={alerts?.total > 0 && (
            <Link to={`/alerts?${new URLSearchParams({ asset_id: assetId, label: assetName(asset) })}`} className="text-xs text-eagle-400 hover:underline">
              View all {alerts.total}
            </Link>
          )}>
          {!alerts ? <Empty>Loading…</Empty> : alerts.items.length ? (
            <ul className="divide-y divide-dark-700/40">
              {alerts.items.map((e) => (
                <li key={e.event_id} className="py-2 flex items-center gap-3">
                  <SevBadge sev={e.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm text-white truncate">{alertLabel(e)}</div>
                    <div className="text-xs text-dark-400 truncate">{renderDetail(e)}</div>
                  </div>
                  <StatusBadge status={e.status} />
                  <span className="text-xs text-dark-400 whitespace-nowrap">{timeAgo(e.last_seen)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No open alerts for this asset.</Empty>}
        </Section>

        {/* Baseline */}
        <Section icon={Bookmark} title="Baseline">
          {baseline ? (
            <dl>
              <Field label="Captured">{fmtDateTime(baseline.captured_at)}</Field>
              <Field label="Set">{baseline.auto_set ? 'Automatically, on first scan' : baseline.captured_from === 'manual' ? 'At creation' : 'By hand'}</Field>
              <Field label="Ports">{baseline.ports_known === false ? 'Not known (passive)' : (baseline.ports?.length ? baseline.ports.join(', ') : 'None')}</Field>
              <Field label="Packages">{baseline.packages_known ? Object.keys(baseline.packages || {}).length : 'Not known yet'}</Field>
              <Field label="OS version">{baseline.os_version}</Field>
            </dl>
          ) : <Empty>No baseline yet. Drift is tracked once a baseline is set.</Empty>}
        </Section>

        {/* Relationships */}
        {!isBusinessOwner && (
          <Section icon={GitBranch} title="Relationships" className="xl:col-span-2"
            right={graph && <span className="text-xs text-dark-400">{neighbors.length} connected</span>}>
            {!graph ? <Empty>Loading…</Empty> : neighbors.length ? (
              <ul className="divide-y divide-dark-700/40">
                {neighbors.map((n) => (
                  <li key={n.asset_id} className="py-2 flex items-center gap-3">
                    <span aria-hidden="true">{(DEVICE_TYPE_META[n.device_type] ?? DEVICE_TYPE_META.unknown).icon}</span>
                    <div className="min-w-0 flex-1">
                      <Link to={`/inventory/${n.asset_id}`} className="text-sm text-white hover:text-eagle-400">{n.hostname || n.ip_address}</Link>
                      <div className="font-mono text-xs text-accent-cyan">{n.ip_address}</div>
                    </div>
                    <span className="text-xs text-dark-300">
                      {[...new Set(neighborEdges(n.asset_id).map((e) => e.relationship_type.replace(/_/g, ' ')))].join(', ')}
                    </span>
                  </li>
                ))}
              </ul>
            ) : <Empty>No relationships recorded. Relationships are inferred from scans and topology.</Empty>}
          </Section>
        )}

        {/* Address history */}
        <Section icon={History} title="Address history" className={isBusinessOwner ? 'xl:col-span-3' : ''}>
          {!addresses ? <Empty>Loading…</Empty> : addresses.length ? (
            <ul className="divide-y divide-dark-700/40">
              {addresses.map((r) => (
                <li key={r.addressId} className="py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sm text-accent-cyan">{r.ipAddress}</span>
                    {r.isCurrent
                      ? <span className="text-[11px] px-1.5 py-0.5 rounded border bg-green-500/10 text-green-400 border-green-500/30">Current</span>
                      : <span className="text-[11px] text-dark-400">Ended {new Date(r.endedAt).toLocaleDateString()}</span>}
                  </div>
                  <div className="text-xs text-dark-400 font-mono lowercase">{r.macAddress || 'no MAC'}{r.networkKey ? ` · net ${r.networkKey.slice(0, 8)}` : ''}</div>
                  <div className="text-[11px] text-dark-500">{new Date(r.firstSeen).toLocaleDateString()} – {new Date(r.lastSeen).toLocaleDateString()}</div>
                </li>
              ))}
            </ul>
          ) : <Empty>No address records.</Empty>}
        </Section>
      </div>

      {editing && (
        <EditAssetModal
          asset={asset}
          onClose={() => setEditing(false)}
          onSave={async (patch) => { await client.patch(`/assets/${assetId}`, patch); await refresh() }}
        />
      )}
      {adoptTarget && (
        <AdoptMatchModal
          asset={asset}
          matches={adoptTarget.matches}
          reasons={adoptTarget.reasons}
          onClose={() => setAdoptTarget(null)}
          onReviewDuplicates={() => { setAdoptTarget(null); setShowDuplicates(true) }}
          onAdopt={async () => {
            try { await setMembership(true); setAdoptTarget(null) } catch (err) { alert(err?.response?.data?.detail || 'Failed to add asset to My Assets') }
          }}
        />
      )}
      {showBlast && <BlastRadiusModal assetId={assetId} onClose={() => setShowBlast(false)} />}
      {showDuplicates && (
        <DuplicatesPanel
          tenantId={asset.tenantId ?? ''}
          centered
          canMerge={user?.role === 'tenant_superadmin'}
          onClose={() => setShowDuplicates(false)}
          onMerged={refresh}
        />
      )}
    </div>
  )
}
