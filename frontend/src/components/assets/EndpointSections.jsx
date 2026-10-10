// Asset detail sections fed by the endpoint inventory an EagleEye agent reports from
// the machine itself (assets.endpointInventory + GET /assets/:id/software).
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { HardDrive, ShieldCheck, Wrench, Radio, Package, Cable, CheckCircle2, XCircle, AlertTriangle, HelpCircle, Search } from 'lucide-react'
import { Section, Field, Empty, fmtDate, fmtDateTime, fmtBytes } from './DetailParts'
import { RISKY_PORTS } from '../common/alertMeta'

const STALE_PATCH_DAYS = 45

const FORM_FACTOR = { laptop: 'Laptop', desktop: 'Desktop', server: 'Server', virtual: 'Virtual machine', unknown: 'Unknown' }
const ROLE = { workstation: 'Workstation', server: 'Server', domain_controller: 'Domain controller' }

// ── Hardware ──
export function HardwareSection({ inv }) {
  const hw = inv.hardware || {}
  const cpu = (hw.cpus || [])[0]
  const disks = hw.disks || []
  return (
    <Section icon={HardDrive} title="Hardware">
      <dl>
        <Field label="Manufacturer">{hw.manufacturer}</Field>
        <Field label="Model">{hw.model}</Field>
        <Field label="Form factor">{FORM_FACTOR[hw.form_factor] ?? hw.form_factor}</Field>
        <Field label="Serial number">{inv.identity?.serial_number}</Field>
        <Field label="Processor">
          {cpu ? <>{cpu.name}<span className="block text-[11px] text-dark-400">{cpu.cores} cores, {cpu.threads} threads{(hw.cpus || []).length > 1 ? ` × ${hw.cpus.length}` : ''}</span></> : null}
        </Field>
        <Field label="Memory">{fmtBytes(hw.memory_bytes)}</Field>
        <Field label="Storage">
          {disks.length ? disks.map((d, i) => (
            <span key={i} className="block">{fmtBytes(d.size_bytes)} {d.media && d.media !== 'Unspecified' ? d.media : ''} <span className="text-[11px] text-dark-400">{d.model}</span></span>
          )) : null}
        </Field>
        <Field label="BIOS">{hw.bios ? `${hw.bios.vendor ?? ''} ${hw.bios.version ?? ''}`.trim() || null : null}</Field>
      </dl>
    </Section>
  )
}

// ── OS (agent view) ──
export function AgentOsFields({ inv }) {
  const os = inv.os || {}
  const id = inv.identity || {}
  return (
    <>
      <Field label="Operating system">
        {os.name}{os.display_version ? ` ${os.display_version}` : ''}
        {os.build && <span className="block text-[11px] text-dark-400">Build {os.build}{os.architecture ? ` · ${os.architecture}` : ''}</span>}
      </Field>
      <Field label="Role">{ROLE[os.role] ?? os.role}</Field>
      <Field label="Domain">{id.part_of_domain ? id.domain : (id.workgroup ? `Workgroup ${id.workgroup}` : null)}</Field>
      <Field label="Installed">{os.install_date ? fmtDate(os.install_date) : null}</Field>
      <Field label="Last boot">{os.last_boot ? fmtDateTime(os.last_boot) : null}</Field>
    </>
  )
}

// ── Patches ──
export function PatchesSection({ inv }) {
  const p = inv.patches || {}
  const stale = p.days_since_last_patch != null && p.days_since_last_patch > STALE_PATCH_DAYS
  return (
    <Section icon={Wrench} title="Patches">
      <dl>
        <Field label="Last update">
          {p.last_patch_id
            ? <span className={stale ? 'text-amber-400' : ''}>{p.last_patch_id}
                <span className="block text-[11px] text-dark-400">{fmtDate(p.last_patch_date)} · {p.days_since_last_patch} day{p.days_since_last_patch === 1 ? '' : 's'} ago</span>
              </span>
            : null}
        </Field>
        <Field label="Updates installed">{p.hotfix_count ?? null}</Field>
        <Field label="Restart pending">
          {p.pending_reboot == null ? null : p.pending_reboot ? <span className="text-amber-400">Yes</span> : 'No'}
        </Field>
      </dl>
      {stale && <p className="mt-3 text-xs text-amber-400">No update in over {STALE_PATCH_DAYS} days. Check Windows Update on this machine.</p>}
    </Section>
  )
}

// ── Security posture ──
// Each check: good | bad | warn | unknown | admin (needs Administrator to read).
function postureChecks(inv) {
  const s = inv.security || {}
  const unavailable = new Set(inv.unavailable || [])
  const av = s.antivirus || []
  const activeAv = av.filter((a) => a.enabled)
  const checks = []

  checks.push({
    label: 'Firewall',
    state: s.firewall_all_enabled == null ? 'unknown' : s.firewall_all_enabled ? 'good' : 'bad',
    detail: (s.firewall || []).map((f) => `${f.profile} ${f.enabled ? 'on' : 'off'}`).join(', ') || null,
  })
  checks.push({
    label: 'Antivirus',
    state: !av.length ? 'unknown' : !activeAv.length ? 'bad' : activeAv.every((a) => a.up_to_date) ? 'good' : 'warn',
    detail: av.length ? av.map((a) => `${a.name}${a.enabled ? '' : ' (off)'}${a.enabled && a.up_to_date === false ? ' (out of date)' : ''}`).join(', ') : null,
  })
  const bl = s.bitlocker
  checks.push({
    label: 'Disk encryption',
    state: unavailable.has('bitlocker') ? 'admin' : !Array.isArray(bl) || !bl.length ? 'unknown'
      : bl.every((v) => String(v.protection).toLowerCase() === 'on') ? 'good' : 'bad',
    detail: Array.isArray(bl) ? bl.map((v) => `${v.drive} ${String(v.protection).toLowerCase()}`).join(', ') : null,
  })
  checks.push({ label: 'Secure Boot', state: s.secure_boot == null ? 'unknown' : s.secure_boot ? 'good' : 'warn' })
  checks.push({
    label: 'TPM', state: unavailable.has('tpm') ? 'admin' : !s.tpm ? 'unknown' : s.tpm.present && s.tpm.ready ? 'good' : 'warn',
    detail: s.tpm ? `${s.tpm.present ? 'present' : 'absent'}${s.tpm.present ? `, ${s.tpm.ready ? 'ready' : 'not ready'}` : ''}` : null,
  })
  checks.push({ label: 'User Account Control', state: s.uac_enabled == null ? 'unknown' : s.uac_enabled ? 'good' : 'bad' })
  checks.push({
    label: 'Remote Desktop', state: s.rdp_enabled == null ? 'unknown' : s.rdp_enabled ? 'warn' : 'good',
    detail: s.rdp_enabled ? 'Enabled' : s.rdp_enabled === false ? 'Disabled' : null,
  })
  checks.push({
    label: 'SMBv1', state: unavailable.has('smb1') ? 'admin' : s.smb1_enabled == null ? 'unknown' : s.smb1_enabled ? 'bad' : 'good',
    detail: s.smb1_enabled ? 'Enabled (obsolete, exploitable)' : s.smb1_enabled === false ? 'Disabled' : null,
  })
  // Names are only reported when the agent was told to include them; the count always is.
  const adminNames = (s.local_admins || []).map((a) => a.name)
  const adminCount = s.local_admin_count ?? (adminNames.length || null)
  checks.push({
    label: 'Local administrators', state: adminCount == null ? 'unknown' : adminCount > 3 ? 'warn' : 'good',
    detail: adminCount == null ? null
      : adminNames.length ? adminNames.join(', ')
        : `${adminCount} account${adminCount === 1 ? '' : 's'} (names not collected)`,
  })
  return checks
}

const STATE_META = {
  good:    { icon: CheckCircle2,  cls: 'text-green-400', text: 'OK' },
  bad:     { icon: XCircle,       cls: 'text-red-400',   text: 'At risk' },
  warn:    { icon: AlertTriangle, cls: 'text-amber-400', text: 'Review' },
  unknown: { icon: HelpCircle,    cls: 'text-dark-400',  text: 'Unknown' },
  admin:   { icon: HelpCircle,    cls: 'text-dark-400',  text: 'Needs Administrator' },
}

export function SecuritySection({ inv }) {
  const checks = postureChecks(inv)
  const issues = checks.filter((c) => c.state === 'bad' || c.state === 'warn').length
  const known = checks.some((c) => c.state === 'good' || c.state === 'bad' || c.state === 'warn')
  const summary = issues ? { text: `${issues} to review`, cls: 'text-amber-400' }
    : known ? { text: 'No issues found', cls: 'text-green-400' }
      : { text: 'Not reported', cls: 'text-dark-400' }
  return (
    <Section icon={ShieldCheck} title="Security posture"
      right={<span className={`text-xs ${summary.cls}`}>{summary.text}</span>}>
      <ul className="divide-y divide-dark-700/40">
        {checks.map((c) => {
          const m = STATE_META[c.state]
          const Icon = m.icon
          return (
            <li key={c.label} className="py-1.5 flex items-start gap-2">
              <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${m.cls}`} aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm text-dark-100">{c.label}</span>
                  <span className={`text-[11px] ${m.cls}`}>{m.text}</span>
                </div>
                {c.detail && <p className="text-[11px] text-dark-400 break-words">{c.detail}</p>}
              </div>
            </li>
          )
        })}
      </ul>
      {(inv.unavailable || []).length > 0 && (
        <p className="mt-3 text-[11px] text-dark-400">Run the agent as Administrator to read the checks marked "Needs Administrator".</p>
      )}
    </Section>
  )
}

// ── Listening services (from the machine itself) ──
const LOCAL_ONLY = /^(127\.|::1$)/

export function ListeningSection({ inv, className = '' }) {
  const [showAll, setShowAll] = useState(false)
  const all = inv.network?.listening || []
  // Ports only bound to loopback are not reachable from the network.
  const exposed = all.filter((l) => !LOCAL_ONLY.test(l.address || ''))
  const rows = showAll ? all : exposed
  return (
    <Section icon={Radio} title="Listening on this machine" className={className}
      right={
        <button onClick={() => setShowAll((v) => !v)} className="text-xs text-eagle-400 hover:underline">
          {showAll ? `Show network-reachable only (${exposed.length})` : `Show all ${all.length}, including local-only`}
        </button>
      }>
      {rows.length ? (
        <div className="overflow-x-auto max-h-80 overflow-y-auto">
          <table className="data-table">
            <thead><tr><th>Port</th><th>Address</th><th>Process</th><th>PID</th></tr></thead>
            <tbody>
              {rows.map((l) => (
                <tr key={`${l.protocol}/${l.address}/${l.port}`}>
                  <td className="font-mono text-sm whitespace-nowrap">
                    {l.port}/{l.protocol}
                    {l.protocol === 'tcp' && RISKY_PORTS[l.port] && <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded border bg-red-500/10 text-red-400 border-red-500/30">{RISKY_PORTS[l.port]}</span>}
                  </td>
                  <td className="font-mono text-xs text-dark-300">{l.address}</td>
                  <td className="text-sm">
                    {l.process || (l.local_only ? <span className="text-[11px] text-dark-500" title="Not reachable from the network, so the program is not collected">local only</span> : '—')}
                  </td>
                  <td className="text-xs text-dark-400">{l.pid ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <Empty>No network-reachable listening ports.</Empty>}
    </Section>
  )
}

// ── Network interfaces ──
export function InterfacesSection({ inv }) {
  const nics = inv.network?.interfaces || []
  const physical = nics.filter((n) => n.physical)
  const others = nics.length - physical.length
  return (
    <Section icon={Cable} title="Network interfaces" right={others > 0 && <span className="text-xs text-dark-400">+{others} virtual/other</span>}>
      {physical.length ? (
        <ul className="divide-y divide-dark-700/40">
          {physical.map((n) => (
            <li key={`${n.name}-${n.mac}`} className="py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-dark-100">{n.name}</span>
                <span className={`text-[11px] ${n.status === 'Up' ? 'text-green-400' : 'text-dark-400'}`}>{n.status}</span>
              </div>
              <div className="font-mono text-xs text-dark-300 lowercase">{n.mac}</div>
              {(n.ipv4 || []).length > 0 && <div className="font-mono text-xs text-accent-cyan">{n.ipv4.join(', ')}</div>}
              {n.description && <div className="text-[11px] text-dark-500">{n.description}</div>}
            </li>
          ))}
        </ul>
      ) : <Empty>No physical network interfaces reported.</Empty>}
    </Section>
  )
}

// ── Software (agent inventory, with the SBOM summary as fallback) ──
export function SoftwareSection({ software, sbom, inventoryAt, className = '' }) {
  const [q, setQ] = useState('')
  const items = software?.items || []
  const filtered = useMemo(() => {
    const term = q.trim().toLowerCase()
    if (!term) return items
    return items.filter((s) => `${s.name} ${s.publisher || ''} ${s.version || ''}`.toLowerCase().includes(term))
  }, [items, q])

  if (software === undefined) return <Section icon={Package} title="Installed software" className={className}><Empty>Loading…</Empty></Section>

  if (!items.length) {
    return (
      <Section icon={Package} title="Installed software" className={className}>
        {sbom ? (
          <dl>
            <Field label="SBOM packages">{sbom.component_count ?? '—'}</Field>
            <Field label="Collected">{fmtDateTime(sbom.generated_at)}</Field>
            <Field label="Tool">{sbom.tool_used}</Field>
            <div className="pt-2"><Link to="/sbom" className="text-xs text-eagle-400 hover:underline">Open in SBOM</Link></div>
          </dl>
        ) : <Empty>No software reported. Install the EagleEye agent on this machine to list its software.</Empty>}
      </Section>
    )
  }

  return (
    <Section icon={Package} title="Installed software" className={className}
      right={<span className="text-xs text-dark-400">{items.length} application{items.length === 1 ? '' : 's'}{inventoryAt ? ` · ${fmtDate(inventoryAt)}` : ''}</span>}>
      <div className="relative mb-3">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
        <input type="text" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name, publisher or version"
          className="input-field pl-10 text-sm w-full" aria-label="Filter installed software" />
      </div>
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Installed</th></tr></thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.softwareId}>
                <td className="text-sm text-dark-100">{s.name}{s.scope === 'user' && <span className="ml-1.5 text-[10px] text-dark-400">(user)</span>}</td>
                <td className="font-mono text-xs text-dark-300">{s.version || '—'}</td>
                <td className="text-sm text-dark-300">{s.publisher || '—'}</td>
                <td className="text-xs text-dark-400 whitespace-nowrap">{s.installDate || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <Empty>No software matches “{q}”.</Empty>}
      </div>
    </Section>
  )
}
