// What a network agent found about an asset (agent-gui/eagleeye/netagent, stored by
// workers/src/routes/network.ts): where the device is plugged in (assets.network_location),
// and for a router or switch it polled, its ports, VLANs and cables (assets.network_device,
// GET /network/links).
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Router } from 'lucide-react'
import client from '../../api/client'
import { Section, Field, Empty, fmtDateTime } from './DetailParts'

/** "SW2 Gi0/3 · VLAN 1" for the Identity section, or null when no network agent placed it. */
export function NetworkLocationField({ location }) {
  if (!location) return null
  const sw = location.switch
    ? (location.switch_asset_id
      ? <Link to={`/inventory/${location.switch_asset_id}`} className="text-eagle-400 hover:underline">{location.switch}</Link>
      : location.switch)
    : null
  return (
    <Field label="Plugged into">
      {sw ? <span>{sw} <span className="font-mono">{location.port}</span></span> : <span className="text-dark-400">Switch port not known</span>}
      {location.vlan != null && <span className="block text-[11px] text-dark-400">VLAN {location.vlan}{location.router ? ` · routed by ${location.router} ${location.interface ?? ''}` : ''}</span>}
      {location.ambiguous && <span className="block text-[11px] text-yellow-400">Seen on more than one switch's edge port (an unmanaged switch in between?)</span>}
      <span className="block text-[11px] text-dark-500">Network agent, {fmtDateTime(location.seen_at)}</span>
    </Field>
  )
}

const uptime = (s) => {
  if (s == null) return null
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600)
  return d ? `${d} d ${h} h` : `${h} h ${Math.floor((s % 3600) / 60)} min`
}

/** A router or switch the network agent polled: its facts, ports and cables. */
export function NetworkDeviceSection({ assetId, device }) {
  const [links, setLinks] = useState(null)
  useEffect(() => {
    if (!device) return
    client.get('/network/links')
      .then(({ data }) => setLinks((data.links ?? []).filter((l) => l.a.asset_id === assetId || l.b.asset_id === assetId)))
      .catch(() => setLinks([]))
  }, [assetId, device])
  if (!device) return null

  const ports = (device.interfaces ?? []).filter((i) => i.name && !/^(Nu|Null)/.test(i.name))
  const neighbour = new Map()
  for (const l of links ?? []) {
    const [mine, other] = l.a.asset_id === assetId ? [l.a, l.b] : [l.b, l.a]
    neighbour.set(mine.port, other)
  }
  const vlans = (device.vlans ?? []).filter((v) => v < 1002 || v > 1005)

  return (
    <Section icon={Router} title="Network device" className="xl:col-span-3"
      right={<span className="text-xs text-dark-400">read over SNMP {fmtDateTime(device.seen_at)}</span>}>
      <div className="grid md:grid-cols-3 gap-6">
        <dl>
          <Field label="Name">{device.name}</Field>
          <Field label="System">{[device.os, device.version].filter(Boolean).join(' ') || null}</Field>
          <Field label="Vendor">{device.vendor}</Field>
          <Field label="Up for">{uptime(device.uptime_seconds)}</Field>
          <Field label="VLANs">{vlans.length ? vlans.join(', ') : null}</Field>
          <Field label="Found">{device.found_via === 'seed' ? 'A seed of the network agent' : device.found_via}</Field>
          {(device.notes ?? []).map((n) => <p key={n} className="text-[11px] text-yellow-400/90 pt-2">{n}</p>)}
        </dl>
        <div className="md:col-span-2 overflow-x-auto">
          {ports.length ? (
            <table className="data-table">
              <thead><tr><th>Port</th><th>Description</th><th>State</th><th>VLAN</th><th>Connected to</th></tr></thead>
              <tbody>
                {ports.map((p) => {
                  const other = neighbour.get(p.name)
                  return (
                    <tr key={p.index}>
                      <td className="font-mono text-sm">{p.name}</td>
                      <td className="text-sm text-dark-300">{p.alias || '—'}</td>
                      <td className={`text-xs ${p.up ? 'text-green-400' : 'text-dark-500'}`}>{p.up == null ? '—' : p.up ? 'up' : 'down'}</td>
                      <td className="text-xs">{p.trunk ? 'trunk' : (p.vlan ?? '—')}</td>
                      <td className="text-sm">
                        {other ? (
                          other.asset_id
                            ? <Link to={`/inventory/${other.asset_id}`} className="text-eagle-400 hover:underline">{other.device} <span className="font-mono">{other.port}</span></Link>
                            : <span>{other.device} <span className="font-mono">{other.port}</span></span>
                        ) : <span className="text-dark-500">—</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          ) : <Empty>No ports reported.</Empty>}
        </div>
      </div>
    </Section>
  )
}
