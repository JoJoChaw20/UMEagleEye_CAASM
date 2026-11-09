// Small parts the Agents page and the agent panel share.
import { useState } from 'react'
import { Check, Copy, Network, Smartphone } from 'lucide-react'
import { formatSeen } from '../../utils/time'

const STATUS_META = {
  online:   { label: 'Online',   cls: 'bg-green-500/20 text-green-400 border-green-500/30',   dot: 'bg-green-400 animate-pulse' },
  degraded: { label: 'Late',     cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400' },
  offline:  { label: 'Offline',  cls: 'bg-red-500/20 text-red-400 border-red-500/30',          dot: 'bg-red-400' },
  retired:  { label: 'Retired',  cls: 'bg-dark-600/40 text-dark-400 border-dark-500/30',       dot: 'bg-dark-500' },
}

export function StatusBadge({ status }) {
  const m = STATUS_META[status] ?? STATUS_META.offline
  return (
    <span
      className={`text-xs px-2 py-0.5 rounded-md border font-medium inline-flex items-center gap-1.5 ${m.cls}`}
      title={status === 'degraded' ? 'No heartbeat for 2 to 10 minutes' : undefined}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  )
}

export function MobileBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border border-violet-500/30 bg-violet-500/10 text-violet-300"
      title="The EagleEye app on a phone or tablet: it reports that device's own inventory and security settings">
      <Smartphone className="w-3 h-3" /> Phone
    </span>
  )
}

export function NetworkBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border border-accent-cyan/30 bg-accent-cyan/10 text-accent-cyan"
      title="Reads the routers and switches over SNMP instead of looking after one computer">
      <Network className="w-3 h-3" /> Network agent
    </span>
  )
}

export function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const copy = async (e) => {
    e.stopPropagation()
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch { /* select by hand */ }
  }
  return (
    <button type="button" onClick={copy} className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors flex-shrink-0" title={label} aria-label={label}>
      {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

export function Seen({ value, nullText }) {
  const s = formatSeen(value, { nullText })
  return <span title={s.title || ''} className={s.stale ? 'text-amber-400' : 'text-dark-300'}>{s.text}</span>
}
