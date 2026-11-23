// IP ranges (CIDR) for the public-address blocklist check (D4): Spamhaus DROP's JSON lines, and whether
// an address falls in a range, for IPv4 and IPv6. Pure.

export interface DropRange { cidr: string; sblid: string }
export interface DropList { ranges: DropRange[]; timestamp: number | null; copyright: string | null }

/** Spamhaus DROP (drop_v4.json / drop_v6.json): one JSON object per line, {"cidr","sblid","rir"}, and a
 *  last {"type":"metadata", "timestamp", "copyright", ...} line. Malformed lines are skipped. */
export function parseDrop(text: string): DropList {
  const out: DropList = { ranges: [], timestamp: null, copyright: null }
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (!t) continue
    let row: Record<string, unknown>
    try {
      row = JSON.parse(t) as Record<string, unknown>
    } catch {
      continue
    }
    if (row.type === 'metadata') {
      if (typeof row.timestamp === 'number') out.timestamp = row.timestamp
      if (typeof row.copyright === 'string') out.copyright = row.copyright.slice(0, 120)
      continue
    }
    if (typeof row.cidr === 'string' && parseCidr(row.cidr)) {
      out.ranges.push({ cidr: row.cidr, sblid: typeof row.sblid === 'string' ? row.sblid.slice(0, 20) : '' })
    }
  }
  return out
}

interface Cidr { v6: boolean; base: bigint; bits: number }

function v4ToBig(ip: string): bigint | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0n
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null
    n = (n << 8n) | BigInt(Number(p))
  }
  return n
}

function v6ToBig(ip: string): bigint | null {
  let s = ip.toLowerCase()
  const tail = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s)          // ::ffff:1.2.3.4
  if (tail) {
    const v4 = v4ToBig(tail[1]!)
    if (v4 === null) return null
    s = `${s.slice(0, -tail[1]!.length)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - rest.length
  if ((halves.length === 2 && missing < 1) || (halves.length === 1 && missing !== 0)) return null
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest]
  let n = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    n = (n << 16n) | BigInt(parseInt(g, 16))
  }
  return n
}

function parseCidr(cidr: string): Cidr | null {
  const [net, len] = cidr.trim().split('/')
  const bits = Number(len)
  if (!net || !Number.isInteger(bits)) return null
  const v6 = net.includes(':')
  if (bits < 0 || bits > (v6 ? 128 : 32)) return null
  const base = v6 ? v6ToBig(net) : v4ToBig(net)
  return base === null ? null : { v6, base, bits }
}

/** Whether `ip` is inside `cidr` (same family only). */
export function inCidr(ip: string, cidr: string): boolean {
  const c = parseCidr(cidr)
  if (!c) return false
  const v6 = ip.includes(':')
  if (v6 !== c.v6) return false
  const n = v6 ? v6ToBig(ip) : v4ToBig(ip)
  if (n === null) return false
  const width = v6 ? 128n : 32n
  const shift = width - BigInt(c.bits)
  return (n >> shift) === (c.base >> shift)
}

/** The ranges `ip` falls in. */
export function rangesContaining(ip: string, ranges: readonly DropRange[]): DropRange[] {
  return ranges.filter((r) => inCidr(ip, r.cidr))
}
