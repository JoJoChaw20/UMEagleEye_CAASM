/**
 * Warninglist (after MISP's warninglists) — PURE (no DB).
 *
 * Values that appear in threat reports but must never raise an alert: public DNS
 * resolvers, private and special-use address ranges, and the big platforms everyone
 * talks to (a phishing page on a cloud host does not make the cloud provider malicious).
 * Such an attribute is kept in its event, marked with the list's name, and ignored by
 * matching. Kept small and in code on purpose: it changes rarely and needs no table.
 * Tested by scripts/ti-events-demo.ts.
 */
import { hostOf, type IocType } from './iocParse'

const PUBLIC_DNS = new Set([
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
  '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6', '94.140.14.14', '94.140.15.15',
  '2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111', '2606:4700:4700::1001',
])

// [network, prefix length] — RFC 1918, loopback, link-local, CGNAT, multicast, reserved
const SPECIAL_V4: Array<[string, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]

// Matched as the domain itself or any subdomain of it.
const WELL_KNOWN_DOMAINS = [
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com',
  'microsoft.com', 'windows.com', 'windowsupdate.com', 'office.com', 'office365.com', 'live.com',
  'outlook.com', 'azure.com', 'azureedge.net', 'msftconnecttest.com', 'bing.com',
  'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com', 'cloudfront.net',
  'cloudflare.com', 'akamai.net', 'akamaiedge.net', 'akamaized.net', 'fastly.net',
  'github.com', 'githubusercontent.com', 'facebook.com', 'whatsapp.net',
  'localhost', 'example.com', 'example.net', 'example.org',
]

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const v = Number(p)
    if (!Number.isInteger(v) || v < 0 || v > 255) return null
    n = n * 256 + v
  }
  return n
}

function inSpecialRange(ip: string): boolean {
  const n = ipv4ToInt(ip)
  if (n === null) {
    const v = ip.toLowerCase()
    return v === '::1' || v.startsWith('fe80:') || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('ff')
  }
  return SPECIAL_V4.some(([net, bits]) => {
    const base = ipv4ToInt(net)!
    const size = 2 ** (32 - bits)
    return n >= base && n < base + size
  })
}

/** The warninglist a value is on ('public-dns', 'special-ip', 'well-known-domain'), or null. */
export function warninglistOf(type: IocType, value: string): string | null {
  if (type === 'ip') {
    if (PUBLIC_DNS.has(value.toLowerCase())) return 'public-dns'
    if (inSpecialRange(value)) return 'special-ip'
    return null
  }
  if (type === 'domain' || type === 'url' || type === 'email') {
    const host = hostOf(type, value).toLowerCase()
    if (PUBLIC_DNS.has(host)) return 'public-dns'
    if (/^[\d.]+$/.test(host) && inSpecialRange(host)) return 'special-ip'
    if (WELL_KNOWN_DOMAINS.some(d => host === d || host.endsWith(`.${d}`))) return 'well-known-domain'
  }
  return null
}

export const WARNINGLIST_LABELS: Record<string, string> = {
  'public-dns': 'Public DNS resolver',
  'special-ip': 'Private or special-use address',
  'well-known-domain': 'Well-known platform domain',
}
