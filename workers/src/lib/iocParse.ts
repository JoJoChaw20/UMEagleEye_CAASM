/**
 * Parsing indicators (IOCs) an analyst pastes into a threat-intel event — PURE (no DB).
 *
 * One value per line (or separated by commas/whitespace). Values copied from reports are
 * often "defanged" so nobody clicks them (hxxp://evil[.]com, 1.2.3[.]4, user[@]mail.com);
 * they are refanged first. The type is detected unless the analyst picked one, and each
 * value is normalised so the same IOC always looks the same (lower-case domains and
 * hashes, upper-case CVE IDs, no trailing dot). Tested by scripts/ti-events-demo.ts.
 */

export const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'cve'] as const
export type IocType = typeof IOC_TYPES[number]

export interface ParsedIoc { type: IocType; value: string }
export interface RejectedIoc { input: string; reason: string }

const MAX_VALUE = 512

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/
const IPV6 = /^[0-9a-f:]+$/i
const CVE = /^CVE-\d{4}-\d{4,}$/i
const HASH = /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/i   // MD5, SHA-1, SHA-256, SHA-512
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i

/** Undo common defanging: hxxp, [.], (.), {.}, [dot], [@], [at], [:]. */
export function refang(raw: string): string {
  return raw.trim()
    .replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[@\]|\(@\)|\[at\]|\(at\)/gi, '@')
    .replace(/\[:\]/g, ':')
    .replace(/^["'<(]+|["'>),;]+$/g, '')
}

function isIpv6(v: string): boolean {
  return v.includes(':') && IPV6.test(v) && (v.match(/:/g)?.length ?? 0) >= 2 && v.length <= 45
}

export function detectType(value: string): IocType | null {
  if (CVE.test(value)) return 'cve'
  if (IPV4.test(value) || isIpv6(value)) return 'ip'
  if (URL_SCHEME.test(value)) return 'url'
  if (HASH.test(value)) return 'hash'
  if (EMAIL.test(value)) return 'email'
  if (DOMAIN.test(value)) return 'domain'
  return null
}

/** The canonical form of a value of a given type, or null when it is not one. */
export function normalise(type: IocType, raw: string): string | null {
  const v = refang(raw)
  if (!v || v.length > MAX_VALUE) return null
  switch (type) {
    case 'cve':    return CVE.test(v) ? v.toUpperCase() : null
    case 'ip':     return IPV4.test(v) ? v : isIpv6(v) ? v.toLowerCase() : null
    case 'hash':   return HASH.test(v) ? v.toLowerCase() : null
    case 'email':  return EMAIL.test(v) ? v.toLowerCase() : null
    case 'domain': {
      const d = v.toLowerCase().replace(/\.$/, '')
      return DOMAIN.test(d) ? d : null
    }
    case 'url': {
      if (!URL_SCHEME.test(v)) return null
      try {
        const u = new URL(v)
        u.hostname = u.hostname.toLowerCase()
        return u.toString()
      } catch {
        return null
      }
    }
  }
}

/** The host a URL or email points at (for the warninglist), else the value itself. */
export function hostOf(type: IocType, value: string): string {
  if (type === 'url') {
    try { return new URL(value).hostname } catch { return value }
  }
  if (type === 'email') return value.slice(value.lastIndexOf('@') + 1)
  return value
}

/**
 * Split pasted text into IOCs. `forced` applies one type to every value (the analyst
 * picked it); otherwise each value's type is detected. Duplicates are dropped.
 */
export function parseIocs(text: string, forced?: IocType): { parsed: ParsedIoc[]; rejected: RejectedIoc[] } {
  const parsed: ParsedIoc[] = []
  const rejected: RejectedIoc[] = []
  const seen = new Set<string>()
  for (const token of text.split(/[\s,;]+/)) {
    const input = token.trim()
    if (!input) continue
    const candidate = refang(input)
    const type = forced ?? detectType(candidate)
    if (!type) {
      rejected.push({ input, reason: 'not an IP, domain, URL, hash, email or CVE ID' })
      continue
    }
    const value = normalise(type, candidate)
    if (!value) {
      rejected.push({ input, reason: `not a valid ${type}` })
      continue
    }
    const key = `${type}:${value}`
    if (seen.has(key)) continue
    seen.add(key)
    parsed.push({ type, value })
  }
  return { parsed, rejected }
}
