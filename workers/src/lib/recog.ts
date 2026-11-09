// Product identification from banners with Rapid7 Recog's fingerprints (BSD-2-Clause; built into
// recog/fingerprints.json by scripts/recog/build-recog.mjs, which keeps only the patterns that still
// pass Recog's own examples in JavaScript). One database per kind of banner.
import bundle from './recog/fingerprints.json'

export type RecogDb = 'ssh' | 'http_server' | 'ftp' | 'smtp' | 'telnet' | 'snmp'

interface Fingerprint { p: string; f: string; a: [string, number, string | null][] }
interface Compiled { re: RegExp; a: Fingerprint['a'] }

const compiled = new Map<RecogDb, Compiled[]>()
function db(name: RecogDb): Compiled[] {
  let list = compiled.get(name)
  if (!list) {
    const raw = ((bundle as unknown as { dbs: Record<string, Fingerprint[]> }).dbs[name] ?? [])
    list = raw.flatMap((fp) => {
      try { return [{ re: new RegExp(fp.p, fp.f), a: fp.a }] } catch { return [] }
    })
    compiled.set(name, list)
  }
  return list
}

/** Recog's params for the first fingerprint of `name` that matches `text` (values interpolated:
 *  "cpe:/a:openbsd:openssh:{service.version}"), or null. */
export function recognize(name: RecogDb, text: string | null | undefined): Record<string, string> | null {
  if (!text) return null
  const input = text.slice(0, 1024)
  for (const fp of db(name)) {
    const m = fp.re.exec(input)
    if (!m) continue
    const out: Record<string, string> = {}
    for (const [key, pos, value] of fp.a) {
      const v = pos > 0 ? m[pos] : value
      if (v != null && v !== '') out[key] = v
    }
    for (const [key, v] of Object.entries(out)) {
      out[key] = v.replace(/\{([\w.]+)\}/g, (_, k: string) => out[k] ?? '-')
    }
    return out
  }
  return null
}

/** A Recog CPE ("cpe:/a:vendor:product:version", the 2.2 URI form) as a CPE 2.3 formatted string,
 *  with `version` (the cleaned one) in place of the URI's when given; null without a usable version
 *  (NVD would then list every version's CVEs). CPE 2.3 escapes everything but letters, digits and
 *  . _ - with a backslash: NVD answers 404 to Cisco's "15.9(3)M12" and finds "15.9\(3\)m12". */
export function cpe23(uri: string | undefined, version?: string | null): string | null {
  if (!uri) return null
  const m = /^cpe:\/([aoh]):([^:]+):([^:]+)(?::([^:]*))?/.exec(uri)
  if (!m) return null
  const [, part, vendor, product, fromUri] = m
  const v = version === undefined ? fromUri : version
  if (!v || v === '-' || /[{}\s]/.test(v)) return null
  const esc = (s: string) => s.toLowerCase().replace(/[^a-z0-9._-]/g, (c) => `\\${c}`)
  return `cpe:2.3:${part}:${esc(vendor!)}:${esc(product!)}:${esc(v)}:*:*:*:*:*:*:*`
}
