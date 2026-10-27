/**
 * Windows patch level: is a machine's Windows build missing fixes Microsoft has released?
 *
 * The reference data comes from Microsoft's Security Update Guide (MSRC CVRF), turned into
 * index.json by scripts/msrc/build-msrc.mjs and uploaded to R2. Each Windows version lists,
 * per Patch Tuesday, the builds that fix that month's CVEs. Updates are cumulative, so a
 * machine is missing every fix whose build is newer than its own (os.build + os.ubr).
 *
 * The answer is one alert per machine (services/windowsPatch.ts), not one per CVE: one
 * update fixes them all. Pure; tested by scripts/windows-patch-demo.ts.
 */

export interface MsrcBuild {
  fixed_build: string   // "10.0.26200.9711"
  kb: string | null
  cves: number
  critical: number
  exploited: number
}
export interface MsrcProduct {
  server: boolean
  core: boolean
  arch: 'x64' | 'arm64' | 'x86' | null
  /** Builds the version's fixes are released for; versions serviced together share them
   *  (Windows 11 24H2 and 25H2 both list 26100 and 26200) */
  builds: number[]
  months: Record<string, MsrcBuild[]>
}
export interface MsrcIndex {
  generated: string
  months: { id: string; released: string; revised: string }[]
  products: Record<string, MsrcProduct>
}

/** Fixes released less than this long ago are not "missing" yet: Windows Update needs a few days. */
export const PATCH_GRACE_DAYS = 7
/** A version with no fixes in this many monthly releases is out of support. Supported versions
 *  do skip a month now and then (Windows 11 26H1 had none in Dec 2025 and Jan 2026). */
export const UNSUPPORTED_AFTER_MONTHS = 3

export type PatchStatus = 'current' | 'behind' | 'unsupported' | 'unknown'
export interface MissingMonth {
  month: string
  released: string
  fixed_build: string
  kb: string | null
  cves: number
  critical: number
  exploited: number
}
export interface PatchAssessment {
  status: PatchStatus
  /** MSRC product name, e.g. "Windows 11 Version 25H2 for x64-based Systems" */
  product: string | null
  /** The machine's build, "10.0.26200.9445" */
  build: string | null
  missing: MissingMonth[]
  cves: number
  critical: number
  exploited: number
  /** The newest build Microsoft has released for this version, and its KB */
  latest: { fixed_build: string; kb: string | null } | null
  reason: string | null
}

type Rec = Record<string, unknown>
const num = (v: unknown): number | null => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN
  return Number.isFinite(n) ? n : null
}

/** The fields of an agent's inventory os block this needs. */
export interface WindowsOs {
  build: number
  ubr: number
  arch: 'x64' | 'arm64' | 'x86' | null
  server: boolean
  /** "25H2"; tells apart versions that share builds */
  displayVersion: string | null
}

/** Windows os block of an inventory, or null for other platforms or missing build numbers. */
export function windowsOs(inventory: unknown): WindowsOs | null {
  const inv = (inventory && typeof inventory === 'object' ? inventory : {}) as Rec
  if (String(inv['platform'] ?? '').toLowerCase() !== 'windows') return null
  const os = (inv['os'] && typeof inv['os'] === 'object' ? inv['os'] : {}) as Rec
  const build = num(os['build'])
  const ubr = num(os['ubr'])
  if (build == null || ubr == null) return null
  // Win32_OperatingSystem.OSArchitecture: "64-bit", "32-bit", "ARM 64-bit Processor"
  const a = String(os['architecture'] ?? '').toLowerCase()
  const arch = a.includes('arm') ? 'arm64' : a.includes('64') ? 'x64' : a.includes('32') ? 'x86' : null
  // ProductType: 1 workstation, 2 domain controller, 3 server
  const pt = num(os['product_type'])
  const dv = typeof os['display_version'] === 'string' ? os['display_version'].trim() : ''
  return { build, ubr, arch, server: pt != null && pt !== 1, displayVersion: dv || null }
}

const parseBuild = (s: string): [number, number] | null => {
  const m = /^10\.0\.(\d+)\.(\d+)$/.exec(s)
  return m ? [Number(m[1]), Number(m[2])] : null
}

/** The MSRC product a machine runs. Server Core shares the full installation's builds;
 *  among versions sharing a build, the one named like the machine's display version wins. */
export function productFor(os: WindowsOs, index: MsrcIndex): string | null {
  const names = Object.keys(index.products).filter(n => {
    const p = index.products[n]!
    return p.builds.includes(os.build) && p.server === os.server && !p.core && (os.arch == null || p.arch === os.arch)
  }).sort()
  const dv = os.displayVersion?.toLowerCase()
  return (dv && names.find(n => n.toLowerCase().includes(`version ${dv}`))) || names[0] || null
}

export function assessPatch(os: WindowsOs | null, index: MsrcIndex | null, now = new Date()): PatchAssessment {
  const empty = (status: PatchStatus, reason: string | null, product: string | null = null): PatchAssessment => ({
    status, product, build: os ? `10.0.${os.build}.${os.ubr}` : null,
    missing: [], cves: 0, critical: 0, exploited: 0, latest: null, reason,
  })
  if (!os) return empty('unknown', 'not a Windows inventory with a build number')
  if (!index || !index.months.length) return empty('unknown', 'no Windows patch data loaded')

  const product = productFor(os, index)
  if (!product) {
    // Older than every version Microsoft still fixes: out of support. Newer (Insider) or an
    // unusual edition: we cannot tell.
    const known = Object.values(index.products).filter(p => p.server === os.server).flatMap(p => p.builds)
    return known.length && os.build < Math.min(...known)
      ? empty('unsupported', 'this Windows version no longer receives security updates')
      : empty('unknown', 'Windows version not in Microsoft\'s data')
  }

  const p = index.products[product]!
  const released = new Map(index.months.map(m => [m.id, m.released]))
  const cutoff = now.getTime() - PATCH_GRACE_DAYS * 86400000
  const missing: MissingMonth[] = []
  let latest: { fixed_build: string; kb: string | null; ubr: number } | null = null
  for (const [month, builds] of Object.entries(p.months)) {
    for (const b of builds) {
      const fb = parseBuild(b.fixed_build)
      if (!fb || fb[0] !== os.build) continue
      if (!latest || fb[1] > latest.ubr) latest = { fixed_build: b.fixed_build, kb: b.kb, ubr: fb[1] }
      const rel = released.get(month) ?? null
      if (fb[1] > os.ubr && rel && new Date(rel).getTime() <= cutoff) {
        missing.push({ month, released: rel, fixed_build: b.fixed_build, kb: b.kb, cves: b.cves, critical: b.critical, exploited: b.exploited })
      }
    }
  }
  missing.sort((a, b) => a.released.localeCompare(b.released) || parseBuild(a.fixed_build)![1] - parseBuild(b.fixed_build)![1])
  const sum = (k: 'cves' | 'critical' | 'exploited') => missing.reduce((n, m) => n + m[k], 0)

  // Microsoft stopped listing this version: it no longer gets fixes, whatever its build.
  const recent = [...index.months].sort((a, b) => a.released.localeCompare(b.released)).slice(-UNSUPPORTED_AFTER_MONTHS)
  const supported = recent.length < UNSUPPORTED_AFTER_MONTHS || recent.some(m => m.id in p.months)
  const base = {
    product, build: `10.0.${os.build}.${os.ubr}`, missing,
    cves: sum('cves'), critical: sum('critical'), exploited: sum('exploited'),
    latest: latest ? { fixed_build: latest.fixed_build, kb: latest.kb } : null,
  }
  if (!supported) return { ...base, status: 'unsupported', reason: 'Microsoft no longer releases security updates for this Windows version' }
  return { ...base, status: missing.length ? 'behind' : 'current', reason: null }
}

/** Alert severity: exploited in the wild > critical fixes > the rest. */
export function patchSeverity(a: PatchAssessment): 'critical' | 'high' | 'medium' {
  if (a.exploited > 0) return 'critical'
  if (a.status === 'unsupported' || a.critical > 0) return 'high'
  return 'medium'
}
