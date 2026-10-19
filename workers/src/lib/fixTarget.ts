import { compareVersions } from './exposure'

// The version to upgrade a package to so that its CVEs are fixed.
//
// Each CVE lists the versions that fix it, often one per release line (Python:
// 3.10.20, 3.11.15, 3.12.13, 3.13.12…; Java: 8.0.491, 11.0.31, 17.0.19…). For one CVE
// the right fix is the SMALLEST listed version above the installed one, which stays on
// the installed line (3.13.3 → 3.13.12, not 3.14.3). The group's target is the highest
// of those, so upgrading to it fixes every CVE that has a fix.

/** "go1.20.12" → "1.20.12", "v2.0" → "2.0": compare the numeric part only. */
const clean = (v: string) => v.trim().replace(/^[^\d]+/, '')

export function fixTarget(installed: string | null | undefined, fixVersions: unknown[]): { to: string | null; fixed: number; noFix: number } {
  const cur = clean(installed ?? '')
  let to: string | null = null
  let fixed = 0
  let noFix = 0
  for (const list of fixVersions) {
    const versions = Array.isArray(list) ? list.map(String).map(clean).filter(Boolean) : []
    const above = cur ? versions.filter(v => compareVersions(v, cur) > 0) : versions
    if (above.length === 0) { noFix++; continue }
    const best = above.reduce((a, b) => (compareVersions(b, a) < 0 ? b : a))
    fixed++
    if (to === null || compareVersions(best, to) > 0) to = best
  }
  return { to, fixed, noFix }
}
