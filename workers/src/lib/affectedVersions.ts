import { compareVersions } from './exposure'
import { fixTarget } from './fixTarget'

// A CVE alert is one per (CVE, package name) on an asset, but a computer can have several
// versions of a package installed (pgAdmin 4 ships brace-expansion 1.1.11, 1.1.12 and
// 2.0.2). Grype reports the CVE once per affected version; the alert keeps all of them in
// details.affected_versions, each with the versions that fix it, and its package_version
// is the OLDEST, so the alert and its "upgrade X to Y" group do not change from one SBOM
// to the next depending on which copy was reported first.

export interface AffectedVersion { version: string; fix_versions: string[] }

/** The most versions kept on one alert. */
export const MAX_AFFECTED_VERSIONS = 20

const byVersion = (a: AffectedVersion, b: AffectedVersion) => compareVersions(a.version, b.version)

/** Every affected version per "cve_id::package_name", oldest first, from all findings
 *  (also those past the alert cap). Findings without a version are left out. Pure. */
export function collectAffectedVersions(
  findings: { cve_id: string; package_name: string; package_version?: string | null; fix_versions?: string[] }[],
): Map<string, AffectedVersion[]> {
  const out = new Map<string, Map<string, Set<string>>>()
  for (const f of findings) {
    if (!f.cve_id || !f.package_name || !f.package_version) continue
    const key = `${f.cve_id}::${f.package_name}`
    const versions = out.get(key) ?? new Map<string, Set<string>>()
    const fixes = versions.get(f.package_version) ?? new Set<string>()
    for (const v of f.fix_versions ?? []) fixes.add(v)
    versions.set(f.package_version, fixes)
    out.set(key, versions)
  }
  return new Map([...out].map(([key, versions]) => [key,
    [...versions].map(([version, fixes]) => ({ version, fix_versions: [...fixes] }))
      .sort(byVersion).slice(0, MAX_AFFECTED_VERSIONS)]))
}

/** For a CVE group ("upgrade <package> <version> to Y"): the other installed versions its
 *  CVEs also affect, each with the version that fixes all of them on that line (null when
 *  none is published). `lists` are the groups' alerts' details.affected_versions. Pure. */
export function alsoAffected(packageVersion: string | null | undefined, lists: unknown[]): { version: string; to: string | null }[] {
  const fixesByVersion = new Map<string, unknown[]>()
  for (const list of lists) {
    if (!Array.isArray(list)) continue
    for (const item of list) {
      const v = (item as Partial<AffectedVersion> | null)?.version
      if (typeof v !== 'string' || v === packageVersion) continue
      const fixes = fixesByVersion.get(v) ?? []
      fixes.push((item as AffectedVersion).fix_versions ?? [])
      fixesByVersion.set(v, fixes)
    }
  }
  return [...fixesByVersion]
    .map(([version, fixes]) => ({ version, to: fixTarget(version, fixes).to }))
    .sort((a, b) => compareVersions(a.version, b.version))
}
