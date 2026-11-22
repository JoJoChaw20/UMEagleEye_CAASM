/**
 * Known-malicious packages in a device's software list (SBOM): a package published to steal or to
 * run an attacker's code (typosquats, hijacked releases such as ua-parser-js 0.7.29). Two sources:
 *   - OSV's malicious-package records (OpenSSF, ids "MAL-..."), asked for each package with
 *     POST https://api.osv.dev/v1/querybatch (services/maliciousPackages.ts);
 *   - package findings the agent's Grype already sent whose weakness is CWE-506 Embedded Malicious
 *     Code or CWE-912 Hidden Functionality (GitHub's malware advisories).
 * A threat-intel alert (cti_match, match_kind 'malicious_package', rule R8), not a flaw to patch: a
 * listed malicious release is a possible compromise (critical, tier 1: investigate within 24 hours);
 * a record that names the whole package only matches by name, so it is reviewed (medium, tier 4):
 * see recordScope. Pure functions.
 */

// The package managers (dependencies.package_manager, from the purl type) OSV knows, with its names.
export const OSV_ECOSYSTEM: Record<string, string> = {
  npm: 'npm', pypi: 'PyPI', nuget: 'NuGet', maven: 'Maven', cargo: 'crates.io', golang: 'Go',
  gem: 'RubyGems', composer: 'Packagist', hex: 'Hex', pub: 'Pub',
}

export const MALWARE_CWES = ['CWE-506', 'CWE-912']
export const OSV_BATCH = 1000          // OSV's limit of queries per querybatch
export const MAL_RULE = 'R8'
export const MAL_SOURCE_OSV = 'OSV malicious packages (OpenSSF)'
export const MAL_SOURCE_ADVISORY = 'Advisory: embedded malicious code'

export interface PackageRow { pm: string | null; name: string; version: string; purl: string | null }

export type OsvQuery = { package: { purl: string } } | { package: { name: string; ecosystem: string }; version: string }

/** The OSV query for a package, or null when OSV does not cover its package manager. The purl names
 *  the package exactly (Maven group, npm scope) and is used when it carries the version. */
export function osvQuery(p: PackageRow): OsvQuery | null {
  const ecosystem = p.pm ? OSV_ECOSYSTEM[p.pm] : undefined
  if (!ecosystem || !p.name || !p.version) return null
  const purl = p.purl?.split(/[?#]/)[0]
  if (purl && purl.startsWith(`pkg:${p.pm}/`) && purl.includes('@')) return { package: { purl } }
  return { package: { name: p.name, ecosystem }, version: p.version }
}

export const isMalwareId = (id: string) => /^MAL-\d{4}-\d+$/.test(id)

/**
 * What a malicious-package record covers: 'version' = listed releases (a hijacked release such as
 * @ctrl/tinycolor 4.1.1-4.1.2): a match is that release, critical. 'name' = every version of the name
 * (a typosquat, or a squat of some company's internal package name: dependency confusion): a match
 * may be a package of the same name from elsewhere (the Bicep VS Code extension is called
 * "vscode-bicep" too), so it is a review, not a compromise.
 */
export type MalScope = 'version' | 'name'

export function recordScope(record: unknown): MalScope {
  const affected = (record as { affected?: Array<{ versions?: unknown[]; ranges?: Array<{ events?: Array<Record<string, string>> }> }> } | null)?.affected
  if (!Array.isArray(affected) || affected.length === 0) return 'name'
  const everything = affected.some((a) =>
    !(Array.isArray(a.versions) && a.versions.length > 0)
    && (a.ranges ?? []).some((r) => {
      const ev = r.events ?? []
      return ev.some((e) => e.introduced === '0') && !ev.some((e) => e.fixed || e.last_affected || e.limit)
    }))
  return everything ? 'name' : 'version'
}

/** Its severity: a listed release is a compromise (critical, tier 1); a name match is reviewed (medium, tier 4). */
export const malSeverity = (scope: MalScope) => (scope === 'version' ? 'critical' : 'medium')

/** The MAL- ids among one querybatch result's vulns. */
export function malIdsOf(result: unknown): string[] {
  const vulns = (result as { vulns?: Array<{ id?: unknown }> } | null)?.vulns
  if (!Array.isArray(vulns)) return []
  return [...new Set(vulns.map((v) => String(v?.id ?? '')).filter(isMalwareId))]
}

/** One alert per (asset, package version): what it says. */
export function malDetails(p: { pm: string | null; name: string; version: string; purl: string | null },
  ids: string[], source: string, summary: string | null, scope: MalScope) {
  const ecosystem = (p.pm && OSV_ECOSYSTEM[p.pm]) || p.pm || 'package'
  return {
    match_scope: scope,
    indicator_type: 'software',
    indicator_value: `${ecosystem}:${p.name}@${p.version}`,
    match_kind: 'malicious_package',
    rule: MAL_RULE,
    matched_on: 'package',
    observed: p.purl ?? `${p.name}@${p.version}`,
    ecosystem,
    package_name: p.name,
    package_version: p.version,
    advisory_ids: ids.slice(0, 10),
    summary,
    sources: [source],
  }
}
