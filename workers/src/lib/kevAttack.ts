// ATT&CK techniques of the CVEs on CISA KEV: how each is exploited and what it leads to. From MITRE's
// Center for Threat-Informed Defense, Mappings Explorer (Apache-2.0; data/kevAttack.json names the
// release). 419 of the ~1,800 KEV CVEs are mapped; the rest have none. PURE.
import KEV from '../data/kevAttack.json'
import { techniqueName } from './attack'

type Entry = { exploit?: string[]; primary?: string[]; secondary?: string[] }
const CVES = (KEV as { cves: Record<string, Entry> }).cves

export interface KevTechniques { exploit: string[]; primary: string[]; secondary: string[]; all: string[] }

/** The CVE's techniques (ids our ATT&CK release knows), empty lists when it is not mapped. */
export function kevTechniques(cveId: string): KevTechniques {
  const e = CVES[cveId.trim().toUpperCase()] ?? {}
  const known = (ids: string[] | undefined) => (ids ?? []).filter((t) => techniqueName(t) !== null)
  const exploit = known(e.exploit), primary = known(e.primary), secondary = known(e.secondary)
  return { exploit, primary, secondary, all: [...new Set([...exploit, ...primary, ...secondary])] }
}

export const KEV_ATTACK_SOURCE = (KEV as { source: string }).source
