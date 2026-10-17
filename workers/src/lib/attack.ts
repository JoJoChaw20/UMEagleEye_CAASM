// MITRE ATT&CK lookups over src/data/attack.json (built by scripts/attack/build-attack.mjs
// from MITRE's official STIX data). Nothing here is guessed: an indicator gets techniques
// only when its malware family is ATT&CK software, or when the feed names techniques itself.
import data from '../data/attack.json'

interface AttackData {
  source: string
  version: string
  modified: string
  tactics: [string, string, string][]                    // [TA id, shortname, name], matrix order
  techniques: Record<string, [string, number[]]>         // T id -> [name, tactic indexes]
  software: Record<string, [string, string[]]>           // S id -> [name, technique ids]
  names: Record<string, string>                          // normalised name or alias -> S id
}

export const ATTACK = data as unknown as AttackData

export const normName = (s: string | null | undefined) => (s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '')

/** ATT&CK software id for the first candidate name (family name, aliases...) that is one. */
export function resolveSoftware(candidates: Array<string | null | undefined>): string | null {
  for (const c of candidates) {
    const id = ATTACK.names[normName(c)]
    if (id) return id
  }
  return null
}

const TECH_RE = /^T\d{4}(\.\d{3})?$/

/** Technique ids from free text such as "T1071", "t1059.001" or "T1071 - Application Layer Protocol"; unknown ids dropped. */
export function techniqueIds(values: Array<string | null | undefined>): string[] {
  const out = new Set<string>()
  for (const v of values) {
    const id = (v ?? '').trim().split(/\s/)[0]?.toUpperCase() ?? ''
    if (TECH_RE.test(id) && ATTACK.techniques[id]) out.add(id)
  }
  return [...out]
}

export const parentOf = (id: string) => id.split('.')[0] ?? id

export function techniqueName(id: string): string | null {
  return ATTACK.techniques[id]?.[0] ?? null
}

/** Shortnames of a technique's tactics, e.g. ['execution']. */
export function tacticsOf(id: string): string[] {
  return (ATTACK.techniques[id]?.[1] ?? []).map((i) => ATTACK.tactics[i]?.[1] ?? '').filter(Boolean)
}

export function softwareName(id: string | null | undefined): string | null {
  return id ? ATTACK.software[id]?.[0] ?? null : null
}

/** Techniques an indicator has: its family's (from ATT&CK) plus any the feed named. */
export function techniquesFor(softwareId: string | null | undefined, explicit: string[] | null | undefined): string[] {
  const fam = softwareId ? ATTACK.software[softwareId]?.[1] ?? [] : []
  if (!explicit?.length) return fam
  return [...new Set([...fam, ...explicit])]
}

/** Every technique id at or under the given ones (T1059 -> T1059, T1059.001...). */
export function expandTechniques(ids: string[]): string[] {
  const want = new Set(ids.map((i) => i.toUpperCase()))
  return Object.keys(ATTACK.techniques).filter((t) => want.has(t) || want.has(parentOf(t)))
}

/** ATT&CK software whose documented techniques include any of the given technique ids. */
export function softwareUsing(techIds: string[]): string[] {
  const want = new Set(techIds)
  return Object.entries(ATTACK.software).filter(([, [, t]]) => t.some((x) => want.has(x))).map(([id]) => id)
}

// ── Matrix ──────────────────────────────────────────────────────────────────────
// Input: feed indicators grouped by (family, ATT&CK software, techniques the feed named).
export interface MatrixGroup { family: string | null; software: string | null; named: string[] | null; count: number }

interface FamilyCount { name: string; software: string | null; iocs: number }
export interface MatrixTechnique {
  id: string
  name: string
  tactics: string[]
  iocs: number
  families: FamilyCount[]       // the largest few
  family_count: number
  subs: Array<{ id: string; name: string; iocs: number }>
}

const FAMILIES_PER_TECHNIQUE = 25
const TOP_UNMATCHED = 12

export function buildMatrix(groups: MatrixGroup[]) {
  const parents = new Map<string, { iocs: number; fam: Map<string, FamilyCount>; subs: Map<string, number> }>()
  const unmatched = new Map<string, number>()
  const familiesSeen = new Set<string>()
  const familiesMatched = new Set<string>()
  let total = 0, withFamily = 0, withAttack = 0

  for (const g of groups) {
    total += g.count
    if (g.family) {
      withFamily += g.count
      familiesSeen.add(g.software ?? `f:${normName(g.family)}`)
      if (g.software) familiesMatched.add(g.software)
      else unmatched.set(g.family, (unmatched.get(g.family) ?? 0) + g.count)
    }
    const techs = techniquesFor(g.software, g.named).filter((t) => ATTACK.techniques[t])
    if (!techs.length) continue
    withAttack += g.count

    const label = softwareName(g.software) ?? g.family ?? 'Techniques named by the feed'
    const famKey = g.software ?? `f:${label}`
    const touched = new Set<string>()
    for (const t of techs) {
      const p = parentOf(t)
      let e = parents.get(p)
      if (!e) parents.set(p, e = { iocs: 0, fam: new Map(), subs: new Map() })
      if (!touched.has(p)) {
        touched.add(p)
        e.iocs += g.count
        const f = e.fam.get(famKey) ?? { name: label, software: g.software, iocs: 0 }
        f.iocs += g.count
        e.fam.set(famKey, f)
      }
      if (t !== p) e.subs.set(t, (e.subs.get(t) ?? 0) + g.count)
    }
  }

  const techniques: MatrixTechnique[] = [...parents].map(([id, e]) => ({
    id,
    // a sub-technique whose parent is not in the data (should not happen) keeps its own name
    name: techniqueName(id) ?? id,
    tactics: tacticsOf(id).length ? tacticsOf(id) : [...new Set([...e.subs.keys()].flatMap(tacticsOf))],
    iocs: e.iocs,
    families: [...e.fam.values()].sort((a, b) => b.iocs - a.iocs).slice(0, FAMILIES_PER_TECHNIQUE),
    family_count: e.fam.size,
    subs: [...e.subs].map(([sid, n]) => ({ id: sid, name: techniqueName(sid) ?? sid, iocs: n })).sort((a, b) => b.iocs - a.iocs),
  })).sort((a, b) => b.iocs - a.iocs)

  return {
    attack: { source: ATTACK.source, version: ATTACK.version, modified: ATTACK.modified },
    tactics: ATTACK.tactics.map(([id, short, name]) => ({
      id, short, name,
      technique_total: Object.entries(ATTACK.techniques).filter(([t, [, tx]]) => !t.includes('.') && tx.some((i) => ATTACK.tactics[i]?.[1] === short)).length,
    })),
    techniques,
    coverage: {
      total,
      with_family: withFamily,
      with_attack: withAttack,
      families: familiesSeen.size,
      families_matched: familiesMatched.size,
      top_unmatched: [...unmatched].sort((a, b) => b[1] - a[1]).slice(0, TOP_UNMATCHED).map(([name, iocs]) => ({ name, iocs })),
    },
  }
}
