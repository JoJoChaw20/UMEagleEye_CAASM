// Builds src/data/attack.json from MITRE ATT&CK's official STIX 2.1 data
// (github.com/mitre-attack/attack-stix-data, Enterprise domain).
//
// The Worker uses it to give feed indicators real ATT&CK techniques: an indicator's
// malware family is looked up among ATT&CK's software (names and aliases), and the
// family's techniques are the ones MITRE documents for it ("uses" relationships).
//
// Run again when MITRE publishes a new release, then deploy:
//   node scripts/attack/build-attack.mjs                  download the latest release
//   node scripts/attack/build-attack.mjs --file x.json    use a file already downloaded
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../../src/data/attack.json')

const fileArg = process.argv.indexOf('--file')
let bundle
if (fileArg > 0) {
  bundle = JSON.parse(await readFile(process.argv[fileArg + 1], 'utf8'))
} else {
  console.log(`Downloading ${URL}`)
  const res = await fetch(URL)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  bundle = await res.json()
}

const objs = bundle.objects
const live = (o) => !o.revoked && !o.x_mitre_deprecated
const extId = (o) => o.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id
// Same normalisation as src/lib/attack.ts normName()
const norm = (s) => (s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '')

const collection = objs.find((o) => o.type === 'x-mitre-collection')
const matrix = objs.find((o) => o.type === 'x-mitre-matrix' && live(o))
const byId = new Map(objs.map((o) => [o.id, o]))

// Tactics in the matrix's own column order
const tactics = matrix.tactic_refs.map((ref) => {
  const t = byId.get(ref)
  return [extId(t), t.x_mitre_shortname, t.name]
})
const tacticIndex = new Map(tactics.map(([, short], i) => [short, i]))

// Techniques and sub-techniques: id -> [name, [tactic indexes]]
const techniques = {}
const techByStix = new Map()
for (const o of objs) {
  if (o.type !== 'attack-pattern' || !live(o)) continue
  const id = extId(o)
  if (!id) continue
  const tix = (o.kill_chain_phases ?? [])
    .filter((p) => p.kill_chain_name === 'mitre-attack' && tacticIndex.has(p.phase_name))
    .map((p) => tacticIndex.get(p.phase_name))
  if (!tix.length) continue
  techniques[id] = [o.name, tix]
  techByStix.set(o.id, id)
}

// Software (malware and tools): id -> [name, [technique ids]]
const softByStix = new Map()
for (const o of objs) {
  if ((o.type === 'malware' || o.type === 'tool') && live(o) && extId(o)) softByStix.set(o.id, o)
}
const uses = new Map()
for (const o of objs) {
  if (o.type !== 'relationship' || o.relationship_type !== 'uses' || !live(o)) continue
  const tech = techByStix.get(o.target_ref)
  if (!tech || !softByStix.has(o.source_ref)) continue
  if (!uses.has(o.source_ref)) uses.set(o.source_ref, new Set())
  uses.get(o.source_ref).add(tech)
}
const software = {}
for (const [stix, o] of softByStix) {
  const t = uses.get(stix)
  if (t?.size) software[extId(o)] = [o.name, [...t].sort()]
}

// Lookup by normalised name: primary names first, so an alias never takes a name.
const names = {}
const add = (n, id) => { const k = norm(n); if (k.length >= 3 && !(k in names)) names[k] = id }
for (const o of softByStix.values()) if (software[extId(o)]) add(o.name, extId(o))
for (const o of softByStix.values()) if (software[extId(o)]) for (const a of o.x_mitre_aliases ?? []) add(a, extId(o))

const version = collection?.x_mitre_version ?? matrix.x_mitre_version ?? '?'
const out = {
  source: 'MITRE ATT&CK Enterprise (attack-stix-data)',
  version,
  modified: (collection?.modified ?? matrix.modified ?? '').slice(0, 10),
  tactics,
  techniques,
  software,
  names,
}
await mkdir(dirname(OUT), { recursive: true })
await writeFile(OUT, JSON.stringify(out))
console.log(`ATT&CK v${version} (${out.modified}): ${tactics.length} tactics, ${Object.keys(techniques).length} techniques, ` +
  `${Object.keys(software).length} software with techniques, ${Object.keys(names).length} names -> ${OUT}`)
