/**
 * attack-matrix-demo.ts — MITRE ATT&CK lookups and the matrix (lib/attack.ts) over
 * src/data/attack.json. PURE (no DB). If MITRE changes a family's techniques in a new
 * release, the counts checked here may need updating after build-attack.mjs.
 * Run: npx esbuild scripts/attack-matrix-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.attack-matrix-demo.cjs && node .attack-matrix-demo.cjs
 */
import {
  ATTACK, buildMatrix, expandTechniques, parentOf, resolveSoftware, softwareUsing, tacticsOf,
  techniqueIds, techniquesFor,
} from '../src/lib/attack'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// ── the data ──
check('15 tactics in matrix order, first and last', [ATTACK.tactics.length, ATTACK.tactics[0]?.[2], ATTACK.tactics[14]?.[2]],
  [15, 'Reconnaissance', 'Impact'])
check('v20 split Defense Evasion', ATTACK.tactics.map((t) => t[2]).filter((n) => /Stealth|Defense/.test(n)),
  ['Stealth', 'Defense Impairment'])
check('PowerShell is an Execution sub-technique', [ATTACK.techniques['T1059.001']?.[0], tacticsOf('T1059.001')], ['PowerShell', ['execution']])

// ── family names -> ATT&CK software ──
check('ThreatFox printable name', resolveSoftware(['Cobalt Strike']), 'S0154')
check('case and punctuation ignored', resolveSoftware(['cobalt-strike']), 'S0154')
check('Malpedia key suffix as a fallback', resolveSoftware(['Some Name', 'cobalt_strike']), 'S0154')
check('alias works (Remcos RAT -> Remcos)', resolveSoftware(['RemcosRAT', 'Remcos']), 'S0332')
check('family ATT&CK does not document', resolveSoftware(['Mirai']), null)
check('empty candidates', resolveSoftware([null, undefined, '']), null)

// ── techniques ──
check('ids from OTX shapes, unknown and junk dropped', techniqueIds(['T1071', 't1059.001', 'T1566 - Phishing', 'T9999', 'phishing']),
  ['T1071', 'T1059.001', 'T1566'])
check('parent of a sub-technique', parentOf('T1059.001'), 'T1059')
check('expand a parent to its sub-techniques', expandTechniques(['T1059']).includes('T1059.001'), true)
check('Cobalt Strike uses PowerShell', softwareUsing(['T1059.001']).includes('S0154'), true)
check('family plus named, no duplicates', techniquesFor(null, ['T1071', 'T1071']), ['T1071'])
check('Cobalt Strike has 73 techniques', techniquesFor('S0154', null).length, 73)

// ── the matrix ──
const m = buildMatrix([
  { family: 'Cobalt Strike', software: 'S0154', named: null, count: 10 },
  { family: 'Remcos', software: 'S0332', named: null, count: 5 },
  { family: 'Mirai', software: null, named: null, count: 7 },
  { family: null, software: null, named: ['T1059.001'], count: 2 },
  { family: null, software: null, named: null, count: 3 },
])
check('coverage counts', [m.coverage.total, m.coverage.with_family, m.coverage.with_attack, m.coverage.families, m.coverage.families_matched],
  [27, 22, 17, 3, 2])
check('unmatched families listed', m.coverage.top_unmatched, [{ name: 'Mirai', iocs: 7 }])
const t1059 = m.techniques.find((t) => t.id === 'T1059')
check('T1059 counts each group once (CS has several T1059 subs)', t1059?.iocs,
  10 + (techniquesFor('S0332', null).some((t) => parentOf(t) === 'T1059') ? 5 : 0) + 2)
check('T1059 lists the feed-named group', t1059?.families.some((f) => f.name === 'Techniques named by the feed'), true)
check('PowerShell sub-technique counted', (t1059?.subs.find((s) => s.id === 'T1059.001')?.iocs ?? 0) >= 12, true)
check('every technique row is a parent with a tactic', m.techniques.every((t) => !t.id.includes('.') && t.tactics.length > 0), true)
check('tactics carry technique totals', m.tactics.every((t) => t.technique_total > 0), true)
check('no matrix rows from groups without techniques', buildMatrix([{ family: 'Mirai', software: null, named: null, count: 1 }]).techniques.length, 0)

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
