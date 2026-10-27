// Builds the Windows patch data from Microsoft's Security Update Guide (MSRC CVRF v3.0,
// api.msrc.microsoft.com, free, no key). One document per Patch Tuesday lists every CVE
// Microsoft fixed that month, with the build of each Windows version that fixes it.
//
// The Worker compares an agent's Windows build (inventory os.build + os.ubr) with these
// fixed builds and raises one alert per device that is behind. Output (uploaded to R2):
//   index.json        Windows versions -> month -> fixed builds with KB and counts
//   cves/<month>.json that month's CVEs (severity, exploited, title) per Windows version
//
// Run after each Patch Tuesday (Microsoft also revises older documents):
//   node scripts/msrc/build-msrc.mjs --out <dir>                  last 12 months
//   node scripts/msrc/build-msrc.mjs --out <dir> --months 3
//   node scripts/msrc/build-msrc.mjs --out <dir> --dir <folder>   documents already downloaded
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises'
import { join } from 'node:path'

const API = 'https://api.msrc.microsoft.com/cvrf/v3.0'
const arg = (name, fallback) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : fallback
}
const OUT = arg('--out')
if (!OUT) throw new Error('--out <dir> is required')
const MONTHS = Number(arg('--months', 12))
const DIR = arg('--dir')

async function getJson(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`)
  return res.json()
}

// The documents to read: newest MONTHS releases, oldest first
async function loadDocs() {
  if (DIR) {
    const files = (await readdir(DIR)).filter((f) => /^\d{4}-[A-Z][a-z]{2}\.json$/.test(f))
    const docs = await Promise.all(files.map(async (f) => JSON.parse(await readFile(join(DIR, f), 'utf8'))))
    return docs.sort((a, b) => date(a) - date(b)).slice(-MONTHS)
  }
  const updates = (await getJson(`${API}/updates`)).value
    .filter((u) => /^\d{4}-[A-Z][a-z]{2}$/.test(u.ID))
    .sort((a, b) => new Date(a.InitialReleaseDate) - new Date(b.InitialReleaseDate))
    .slice(-MONTHS)
  const docs = []
  for (const u of updates) {
    console.log(`Downloading ${u.ID}`)
    docs.push(await getJson(u.CvrfUrl))
  }
  return docs
}
const date = (doc) => new Date(doc.DocumentTracking.InitialReleaseDate)

// Windows itself, not the Store extensions or .NET shipped "on Windows 11 ..."
const WINDOWS = /^Windows (10|11|Server) /i
const isWindows = (name) => WINDOWS.test(name) && !/ on Windows /i.test(name)

function productNames(tree) {
  const names = {}
  const walk = (branches) => {
    for (const b of branches ?? []) {
      for (const p of b.FullProductName ?? []) names[p.ProductID] = p.Value
      walk(b.Branch)
    }
  }
  for (const p of tree.FullProductName ?? []) names[p.ProductID] = p.Value
  walk(tree.Branch)
  return names
}

// "Windows 11 Version 25H2 for x64-based Systems" -> how the Worker recognises a device
function describe(name) {
  const server = /^Windows Server/i.test(name)
  // Server names carry no architecture: Windows Server 2016 and later are x64 only
  const arch = /ARM64/i.test(name) ? 'arm64' : /32-bit|x86/i.test(name) ? 'x86' : /x64|64-bit/i.test(name) || server ? 'x64' : null
  return {
    server,
    core: /Server Core/i.test(name),
    arch,
  }
}

const BUILD = /^10\.0\.(\d+)\.(\d+)$/

const docs = await loadDocs()
const index = { generated: new Date().toISOString(), source: API, months: [], products: {} }
await mkdir(join(OUT, 'cves'), { recursive: true })

// Pass 1: every (Windows version, build, CVE) with the LOWEST patch number that fixes it.
// A CVE can be listed twice: under two builds in one month (December 2025 listed 387 Windows
// 11 CVEs under both .7392 and .7462), or again in a later month. A machine on either build
// has the fix, so it counts once, at the lowest; counting both would inflate the numbers
// and could alert a machine that is already fixed.
const fixes = {}   // name -> "build|CVE" -> { month, ubr, fixed, kb }
const info = {}    // month -> CVE -> [title, severity, exploited]
for (const doc of docs) {
  const month = doc.DocumentTracking.Identification.ID.Value
  index.months.push({ id: month, released: doc.DocumentTracking.InitialReleaseDate, revised: doc.DocumentTracking.CurrentReleaseDate })
  const names = productNames(doc.ProductTree)
  for (const v of doc.Vulnerability ?? []) {
    const exploited = (v.Threats ?? []).some((t) => t.Type === 1 && /Exploited:Yes/.test(t.Description?.Value ?? ''))
    for (const r of v.Remediations ?? []) {
      // Type 2 = vendor fix; FixedBuild is given for Windows cumulative updates
      const m = BUILD.exec(r.FixedBuild ?? '')
      if (r.Type !== 2 || !m) continue
      for (const pid of r.ProductID ?? []) {
        const name = names[pid]
        if (!name || !isWindows(name)) continue
        const sev = (v.Threats ?? []).find((t) => t.Type === 3 && (t.ProductID ?? []).includes(pid))?.Description?.Value
        // [title, severity, exploited]; Windows versions share one severity in practice
        ;(info[month] ??= {})[v.CVE] ??= [v.Title?.Value ?? '', sev ?? null, exploited]
        const key = `${m[1]}|${v.CVE}`
        const prev = (fixes[name] ??= {})[key]
        if (!prev || Number(m[2]) < prev.ubr) {
          fixes[name][key] = { month, ubr: Number(m[2]), fixed: r.FixedBuild, kb: r.Description?.Value ?? null }
        }
      }
    }
  }
}

// Pass 2: group by month and fixed build, count, and write one CVE file per month.
const files = Object.fromEntries(index.months.map((m) => [m.id, { month: m.id, cves: {}, products: {} }]))
for (const [name, entries] of Object.entries(fixes)) {
  // Versions serviced together share fixes and list both builds (Windows 11 24H2 and
  // 25H2: 26100 and 26200 with the same patch number), so keep every build seen.
  const p = (index.products[name] = { ...describe(name), builds: [], months: {} })
  const groups = {}   // month -> fixed build -> { kb, cves[] }
  for (const [key, f] of Object.entries(entries)) {
    const cve = key.split('|')[1]
    const major = Number(key.split('|')[0])
    if (!p.builds.includes(major)) p.builds.push(major)
    const g = ((groups[f.month] ??= {})[f.fixed] ??= { kb: f.kb, cves: [] })
    g.cves.push(cve)
    files[f.month].cves[cve] = info[f.month][cve]
  }
  p.builds.sort((a, b) => a - b)
  for (const [month, builds] of Object.entries(groups)) {
    p.months[month] = Object.entries(builds).map(([fixed, g]) => ({
      fixed_build: fixed, kb: g.kb, cves: g.cves.length,
      critical: g.cves.filter((c) => info[month][c][1] === 'Critical').length,
      exploited: g.cves.filter((c) => info[month][c][2]).length,
    }))
    ;(files[month].products[name] = {})
    for (const [fixed, g] of Object.entries(builds)) files[month].products[name][fixed] = g.cves
  }
}
for (const f of Object.values(files)) {
  await writeFile(join(OUT, 'cves', `${f.month}.json`), JSON.stringify(f))
  const pairs = Object.values(f.products).reduce((n, b) => n + Object.values(b).reduce((k, x) => k + x.length, 0), 0)
  console.log(`${f.month}: ${Object.keys(f.cves).length} Windows CVEs, ${Object.keys(f.products).length} versions, ${pairs} (version, CVE) pairs`)
}

await writeFile(join(OUT, 'index.json'), JSON.stringify(index))
console.log(`Wrote ${OUT}: ${Object.keys(index.products).length} Windows versions over ${index.months.length} months`)
