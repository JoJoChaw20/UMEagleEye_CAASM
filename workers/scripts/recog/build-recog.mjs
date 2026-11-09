// Builds src/lib/recog/fingerprints.json from Rapid7 Recog (BSD-2-Clause, github.com/rapid7/recog):
// the fingerprint databases for the banners EagleEye's agent uploads (SSH, HTTP Server headers, FTP,
// SMTP, Telnet, SNMP sysDescr). Recog's patterns are Ruby regular expressions; each is converted to
// JavaScript and kept ONLY if it still matches every example Recog ships with it and extracts the
// values those examples expect. The rest are listed and left out.
//
//   node scripts/recog/build-recog.mjs                 # latest Recog (main)
//   node scripts/recog/build-recog.mjs --dir <folder>  # from XML files already downloaded
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = new URL('../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')
const OUT = join(ROOT, 'src/lib/recog')
const DBS = { ssh: 'ssh_banners', http_server: 'http_servers', ftp: 'ftp_banners', smtp: 'smtp_banners',
  telnet: 'telnet_banners', snmp: 'snmp_sysdescr' }
const RAW = 'https://raw.githubusercontent.com/rapid7/recog/main'
const KEEP = /^(service|os|hw)\.(vendor|product|family|version|cpe23|device)$/      // the params EagleEye uses

const dirArg = process.argv.indexOf('--dir')
const dir = dirArg > 0 ? process.argv[dirArg + 1] : null

const unescapeXml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/&amp;/g, '&')
const attrs = (s) => Object.fromEntries([...s.matchAll(/([\w.:-]+)="([^"]*)"/g)].map((m) => [m[1], unescapeXml(m[2])]))

/** A Ruby regular expression as a JavaScript one, or null when it uses what JavaScript lacks. */
export function toJs(pattern, flags = '') {
  let p = pattern, f = 'm'                                       // Ruby's ^ and $ always match at line breaks
  if (/REG_ICASE/.test(flags)) f += 'i'
  if (/REG_MULTILINE|REG_DOT_NEWLINE/.test(flags)) f += 's'
  // leading inline options: (?i) (?m) (?im) ... — Ruby (?m) is "dot matches newline"
  const lead = /^\(\?([imx]+)\)/.exec(p)
  if (lead) {
    if (lead[1].includes('i') && !f.includes('i')) f += 'i'
    if (lead[1].includes('m') && !f.includes('s')) f += 's'
    if (lead[1].includes('x')) return null
    p = p.slice(lead[0].length)
  }
  if (/\(\?[imx-]+[):]/.test(p)) return null                   // options in the middle
  if (/\(\?>|[*+?}]\+/.test(p)) return null                    // atomic groups, possessive quantifiers
  // \A and \z are the absolute start and end of the text (^ and $ are per line, as in Ruby)
  p = p.replace(/\\A/g, '(?<![\\s\\S])').replace(/\\z/g, '(?![\\s\\S])').replace(/\\Z/g, '(?=\\n?(?![\\s\\S]))')
    .replace(/\\h/g, '[0-9A-Fa-f]').replace(/\\H/g, '[^0-9A-Fa-f]')
  try { return { p, f, re: new RegExp(p, f) } } catch { return null }
}

function parse(xml) {
  const out = []
  for (const m of xml.matchAll(/<fingerprint\b([^>]*)>([\s\S]*?)<\/fingerprint>/g)) {
    const a = attrs(m[1])
    const body = m[2]
    const params = [...body.matchAll(/<param\b([^>]*)\/>/g)].map((x) => attrs(x[1]))
    const examples = [...body.matchAll(/<example\b([^>]*)>([\s\S]*?)<\/example>/g)].map((x) => {
      const ea = attrs(x[1])
      let text = unescapeXml(x[2])
      if (ea._encoding === 'base64') text = Buffer.from(text, 'base64').toString('latin1')
      return { text, expect: ea }
    })
    out.push({ pattern: a.pattern, flags: a.flags ?? '', params, examples, description: (body.match(/<description>([\s\S]*?)<\/description>/) ?? [])[1]?.trim() })
  }
  return out
}

async function source(name) {
  if (dir) return readFileSync(join(dir, `${name}.xml`), 'utf8')
  const res = await fetch(`${RAW}/xml/${name}.xml`)
  if (!res.ok) throw new Error(`${name}.xml: HTTP ${res.status}`)
  return res.text()
}

const bundle = { source: 'Rapid7 Recog, https://github.com/rapid7/recog (BSD-2-Clause)', built: new Date().toISOString().slice(0, 10), dbs: {} }
const report = []
for (const [db, file] of Object.entries(DBS)) {
  const fps = parse(await source(file))
  let kept = 0, unsupported = 0, failedExamples = 0, noUse = 0
  bundle.dbs[db] = []
  for (const fp of fps) {
    const params = fp.params.filter((x) => KEEP.test(x.name)).map((x) => [x.name, Number(x.pos), x.value ?? null])
    if (!params.some(([n]) => /\.(product|cpe23)$/.test(n))) { noUse++; continue }
    const js = toJs(fp.pattern, fp.flags)
    if (!js) { unsupported++; report.push(`${db}: unsupported  ${fp.pattern}`); continue }
    // every example must still match and give the values it expects (e.g. service.version)
    const ok = fp.examples.every(({ text, expect }) => {
      const m = js.re.exec(text)
      if (!m) return false
      return fp.params.filter((x) => Number(x.pos) > 0 && expect[x.name] !== undefined)
        .every((x) => (m[Number(x.pos)] ?? '') === expect[x.name])
    })
    if (!ok) { failedExamples++; report.push(`${db}: examples fail  ${fp.pattern}`); continue }
    bundle.dbs[db].push({ p: js.p, f: js.f, a: params })
    kept++
  }
  console.log(`${db.padEnd(12)} ${fps.length} fingerprints: kept ${kept}, not about a product ${noUse}, unsupported in JavaScript ${unsupported}, examples failed ${failedExamples}`)
}
mkdirSync(OUT, { recursive: true })
writeFileSync(join(OUT, 'fingerprints.json'), JSON.stringify(bundle))
writeFileSync(join(OUT, 'skipped.txt'), report.join('\n') + '\n')
const license = dir ? readFileSync(join(dir, 'LICENSE'), 'utf8') : await (await fetch(`${RAW}/LICENSE`)).text()
writeFileSync(join(OUT, 'LICENSE-recog.txt'), license)
console.log(`wrote ${join(OUT, 'fingerprints.json')} (${(JSON.stringify(bundle).length / 1024).toFixed(0)} KiB)`)
