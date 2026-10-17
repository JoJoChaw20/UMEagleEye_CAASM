// Builds src/data/cwe.json (CWE id -> name) from MITRE's official CWE list
// (cwe.mitre.org, the full XML catalogue: weaknesses, categories and views, including
// deprecated and obsolete entries, since NVD still tags older CVEs with them).
//
// CVE alerts show these names next to the CWE IDs Grype reports. Run again when MITRE
// publishes a new CWE version (a few times a year), then deploy:
//   node scripts/cwe/build-cwe.mjs                 download the latest list
//   node scripts/cwe/build-cwe.mjs --file x.zip    use a cwec_latest.xml.zip already downloaded
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { inflateRawSync } from 'node:zlib'

const URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../../src/data/cwe.json')

const fileArg = process.argv.indexOf('--file')
let zip
if (fileArg > 0) {
  zip = await readFile(process.argv[fileArg + 1])
} else {
  console.log(`Downloading ${URL}`)
  const res = await fetch(URL)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  zip = Buffer.from(await res.arrayBuffer())
}

// The archive holds one file (cwec_vX.Y.xml). Read it through the central directory.
function firstEntry(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  if (eocd < 0) throw new Error('not a zip file')
  const cd = buf.readUInt32LE(eocd + 16)
  if (buf.readUInt32LE(cd) !== 0x02014b50) throw new Error('bad central directory')
  const method = buf.readUInt16LE(cd + 10)
  const size = buf.readUInt32LE(cd + 20)
  const local = buf.readUInt32LE(cd + 42)
  const data = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28)
  const raw = buf.subarray(data, data + size)
  if (method === 0) return raw
  if (method === 8) return inflateRawSync(raw)
  throw new Error(`unsupported zip method ${method}`)
}

const xml = firstEntry(zip).toString('utf8')
const unescape = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')

const names = {}
for (const m of xml.matchAll(/<(Weakness|Category|View) ID="(\d+)" Name="([^"]*)"/g)) {
  names[m[2]] = unescape(m[3])
}
const version = xml.match(/<Weakness_Catalog [^>]*Version="([^"]+)"/)?.[1] ?? '?'
const date = xml.match(/<Weakness_Catalog [^>]*Date="([^"]+)"/)?.[1] ?? ''

await mkdir(dirname(OUT), { recursive: true })
await writeFile(OUT, JSON.stringify({ source: 'MITRE CWE', version, date, names }))
console.log(`CWE v${version} (${date}): ${Object.keys(names).length} entries -> ${OUT}`)
