// Uploads the output of build-msrc.mjs to R2, where the Worker reads it (services/windowsPatch.ts).
//   node scripts/msrc/upload-msrc.mjs <dir> staging
//   node scripts/msrc/upload-msrc.mjs <dir> production
// Uses wrangler, so it needs `wrangler login` locally or CLOUDFLARE_API_TOKEN in CI.
// The CVE files go first and index.json last, so the Worker never sees an index that
// points at a month file not uploaded yet.
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const BUCKETS = { staging: 'umeagleeye-reports-staging', production: 'umeagleeye-reports' }
const [dir, target] = process.argv.slice(2)
if (!dir || !BUCKETS[target]) {
  console.error('Usage: node scripts/msrc/upload-msrc.mjs <dir> <staging|production>')
  process.exit(1)
}

function put(key, file) {
  const res = spawnSync('npx', ['wrangler', 'r2', 'object', 'put', `${BUCKETS[target]}/${key}`,
    '--file', file, '--content-type', 'application/json', '--remote'], { stdio: 'inherit', shell: process.platform === 'win32' })
  if (res.status !== 0) throw new Error(`Upload of ${key} failed`)
}

const months = (await readdir(join(dir, 'cves'))).filter((f) => f.endsWith('.json'))
for (const f of months) put(`msrc/cves/${f}`, join(dir, 'cves', f))
put('msrc/index.json', join(dir, 'index.json'))
console.log(`Uploaded ${months.length} month files and index.json to ${BUCKETS[target]}`)
