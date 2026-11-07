// Runs the pure-logic unit tests (src/**/*.test.ts): each is bundled with esbuild and
// run with Node's test runner. Worker routes are checked on staging, not here.
//   npm test
import { build } from 'esbuild'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'

const root = new URL('../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')
const find = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? find(join(dir, e.name)) : e.name.endsWith('.test.ts') ? [join(dir, e.name)] : [])
const tests = find(join(root, 'src'))
const out = mkdtempSync(join(tmpdir(), 'eagleeye-tests-'))
try {
  const files = []
  for (const file of tests) {
    const target = join(out, relative(join(root, 'src'), file).replace(/[\/]/g, '_').replace(/\.ts$/, '.mjs'))
    await build({ entryPoints: [file], bundle: true, platform: 'node', format: 'esm', outfile: target, logLevel: 'error' })
    files.push(target)
  }
  const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' })
  process.exitCode = result.status ?? 1
} finally {
  rmSync(out, { recursive: true, force: true })
}
