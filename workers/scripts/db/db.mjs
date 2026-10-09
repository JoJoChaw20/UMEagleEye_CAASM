// Guarded wrapper around drizzle-kit so a migration can never silently hit the wrong database.
//
//   node scripts/db/db.mjs generate
//   node scripts/db/db.mjs status   <staging|production>
//   node scripts/db/db.mjs migrate  <staging|production>
//   node scripts/db/db.mjs baseline <staging|production> [--apply]
//
// Credentials come from workers/.env.staging or workers/.env.production (git-ignored), never from
// the root .env. Each file must declare DB_TARGET matching the target you name on the command line.
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { createInterface } from 'node:readline/promises'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { readMigrationFiles } from 'drizzle-orm/migrator'
import { ROOT, die, loadEnvFile, describe } from './lib.mjs'

const DRIZZLE_DIR = path.join(ROOT, 'drizzle')
const KIT_BIN = path.join(ROOT, 'node_modules/drizzle-kit/bin.cjs')
const TARGETS = ['staging', 'production']

async function confirm(target, host) {
  if (target !== 'production') return
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question(`\nThis writes to PRODUCTION (${host}). Type "production" to continue: `)
  rl.close()
  if (answer.trim() !== 'production') die('Not confirmed. Nothing was changed.')
}

async function inspect(sql) {
  const [{ hist }] = await sql(`select to_regclass('drizzle.__drizzle_migrations') as hist`)
  const [{ has_tables }] = await sql(`select to_regclass('public.users') is not null as has_tables`)
  let last = null
  let rows = 0
  if (hist) {
    const [{ n }] = await sql(`select count(*)::int as n from drizzle.__drizzle_migrations`)
    rows = n
    if (n > 0) {
      const [r] = await sql(`select created_at from drizzle.__drizzle_migrations order by created_at desc limit 1`)
      last = Number(r.created_at)
    }
  }
  const journal = JSON.parse(readFileSync(path.join(DRIZZLE_DIR, 'meta/_journal.json'), 'utf8'))
  const pending = journal.entries.filter(e => last === null || last < e.when)
  return { hasHistory: rows > 0, hasTables: has_tables, pending }
}

function printState(state) {
  console.log(`History table rows : ${state.hasHistory ? 'yes' : 'none'}`)
  console.log(`App tables present : ${state.hasTables ? 'yes' : 'no'}`)
  console.log(`Pending migrations : ${state.pending.length ? state.pending.map(e => e.tag).join(', ') : 'none'}`)
}

async function main() {
  const [cmd, target, ...flags] = process.argv.slice(2)

  if (cmd === 'generate') {
    const r = spawnSync(process.execPath, [KIT_BIN, 'generate', ...(target ? [target, ...flags] : [])], { stdio: 'inherit', cwd: ROOT })
    process.exit(r.status ?? 1)
  }

  if (!['status', 'migrate', 'baseline'].includes(cmd) || !TARGETS.includes(target)) {
    die('usage: db.mjs generate | status|migrate|baseline <staging|production> [--apply]')
  }

  const vars = loadEnvFile(target)
  const host = describe(vars.DATABASE_URL)
  console.log(`\nTarget : ${target.toUpperCase()}\nDatabase: ${host}\n`)
  const sql = neon(vars.DATABASE_URL)
  const state = await inspect(sql)
  printState(state)

  if (cmd === 'status') return

  if (cmd === 'migrate') {
    if (!state.hasHistory && state.hasTables) {
      die('This database has tables but no migration history. Run "baseline" first so the baseline is recorded, not re-run.')
    }
    if (state.pending.length === 0) return console.log('\nNothing to apply.')
    await confirm(target, host)
    const r = spawnSync(process.execPath, [KIT_BIN, 'migrate'], {
      stdio: 'inherit', cwd: ROOT, env: { ...process.env, DATABASE_URL: vars.DATABASE_URL },
    })
    process.exit(r.status ?? 1)
  }

  // baseline: record the existing migration files as already applied, WITHOUT running them.
  if (state.hasHistory) die('Migration history already exists here; baseline is not needed.')
  if (!state.hasTables) die('This database is empty. Use "migrate" to build it instead of baseline.')
  const migrations = readMigrationFiles({ migrationsFolder: DRIZZLE_DIR })
  console.log(`\nWould record ${migrations.length} migration(s) as applied (no SQL from them is executed):`)
  migrations.forEach(m => console.log(`  hash ${m.hash.slice(0, 12)}…  created_at ${m.folderMillis}`))
  if (!flags.includes('--apply')) return console.log('\nDry run only. Re-run with --apply to write.')
  await confirm(target, host)
  await sql.transaction([
    sql(`create schema if not exists drizzle`),
    sql(`create table if not exists drizzle.__drizzle_migrations (id serial primary key, hash text not null, created_at bigint)`),
    ...migrations.map(m => sql(`insert into drizzle.__drizzle_migrations (hash, created_at) values ($1, $2)`, [m.hash, m.folderMillis])),
  ])
  console.log('\nBaseline recorded.')
}

main().catch(e => die(e.message))
