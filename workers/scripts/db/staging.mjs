// Staging-only data safety. Never targets production.
//
//   node scripts/db/staging.mjs mark              create the staging marker table (once, on the branch)
//   node scripts/db/staging.mjs sanitize          dry run: count what would change
//   node scripts/db/staging.mjs sanitize --apply  scrub personal data and credentials
//
// Reads workers/.env.staging (DB_TARGET=staging). Optional KEEP_EMAILS=a@x.com,b@y.com in that file
// names the accounts you still need to log in with on staging; they keep their login, all others
// are pseudonymised. sanitize refuses unless (1) the host differs from .env.production's host and
// (2) the staging_marker table exists, so it cannot be pointed at production by mistake.
import { neon } from '@neondatabase/serverless'
import { die, loadEnvFile, describe, productionHost } from './lib.mjs'

const [cmd, ...flags] = process.argv.slice(2)
if (!['mark', 'sanitize'].includes(cmd)) die('usage: staging.mjs mark | sanitize [--apply]')

const vars = loadEnvFile('staging')
const host = new URL(vars.DATABASE_URL).hostname
const prodHost = productionHost()
if (prodHost && prodHost === host) die(`.env.staging points at the PRODUCTION host (${host}). Refusing.`)
if (!prodHost) console.log('Note: .env.production not found, so the production-host check was skipped.')
console.log(`\nTarget : STAGING\nDatabase: ${describe(vars.DATABASE_URL)}\n`)

const sql = neon(vars.DATABASE_URL)
const [{ marker }] = await sql(`select to_regclass('public.staging_marker') as marker`)

if (cmd === 'mark') {
  if (marker) {
    console.log('staging_marker already exists. Nothing to do.')
    process.exit(0)
  }
  await sql.transaction([
    sql(`create table public.staging_marker (value text primary key, created_at timestamptz not null default now())`),
    sql(`insert into public.staging_marker (value) values ('staging')`),
  ])
  console.log('staging_marker created. This branch is now identified as staging.')
  process.exit(0)
}

// ── sanitize ──
if (!marker) die('No staging_marker table here. Run "mark" on the staging branch first.')
const [{ value }] = await sql(`select value from public.staging_marker limit 1`)
if (value !== 'staging') die(`staging_marker holds "${value}", expected "staging". Refusing.`)

const keep = (vars.KEEP_EMAILS ?? '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
const [{ n: kept }] = await sql(`select count(*)::int as n from users where lower(email) = any($1)`, [keep])
if (keep.length === 0) die('Set KEEP_EMAILS in .env.staging to the account(s) you will log in with on staging. Otherwise nobody could log in.')
if (kept === 0) die(`None of KEEP_EMAILS exist in users. Check the spelling. (Looked for: ${keep.join(', ')})`)

// MFA columns and tables of migration 0037; a branch taken before 0037 has none of them.
const [{ mfa }] = await sql(`select to_regclass('public.mfa_recovery_codes') is not null as mfa`)

const [counts] = await sql(`select
  (select count(*) from users where lower(email) <> all($1))::int as users_scrambled,
  (select count(*) from users where lower(email) = any($1))::int as users_kept,
  (select count(*) from agents)::int as agents,
  (select count(distinct owner) from assets where owner is not null)::int as owners,
  (select count(*) from audit_logs)::int as audit_logs`, [keep])
if (mfa) {
  const [m] = await sql(`select
    (select count(*) from mfa_recovery_codes c join users u on u.user_id = c.user_id where lower(u.email) <> all($1))::int as recovery_codes,
    (select count(*) from platform_mfa_resets)::int as platform_mfa_resets`, [keep])
  Object.assign(counts, m)
}
console.log('Would change:')
console.table([counts])
if (!flags.includes('--apply')) {
  console.log('Dry run only. Re-run with --apply to write.')
  process.exit(0)
}

await sql.transaction([
  // Everyone except KEEP_EMAILS: pseudonymous identity, no login path, no linked accounts.
  sql(`update users set
         username = 'user_' || substr(md5(user_id::text), 1, 8),
         email = 'user_' || substr(md5(user_id::text), 1, 8) || '@staging.invalid',
         password_hash = 'google_oauth_no_password',
         google_id = null, totp_secret = null, mfa_enabled = false, telegram_chat_id = null
       where lower(email) <> all($1)`, [keep]),
  ...(mfa ? [
    // The rest of their MFA state (0037), and every break-glass reset: production's secret and link
    // hashes must not act on staging. Kept accounts keep their recovery codes.
    sql(`update users set mfa_pending_secret = null, totp_last_step = null where lower(email) <> all($1)`, [keep]),
    sql(`delete from mfa_recovery_codes where user_id in (select user_id from users where lower(email) <> all($1))`, [keep]),
    sql(`delete from platform_mfa_resets`),
  ] : []),
  // Kept accounts still log in, but staging must never message real chats.
  sql(`update users set telegram_chat_id = null where lower(email) = any($1)`, [keep]),
  // Production agent keys must not authenticate against staging.
  sql(`update agents set api_key_hash = 'revoked_on_staging', status = 'offline', last_heartbeat = null`),
  // Stable pseudonyms for asset owners ("Owner 1", "Owner 2", ...).
  sql(`update assets a set owner = 'Owner ' || r.n
       from (select owner, dense_rank() over (order by owner)::int as n
             from (select distinct owner from assets where owner is not null) d) r
       where a.owner = r.owner`),
  sql(`delete from audit_logs`),
])
console.log('Sanitised. Kept accounts: ' + keep.join(', '))
