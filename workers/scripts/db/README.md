# Database migrations

Schema source of truth: `src/db/schema.ts`. Migrations live in `drizzle/` and are applied with
`scripts/db/db.mjs`, which refuses to run against a database that does not match the target you name.

## Setup (once)
Copy `.env.staging.example` to `.env.staging` and `.env.production.example` to `.env.production`
(both git-ignored) and fill in `DATABASE_URL` (`postgresql://...`, not `+asyncpg`). Each file's
`DB_TARGET` must match its name, or the script stops.

## Commands
| Command | Effect |
|---|---|
| `npm run db:generate` | Diff `schema.ts` against the last snapshot and write a new SQL file. Touches no database. |
| `npm run db:status:staging` / `db:status:prod` | Read-only. Shows the target and the pending migrations. |
| `npm run db:migrate:staging` / `db:migrate:prod` | Apply pending migrations. Production asks you to type `production`. |
| `npm run db:baseline:prod` / `db:baseline:prod:apply` | Dry run / write. (PowerShell drops `npm run x -- --flag`, so use the separate `:apply` script.) |

`db:push` was removed on purpose: it rewrites the live schema from `schema.ts` with no history.

## Baseline
`drizzle/0000_baseline.sql` creates the whole schema for an empty database. The existing production
database already has that schema, so it is **recorded as applied** with `db:baseline:prod` instead
of being run. Do this once, before creating the staging branch, so the branch inherits the record.
The older hand-applied SQL is archived in `drizzle/legacy/`.

## Release order
1. Edit `schema.ts`, run `db:generate`, review the SQL (prefer additive changes).
2. `db:migrate:staging`, test at the staging URL.
3. Take a fresh `pg_dump` of production.
4. `db:migrate:prod`, then deploy the Worker, then the frontend.
