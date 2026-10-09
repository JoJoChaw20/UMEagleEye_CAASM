# Staging environment

Staging is a full copy of the stack that never touches production data.

| Layer | Production | Staging |
|---|---|---|
| Frontend | umeagleeye.csnet.my (Pages `main`) | https://staging.umeagleeye.pages.dev (Pages `staging`) |
| API | `umeagleeye-api` | `umeagleeye-api-staging` (no cron triggers) |
| Database | Neon `production` branch | Neon `staging` branch (sanitised copy, see `workers/scripts/db/`) |
| KV / R2 / queues | existing | `*-staging` copies |

## One-time setup (run in `workers/`, wrangler logged in)

```powershell
npx wrangler kv namespace create KV_CACHE_STAGING      # copy the id into wrangler.toml [[env.staging.kv_namespaces]]
npx wrangler r2 bucket create umeagleeye-reports-staging
npx wrangler queues create advisory-queue-staging
npx wrangler queues create report-queue-staging
```

Secrets (each prompts for the value; always include `--env staging`):

```powershell
npx wrangler secret put DATABASE_URL --env staging        # staging Neon branch, postgresql://...
npx wrangler secret put JWT_SECRET_KEY --env staging      # NEW random value, never the production one
npx wrangler secret put GOOGLE_CLIENT_ID --env staging    # same client id as production
npx wrangler secret put OPENROUTER_API_KEY --env staging
npx wrangler secret put DEEPSEEK_API_KEY --env staging
npx wrangler secret put OTX_API_KEY --env staging
npx wrangler secret put THREATFOX_API_KEY --env staging
npx wrangler secret put NVD_API_KEY --env staging
```

Random JWT secret: `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`

Google Cloud Console: add `https://staging.umeagleeye.pages.dev` to the OAuth client's authorised JavaScript origins.

## Deploying to staging

```powershell
cd workers;  npm run deploy:staging     # API
cd ../frontend; npm run deploy:staging  # frontend -> staging.umeagleeye.pages.dev
```

## Promoting to production (order matters)
1. Test on staging.
2. Fresh `pg_dump` of production.
3. `npm run db:migrate:prod` (in `workers/`), if the change has a migration.
4. `npm run deploy` in `workers/`, then in `frontend/`.
