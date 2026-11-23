import type { Ai, AnalyticsEngineDataset, DurableObjectNamespace, Queue, R2Bucket, KVNamespace } from '@cloudflare/workers-types'

export interface Env {
  // ── Secrets ──
  DATABASE_URL: string
  JWT_SECRET_KEY: string
  GOOGLE_CLIENT_ID: string
  OPENROUTER_API_KEY: string
  DEEPSEEK_API_KEY: string
  OTX_API_KEY: string
  THREATFOX_API_KEY: string
  NVD_API_KEY?: string     // NVD's CVE search for services identified on devices without an agent (services/serviceCves.ts)
  CF_ACCOUNT_ID?: string   // with CF_ANALYTICS_TOKEN: reads performance history (kg/perf.ts)
  CF_ANALYTICS_TOKEN?: string
  PLATFORM_MFA_RESET?: string  // one-time break-glass secret for the Platform Superadmin's MFA
  // ── Vars ──
  APP_ENV: string
  MFA_EXEMPT_USERNAMES?: string
  MFA_EXEMPT_SUPERADMINS?: string  // "true": Platform Superadmins sign in without MFA (lib/mfaFlow.ts isMfaExempt)
  OPENROUTER_MODEL: string
  SCAN_DEFAULT_SUBNET: string
  JWT_EXPIRE_MINUTES: string
  FRONTEND_URL: string
  MAIL_FROM?: string       // sender address; with EMAIL, turns email on (services/mailer.ts)

  // ── Bindings ──
  REPORTS_BUCKET: R2Bucket
  KV_CACHE: KVNamespace
  ADVISORY_QUEUE: Queue
  REPORT_QUEUE: Queue
  AI?: Ai                  // embeddings for the knowledge graph
  EMAIL?: { send(msg: unknown): Promise<unknown> }  // Cloudflare Email binding; absent = email off
  PERF?: AnalyticsEngineDataset  // request and job timings
  // Routine agent check-ins answered without the database (durable/agentHub.ts); absent = always the database
  AGENT_HUB?: DurableObjectNamespace<import('./durable/agentHub').AgentHub>
}

export interface JWTPayload {
  sub: string        // user_id
  role: string
  username: string
  tenant_id?: string
  iat: number
  exp: number
  purpose?: unknown  // set only on MFA step tokens, never on access tokens
}

export interface AuthUser {
  userId: string
  role: string
  username: string
  tenantId?: string
  actions: string[]
}
