import type { Queue, R2Bucket, KVNamespace } from '@cloudflare/workers-types'

export interface Env {
  // ── Secrets ──
  DATABASE_URL: string
  JWT_SECRET_KEY: string
  GOOGLE_CLIENT_ID: string
  OPENROUTER_API_KEY: string
  DEEPSEEK_API_KEY: string
  OTX_API_KEY: string
  THREATFOX_API_KEY: string
  NVD_API_KEY: string
  // ── Vars ──
  APP_ENV: string
  OPENROUTER_MODEL: string
  SCAN_DEFAULT_SUBNET: string
  JWT_EXPIRE_MINUTES: string
  FRONTEND_URL: string

  // ── Bindings ──
  REPORTS_BUCKET: R2Bucket
  KV_CACHE: KVNamespace
  ADVISORY_QUEUE: Queue
  REPORT_QUEUE: Queue
  HYPERDRIVE: Hyperdrive
}

export interface JWTPayload {
  sub: string        // user_id
  role: string
  username: string
  tenant_id?: string
  iat: number
  exp: number
}

export interface AuthUser {
  userId: string
  role: string
  username: string
  tenantId?: string
}
