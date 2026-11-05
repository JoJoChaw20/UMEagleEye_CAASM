/**
 * mcp/scope.ts — the tenant filter every tool applies. It fails closed: a user other than
 * the platform superadmin with no tenant sees nothing (the auth middleware already refuses
 * such accounts; this keeps the tools safe even without it).
 */
import { eq, sql, type SQL } from 'drizzle-orm'
import { assets } from '../db/schema'
import { advisoryInTenant } from '../lib/advisoryScope'
import type { DB } from '../db/client'

interface ScopeCtx { db: DB; user: { role: string }; tenantId?: string }

const noTenant = (ctx: ScopeCtx) => ctx.user.role !== 'superadmin' && !ctx.tenantId

export const assetScope = (ctx: ScopeCtx): SQL | undefined =>
  (ctx.tenantId ? eq(assets.tenantId, ctx.tenantId) : noTenant(ctx) ? sql`false` : undefined)

export const advScope = (ctx: ScopeCtx): SQL | undefined =>
  (ctx.tenantId ? advisoryInTenant(ctx.db, ctx.tenantId) : noTenant(ctx) ? sql`false` : undefined)
