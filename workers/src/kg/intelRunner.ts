/**
 * intelRunner.ts - the chat's live lookups (lookup_cve, lookup_attack_technique, lookup_cwe), run with
 * the same tools and access rules as the MCP server (mcp/intel.ts, mcp/tools.ts canUse). The tenant
 * comes from the signed-in user, never from the model; arguments are validated again here.
 */
import { z } from 'zod'
import { getDb } from '../db/client'
import type { Env } from '../types'
import { INTEL_TOOLS } from '../mcp/intel'
import { canUse, type ToolContext, type ToolUser } from '../mcp/tools'
import type { GraphCtx, IntelToolName } from './agent'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** The tenant a lookup counts in: the user's own; for the superadmin the picked one or none (all, as counts). */
export function intelTenant(user: ToolUser, pickedTenant: string | null | undefined): string | undefined {
  if (user.role === 'superadmin') return pickedTenant && UUID.test(pickedTenant) ? pickedTenant : undefined
  return user.tenantId ?? undefined
}

export function intelRunner(env: Env, user: ToolUser, pickedTenant: string | null | undefined): NonNullable<GraphCtx['intel']> {
  let ctx: ToolContext | null = null
  return async (name: IntelToolName, args: Record<string, unknown>) => {
    const tool = INTEL_TOOLS.find(t => t.name === name)
    if (!tool) return { error: 'Unknown lookup.' }
    if (!canUse(tool, user)) return { error: 'This user\'s role cannot use that lookup.' }
    const parsed = z.object(tool.input).strict().safeParse(args)
    if (!parsed.success) return { error: `Invalid arguments: ${parsed.error.issues[0]?.message ?? 'wrong shape'}` }
    // A user other than the superadmin with no tenant reads nothing (scope.ts fails closed too).
    // The database client is made on first use: the bundled CWE and ATT&CK lookups never need it.
    let db: ToolContext['db'] | null = null
    ctx ??= { get db() { return (db ??= getDb(env.DATABASE_URL)) }, env, user, tenantId: intelTenant(user, pickedTenant) }
    try {
      return await tool.run(ctx, parsed.data)
    } catch (err) {
      console.error(`[kg-intel] ${name} failed:`, err instanceof Error ? err.message : err)
      return { error: 'The lookup failed; answer without it.' }
    }
  }
}
