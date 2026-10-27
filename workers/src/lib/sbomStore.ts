/**
 * Where an asset's SBOM file lives, and what of it is kept in the database.
 *
 * The full CycloneDX JSON goes to R2 (one object per asset, overwritten by each new
 * SBOM); Neon keeps only a small summary in sboms.raw_data plus one `dependencies` row
 * per component, so the database (Neon free plan) does not grow with SBOM size.
 * SBOMs stored before this change still have the whole document in raw_data.
 */

export const sbomObjectKey = (assetId: string) => `sboms/${assetId}.json`

type Json = Record<string, unknown>

/** Summary stored in sboms.raw_data for an SBOM whose document is in R2. `run` is how the
 *  agent built it (2.2.6+), including the folders it could not list this time. */
export function sbomSummary(doc: Json, componentCount: number, scope: unknown, run?: unknown): Json {
  const meta = (doc.metadata ?? {}) as Json
  const tools = meta.tools as Json | unknown[] | undefined
  const toolComponents = Array.isArray(tools) ? tools : Array.isArray((tools as Json | undefined)?.components) ? (tools as Json).components as unknown[] : []
  const tool = toolComponents[0] as Json | undefined
  return {
    stored_in: 'r2',
    component_count: componentCount,
    spec_version: doc.specVersion ?? null,
    generated_by: tool ? `${tool.name ?? 'syft'} ${tool.version ?? ''}`.trim() : null,
    scope: Array.isArray(scope) ? scope.slice(0, 50).map(String) : [],
    ...(run ? { run } : {}),
  }
}

/** CycloneDX licences ({license:{id|name}} or {expression}) as plain strings. */
export function licenseNames(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null
  const names = raw.map((entry) => {
    const e = (entry ?? {}) as Json
    const lic = (e.license ?? {}) as Json
    return String(lic.id ?? lic.name ?? e.expression ?? '').trim()
  }).filter(Boolean)
  return names.length ? [...new Set(names)].slice(0, 10) : null
}

/** True when an SBOM's raw_data is only the summary (document in R2). */
export const isStoredInR2 = (rawData: unknown) => (rawData as Json | null)?.stored_in === 'r2'
