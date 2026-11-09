// Vulnerable services seen from the network (step 3, Part 3; rules in lib/serviceIdentity.ts).
// Runs as a queue job after an active scan or a network-agent crawl, never during the upload: each
// device's ports are identified with Recog, NVD lists the CVEs of each product version (cached for a
// day in KV), CISA's exploited list marks the urgent ones, and one alert per device and product is
// raised, refreshed or closed. On a device with an SBOM, a product the SBOM lists at that version
// is left to Grype; the rest (containers, programs installed by hand) is checked here. NVD is asked for at most NVD_PER_JOB product versions per job; the
// devices still waiting go into a follow-up job.
import { and, eq, ilike, inArray, or, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { assets, ctiIndicators, dependencies, events, sboms } from '../db/schema'
import { identifyServices, inSbom, planServices, productKey, sbomNames, serviceFinding, type CveRef, type OpenServiceAlert,
  type SbomPackage, type ServiceFinding } from '../lib/serviceIdentity'
import { KEV_SOURCE } from './threatIntel'

const NVD_PER_JOB = 10
const CACHE_SECONDS = 86_400
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

export interface ServiceCveJob { type: 'service_cves'; assetIds: string[]; scannedPorts?: number[] | null }
export interface ServiceCveResult { devices: number; created: number; refreshed: number; resolved: number; nvdCalls: number; deferred: string[] }

interface NvdCve { cve?: { id?: string; vulnStatus?: string; metrics?: Record<string, { cvssData?: { baseScore?: number } }[]> } }

/** The CVEs NVD lists for one product version (CPE 2.3), from the cache or NVD; null when not
 *  fetched (budget used up, or NVD failed: the device is tried again by a later job or scan). */
async function cvesFor(cpe: string, kv: KVNamespace, nvdKey: string | undefined, budget: { left: number; calls: number }): Promise<{ id: string; cvss: number | null }[] | null> {
  const key = `nvd:cpe:${cpe}`
  const cached = await kv.get(key).catch(() => null)
  if (cached) return JSON.parse(cached)
  if (budget.left <= 0) return null
  budget.left--; budget.calls++
  try {
    const res = await fetch(`${NVD}?virtualMatchString=${encodeURIComponent(cpe)}&resultsPerPage=2000`, {
      headers: { ...(nvdKey ? { apiKey: nvdKey } : {}), 'User-Agent': 'UMEagleEye' }, signal: AbortSignal.timeout(20_000),
    })
    if (!res.ok) { console.error(`[service_cves] NVD ${res.status} for ${cpe}`); return null }
    const data = await res.json() as { vulnerabilities?: NvdCve[] }
    const list = (data.vulnerabilities ?? []).filter((v) => v.cve?.id && v.cve.vulnStatus !== 'Rejected').map((v) => {
      const m = v.cve!.metrics ?? {}
      const score = (m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV40 ?? m.cvssMetricV2 ?? [])[0]?.cvssData?.baseScore
      return { id: v.cve!.id!, cvss: typeof score === 'number' ? score : null }
    })
    await kv.put(key, JSON.stringify(list), { expirationTtl: CACHE_SECONDS }).catch(() => {})
    return list
  } catch (err) {
    console.error(`[service_cves] NVD lookup failed for ${cpe}:`, err)
    return null
  }
}

export async function runServiceCves(db: DB, kv: KVNamespace, nvdKey: string | undefined, job: ServiceCveJob,
  now = new Date()): Promise<ServiceCveResult> {
  const result: ServiceCveResult = { devices: 0, created: 0, refreshed: 0, resolved: 0, nvdCalls: 0, deferred: [] }
  const ids = [...new Set(job.assetIds)].slice(0, 500)
  if (!ids.length) return result
  const [devices, withSbom, existing] = await Promise.all([
    db.select({ assetId: assets.assetId, osInfo: assets.osInfo, internetFacing: assets.isInternetFacing })
      .from(assets).where(inArray(assets.assetId, ids)),
    db.select({ assetId: sboms.assetId }).from(sboms).where(inArray(sboms.assetId, ids)),
    db.select({ eventId: events.eventId, assetId: events.assetId, status: events.status, details: events.details })
      .from(events).where(and(eq(events.eventType, 'vulnerable_service'), inArray(events.assetId, ids))),
  ])
  const sbomSet = new Set(withSbom.map((r) => r.assetId))
  const checked = job.scannedPorts?.length ? new Set(job.scannedPorts) : null
  const budget = { left: NVD_PER_JOB, calls: 0 }

  // 0) identify; on a device with an SBOM, which of those products its package list already has
  const identifiedOf = new Map(devices.map((d) => {
    const os = (d.osInfo ?? {}) as { services?: unknown; snmp_sysdescr?: string }
    return [d.assetId, identifyServices(os.services, os.snmp_sysdescr)] as const
  }))
  const packagesOf = new Map<string, SbomPackage[]>()
  const names = [...new Set([...identifiedOf].filter(([id]) => sbomSet.has(id)).flatMap(([, list]) => list.flatMap(sbomNames)))]
  if (names.length) {
    const rows = await db.selectDistinct({ assetId: dependencies.assetId, name: dependencies.name, version: dependencies.version })
      .from(dependencies)
      .where(and(inArray(dependencies.assetId, [...sbomSet]), or(...names.map((n) => ilike(dependencies.name, `%${n}%`)))))
    for (const r of rows) packagesOf.set(r.assetId, [...(packagesOf.get(r.assetId) ?? []), { name: r.name, version: r.version }])
  }
  const coveredOf = new Map<string, Set<string>>()          // "key@port" the device's SBOM lists

  // 1) fetch the CVEs of every product version (within the NVD budget)
  const perDevice = new Map<string, { identified: ReturnType<typeof identifyServices>; cves: Map<string, CveRef[]> }>()
  const kevNeeded = new Set<string>()
  for (const d of devices) {
    let identified = identifiedOf.get(d.assetId) ?? []
    if (sbomSet.has(d.assetId)) {
      const packages = packagesOf.get(d.assetId) ?? []
      const covered = identified.filter((s) => inSbom(s, packages))
      coveredOf.set(d.assetId, new Set(covered.map((s) => `${productKey(s)}@${s.port}`)))
      identified = identified.filter((s) => !covered.includes(s))
    }
    const cves = new Map<string, CveRef[]>()
    let complete = true
    for (const s of identified) {
      if (!s.cpe || cves.has(s.cpe)) continue
      const list = await cvesFor(s.cpe, kv, nvdKey, budget)
      if (list === null) { complete = false; break }
      cves.set(s.cpe, list)
      for (const c of list) kevNeeded.add(c.id)
    }
    if (!complete) { result.deferred.push(d.assetId); continue }
    perDevice.set(d.assetId, { identified, cves })
  }
  result.nvdCalls = budget.calls
  const kev = new Set<string>()
  if (kevNeeded.size) {
    const rows = await db.select({ value: ctiIndicators.value }).from(ctiIndicators)
      .where(and(eq(ctiIndicators.indicatorType, 'cve'), eq(ctiIndicators.source, KEV_SOURCE), inArray(ctiIndicators.value, [...kevNeeded])))
    for (const r of rows) kev.add(r.value)
  }

  // 2) the alerts
  const byAsset = new Map<string, (OpenServiceAlert & { port?: number })[]>()
  for (const e of existing) {
    const dd = (e.details ?? {}) as { key?: string; port?: number }
    if (!dd.key) continue
    const list = byAsset.get(e.assetId) ?? []
    list.push({ eventId: e.eventId, status: e.status, key: dd.key, port: dd.port })
    byAsset.set(e.assetId, list)
  }
  const stmts: unknown[] = []
  for (const d of devices) {
    const got = perDevice.get(d.assetId)
    if (!got) continue
    result.devices++
    const findings: ServiceFinding[] = []
    for (const s of got.identified) {
      const list = (s.cpe ? got.cves.get(s.cpe) : null) ?? []
      const f = serviceFinding(s, list.map((c) => ({ ...c, kev: kev.has(c.id) })), !!d.internetFacing)
      if (f && sbomSet.has(d.assetId)) f.details.outside_sbom = true
      if (f && !findings.some((x) => x.key === f.key)) findings.push(f)
    }
    const mine = byAsset.get(d.assetId) ?? []
    const portOf = (key: string) => mine.find((m) => m.key === key)?.port
    const plan = planServices(findings, mine, {
      onAlertPort: (key) => {
        const p = portOf(key)
        if (p == null) return null
        if (coveredOf.get(d.assetId)?.has(`${key}@${p}`)) return 'sbom'
        return got.identified.some((s) => s.port === p && productKey(s) === key) ? 'no_cve' : null
      },
      checkedPortsOf: (key) => { const p = portOf(key); return !!checked && p != null && checked.has(p) },
    })
    for (const f of plan.create) {
      stmts.push(db.insert(events).values({ assetId: d.assetId, eventType: 'vulnerable_service', severity: f.severity,
        details: f.details, firstSeen: now, lastSeen: now }))
    }
    for (const r of plan.refresh) {
      stmts.push(db.update(events).set({
        severity: r.finding.severity, details: r.finding.details, lastSeen: now, updatedAt: now,
        occurrences: sql`${events.occurrences} + 1`,
        ...(r.reopen ? { status: 'open' as const, resolvedAt: null, resolvedBy: null, resolutionNote: null } : {}),
      }).where(eq(events.eventId, r.eventId)))
    }
    for (const r of plan.resolve) {
      stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: r.why })
        .where(eq(events.eventId, r.eventId)))
    }
    result.created += plan.create.length
    result.refreshed += plan.refresh.length
    result.resolved += plan.resolve.length
  }
  for (let i = 0; i < stmts.length; i += 200) {
    const part = stmts.slice(i, i + 200)
    if (part.length) await db.batch(part as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
  return result
}
