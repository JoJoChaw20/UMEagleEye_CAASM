import type { DB } from '../db/client'
import { assets, events } from '../db/schema'
import { isNotNull, isNull } from 'drizzle-orm'

interface OsInfo {
  ports?: number[]
  packages?: Record<string, string>
  os_name?: string
  os_version?: string
}

function detectDrift(
  baseline: OsInfo,
  current: OsInfo
): Array<{ type: string; severity: 'low' | 'medium' | 'high' | 'critical'; details: Record<string, unknown> }> {
  const drifts: Array<{ type: string; severity: 'low' | 'medium' | 'high' | 'critical'; details: Record<string, unknown> }> = []

  const basePorts = new Set(baseline.ports ?? [])
  const curPorts = new Set(current.ports ?? [])

  // New open ports
  for (const p of curPorts) {
    if (!basePorts.has(p)) {
      drifts.push({
        type: 'port_opened',
        severity: p < 1024 ? 'high' : 'medium',
        details: { port: p },
      })
    }
  }

  // Closed ports (port_closed = low severity)
  for (const p of basePorts) {
    if (!curPorts.has(p)) {
      drifts.push({
        type: 'port_closed',
        severity: 'low',
        details: { port: p },
      })
    }
  }

  // OS version change
  if (baseline.os_version && current.os_version && baseline.os_version !== current.os_version) {
    const isDowngrade = baseline.os_version > current.os_version
    drifts.push({
      type: isDowngrade ? 'version_downgrade' : 'version_upgrade',
      severity: isDowngrade ? 'high' : 'low',
      details: { from: baseline.os_version, to: current.os_version },
    })
  }

  // Package changes
  const basePkgs = baseline.packages ?? {}
  const curPkgs = current.packages ?? {}

  for (const [pkg, ver] of Object.entries(curPkgs)) {
    if (!(pkg in basePkgs)) {
      drifts.push({ type: 'new_package', severity: 'low', details: { package: pkg, version: ver } })
    } else if (basePkgs[pkg] !== ver) {
      const isDowngrade = (basePkgs[pkg] ?? '') > ver
      drifts.push({
        type: isDowngrade ? 'version_downgrade' : 'version_upgrade',
        severity: isDowngrade ? 'medium' : 'low',
        details: { package: pkg, from: basePkgs[pkg], to: ver },
      })
    }
  }
  for (const pkg of Object.keys(basePkgs)) {
    if (!(pkg in curPkgs)) {
      drifts.push({ type: 'removed_package', severity: 'low', details: { package: pkg } })
    }
  }

  return drifts
}

export async function runDriftAudit(db: DB): Promise<number> {
  // Fetch assets that have a baseline and have been scanned
  const assetRows = await db
    .select()
    .from(assets)
    .where(isNotNull(assets.baselineState))

  let driftCount = 0

  for (const asset of assetRows) {
    if (!asset.baselineState || !asset.osInfo) continue

    const baseline = asset.baselineState as OsInfo
    const current = asset.osInfo as OsInfo
    const drifts = detectDrift(baseline, current)

    for (const drift of drifts) {
      // Avoid duplicate events: check if same event was recorded in last 24h
      await db.insert(events).values({
        assetId: asset.assetId,
        eventType: drift.type as typeof events.$inferInsert['eventType'],
        severity: drift.severity,
        details: drift.details,
      })
      driftCount++
    }
  }

  return driftCount
}
