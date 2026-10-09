// Shared display metadata and helpers for the Inventory page and Asset detail page.

export const DEVICE_TYPE_META = {
  server:      { icon: '🖥️', label: 'Server' },
  workstation: { icon: '💻', label: 'Workstation' },
  network:     { icon: '🌐', label: 'Network' },
  iot:         { icon: '📡', label: 'IoT' },
  unknown:     { icon: '❓', label: 'Unknown' },
}

// source = the LAST observation method only (membership is in_my_assets).
export const SOURCE_META = {
  manual:       { label: 'Manual',       cls: 'bg-dark-600/40 text-dark-300 border-dark-500/30' },
  scan_active:  { label: 'Active scan',  cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  scan_passive: { label: 'Passive scan', cls: 'bg-dark-600/40 text-dark-400 border-dark-500/30' },
}

export const SCOPES = {
  mine:       { label: 'My Assets',  inMyAssets: 'true' },
  discovered: { label: 'Discovered', inMyAssets: 'false' },
}

export const assetName = (a) => a?.hostname || a?.ipAddress || a?.ip_address || 'Unnamed asset'

// Index duplicate groups (GET /assets/duplicates) by asset id: each asset maps to
// the OTHER members of its group plus the group's reasons and confidence. The same
// evidence rules drive Duplicates/merge, so a "match" here is exactly what the
// Duplicates panel would show.
export function buildMatchIndex(groups) {
  const index = new Map()
  for (const g of groups || []) {
    for (const a of g.assets) {
      index.set(a.assetId, {
        groupId: g.groupId,
        confidence: g.confidence,
        reasons: g.reasons,
        others: g.assets.filter((o) => o.assetId !== a.assetId),
      })
    }
  }
  return index
}
