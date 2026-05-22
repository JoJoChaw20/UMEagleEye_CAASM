/**
 * reset-and-reimport.mjs
 *
 * Clears all assets / topology / relationships then re-imports both company
 * CSV files and rebuilds topology + graph relationships from scratch.
 *
 * Usage (run from project root):
 *   node --env-file=.env scripts/reset-and-reimport.mjs
 */

import { neon } from '../workers/node_modules/@neondatabase/serverless/index.mjs'
import fs   from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT      = path.resolve(__dirname, '..')

// ── DB connection ─────────────────────────────────────────────────
const DATABASE_URL = process.env.DATABASE_URL
if (!DATABASE_URL) { console.error('DATABASE_URL not set'); process.exit(1) }
const sql = neon(DATABASE_URL)

// ── Helpers ───────────────────────────────────────────────────────
function parseCSVRow(line) {
  const result = []
  let current = '', inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++ }
      else { inQuotes = !inQuotes }
    } else if (ch === ',' && !inQuotes) {
      result.push(current.trim()); current = ''
    } else {
      current += ch
    }
  }
  result.push(current.trim())
  return result
}

function getSubnet(ip) { return ip.split('.').slice(0, 3).join('.') }

function classifyAsset(hostname, deviceType, isInternetFacing) {
  const h = (hostname ?? '').toLowerCase()
  if (deviceType === 'network') {
    if (isInternetFacing)                                     return { nodeType: 'gateway',      layer: 1 }
    if (/^(fw|gw|firewall)[-_]/.test(h))                     return { nodeType: 'router',       layer: 2 }
    if (/(core[-_])(sw|switch|router|rtr)/.test(h))          return { nodeType: 'switch',       layer: 2 }
    if (/(^router[-_]|^rtr[-_]|lab[-_]router)/.test(h))     return { nodeType: 'router',       layer: 2 }
    if (/(dist[-_])(sw|switch|router)/.test(h))              return { nodeType: 'switch',       layer: 3 }
    if (/(wifi|^ap[-_]|wap[-_]|access[-_]?point)/.test(h))  return { nodeType: 'access_point', layer: 3 }
    return { nodeType: 'switch', layer: 3 }
  }
  if (deviceType === 'server')      return { nodeType: 'host', layer: isInternetFacing ? 2 : 4 }
  if (deviceType === 'workstation') return { nodeType: 'host', layer: 5 }
  if (deviceType === 'iot')         return { nodeType: 'host', layer: 6 }
  return { nodeType: 'host', layer: 4 }
}

const TYPE_SCORE = { switch: 4, router: 3, gateway: 2, access_point: 2, host: 0 }

function resolveParent(node, others) {
  const subnetCandidates = others
    .filter(n => n.subnet === node.subnet && n.layer < node.layer)
    .sort((a, b) => b.layer - a.layer || (TYPE_SCORE[b.nodeType] ?? 0) - (TYPE_SCORE[a.nodeType] ?? 0))
  if (subnetCandidates.length > 0) return subnetCandidates[0].nodeId

  const targetLayer = node.layer - 1
  const layerCandidates = others
    .filter(n => n.layer === targetLayer)
    .sort((a, b) => (TYPE_SCORE[b.nodeType] ?? 0) - (TYPE_SCORE[a.nodeType] ?? 0))
  if (layerCandidates.length > 0) {
    const lastOctet = parseInt(node.ip.split('.').pop() ?? '1', 10)
    return layerCandidates[lastOctet % layerCandidates.length].nodeId
  }

  const fallback = others.filter(n => n.layer < node.layer).sort((a, b) => b.layer - a.layer)
  return fallback[0]?.nodeId ?? null
}

function pickHub(subnetAssets) {
  return [...subnetAssets].sort((a, b) => {
    // Neon HTTP driver returns snake_case column names
    const aNet = (a.device_type ?? a.deviceType) === 'network'
    const bNet = (b.device_type ?? b.deviceType) === 'network'
    if (aNet && !bNet) return -1
    if (!aNet && bNet) return 1
    const aIp = (a.ip_address ?? a.ipAddress ?? '0.0.0.0')
    const bIp = (b.ip_address ?? b.ipAddress ?? '0.0.0.0')
    return parseInt(aIp.split('.').pop() ?? '0', 10) -
           parseInt(bIp.split('.').pop() ?? '0', 10)
  })[0]
}

// ── Load CSV file → array of row objects ──────────────────────────
function loadCSV(filePath) {
  const lines = fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  const headers = parseCSVRow(lines[0]).map(h => h.toLowerCase().replace(/\s+/g, '_'))
  const rows = []
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCSVRow(lines[i])
    const row = {}
    headers.forEach((h, idx) => { row[h] = cols[idx] ?? '' })
    rows.push(row)
  }
  return rows
}

// ── Step 1: Clear all data ────────────────────────────────────────
async function clearAll() {
  console.log('\n[1/4] Clearing topology_nodes, asset_relationships, assets …')
  await sql`DELETE FROM topology_nodes`
  await sql`DELETE FROM asset_relationships`
  await sql`DELETE FROM assets`
  console.log('      ✓ All cleared')
}

// ── Step 2: Import assets from a CSV for a given tenant ───────────
async function importCSV(csvPath, tenantId, tenantName) {
  const rows = loadCSV(csvPath)
  console.log(`\n[2/4] Importing ${rows.length} rows for "${tenantName}" …`)

  const VALID = new Set(['server', 'workstation', 'network', 'iot', 'unknown'])

  for (const row of rows) {
    const ip = row['ip_address']
    if (!ip) continue

    const rawScore    = parseInt(row['criticality_score'] ?? '5')
    const score       = isNaN(rawScore) ? 5 : Math.min(10, Math.max(1, rawScore))
    const dtRaw       = row['device_type']?.toLowerCase()
    const deviceType  = VALID.has(dtRaw) ? dtRaw : 'unknown'
    const isFacing    = row['is_internet_facing']?.toLowerCase() === 'true'

    const osInfo = {}
    if (row['os_name'])    osInfo.name    = row['os_name']
    if (row['os_version']) osInfo.version = row['os_version']
    if (row['open_ports']) {
      osInfo.ports = row['open_ports'].split(/[\s,]+/).map(p => p.trim()).filter(Boolean)
    }

    await sql`
      INSERT INTO assets
        (tenant_id, hostname, ip_address, mac_address, owner, device_type,
         hardware_vendor, os_info, criticality_score, is_internet_facing)
      VALUES
        (${tenantId}, ${row['hostname'] || null}, ${ip},
         ${row['mac_address'] || null}, ${row['owner'] || null},
         ${deviceType}, ${row['hardware_vendor'] || null},
         ${JSON.stringify(osInfo)}, ${score}, ${isFacing})
      ON CONFLICT DO NOTHING
    `
  }
  console.log(`      ✓ ${rows.length} rows inserted for "${tenantName}"`)
}

// ── Step 3: Infer topology for all tenants ────────────────────────
async function inferTopology() {
  console.log('\n[3/4] Inferring topology …')

  const allTenants = await sql`SELECT tenant_id, name FROM tenants`

  for (const tenant of allTenants) {
    const tid = tenant.tenant_id

    const tenantAssets = await sql`
      SELECT asset_id, hostname, ip_address, device_type, is_internet_facing, criticality_score
      FROM assets WHERE tenant_id = ${tid}
    `
    if (tenantAssets.length === 0) continue

    // Insert nodes without parents first
    const insertedNodes = []
    for (const asset of tenantAssets) {
      const { nodeType, layer } = classifyAsset(
        asset.hostname, asset.device_type, asset.is_internet_facing
      )
      const [node] = await sql`
        INSERT INTO topology_nodes
          (asset_id, tenant_id, node_type, layer, label, metadata)
        VALUES (
          ${asset.asset_id}, ${tid}, ${nodeType}, ${layer},
          ${asset.hostname ?? asset.ip_address},
          ${JSON.stringify({
            ip_address:       asset.ip_address,
            device_type:      asset.device_type,
            criticality_score: asset.criticality_score,
            is_internet_facing: asset.is_internet_facing,
          })}
        )
        RETURNING node_id, asset_id, node_type, layer
      `
      insertedNodes.push({
        nodeId:   node.node_id,
        assetId:  node.asset_id,
        nodeType: node.node_type,
        layer:    node.layer,
        ip:       asset.ip_address,
        subnet:   getSubnet(asset.ip_address),
      })
    }

    // Resolve parents and update
    for (const node of insertedNodes) {
      if (node.layer === 1) continue
      const others  = insertedNodes.filter(n => n.nodeId !== node.nodeId)
      const parentId = resolveParent(node, others)
      if (parentId) {
        await sql`
          UPDATE topology_nodes SET parent_node_id = ${parentId}
          WHERE node_id = ${node.nodeId}
        `
      }
    }

    console.log(`      ✓ ${insertedNodes.length} topology nodes for "${tenant.name}"`)
  }
}

// ── Step 4: Infer relationships (graph) for all tenants ───────────
async function inferRelationships() {
  console.log('\n[4/4] Inferring asset relationships (graph) …')

  const allTenants = await sql`SELECT tenant_id, name FROM tenants`

  for (const tenant of allTenants) {
    const tid = tenant.tenant_id

    const tenantAssets = await sql`
      SELECT asset_id, hostname, ip_address, device_type, is_internet_facing
      FROM assets WHERE tenant_id = ${tid}
    `
    if (tenantAssets.length === 0) continue

    // Group by /24 subnet
    const subnetGroups = new Map()
    for (const a of tenantAssets) {
      const s = getSubnet(a.ip_address)
      if (!subnetGroups.has(s)) subnetGroups.set(s, [])
      subnetGroups.get(s).push(a)
    }

    const rels = []

    // same_subnet: hub MUST be a network device — prevents endpoint→endpoint edges
    for (const subnetAssets of subnetGroups.values()) {
      if (subnetAssets.length < 2) continue
      const hub = pickHub(subnetAssets)
      if ((hub.device_type ?? hub.deviceType) !== 'network') continue
      for (const a of subnetAssets) {
        if (a.asset_id === hub.asset_id) continue
        rels.push({ src: hub.asset_id, tgt: a.asset_id, type: 'same_subnet', conf: '1.00' })
      }
    }

    // connects_to: route inter-subnet edges through the dedicated L3 router when one
    // exists in the gateway subnet (rtr does inter-VLAN routing, not the firewall).
    const sortByLastOctet = (a, b) =>
      parseInt((a.ip_address ?? a.ipAddress ?? '0').split('.').pop() ?? '0') -
      parseInt((b.ip_address ?? b.ipAddress ?? '0').split('.').pop() ?? '0')

    const gateway = (
      tenantAssets.filter(a => (a.is_internet_facing || a.isInternetFacing) && (a.device_type ?? a.deviceType) === 'network').sort(sortByLastOctet)[0]
      ?? tenantAssets.filter(a => (a.device_type ?? a.deviceType) === 'network').sort((a, b) => (a.ip_address ?? a.ipAddress ?? '').localeCompare(b.ip_address ?? b.ipAddress ?? ''))[0]
    )

    // Prefer a dedicated router in the gateway subnet so the graph shows the correct
    // routing path (rtr → dist-sw) instead of the firewall acting as the L3 hub.
    const routingAnchor = gateway
      ? (tenantAssets.find(a => {
          const dt = a.device_type ?? a.deviceType
          const ip = a.ip_address ?? a.ipAddress ?? ''
          const h = (a.hostname ?? '').toLowerCase()
          const facing = a.is_internet_facing || a.isInternetFacing
          return dt === 'network' && !facing
            && getSubnet(ip) === getSubnet(gateway.ip_address ?? gateway.ipAddress ?? '')
            && /^(rtr[-_]|router[-_]|lab[-_]router)/i.test(h)
        }) ?? gateway)
      : gateway

    if (routingAnchor) {
      const anchorSubnet = getSubnet(routingAnchor.ip_address ?? routingAnchor.ipAddress ?? '')
      for (const [subnet, subnetAssets] of subnetGroups.entries()) {
        if (subnet === anchorSubnet) continue
        const hub = pickHub(subnetAssets)
        if (hub && (hub.device_type ?? hub.deviceType) === 'network') {
          rels.push({ src: routingAnchor.asset_id, tgt: hub.asset_id, type: 'connects_to', conf: '0.90' })
        }
      }
    }

    // Orphan remediation: assets with no edges get a connects_to from the gateway
    const edgedIds = new Set(rels.flatMap(r => [r.src, r.tgt]))
    if (gateway) {
      for (const a of tenantAssets) {
        if (!edgedIds.has(a.asset_id) && a.asset_id !== gateway.asset_id) {
          rels.push({ src: gateway.asset_id, tgt: a.asset_id, type: 'connects_to', conf: '0.70' })
        }
      }
    }

    // Insert relationships
    for (const r of rels) {
      await sql`
        INSERT INTO asset_relationships
          (source_asset_id, target_asset_id, relationship_type, confidence)
        VALUES (${r.src}, ${r.tgt}, ${r.type}, ${r.conf})
        ON CONFLICT DO NOTHING
      `
    }

    console.log(`      ✓ ${rels.length} relationships for "${tenant.name}"`)
  }
}

// ── Main ──────────────────────────────────────────────────────────
async function main() {
  console.log('=== UMEagleEye — Reset & Re-import ===')

  // Resolve tenant IDs
  const tenants = await sql`SELECT tenant_id, slug, name FROM tenants`
  console.log('\nTenants found:')
  tenants.forEach(t => console.log(`  ${t.name}  (${t.tenant_id})  slug=${t.slug}`))

  const cfTenant = tenants.find(t =>
    t.slug?.toLowerCase().includes('cyber') || t.name?.toLowerCase().includes('cyber'))
  const vnTenant = tenants.find(t =>
    t.slug?.toLowerCase().includes('vanilla') || t.name?.toLowerCase().includes('vanilla'))

  if (!cfTenant) { console.error('\nERROR: Cyberforce tenant not found'); process.exit(1) }
  if (!vnTenant) { console.error('\nERROR: Vanilla tenant not found');    process.exit(1) }

  const cfCSV = path.join(ROOT, 'cyberforce_corporation_assets.csv')
  const vnCSV = path.join(ROOT, 'vanilla_corporation_assets.csv')

  if (!fs.existsSync(cfCSV)) { console.error(`CSV not found: ${cfCSV}`); process.exit(1) }
  if (!fs.existsSync(vnCSV)) { console.error(`CSV not found: ${vnCSV}`); process.exit(1) }

  await clearAll()
  await importCSV(cfCSV, cfTenant.tenant_id, cfTenant.name)
  await importCSV(vnCSV, vnTenant.tenant_id, vnTenant.name)
  await inferTopology()
  await inferRelationships()

  console.log('\n=== Done ===\n')
}

main().catch(err => { console.error(err); process.exit(1) })
