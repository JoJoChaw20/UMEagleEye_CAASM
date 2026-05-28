import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, sql, desc, ne } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { scanResults, agents, assets } from '../db/schema'
import { computeCriticality } from '../lib/criticality'

// ── Ingest helpers ───────────────────────────────────────────────
type NmapPort = { port: number; protocol?: string; service?: string; product?: string; version?: string }

// ── Real-time MAC vendor lookup (api.macvendors.com) ────────────────────────
// Resolves the hardware vendor name from a MAC address at scan time.
// Returns null on error, rate limit, or unknown MAC — non-fatal.
async function fetchMacVendor(mac: string | null | undefined): Promise<string | null> {
  if (!mac) return null
  try {
    // Normalise: strip extra chars, keep first 6 hex digits (OUI)
    const clean = mac.replace(/[^0-9a-fA-F]/g, '').substring(0, 6)
    if (clean.length < 6) return null
    const res = await fetch(`https://api.macvendors.com/${encodeURIComponent(clean)}`, {
      headers: { 'User-Agent': 'EagleEye-CAASM/2.0' },
      signal: AbortSignal.timeout(4000),  // 4s timeout per lookup
    })
    if (!res.ok) return null  // 404 = unknown, 429 = rate limited
    const vendor = (await res.text()).trim()
    return vendor || null
  } catch {
    return null  // network error, timeout — always non-fatal
  }
}

function inferDeviceType(
  ports: NmapPort[],
  ip?: string,
  os?: Record<string, unknown> | null,
): 'server' | 'workstation' | 'network' | 'iot' | 'unknown' {
  if (ip) {
    const last = ip.split('.').pop()
    if (last === '1' || last === '254') return 'network'
  }
  const text = ports.map(p => `${p.product ?? ''} ${p.service ?? ''}`).join(' ').toLowerCase()
  if (/busybox|router|cisco|juniper|aruba|mikrotik|ubiquiti|fortigate|panos|snmp/.test(text)) return 'network'
  if (/rdp|remote.desktop/.test(text) || ports.some(p => p.port === 3389)) return 'workstation'
  if (ports.some(p => [22, 80, 443, 3306, 5432, 8080, 8443, 6379, 27017, 1433].includes(p.port))) return 'server'

  // OS-based fallback when no port signal is available
  if (os) {
    const hint = String(os.dhcp_device_hint ?? os.name ?? os.fingerbank_device ?? '').toLowerCase()
    if (/windows|macos|darwin|desktop|workstation|laptop/.test(hint)) return 'workstation'
    if (/android|iphone|ipad|mobile/.test(hint)) return 'iot'
    if (/server/.test(hint) || (/linux|ubuntu|debian|centos|rhel/.test(hint) && !/desktop/.test(hint))) return 'server'
    if (/cisco|router|switch|ap |access.point|aruba|ubiquiti/.test(hint)) return 'network'
  }

  return 'unknown'
}

function buildOsInfo(os: Record<string, unknown> | null | undefined, ports: NmapPort[]): Record<string, unknown> {
  if (os && Object.keys(os).length > 0) return os
  if (ports.length === 0) return {}
  return {
    ports: ports.map(p => `${p.port}/${p.protocol ?? 'tcp'}`),
    products: [...new Set(ports.map(p => p.product).filter(Boolean))],
    versions: [...new Set(ports.map(p => p.version).filter(Boolean))],
  }
}

function isGatewayIp(ip: string): boolean {
  const last = ip.split('.').pop()
  return last === '1' || last === '254'
}

const app = new Hono<{ Bindings: Env }>()

// ── Helper: SHA-256 hex digest ───────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder()
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(input))
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ── GET / ─── list scans for authenticated user ──────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantCondition = (user.role !== 'superadmin' && user.tenantId)
      ? eq(scanResults.tenantId, user.tenantId)
      : undefined

    const whereClause = tenantCondition
      ? and(ne(scanResults.scanType, 'sbom'), tenantCondition)
      : ne(scanResults.scanType, 'sbom')

    const rows = await db
      .select()
      .from(scanResults)
      .where(whereClause)
      .orderBy(desc(scanResults.startedAt))
      .limit(100)

    return c.json({ scans: rows, total: rows.length })
  } catch (err) {
    console.error('scans GET / error:', err)
    return c.json({ detail: 'Failed to fetch scans' }, 500)
  }
})

// ── GET /pending ─── agent polls for pending scans ───────────────
app.get('/pending', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }
    const incomingKey = authHeader.slice(7)
    const enc = new TextEncoder()
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(incomingKey))
    const incomingKeyHash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('')

    const agentId = c.req.header('X-Agent-ID')
    if (!agentId) return c.json({ detail: 'X-Agent-ID header required' }, 400)

    const db = getDb(c.env.DATABASE_URL)
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent || incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid agent credentials' }, 401)
    }

    await db.update(agents)
      .set({ status: 'online', lastHeartbeat: new Date() })
      .where(eq(agents.agentId, agentId))

    // Auto-expire passive scans pending > 10 min — they loop forever when agent
    // isn't in --passive mode and the agent already marks them failed anyway.
    await db.update(scanResults)
      .set({ status: 'failed', completedAt: new Date() })
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.status, 'pending'),
        eq(scanResults.scanType, 'passive'),
        sql`${scanResults.startedAt} < now() - interval '10 minutes'`,
      ))

    const pending = await db
      .select()
      .from(scanResults)
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.status, 'pending'),
        // Skip SBOM scans whose asset (stored in subnet) no longer exists
        sql`(${scanResults.scanType} != 'sbom' OR EXISTS (
          SELECT 1 FROM assets WHERE asset_id::text = ${scanResults.subnet}
        ))`,
      ))
      .limit(5)

    return c.json({ scans: pending })
  } catch (err) {
    console.error('scans GET /pending error:', err)
    return c.json({ detail: 'Failed to fetch pending scans' }, 500)
  }
})

// ── POST /active ─────────────────────────────────────────────────
// Subnet validation helpers (mirrors frontend logic)
function isValidIpv4(ip: string): boolean {
  return /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(ip)
}

function isValidSubnet(value: string): boolean {
  const trimmed = value.trim()
  if (!trimmed) return false
  const [ip, prefix] = trimmed.split('/')
  if (!ip || !isValidIpv4(ip)) return false
  if (prefix !== undefined) {
    const num = Number(prefix)
    if (!Number.isInteger(num) || num < 0 || num > 32) return false
  }
  return true
}

const activeScanSchema = z.object({
  subnet: z
    .string()
    .optional()
    .refine((v) => v === undefined || v === 'arp-discovery' || isValidSubnet(v), {
      message: 'Invalid subnet — must be a valid IPv4 address or CIDR range (e.g. 192.168.1.0/24)',
    }),
  agent_id: z.string().uuid().optional(),
  tenant_id: z.string().uuid().nullable().optional(),
  scan_type: z.enum(['active', 'passive']).optional().default('active'),
})

app.post('/active', authMiddleware, zValidator('json', activeScanSchema, (result, c) => {
  if (!result.success) {
    const firstIssue = result.error.issues[0]
    const detail = firstIssue?.message ?? 'Invalid request body'
    return c.json({ detail }, 400)
  }
}), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { subnet, agent_id, tenant_id, scan_type } = c.req.valid('json')

    const effectiveScanType = scan_type ?? 'active'
    const effectiveSubnet = effectiveScanType === 'passive' ? 'arp-discovery' : (subnet ?? c.env.SCAN_DEFAULT_SUBNET ?? '192.168.1.0/24')

    // Derive tenant: explicit body > agent's tenant > user's tenant
    let effectiveTenantId = tenant_id !== undefined ? tenant_id : (user.tenantId ?? null)
    if (!effectiveTenantId && agent_id) {
      const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)
      if (agent?.tenantId) effectiveTenantId = agent.tenantId
    }

    // Passive scans are ARP-driven on the agent side — they run continuously
    // via the --passive flag. Triggering one from the UI just creates a record
    // so the dashboard shows it; no nmap dispatch is needed.
    const scanRows = await db
      .insert(scanResults)
      .values({
        agentId: agent_id ?? null,
        tenantId: effectiveTenantId,
        scanType: effectiveScanType,
        subnet: effectiveSubnet,
        status: 'pending',
        hostsDiscovered: 0,
        rawResults: [],
      })
      .returning()

    const scan = scanRows[0]
    if (!scan) {
      return c.json({ detail: 'Failed to create scan record' }, 500)
    }

    // Notify agent via Telegram if agent_id is provided
    if (agent_id && c.env.TELEGRAM_BOT_TOKEN && c.env.TELEGRAM_CHAT_ID) {
      const mode = effectiveScanType === 'passive' ? 'Passive (ARP)' : 'Active (Nmap)'
      const message = `Scan Dispatched\nMode: ${mode}\nScan ID: ${scan.scanId}\nSubnet: ${effectiveSubnet}\nAgent: ${agent_id}\nTriggered by: ${user.username}`
      fetch(`https://api.telegram.org/bot${c.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: c.env.TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: 'Markdown',
        }),
      }).catch((err) => console.error('Telegram notify error:', err))
    }

    const message = effectiveScanType === 'passive'
      ? 'Passive scan registered — agent will flush ARP discoveries to this record'
      : 'Scan dispatched to agent'

    return c.json({ scan_id: scan.scanId, status: scan.status, scan_type: effectiveScanType, message }, 202)
  } catch (err) {
    console.error('scans POST /active error:', err)
    return c.json({ detail: 'Failed to initiate scan' }, 500)
  }
})

// ── POST /ingest ─────────────────────────────────────────────────
const hostSchema = z.object({
  ip: z.string().min(1).max(45),
  hostname: z.string().max(255).nullish(),
  mac: z.string().max(17).nullish(),
  ports: z.array(z.unknown()).optional(),
  os: z.record(z.unknown()).nullish(),
})

const ingestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id: z.string().uuid().optional(),   // optional for passive auto-ingest
  scan_type: z.enum(['active', 'passive']).optional().default('active'),
  hosts: z.array(hostSchema),
})

app.post('/ingest', zValidator('json', ingestSchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    // Agent authentication via API key
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }

    const incomingKey = authHeader.slice(7)
    const incomingKeyHash = await sha256Hex(incomingKey)

    const { agent_id, scan_id, scan_type, hosts } = c.req.valid('json')
    const isPassive = scan_type === 'passive'

    // Fetch agent and verify API key hash
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)

    if (!agent) {
      return c.json({ detail: 'Agent not found' }, 401)
    }

    // Constant-time comparison: compare SHA-256 of incoming key vs stored hash
    if (incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    // Update agent heartbeat and status
    await db
      .update(agents)
      .set({ status: 'online', lastHeartbeat: new Date() })
      .where(eq(agents.agentId, agent_id))

    const tenantId = agent.tenantId

    // ── Pre-fetch existing asset records to stabilise LLM context ──
    // For each discovered host, look up its existing DB record (if any).
    // We pass existing description/deviceType to the LLM so it doesn't
    // flip-flop between scans when port data is sparse or missing.
    const existingAssetMap: Map<string, { deviceType: string; hostname: string | null; owner: string | null }> = new Map()
    for (const host of hosts) {
      try {
        const conds = [eq(assets.ipAddress, host.ip)]
        if (tenantId) conds.push(eq(assets.tenantId, tenantId))
        const [found] = await getDb(c.env.DATABASE_URL)
          .select({ deviceType: assets.deviceType, hostname: assets.hostname, owner: assets.owner })
          .from(assets)
          .where(and(...conds))
          .limit(1)
        if (found) existingAssetMap.set(host.ip, found)
      } catch { /* non-fatal */ }
    }

    // ── Resolve MAC vendor names in real-time (parallel, non-blocking) ──
    // Fetches the actual vendor string (e.g. "TP-Link Technologies Co. Ltd.")
    // from api.macvendors.com for each host. This replaces any static OUI table
    // and gives the LLM genuine, up-to-date manufacturer context.
    const macVendorMap: Map<string, string | null> = new Map()
    await Promise.all(
      hosts.map(async (h) => {
        const vendor = await fetchMacVendor(h.mac as string | null)
        macVendorMap.set(h.ip, vendor)
      })
    )

    // ── LLM Asset Suggestion (DeepSeek via OpenRouter) ──
    let enhancedHosts = [...hosts]
    if (hosts.length > 0 && c.env.OPENROUTER_API_KEY) {
      try {
        // Build enriched payload: real vendor name + existing DB context
        const payload = hosts.map(h => {
          const existing = existingAssetMap.get(h.ip)
          return {
            ip: h.ip,
            mac: h.mac,
            mac_vendor: macVendorMap.get(h.ip) ?? null,  // e.g. "TP-Link Technologies Co. Ltd."
            os: h.os,
            ports: h.ports,
            existing_device_type: existing?.deviceType ?? null,
            existing_hostname: existing?.hostname ?? null,
            existing_owner: existing?.owner ?? null,
          }
        })

        const systemPrompt = `You are a CAASM security analyst. Analyze these discovered network hosts.
You MUST return a JSON object with a single root key "hosts" containing an array of objects. Each object MUST have exactly these keys:
"ip": the host's IP address
"description": A concise, specific description of the device (e.g., "TP-Link Router", "Windows 10 Workstation", "Raspberry Pi IoT Device", "Ubuntu Server"). Use brand names when available. Be specific.
"suggestion": One of exactly: "Accept - Corporate Device", "Ignore - Personal Device", or "Investigate - Unknown"

Rules for consistent, accurate output:
- If existing_hostname or existing_device_type is present for an IP, PRESERVE the prior classification unless new scan data clearly contradicts it.
- If "os.fingerbank_device" is present, use it as the definitive device name (highest confidence).
- If "os.dhcp_device_hint" is present (e.g., "Windows", "Android"), use it as the primary device-type signal.
- If "os.dhcp_vendor_class" starts with "MSFT" → Windows device; "android-dhcp" → Android phone; "dhcpcd" → Linux device.
- If "os.name" is present (from nmap smb-os-discovery), use it for the exact Windows/Linux version.
- If "mac_vendor" is present and no other signals exist, use it to identify the manufacturer.
- If "hostname" contains words like "router", "switch", "ap", "printer", "cam" → strong device-type signal.
- If "existing_device_type" is "network", lean toward "Accept - Corporate Device".
- Gateway IPs (ending in .1 or .254) are ALWAYS network infrastructure — use "Accept - Corporate Device".
- Only use "Investigate - Unknown" when there is genuinely NO identifying information (no vendor, no ports, no DHCP, no hostname, no existing record).

Example:
{ "hosts": [ { "ip": "192.168.0.1", "description": "TP-Link Home Router", "suggestion": "Accept - Corporate Device" } ] }`

        const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${c.env.OPENROUTER_API_KEY}`,
          },
          body: JSON.stringify({
            model: c.env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat',
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: JSON.stringify(payload) }
            ],
            response_format: { type: 'json_object' }
          })
        })

        if (res.ok) {
          const data = await res.json() as any
          let content = data.choices?.[0]?.message?.content || '[]'

          // Robust JSON extraction: find first [ or { and last ] or }
          const firstBrace = content.indexOf('{')
          const firstBracket = content.indexOf('[')
          const lastBrace = content.lastIndexOf('}')
          const lastBracket = content.lastIndexOf(']')

          let startIdx = -1
          let endIdx = -1

          if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) {
            startIdx = firstBracket
            endIdx = lastBracket
          } else if (firstBrace !== -1) {
            startIdx = firstBrace
            endIdx = lastBrace
          }

          if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
            content = content.substring(startIdx, endIdx + 1)
          }

          try {
            const parsed = JSON.parse(content)
            type LlmHost = { ip: string; description: string; suggestion: string }
            if (Array.isArray(parsed) && parsed.length > 0 && !Array.isArray(parsed[0])) {
              const parsedArray = parsed as LlmHost[]
              enhancedHosts = hosts.map(h => {
                const match = parsedArray.find((p) => p.ip?.trim() === h.ip?.trim())
                return match ? { ...h, description: match.description, suggestion: match.suggestion } : h
              })
            } else if (parsed && Array.isArray(parsed.hosts)) {
              enhancedHosts = (hosts as typeof enhancedHosts).map(h => {
                const match = (parsed.hosts as LlmHost[]).find((p) => p.ip?.trim() === h.ip?.trim())
                return match ? { ...h, description: match.description, suggestion: match.suggestion } : { ...h }
              })
            }
          } catch (parseErr) {
            console.error('Failed to parse LLM JSON:', parseErr, 'Raw content:', content)
          }
        } else {
          console.error('OpenRouter API returned error:', res.status)
        }
      } catch (err) {
        console.error('LLM asset suggestion failed:', err)
      }

      // Fallback: if LLM produced no description/suggestion, use a deterministic fallback
      enhancedHosts = enhancedHosts.map(h => {
        const hAny = h as Record<string, unknown>
        if (!hAny['description']) {
          const existing = existingAssetMap.get(h.ip)
          const vendor = macVendorMap.get(h.ip)
          hAny['description'] = existing?.hostname
            ? `${vendor ?? 'Unknown'} Device (${existing.hostname})`
            : (vendor ? `${vendor} Device` : 'AI analysis could not be generated for this asset.')
        }
        if (!hAny['suggestion']) {
          const existing = existingAssetMap.get(h.ip)
          const last = h.ip.split('.').pop()
          const isGateway = last === '1' || last === '254'
          hAny['suggestion'] = isGateway ? 'Accept - Corporate Device'
            : (existing ? 'Accept - Corporate Device' : 'Investigate - Unknown')
        }
        return h
      })
    }

    // Resolve scan record: use provided scan_id, or auto-create one for passive
    let effectiveScanId: string
    if (scan_id) {
      const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scan_id)).limit(1)
      if (!scan) return c.json({ detail: 'Scan not found' }, 404)
      effectiveScanId = scan_id
    } else if (isPassive) {
      // Auto-create a passive scan record so results appear in the dashboard
      const [newScan] = await db
        .insert(scanResults)
        .values({
          agentId: agent_id,
          tenantId: tenantId ?? null,
          scanType: 'passive',
          subnet: 'arp-discovery',
          status: 'completed',
          hostsDiscovered: enhancedHosts.length,
          rawResults: enhancedHosts,
          completedAt: new Date(),
        })
        .returning()
      if (!newScan) return c.json({ detail: 'Failed to create passive scan record' }, 500)
      effectiveScanId = newScan.scanId
    } else {
      return c.json({ detail: 'scan_id is required for active scans' }, 400)
    }

    // Upsert assets — atomic ON CONFLICT so concurrent agents never create duplicates
    const upsertedAssetIds: string[] = []
    for (const host of enhancedHosts) {
      const ports = (host.ports ?? []) as NmapPort[]
      const deviceType = inferDeviceType(ports, host.ip, host.os as Record<string, unknown> | null)
      const osInfo = buildOsInfo(host.os as Record<string, unknown> | null, ports)
      const internetFacing = isGatewayIp(host.ip)

      // Fetch existing record to preserve owner + stable device type
      const conditions = [eq(assets.ipAddress, host.ip)]
      if (tenantId) conditions.push(eq(assets.tenantId, tenantId))
      const [existing] = await db.select().from(assets).where(and(...conditions)).limit(1)

      const resolvedDeviceType = (existing?.deviceType && existing.deviceType !== 'unknown')
        ? existing.deviceType : deviceType
      const resolvedOwner = existing?.owner ?? null

      const critScore = computeCriticality({
        deviceType: resolvedDeviceType,
        isInternetFacing: internetFacing,
        hostname: host.hostname ?? existing?.hostname,
        owner: resolvedOwner,
        osInfo,
      }).score

      // Insert or update — conflict on (ip_address, tenant_id) → update in place
      const [upserted] = await db
        .insert(assets)
        .values({
          tenantId: tenantId || null,
          ipAddress: host.ip,
          hostname: host.hostname ?? existing?.hostname ?? null,
          macAddress: host.mac ?? existing?.macAddress ?? null,
          deviceType: resolvedDeviceType,
          osInfo,
          isInternetFacing: internetFacing,
          criticalityScore: critScore,
          source: isPassive ? 'scan_passive' : 'scan_active',
          lastScanned: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: tenantId
            ? [assets.ipAddress, assets.tenantId]
            : [assets.ipAddress],
          set: {
            hostname: sql`COALESCE(assets.hostname, EXCLUDED.hostname)`,
            macAddress: sql`COALESCE(EXCLUDED.mac_address, assets.mac_address)`,
            osInfo: sql`EXCLUDED.os_info`,
            deviceType: sql`CASE WHEN assets.device_type = 'unknown' THEN EXCLUDED.device_type ELSE assets.device_type END`,
            isInternetFacing: sql`EXCLUDED.is_internet_facing`,
            criticalityScore: sql`EXCLUDED.criticality_score`,
            lastScanned: sql`EXCLUDED.last_scanned`,
            updatedAt: sql`now()`,
          },
        })
        .returning({ assetId: assets.assetId })

      if (upserted?.assetId) upsertedAssetIds.push(upserted.assetId)
    }

    // Mark scan completed — unified for active, dashboard-triggered passive, and
    // auto-created passive records (auto-created are already 'completed' but this is idempotent)
    await db
      .update(scanResults)
      .set({
        status: 'completed',
        hostsDiscovered: enhancedHosts.length,
        rawResults: enhancedHosts,
        completedAt: new Date(),
      })
      .where(eq(scanResults.scanId, effectiveScanId))

    // Trigger drift check advisory for each asset
    for (const assetId of upsertedAssetIds) {
      await c.env.ADVISORY_QUEUE.send({
        type: 'drift_check',
        assetId,
        scanId: effectiveScanId,
        agentId: agent_id,
      })
    }

    return c.json({
      message: 'Scan results ingested',
      scan_id: effectiveScanId,
      scan_type: isPassive ? 'passive' : 'active',
      hosts_discovered: hosts.length,
      assets_upserted: upsertedAssetIds.length,
    })
  } catch (err) {
    console.error('scans POST /ingest error:', err)
    return c.json({ detail: 'Failed to ingest scan results' }, 500)
  }
})

// ── POST /fail ───────────────────────────────────────────────────
app.post('/fail', async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const authHeader = c.req.header('Authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }

    const incomingKey = authHeader.slice(7)
    const incomingKeyHash = await sha256Hex(incomingKey)

    const { agent_id, scan_id } = await c.req.json()

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)

    if (!agent) {
      return c.json({ detail: 'Agent not found' }, 401)
    }

    if (incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    if (scan_id) {
      await db
        .update(scanResults)
        .set({ status: 'failed', completedAt: new Date() })
        .where(eq(scanResults.scanId, scan_id))
    }

    return c.json({ message: 'Scan marked as failed' })
  } catch (err) {
    console.error('scans POST /fail error:', err)
    return c.json({ detail: 'Failed to mark scan as failed' }, 500)
  }
})

// ── GET /status/:scanId ──────────────────────────────────────────
app.get('/status/:scanId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { scanId } = c.req.param()

    const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scanId)).limit(1)

    if (!scan) {
      return c.json({ detail: 'Scan not found' }, 404)
    }

    // Tenant check
    if (user.role !== 'superadmin' && user.tenantId && scan.tenantId !== user.tenantId) {
      return c.json({ detail: 'Scan not found' }, 404)
    }

    return c.json(scan)
  } catch (err) {
    console.error('scans GET /status error:', err)
    return c.json({ detail: 'Failed to fetch scan status' }, 500)
  }
})

export default app
