import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'

const BATCH_SIZE = 100   // rows per INSERT statement

type CtiRow = typeof ctiIndicators.$inferInsert

interface OtxPulse {
  indicators: Array<{ type: string; indicator: string }>
  attack_ids?: Array<{ name: string; display_name: string }>
  tags?: string[]
}

interface ThreatFoxIoc {
  ioc: string
  ioc_type: string
  confidence_level: number
  malware?: string
  threat_type?: string
  tags?: string[] | null
}

// ── MITRE ATT&CK technique ID → tactic name ──────────────────────────────────
// OTX attack_ids give technique codes (T1566) not tactic names — look them up.
const TECHNIQUE_TO_TACTIC: Record<string, string> = {
  // Reconnaissance
  T1595:'Reconnaissance', T1592:'Reconnaissance', T1589:'Reconnaissance',
  T1590:'Reconnaissance', T1591:'Reconnaissance', T1596:'Reconnaissance',
  T1597:'Reconnaissance', T1598:'Reconnaissance',
  // Resource Development
  T1583:'Resource Development', T1584:'Resource Development', T1585:'Resource Development',
  T1586:'Resource Development', T1587:'Resource Development', T1588:'Resource Development',
  T1608:'Resource Development',
  // Initial Access
  T1189:'Initial Access', T1190:'Initial Access', T1133:'Initial Access',
  T1200:'Initial Access', T1566:'Initial Access', T1091:'Initial Access',
  T1195:'Initial Access', T1199:'Initial Access',
  // Execution
  T1059:'Execution', T1203:'Execution', T1559:'Execution', T1106:'Execution',
  T1053:'Execution', T1129:'Execution', T1072:'Execution', T1569:'Execution',
  T1204:'Execution', T1047:'Execution',
  // Persistence
  T1098:'Persistence', T1197:'Persistence', T1547:'Persistence', T1037:'Persistence',
  T1176:'Persistence', T1554:'Persistence', T1136:'Persistence', T1543:'Persistence',
  T1546:'Persistence', T1574:'Persistence', T1525:'Persistence', T1137:'Persistence',
  T1542:'Persistence', T1078:'Persistence',
  // Privilege Escalation
  T1548:'Privilege Escalation', T1134:'Privilege Escalation', T1055:'Privilege Escalation',
  T1484:'Privilege Escalation', T1611:'Privilege Escalation',
  // Defense Evasion
  T1140:'Defense Evasion', T1006:'Defense Evasion', T1480:'Defense Evasion',
  T1211:'Defense Evasion', T1222:'Defense Evasion', T1564:'Defense Evasion',
  T1562:'Defense Evasion', T1070:'Defense Evasion', T1202:'Defense Evasion',
  T1036:'Defense Evasion', T1578:'Defense Evasion', T1112:'Defense Evasion',
  T1027:'Defense Evasion', T1647:'Defense Evasion', T1207:'Defense Evasion',
  T1014:'Defense Evasion', T1218:'Defense Evasion', T1216:'Defense Evasion',
  T1553:'Defense Evasion', T1221:'Defense Evasion', T1205:'Defense Evasion',
  T1127:'Defense Evasion', T1535:'Defense Evasion', T1550:'Defense Evasion',
  T1497:'Defense Evasion', T1600:'Defense Evasion',
  // Credential Access
  T1110:'Credential Access', T1555:'Credential Access', T1212:'Credential Access',
  T1187:'Credential Access', T1606:'Credential Access', T1056:'Credential Access',
  T1557:'Credential Access', T1556:'Credential Access', T1111:'Credential Access',
  T1621:'Credential Access', T1040:'Credential Access', T1003:'Credential Access',
  T1528:'Credential Access', T1558:'Credential Access', T1539:'Credential Access',
  T1552:'Credential Access',
  // Discovery
  T1087:'Discovery', T1010:'Discovery', T1217:'Discovery', T1580:'Discovery',
  T1538:'Discovery', T1526:'Discovery', T1619:'Discovery', T1613:'Discovery',
  T1622:'Discovery', T1482:'Discovery', T1083:'Discovery', T1615:'Discovery',
  T1046:'Discovery', T1135:'Discovery', T1201:'Discovery', T1120:'Discovery',
  T1069:'Discovery', T1057:'Discovery', T1012:'Discovery', T1018:'Discovery',
  T1518:'Discovery', T1082:'Discovery', T1614:'Discovery', T1016:'Discovery',
  T1049:'Discovery', T1033:'Discovery', T1007:'Discovery', T1124:'Discovery',
  // Lateral Movement
  T1210:'Lateral Movement', T1534:'Lateral Movement', T1570:'Lateral Movement',
  T1563:'Lateral Movement', T1021:'Lateral Movement', T1080:'Lateral Movement',
  // Collection
  T1560:'Collection', T1123:'Collection', T1119:'Collection', T1115:'Collection',
  T1530:'Collection', T1213:'Collection', T1005:'Collection', T1039:'Collection',
  T1025:'Collection', T1074:'Collection', T1114:'Collection', T1185:'Collection',
  T1113:'Collection', T1125:'Collection',
  // Command and Control
  T1071:'Command and Control', T1092:'Command and Control', T1132:'Command and Control',
  T1001:'Command and Control', T1568:'Command and Control', T1573:'Command and Control',
  T1008:'Command and Control', T1105:'Command and Control', T1104:'Command and Control',
  T1095:'Command and Control', T1571:'Command and Control', T1572:'Command and Control',
  T1090:'Command and Control', T1219:'Command and Control', T1102:'Command and Control',
  // Exfiltration
  T1020:'Exfiltration', T1030:'Exfiltration', T1048:'Exfiltration', T1041:'Exfiltration',
  T1011:'Exfiltration', T1052:'Exfiltration', T1567:'Exfiltration', T1029:'Exfiltration',
  T1537:'Exfiltration',
  // Impact
  T1531:'Impact', T1485:'Impact', T1486:'Impact', T1565:'Impact', T1491:'Impact',
  T1561:'Impact', T1499:'Impact', T1495:'Impact', T1490:'Impact', T1498:'Impact',
  T1496:'Impact', T1489:'Impact', T1529:'Impact',
}

// ── ThreatFox threat_type → MITRE tactic ─────────────────────────────────────
const THREATFOX_TYPE_TO_TACTIC: Record<string, string> = {
  botnet_cc:        'Command and Control',
  c2:               'Command and Control',
  payload_delivery: 'Initial Access',
  banking_trojan:   'Collection',
  ransomware:       'Impact',
  infostealer:      'Collection',
  loader:           'Execution',
  rat:              'Command and Control',
  dropper:          'Execution',
  exploit:          'Initial Access',
  phishing:         'Initial Access',
  malware:          'Execution',
}

// ── OTX pulse tag → MITRE tactic (fallback when attack_ids absent) ────────────
// Community pulse tags are free-text but converge on a small vocabulary.
const OTX_TAG_TO_TACTIC: Record<string, string> = {
  // Initial Access
  phishing: 'Initial Access', 'spear-phishing': 'Initial Access',
  spearphishing: 'Initial Access', exploit: 'Initial Access',
  vulnerability: 'Initial Access', 'drive-by': 'Initial Access',
  // Execution
  malware: 'Execution', trojan: 'Execution', virus: 'Execution',
  worm: 'Execution', dropper: 'Execution', loader: 'Execution',
  downloader: 'Execution', backdoor: 'Execution',
  // Command and Control
  c2: 'Command and Control', 'c&c': 'Command and Control',
  botnet: 'Command and Control', rat: 'Command and Control',
  'remote-access': 'Command and Control', 'command-and-control': 'Command and Control',
  // Collection
  infostealer: 'Collection', stealer: 'Collection', keylogger: 'Collection',
  credential: 'Collection', 'data-theft': 'Collection', spy: 'Collection',
  // Impact
  ransomware: 'Impact', wiper: 'Impact', destructive: 'Impact',
  // Exfiltration
  exfiltration: 'Exfiltration',
  // Persistence
  persistence: 'Persistence', rootkit: 'Persistence',
  // Lateral Movement
  'lateral-movement': 'Lateral Movement', lateral_movement: 'Lateral Movement',
  // Privilege Escalation
  'privilege-escalation': 'Privilege Escalation',
}

// ── OTX indicator type → last-resort default tactic ───────────────────────────
// Used only when neither attack_ids nor pulse tags resolve a tactic.
// Reflects the most statistically common role for each type in OTX threat data.
const OTX_TYPE_DEFAULT_TACTIC: Record<string, string> = {
  ip:     'Command and Control',  // majority of malicious IPs in OTX are C2 hosts
  domain: 'Command and Control',  // most malicious domains are C2 / phishing infra
  url:    'Initial Access',       // URLs are typically delivery / phishing vectors
  hash:   'Execution',            // file hashes identify malware samples
  email:  'Initial Access',       // email addresses appear in phishing campaigns
}

/** Derive tactic from a MITRE technique code like "T1566" or "T1566.001". */
function tacticFromTechniqueCode(code: string | null | undefined): string | null {
  if (!code) return null
  const base = (code.split('.')[0] ?? code).toUpperCase()
  return TECHNIQUE_TO_TACTIC[base] ?? null
}

function mapOtxType(t: string): 'ip' | 'domain' | 'hash' | 'url' | 'email' | null {
  const m: Record<string, 'ip' | 'domain' | 'hash' | 'url' | 'email'> = {
    'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
    'URL': 'url', 'FileHash-MD5': 'hash', 'FileHash-SHA256': 'hash',
    'FileHash-SHA1': 'hash', 'email': 'email',
  }
  return m[t] ?? null
}

function mapThreatFoxType(t: string): 'ip' | 'domain' | 'hash' | 'url' | null {
  if (t === 'ip:port' || t === 'ip') return 'ip'
  if (t.includes('domain')) return 'domain'
  if (t.includes('hash') || t.includes('md5') || t.includes('sha')) return 'hash'
  if (t.includes('url')) return 'url'
  return null
}

/** Upsert rows in chunks — each chunk = one INSERT … ON CONFLICT statement. */
async function batchUpsert(db: DB, rows: CtiRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE)
    await db
      .insert(ctiIndicators)
      .values(chunk)
      .onConflictDoUpdate({
        target: ctiIndicators.value,
        set: {
          lastSeen:        sql`excluded.last_seen`,
          attackTactic:    sql`excluded.attack_tactic`,
          attackTechnique: sql`excluded.attack_technique`,
          confidenceScore: sql`excluded.confidence_score`,
        },
      })
  }
}

// ── OTX ──────────────────────────────────────────────────────────────
export async function ingestOtx(db: DB, apiKey: string): Promise<number> {
  if (!apiKey) {
    console.log('[OTX] No API key — skipping')
    return 0
  }

  // /pulses/activity returns recent community pulses, not just subscriptions
  const res = await fetch(
    'https://otx.alienvault.com/api/v1/pulses/activity?limit=50&page=1',
    { headers: { 'X-OTX-API-KEY': apiKey } },
  )
  if (!res.ok) {
    console.error('[OTX] HTTP error:', res.status, await res.text().catch(() => ''))
    return 0
  }

  const data = await res.json() as { results?: OtxPulse[]; count?: number }
  console.log(`[OTX] ${data.results?.length ?? 0} pulses (total=${data.count ?? '?'})`)

  const rows: CtiRow[] = []
  const now = new Date()

  for (const pulse of data.results ?? []) {
    // Level 1 — authoritative: attack_ids carry explicit MITRE technique codes
    const techniqueCode = pulse.attack_ids?.[0]?.name ?? null
    let pulsetactic     = tacticFromTechniqueCode(techniqueCode)

    // Level 2 — tag-based: pulse tags (e.g. "ransomware", "botnet") → tactic
    if (!pulsetactic && pulse.tags?.length) {
      for (const tag of pulse.tags) {
        const mapped = OTX_TAG_TO_TACTIC[tag.toLowerCase().trim()]
        if (mapped) { pulsetactic = mapped; break }
      }
    }

    for (const ind of pulse.indicators ?? []) {
      const itype = mapOtxType(ind.type)
      if (!itype || !ind.indicator) continue

      // Level 3 — type default: most probable tactic for this indicator type
      const tactic = pulsetactic ?? OTX_TYPE_DEFAULT_TACTIC[itype] ?? null

      rows.push({
        source:          'AlienVault OTX',
        indicatorType:   itype,
        value:           ind.indicator,
        confidenceScore: '0.70',
        attackTactic:    tactic,
        attackTechnique: techniqueCode,
        lastSeen:        now,
      })
    }
  }

  if (!rows.length) { console.log('[OTX] No usable indicators'); return 0 }

  console.log(`[OTX] Upserting ${rows.length} rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// ── ThreatFox ────────────────────────────────────────────────────────
export async function ingestThreatFox(db: DB, apiKey: string): Promise<number> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (apiKey) headers['Auth-Key'] = apiKey

  const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers,
    body: JSON.stringify({ query: 'get_iocs', days: 7 }),
  })

  if (!res.ok) {
    console.error('[ThreatFox] HTTP error:', res.status, await res.text().catch(() => ''))
    return 0
  }

  const data = await res.json() as { query_status?: string; data?: ThreatFoxIoc[] }
  console.log(`[ThreatFox] query_status=${data.query_status} records=${data.data?.length ?? 0}`)

  if (!data.data?.length) return 0

  const now  = new Date()
  const seen = new Set<string>()
  const rows: CtiRow[] = []

  for (const ioc of data.data) {
    const itype = mapThreatFoxType(ioc.ioc_type)
    if (!itype || !ioc.ioc) continue

    // ip:port → strip port so it can cross-ref internal asset IPs
    const value = itype === 'ip' && ioc.ioc.includes(':')
      ? (ioc.ioc.split(':')[0] ?? ioc.ioc)
      : ioc.ioc

    if (seen.has(value)) continue
    seen.add(value)

    rows.push({
      source:          'ThreatFox',
      indicatorType:   itype,
      value,
      confidenceScore: ((ioc.confidence_level ?? 50) / 100).toFixed(2),
      attackTactic:    THREATFOX_TYPE_TO_TACTIC[ioc.threat_type ?? ''] ?? null,
      lastSeen:        now,
    })
  }

  console.log(`[ThreatFox] Upserting ${rows.length} unique rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// ── Combined ─────────────────────────────────────────────────────────
export async function ingestAllFeeds(
  db: DB,
  otxKey: string,
  threatFoxKey: string,
): Promise<{ otx: number; threatfox: number }> {
  const [otxResult, tfResult] = await Promise.allSettled([
    ingestOtx(db, otxKey),
    ingestThreatFox(db, threatFoxKey),
  ])

  const otx       = otxResult.status === 'fulfilled' ? otxResult.value : 0
  const threatfox = tfResult.status  === 'fulfilled' ? tfResult.value  : 0

  if (otxResult.status === 'rejected') console.error('[OTX] Fatal:', otxResult.reason)
  if (tfResult.status  === 'rejected') console.error('[ThreatFox] Fatal:', tfResult.reason)

  console.log(`[CTI] Done — OTX: ${otx}, ThreatFox: ${threatfox}`)
  return { otx, threatfox }
}
