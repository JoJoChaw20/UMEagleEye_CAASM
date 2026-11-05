/**
 * advisoryKit.ts — PURE helpers for AI advisories (no DB, no network).
 *
 * Design: code owns the FACTS (versions, KEV/EPSS flags, commands, source links,
 * urgency); the model only writes prose around them. The same facts drive a
 * rule-based advisory, so a useful advisory exists even with no AI key or when the
 * AI call fails. Everything here is free and offline.
 *
 * The advisory is stored in the existing text columns with labelled lines, so older
 * readers (chatbot, dashboard, PDF) keep working and no migration is needed:
 *
 *   1. step            <- numbered steps (what every reader already parses)
 *   Why now: ...
 *   Command: ...       <- repeatable
 *   Verify: ...
 *   Rollback: ...
 *   Confidence: High - reason
 *   Sources: label url | label url
 *   Basis: AI + NVD, OSV | Rule-based
 */
import { fixTarget } from './fixTarget'

// ── Untrusted text ───────────────────────────────────────────────
// Hostnames, banners, DHCP names and package names come off the network and can be
// attacker-controlled. They only ever reach the model as quoted JSON data.
export function sanitizeText(value: unknown, max = 160): string {
  return String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max)
}

/** A package name / version safe to show inside a shell command (else null). */
export function safeToken(value: unknown): string | null {
  const s = String(value ?? '').trim()
  return /^[A-Za-z0-9][A-Za-z0-9._+:@/~-]{0,127}$/.test(s) ? s : null
}

const cleanVersion = (v: string) => v.trim().replace(/^[^\d]+/, '')

// ── Commands per package ecosystem (Syft package types) ──────────
export interface CommandSet { upgrade: string[]; verify: string | null; rollback: string | null; note?: string }

export function commandsFor(args: {
  packageType: string | null; pkg: string | null; installed: string | null; to: string | null; windows: boolean
}): CommandSet {
  const type = (args.packageType ?? '').toLowerCase()
  const pkg = safeToken(args.pkg)
  const to = safeToken(args.to ? cleanVersion(args.to) : null)
  const was = safeToken(args.installed ? cleanVersion(args.installed) : null)
  if (!pkg) return { upgrade: [], verify: null, rollback: null }

  switch (type) {
    case 'deb':
      return { upgrade: [`sudo apt update && sudo apt install --only-upgrade ${pkg}`], verify: `dpkg -l ${pkg}`,
               rollback: was ? `sudo apt install ${pkg}=${was}` : null }
    case 'rpm':
      return { upgrade: [`sudo dnf upgrade ${pkg}`], verify: `rpm -q ${pkg}`,
               rollback: `sudo dnf history undo last` }
    case 'apk':
      return { upgrade: [`apk update && apk upgrade ${pkg}`], verify: `apk info -v ${pkg}`, rollback: null }
    case 'python':
      return { upgrade: [to ? `pip install --upgrade "${pkg}>=${to}"` : `pip install --upgrade ${pkg}`],
               verify: `pip show ${pkg}`, rollback: was ? `pip install "${pkg}==${was}"` : null }
    case 'npm':
      return { upgrade: [to ? `npm install ${pkg}@${to}` : `npm update ${pkg}`], verify: `npm ls ${pkg}`,
               rollback: was ? `npm install ${pkg}@${was}` : null }
    case 'go-module':
      return { upgrade: [to ? `go get ${pkg}@v${to} && go mod tidy` : `go get -u ${pkg} && go mod tidy`],
               verify: `go list -m ${pkg}`, rollback: was ? `go get ${pkg}@v${was}` : null }
    case 'gem':
      return { upgrade: [`bundle update ${pkg}`], verify: `bundle list | grep ${pkg}`, rollback: null }
    case 'nuget':
    case 'dotnet':
      return { upgrade: [to ? `dotnet add package ${pkg} --version ${to}` : `dotnet add package ${pkg}`],
               verify: `dotnet list package`, rollback: was ? `dotnet add package ${pkg} --version ${was}` : null }
    case 'rust-crate':
      return { upgrade: [to ? `cargo update -p ${pkg} --precise ${to}` : `cargo update -p ${pkg}`],
               verify: `cargo tree -i ${pkg}`, rollback: null }
    case 'php-composer':
      return { upgrade: [`composer update ${pkg}`], verify: `composer show ${pkg}`, rollback: null }
    case 'java-archive':
    case 'maven':
      return { upgrade: [], verify: null, rollback: null,
               note: `Raise the ${pkg} dependency${to ? ` to ${to}` : ''} in pom.xml or build.gradle and rebuild; also replace any bundled copy of the JAR.` }
    default:
      return { upgrade: [], verify: null, rollback: null,
               note: args.windows
                 ? `Update ${pkg} with its installer or winget (winget upgrade --id <package id>), then restart the application.`
                 : `Update ${pkg} with the vendor's installer or your package manager.` }
  }
}

// ── Urgency ──────────────────────────────────────────────────────
export interface Urgency { level: 'now' | 'soon' | 'planned'; window: string; reasons: string[] }

export function urgencyFor(f: {
  kev: boolean; threatIntel: boolean; epss: number | null; cvss: number | null
  internetFacing: boolean; criticality: number | null; severity: string
}): Urgency {
  const reasons: string[] = []
  if (f.threatIntel) reasons.push('named by threat intelligence')
  if (f.kev) reasons.push('on CISA Known Exploited Vulnerabilities')
  if ((f.epss ?? 0) >= 0.1) reasons.push(`EPSS ${Math.round((f.epss ?? 0) * 100)}% chance of exploitation in 30 days`)
  if (f.internetFacing) reasons.push('the asset is internet-facing')
  if ((f.criticality ?? 0) >= 8) reasons.push(`the asset is critical (${f.criticality}/10)`)
  if (f.cvss != null && f.cvss >= 9) reasons.push(`CVSS ${f.cvss}`)

  if (f.threatIntel || f.kev) return { level: 'now', window: 'within 72 hours', reasons }
  const severe = f.severity === 'critical' || f.severity === 'high'
  if ((f.epss ?? 0) >= 0.1 || (f.internetFacing && severe) || ((f.criticality ?? 0) >= 8 && severe)) {
    return { level: 'soon', window: 'within 7 days', reasons }
  }
  return { level: 'planned', window: 'in the next maintenance window', reasons }
}

// ── Facts handed to the model and to the rule-based writer ───────
export interface AdvisoryFacts {
  eventType: string
  severity: string
  asset: { label: string; type: string; os: string | null; owner: string | null; criticality: number | null
           internetFacing: boolean; windows: boolean; ports: number[] }
  neighbours: { total: number; critical: number }
  cve?: {
    id: string; pkg: string | null; packageType: string | null; installed: string | null
    cvss: number | null; epss: number | null; kev: boolean; threatIntel: boolean; tiTitles: string[]
    cwe: string[]; description: string | null
    group: { openCves: number; kevCves: number; fixTo: string | null; fixedCount: number; noFixCount: number }
    nvd?: { vector: string | null; attackVector: string | null; complexity: string | null
            privileges: string | null; userInteraction: string | null; published: string | null }
    osv?: { summary: string | null; aliases: string[] }
  }
  other: Record<string, unknown>
  urgency: Urgency
  commands: CommandSet
  sources: Array<{ label: string; url: string }>
}

export function buildSources(cve: AdvisoryFacts['cve'] | undefined, extra: Array<{ label: string; url: string }> = []) {
  const out: Array<{ label: string; url: string }> = []
  if (cve) {
    out.push({ label: cve.id, url: `https://nvd.nist.gov/vuln/detail/${cve.id}` })
    if (cve.kev) out.push({ label: 'CISA KEV catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' })
    if (cve.epss != null) out.push({ label: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cve.id}` })
    for (const a of (cve.osv?.aliases ?? []).filter(x => /^GHSA-/.test(x)).slice(0, 1)) {
      out.push({ label: a, url: `https://github.com/advisories/${a}` })
    }
  }
  for (const e of extra) if (!out.some(o => o.url === e.url)) out.push(e)
  return out.slice(0, 6)
}

// ── Rule-based advisory (no AI) ──────────────────────────────────
export interface AdvisoryDraft {
  summary: string
  steps: string[]
  whyNow: string | null
  verify: string | null
  rollback: string | null
  confidence: { level: 'High' | 'Medium' | 'Low'; reason: string }
}

const UPPER = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

export function ruleBasedDraft(f: AdvisoryFacts): AdvisoryDraft {
  const a = f.asset
  const where = `${a.label}${a.owner ? ` (owner: ${a.owner})` : ''}`
  const whyNow = f.urgency.reasons.length ? `${UPPER(f.urgency.reasons.join('; '))}.` : null
  const reach = f.neighbours.total > 0
    ? ` It is connected to ${f.neighbours.total} other asset${f.neighbours.total === 1 ? '' : 's'}${f.neighbours.critical ? `, ${f.neighbours.critical} of them critical` : ''}.` : ''

  if (f.cve) {
    const c = f.cve
    const pkg = c.pkg ?? 'the package'
    const fix = c.group.fixTo
    const summary = `${c.id} affects ${pkg}${c.installed ? ` ${c.installed}` : ''} on ${where}.`
      + (c.description ? ` ${sanitizeText(c.description, 220)}` : '')
      + (c.kev ? ' It is known to be exploited in the wild.' : '') + reach
    const steps: string[] = []
    steps.push(fix
      ? `Upgrade ${pkg}${c.installed ? ` from ${cleanVersion(c.installed)}` : ''} to ${fix}. This one change fixes ${c.group.fixedCount} of ${c.group.openCves} open CVE${c.group.openCves === 1 ? '' : 's'} on this package${c.group.kevCves ? `, including ${c.group.kevCves} on the KEV list` : ''}.`
      : `No fixed version is published for ${pkg} yet. Apply the vendor's mitigation, or restrict access to the affected service until a fix is released.`)
    if (f.commands.note) steps.push(f.commands.note)
    else if (f.commands.upgrade.length) steps.push('Run the command below during a change window, then restart any service that uses the package.')
    if (a.internetFacing && !fix) steps.push('Limit exposure meanwhile: restrict the service to trusted networks or place it behind a VPN or reverse proxy.')
    steps.push(`Rescan the SBOM of ${a.label} (SBOM page → Run SBOM scan). The alert closes by itself once ${pkg} is no longer reported at a vulnerable version.`)
    const verify = f.commands.verify
      ? `Run ${f.commands.verify} and confirm ${fix ? `version ${fix} or later` : 'the new version'}; then rescan the SBOM.`
      : 'Rescan the SBOM and confirm the alert closes.'
    const level = c.cvss != null && fix ? 'High' : fix ? 'Medium' : 'Low'
    return {
      summary, steps, whyNow, verify, rollback: f.commands.rollback
        ? `If the upgrade breaks the service, restore the previous version: ${f.commands.rollback}`
        : 'Take a snapshot or backup before upgrading so you can roll back.',
      confidence: { level, reason: fix ? 'fix version computed from scanner data' : 'no fixed version known' },
    }
  }

  switch (f.eventType) {
    case 'port_opened': {
      const ports = (f.other.port ? [f.other.port] : a.ports).slice(0, 4).join(', ')
      const svc = typeof f.other.service_on_port === 'string' && !/^not identified/.test(f.other.service_on_port) ? f.other.service_on_port : null
      return {
        summary: `A new network port${ports ? ` (${ports}${f.other.protocol ? `/${f.other.protocol}` : ''})` : ''}${svc ? ` running ${svc}` : ''} appeared on ${where}${a.os ? ` (${a.os})` : ''}. If nobody opened it on purpose, it widens the attack surface.${reach}`,
        steps: [
          'Identify the process listening on the port (netstat -ano on Windows, ss -tulpn on Linux).',
          'If the service is expected, document it and accept the change; if not, stop and remove it.',
          a.internetFacing ? 'The host is internet-facing: block the port at the firewall unless it must be public.' : 'Restrict the port to trusted subnets with a host or network firewall rule.',
        ],
        whyNow, verify: 'Rescan the asset and confirm the port is closed or accepted.', rollback: null,
        confidence: { level: 'Medium', reason: 'based on scan data only' },
      }
    }
    case 'new_device':
      return {
        summary: `A device not seen before joined the network: ${where}.${reach}`,
        steps: ['Confirm with the device owner or DHCP/switch records who it belongs to.',
                'If it is authorised, add an owner and move it to My Assets; if not, isolate it from the network.',
                'Check its open ports and services in the asset page for anything unexpected.'],
        whyNow, verify: 'Confirm the asset has an owner and no unexpected open ports.', rollback: null,
        confidence: { level: 'Medium', reason: 'based on discovery data only' },
      }
    case 'cti_match':
      return {
        summary: `${where} matches a threat-intelligence indicator. This is a possible compromise indicator, not confirmation.${reach}`,
        steps: ['Open the alert\'s "Why this alert" panel and read the matching indicator and its source.',
                'Check the host for the behaviour the indicator describes (unexpected connections, new processes, new accounts).',
                'If anything is suspicious, isolate the host and preserve logs before you remediate.',
                'If it is a false positive, mark it so the match does not reopen.'],
        whyNow: whyNow ?? 'Threat-intelligence matches indicate possible compromise.', verify: 'Confirm no suspicious activity remains and the match is resolved.',
        rollback: null, confidence: { level: 'Medium', reason: 'indicator match, not proof of compromise' },
      }
    case 'version_downgrade':
      return {
        summary: `A package or OS component on ${where} moved to an older version. Downgrades can reintroduce fixed vulnerabilities.${reach}`,
        steps: ['Find out who or what changed the version (package manager history, deployment logs).',
                'If unintended, restore the newer version and find the cause.',
                'If intended, record the reason and accept the change.'],
        whyNow, verify: 'Rescan and confirm the version is as expected.', rollback: null,
        confidence: { level: 'Medium', reason: 'based on version drift' },
      }
    default:
      return {
        summary: `A ${f.eventType.replace(/_/g, ' ')} change (${f.severity}) was detected on ${where}.${reach}`,
        steps: ['Review the change details in the alert and decide whether it was planned.',
                'If planned, accept the change to update the baseline; if not, investigate who made it and revert it.',
                'Rescan the asset afterwards to confirm it matches the baseline.'],
        whyNow, verify: 'Rescan the asset and confirm it matches the baseline.', rollback: null,
        confidence: { level: 'Low', reason: 'generic guidance; limited context for this change type' },
      }
  }
}

// ── Validate model output (never trust it) ───────────────────────
const URL_RE = /https?:\/\/\S+/gi

function cleanProse(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null
  const s = sanitizeText(v.replace(URL_RE, '').replace(/`/g, ''), max)
  return s.length >= 3 ? s : null
}

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi

/** Every CVE id in a text, upper-cased. */
export function cveIdsIn(text: string): string[] {
  return [...new Set((text.match(CVE_RE) ?? []).map(s => s.toUpperCase()))]
}

/** Parses the model's JSON. Returns null (the caller keeps the rule-based draft) when it is
 *  not usable, including when it names a CVE that is not in the facts it was given: an
 *  invented id is worse than no AI text. Confidence always comes from the rules, which know
 *  whether a fix version was computed; the model's own rating is ignored. */
export function parseAiDraft(raw: string, fallback: AdvisoryDraft, knownCves: string[] = []): AdvisoryDraft | null {
  let obj: Record<string, unknown>
  try {
    const body = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim()
    const start = body.indexOf('{'); const end = body.lastIndexOf('}')
    obj = JSON.parse(start >= 0 && end > start ? body.slice(start, end + 1) : body)
  } catch { return null }
  const summary = cleanProse(obj.summary, 700)
  const stepsRaw = Array.isArray(obj.steps) ? obj.steps : typeof obj.recommended_action === 'string' ? String(obj.recommended_action).split('\n') : []
  const steps = stepsRaw.map(s => cleanProse(String(s).replace(/^\s*\d+[.)]\s*/, ''), 320)).filter((s): s is string => !!s).slice(0, 6)
  if (!summary || steps.length === 0) return null
  const draft: AdvisoryDraft = {
    summary, steps,
    whyNow: cleanProse(obj.why_now, 300) ?? fallback.whyNow,
    verify: cleanProse(obj.verify, 300) ?? fallback.verify,
    rollback: cleanProse(obj.rollback, 300) ?? fallback.rollback,
    confidence: fallback.confidence,
  }
  const known = new Set(knownCves.map(s => s.toUpperCase()))
  const prose = [draft.summary, ...draft.steps, draft.whyNow, draft.verify, draft.rollback].filter(Boolean).join(' ')
  if (cveIdsIn(prose).some(id => !known.has(id))) return null
  return draft
}

// ── Storage format ───────────────────────────────────────────────
export function formatAdvisoryText(draft: AdvisoryDraft, facts: AdvisoryFacts, basis: string): string {
  const lines: string[] = draft.steps.map((s, i) => `${i + 1}. ${s}`)
  lines.push('')
  if (draft.whyNow) lines.push(`Why now: ${draft.whyNow} Target: ${facts.urgency.window}.`)
  else lines.push(`Why now: Target ${facts.urgency.window}.`)
  for (const cmd of facts.commands.upgrade) lines.push(`Command: ${cmd}`)
  if (draft.verify) lines.push(`Verify: ${draft.verify}`)
  if (draft.rollback) lines.push(`Rollback: ${draft.rollback}`)
  lines.push(`Confidence: ${draft.confidence.level} - ${draft.confidence.reason}`)
  if (facts.sources.length) lines.push(`Sources: ${facts.sources.map(s => `${s.label} ${s.url}`).join(' | ')}`)
  lines.push(`Basis: ${basis}`)
  return lines.join('\n')
}

// ── Group fix summary over a package's open CVE alerts ───────────
export function groupSummary(installed: string | null, rows: Array<{ kev: boolean; fixVersions: unknown }>) {
  const t = fixTarget(installed, rows.map(r => r.fixVersions))
  return {
    openCves: rows.length,
    kevCves: rows.filter(r => r.kev).length,
    fixTo: t.to,
    fixedCount: t.fixed,
    noFixCount: t.noFix,
  }
}
