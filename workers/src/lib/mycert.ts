/**
 * MyCERT (CyberSecurity Malaysia) advisories — PURE parsing, no network or database.
 *
 * MyCERT publishes advisories and alerts without credentials: an RSS feed of the newest 20
 * (https://www.mycert.org.my/portal/rss) and one HTML page per advisory. The feed items hold only
 * the title, the link and "Published date: 11 November 2026, 9:33 pm" (Malaysia time, no zone); the
 * page holds the rest, under numbered headings whose numbers change from one advisory to the next
 * ("4.0 Indicators of Compromise" in one, "4.0 Affected Products" in another), so sections are
 * found by their heading's words.
 *
 * What is taken from a page (services/mycert.ts stores it as a platform threat-intel event):
 *   - the CVE IDs it names, except in its References;
 *   - which of them it says are exploited in the wild (exploitedCves): a sentence naming the CVE
 *     and saying so, not negated ("no evidence of exploitation"), or the title saying so;
 *   - indicators: MyCERT defangs every domain, URL, IP and email address it lists ("evil[.]com"),
 *     so only defanged ones count (a plain "ethers.js" or "1.1.1.1" in the text is not an IOC);
 *     file hashes only in an Indicators of Compromise section. A table row that says the value is
 *     legitimate, shared or "context only", or not to be blocked, is kept for reference only;
 *   - ATT&CK technique IDs, MyCERT's own rating ("MyCERT rates this HIGH"), the affected products
 *     and the opening paragraph.
 */
import { detectType, hostOf, normalise, refang, type IocType } from './iocParse'
import { warninglistOf } from './warninglist'
import { techniqueIds } from './attack'

export const MYCERT_ORIGIN = 'mycert'
export const MYCERT_SOURCE = 'MyCERT'
export const MYCERT_RSS_URL = 'https://www.mycert.org.my/portal/rss'
// The page of one advisory by its number: the stable link (the feed's own links use a page id).
export const mycertAdvisoryUrl = (id: string) => `https://www.mycert.org.my/portal/advisory?id=${encodeURIComponent(id)}`

export type MycertKind = 'advisory' | 'alert' | 'report' | 'other'
export type MycertRating = 'critical' | 'high' | 'medium' | 'low'

export interface MycertRssItem { id: string; title: string; link: string; publishedAt: Date | null }

export interface MycertIoc { type: IocType; value: string; toIds: boolean; comment: string | null }

export interface MycertAdvisory {
  id: string                 // MA-1506.112026
  number: number             // 1506
  kind: MycertKind
  headline: string           // the title after "MyCERT Advisory - "
  publishedAt: Date | null   // the page's date, midnight Malaysia time
  tags: string[]             // MyCERT's own keywords
  rating: MycertRating | null
  summary: string
  cves: string[]
  exploitedCves: string[]
  exploitedEvidence: Record<string, string>   // CVE → MyCERT's sentence saying it is exploited
  products: string[]
  iocs: MycertIoc[]
  techniques: string[]       // T-numbers as written; the caller keeps the ones ATT&CK has
}

// ── text helpers ─────────────────────────────────────────────────
const NAMED: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—', hellip: '…',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', middot: '·', copy: '©', reg: '®', trade: '™',
}

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m
    }
    return NAMED[e.toLowerCase()] ?? m
  })
}

const clean = (s: string) => decodeEntities(s.replace(/<[^>]*>/g, ' ')).replace(/[\s ]+/g, ' ').trim()

/** HTML as lines of text: one per paragraph, list item or table row; a row's cells separated by tabs. */
export function htmlLines(html: string): string[] {
  const text = html
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, '')
    .replace(/<\/t[dh]>/gi, '\t')
    .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d|table|ul|ol)>/gi, '\n')
  return text.split('\n')
    .map((l) => l.split('\t').map(clean).filter((c, i, all) => c || i < all.length - 1).join('\t').replace(/\t+$/, ''))
    .filter((l) => l.replace(/\t/g, '').trim() !== '')
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

/** "11 Nov 2026" or "11 November 2026, 9:33 pm" (Malaysia time, UTC+8) as a Date; null when unreadable. */
export function parseMytDate(text: string): Date | null {
  const m = /(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})(?:\s*,?\s*(\d{1,2}):(\d{2})\s*(am|pm)?)?/i.exec(text)
  if (!m) return null
  const month = MONTHS.indexOf(m[2]!.slice(0, 3).toLowerCase())
  if (month < 0) return null
  let hour = m[4] ? Number(m[4]) : 0
  const ampm = m[6]?.toLowerCase()
  if (ampm === 'pm' && hour < 12) hour += 12
  if (ampm === 'am' && hour === 12) hour = 0
  const utc = Date.UTC(Number(m[3]), month, Number(m[1]), hour - 8, m[5] ? Number(m[5]) : 0)
  return Number.isNaN(utc) ? null : new Date(utc)
}

const ID_RE = /^(MA-(\d+)\.\d{6})\b/

// ── RSS ──────────────────────────────────────────────────────────
const tag = (xml: string, name: string) => {
  const m = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i').exec(xml)
  return m ? m[1]!.replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/, '$1').trim() : ''
}

/** The feed's items (newest first, as MyCERT lists them); items without an advisory number are left out. */
export function parseMycertRss(xml: string): MycertRssItem[] {
  const out: MycertRssItem[] = []
  for (const m of xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)) {
    const title = clean(tag(m[1]!, 'title'))
    const id = ID_RE.exec(title)?.[1]
    if (!id) continue
    out.push({
      id, title,
      link: decodeEntities(tag(m[1]!, 'link')),
      publishedAt: parseMytDate(clean(tag(m[1]!, 'description'))),
    })
  }
  return out
}

// ── advisory page ────────────────────────────────────────────────
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi
const TECHNIQUE_RE = /\bT1\d{3}(?:\.\d{3})?\b/g
const HEADING_RE = /^(\d{1,2})\.(\d{1,2})\.?\s+(\S.{0,110})$/
// A value given as exploited in the wild. A CISA KEV listing counts (CISA lists only exploited CVEs),
// said as a listing: "added to the KEV catalog", "still listed in KEV", not a bare "KEV".
const EXPLOITED_RE = /\b(actively[ -]exploited|exploited in the wild|in[- ]the[- ]wild exploitation|active(?:ly)? exploitation|being (?:actively )?exploited|under (?:active )?exploitation|exploitation (?:has been |was |is )?(?:observed|detected|confirmed|reported|seen)|confirmed exploitation|(?:added|listed|included|remains?|still listed) (?:to|in|on) (?:the )?(?:CISA(?:'s|’s)? )?(?:KEV|Known Exploited Vulnerabilities)|KEV[- ]listed)\b/i
// a title is short: "Hardening After New Exploitations" says it too
const TITLE_EXPLOITED_RE = /\bexploit(?:ed|ations?)\b/i
const NEGATED_RE = /\b(no (?:[\w-]+ ){0,3}(?:evidence|reports?|indications?|signs?) (?:of|that)|not (?:yet |been |currently |publicly |known to (?:be|have been) )*(?:actively )?exploited|not (?:yet |been |currently )*(?:listed|added|included)|not (?:in|on) (?:the )?(?:CISA(?:'s|’s)? )?(?:KEV|Known Exploited)|no (?:[\w-]+ ){0,3}exploitation|none (?:of [\w ]{1,30})?(?:is|are) (?:in|on|listed)|not aware of|there is no|has not been|have not been|is not known|unexploited|before (?:it is|they are) exploited|could be exploited|may be exploited|if exploited|once exploited)\b/i
// a References line pointing at the CVE's KEV entry
const KEV_REFERENCE_RE = /known[- ]exploited[- ]vulnerabilities/i
// a table row saying its value must not be blocked or alerted on as-is
const REFERENCE_ONLY_RE = /\b(do not (?:blanket[- ])?(?:block|blocklist|block-list)|not (?:be )?block(?:ed|listed)?|legitimate|context only|unrelated (?:business|site|content|service)|shared (?:hosting|service|infrastructure)|false positive|benign|sinkhole[d]?|parked)\b/i
const DEFANGED_RE = /\[\.\]|\[dot\]|\(\.\)|\{\.\}|\[at\]|\[@\]|^hxxps?:/i
const HASH_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i

interface Section { major: number; minor: number; title: string; lines: string[] }

// MyCERT's contact block at the end of every advisory ("For further enquiries, please contact MyCERT
// ... E-mail: cyber999[at]cybersecurity.my"): not part of the advisory, runs to the next heading.
const CONTACT_RE = /^for further enquiries\b/i
const OWN_HOSTS = /(^|\.)(cybersecurity\.my|mycert\.org\.my)$/i

function sections(lines: string[]): Section[] {
  const out: Section[] = [{ major: 0, minor: 0, title: '', lines: [] }]
  let contact = false
  for (const line of lines) {
    const h = !line.includes('\t') ? HEADING_RE.exec(line) : null
    if (h) {
      contact = false
      out.push({ major: Number(h[1]), minor: Number(h[2]), title: h[3]!.trim(), lines: [] })
    } else if (contact || CONTACT_RE.test(line)) {
      contact = true
    } else {
      out[out.length - 1]!.lines.push(line)
    }
  }
  return out
}

/** Sections under a top-level heading (N.0) that matches `re`, and sub-headings that match it alone
 *  ("4.1 Indicators of Compromise" under "4.0 Technical Details"). */
function region(all: Section[], re: RegExp): Set<Section> {
  const out = new Set<Section>()
  let major = -1
  for (const s of all) {
    if (s.minor === 0) major = s.major > 0 && re.test(s.title) ? s.major : -1
    if (s.major === major || (s.minor > 0 && re.test(s.title))) out.add(s)
  }
  return out
}

const IOC_HEADING = /indicators? of compromise|\bIoCs?\b|indicators/i
const REFERENCES_HEADING = /^references?\b|^sources?\b|^further reading/i
const AFFECTED_HEADING = /affected|vulnerable (?:products|versions)/i
const INTRO_HEADING = /introduction|overview|background|summary|description/i

/** One indicator from a word of the text, or null. Network values count only when defanged. */
export function iocOf(word: string, inIocSection: boolean): { type: IocType; value: string } | null {
  const w = word.replace(/^[("'“‘<\[]+(?!\.)/, '').replace(/[)"'”’>,;:.]+$/, '')
  if (!w) return null
  if (HASH_RE.test(w)) return inIocSection ? { type: 'hash', value: w.toLowerCase() } : null
  if (!DEFANGED_RE.test(w)) return null
  let v = refang(w)
  let type = detectType(v)
  if (!type || type === 'cve') {
    // a host with a path and no scheme ("evil[.]com/x.jpg"): the host
    const host = v.split(/[/?#]/)[0]!.replace(/:\d+$/, '')
    v = host
    type = detectType(host)
  }
  if (!type || type === 'cve' || type === 'software') return null
  const value = normalise(type, v)
  if (!value || OWN_HOSTS.test(hostOf(type, value))) return null
  // a masked address ("62.90.129[.]xxx"): "xxx" is a top-level domain, but this is no domain
  if (type === 'domain' && /^(\d+\.)+[a-z]+$/.test(value)) return null
  return { type, value }
}

function iocsOfLine(line: string, inIocSection: boolean): { type: IocType; value: string }[] {
  // A table row: the values in its first cell holding any (the rest describe it: source, status,
  // the address a domain resolved to). A line of text: every value in it.
  const cells = line.split('\t')
  for (const cell of cells) {
    const found = cell.split(/[\s,;|]+/).map((w) => iocOf(w, inIocSection)).filter((x): x is { type: IocType; value: string } => !!x)
    if (found.length || cells.length === 1) return found
  }
  return []
}

/**
 * PURE: the CVEs a text says are exploited in the wild, each with the sentence that says so. A
 * paragraph's sentence saying so names them, or the paragraph's next sentence does ("...warning of the
 * active exploitation of multiple vulnerabilities. The vulnerabilities, tracked as CVE-..."). The title
 * counts too; when it names no CVE and the advisory has one, that one. A public exploit or proof of
 * concept is not exploitation, and neither is a negated sentence ("not listed in KEV").
 */
export function exploitedEvidence(paragraphs: string[], title: string, cves: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  const add = (c: string, why: string) => { const id = c.toUpperCase(); if (cves.includes(id) && !out[id]) out[id] = why.slice(0, 300) }
  const said = (s: string) => EXPLOITED_RE.test(s) && !NEGATED_RE.test(s)
  for (const p of paragraphs) {
    let pending: string | null = null
    for (const s of p.replace(/\t/g, ' ').split(/(?<=[.!?])\s+(?=[A-Z(“"])/)) {
      const named = s.match(CVE_RE) ?? []
      if (said(s)) {
        for (const c of named) add(c, s)
        pending = named.length ? null : s
      } else if (pending && named.length && !NEGATED_RE.test(s)) {
        for (const c of named) add(c, `${pending} ${s}`)
        pending = null
      } else {
        pending = null
      }
    }
  }
  if (said(title) || (TITLE_EXPLOITED_RE.test(title) && !NEGATED_RE.test(title))) {
    const inTitle = title.match(CVE_RE) ?? []
    for (const c of inTitle.length ? inTitle : cves.length === 1 ? cves : []) add(c, title)
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)))
}

const RATING_RE = /\bMyCERT\s+(?:rates|rated|assesses|assessed|considers|classifies|classified)\b[^.]{0,60}?\b(critical|high|medium|moderate|low)\b/i

/** The advisory on a MyCERT advisory page; null when the page holds none (an error page). */
export function parseMycertAdvisory(html: string): MycertAdvisory | null {
  const head = /<h[46][^>]*>\s*(MA-\d+\.\d{6})\s*:\s*([\s\S]*?)<\/h[46]>/i.exec(html)
  if (!head) return null
  const id = head[1]!
  const fullTitle = clean(head[2]!)
  const kindWord = /^MyCERT\s+(Advisory|Alert|Report)\b/i.exec(fullTitle)?.[1]?.toLowerCase()
  const headline = fullTitle.replace(/^MyCERT\s+(?:Advisory|Alert|Report)\s*[-–—:]\s*/i, '').trim() || fullTitle

  // The date, kind and keywords follow the title: <li><i class="fas fa-calendar-alt"></i> 11 Nov 2026</li>...
  const after = html.slice(head.index + head[0].length)
  const metaEnd = after.search(/<\/ul>/i)
  const meta = metaEnd >= 0 ? after.slice(0, metaEnd) : ''
  const metaItem = (icon: RegExp) => {
    for (const li of meta.split(/<li\b/i)) if (icon.test(li)) return clean(li.replace(/^[^>]*>/, ''))
    return ''
  }
  const typeText = metaItem(/fa-file\b/).toLowerCase()
  const kind: MycertKind = (['advisory', 'alert', 'report'] as const).find((k) => typeText.includes(k))
    ?? (kindWord as MycertKind | undefined) ?? 'other'
  const tags = metaItem(/fa-tags?\b/).split(',').map((t) => t.trim()).filter((t) => t && t.length <= 50)

  // The body: the post's content block, up to the page's side bar.
  const start = after.search(/class="(?:post-cont|desc-news)"/i)
  let body = start >= 0 ? after.slice(start) : after
  const end = body.search(/start blog right|class="side-bar"|class="blog-list-simple"/i)
  if (end > 0) body = body.slice(0, end)
  body = body.replace(/^[^>]*>/, '')

  const all = sections(htmlLines(body))
  const refs = region(all, REFERENCES_HEADING)
  const iocSections = region(all, IOC_HEADING)
  const kept = all.filter((s) => !refs.has(s))
  const text = kept.flatMap((s) => [s.title, ...s.lines])

  const cvesIn = (lines: string[]) => [...new Set(lines.flatMap((l) => l.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))].sort()
  const refLines = [...refs].flatMap((s) => s.lines)
  // Older advisories name the CVE only in their References (an NVD or KEV link): then those.
  const named = cvesIn([fullTitle, tags.join(' '), ...text])
  const cves = named.length ? named : cvesIn(refLines)
  const evidence = exploitedEvidence(text, fullTitle, cves)
  for (const line of refLines) {
    if (!KEV_REFERENCE_RE.test(line) || NEGATED_RE.test(line)) continue
    for (const c of cvesIn([line])) if (cves.includes(c) && !evidence[c]) evidence[c] = `Listed in CISA's Known Exploited Vulnerabilities catalog (MyCERT's references: ${line.slice(0, 200)})`
  }

  const byKey = new Map<string, MycertIoc>()
  for (const s of kept) {
    const inIoc = iocSections.has(s)
    for (const line of s.lines) {
      const refOnly = REFERENCE_ONLY_RE.test(line)
      for (const ioc of iocsOfLine(line, inIoc)) {
        const key = `${ioc.type}:${ioc.value}`
        const prev = byKey.get(key)
        // listed twice: kept for reference when either place says so
        if (prev) { if (refOnly) prev.toIds = false; continue }
        byKey.set(key, { ...ioc, toIds: !refOnly, comment: line.replace(/\t/g, ' | ').slice(0, 300) })
      }
    }
  }

  // Affected products: a table's first column (not its header row), else the section's short lines
  // (a list); the prose around them is left out.
  const affected = [...region(all, AFFECTED_HEADING)].flatMap((s) => s.lines)
  const rows = affected.filter((l) => l.includes('\t'))
  const products = [...new Set((rows.length ? rows.map((l) => l.split('\t')[0]!.trim()) : affected.filter((l) => l.length <= 120 && !l.endsWith(':')))
    // a header row: "Product", "Product / component", "Distribution", "Affected versions"...
    .filter((p) => p && !/^(products?|software|platforms?|affected( (products?|versions?|software))?|vendors?|components?|versions?|distributions?|items?|names?|packages?|systems?)(\s*[/&,]\s*\w+)*$/i.test(p))
    .map((p) => p.slice(0, 160)))].slice(0, 15)

  const intro = all.find((s) => s.major > 0 && INTRO_HEADING.test(s.title)) ?? all.find((s) => s.major > 0)
  let summary = ''
  for (const line of intro?.lines ?? []) {
    if (line.includes('\t')) continue
    summary = summary ? `${summary} ${line}` : line
    if (summary.length >= 400) break
  }
  if (summary.length > 700) {
    const cut = summary.slice(0, 700)
    summary = cut.slice(0, Math.max(cut.lastIndexOf('. ') + 1, 500)).trim()
  }

  const ratingWord = (text.join(' ').match(RATING_RE)?.[1] ?? '').toLowerCase()
  const rating: MycertRating | null = ratingWord === 'moderate' ? 'medium' : (['critical', 'high', 'medium', 'low'] as const).find((r) => r === ratingWord) ?? null

  return {
    id,
    number: Number(ID_RE.exec(id)?.[2] ?? 0),
    kind,
    headline,
    publishedAt: parseMytDate(metaItem(/fa-calendar/)),
    tags,
    rating,
    summary,
    cves,
    exploitedCves: Object.keys(evidence).sort(),
    exploitedEvidence: evidence,
    products,
    iocs: [...byKey.values()],
    techniques: [...new Set(text.flatMap((l) => l.match(TECHNIQUE_RE) ?? []))].sort(),
  }
}

/** The event's threat level: MyCERT's own rating, else high when it names an exploited CVE. */
export function mycertThreatLevel(a: Pick<MycertAdvisory, 'rating' | 'exploitedCves'>): 'low' | 'medium' | 'high' {
  if (a.rating === 'critical' || a.rating === 'high') return 'high'
  if (a.rating === 'medium' || a.rating === 'low') return a.rating
  return a.exploitedCves.length ? 'high' : 'medium'
}

/** The event title shown on alerts: "MyCERT MA-1506: Actively Exploited Outlook Zero-Day (CVE-2026-124194)". */
export function mycertEventTitle(a: Pick<MycertAdvisory, 'id' | 'headline'>): string {
  const short = a.id.replace(/\.\d{6}$/, '')
  const t = `MyCERT ${short}: ${a.headline}`
  return t.length <= 200 ? t : `${t.slice(0, 197).trimEnd()}...`
}

export interface MycertEventRow {
  externalId: string
  title: string
  description: string
  threatLevel: 'low' | 'medium' | 'high'
  tags: string[]
  attackTechniques: string[] | null
  exploitedCves: string[]
  publishedAt: Date
  sourceMeta: {
    url: string; kind: MycertKind; rating: MycertRating | null; products: string[]
    exploited_evidence: Record<string, string>; ioc_count: number; cve_count: number
  }
}
export interface MycertAttributeRow { indicator_type: IocType; value: string; to_ids: boolean; comment: string | null; warning: string | null }

/**
 * PURE: the platform event and its attributes for an advisory (services/mycert.ts saves them).
 * `listedAt` is the time the feed gives (the page has the day only). CVEs are attributes like an
 * analyst's ("flag CVE alerts"); indicators carry the warninglist they are on (never alert) and
 * MyCERT's row as their comment.
 */
export function mycertRecords(a: MycertAdvisory, listedAt: Date | null, now = new Date()): { event: MycertEventRow; attributes: MycertAttributeRow[] } {
  const techniques = techniqueIds(a.techniques)
  const url = mycertAdvisoryUrl(a.id)
  const byValue = new Map<string, MycertAttributeRow>()
  for (const c of a.cves) {
    byValue.set(c, { indicator_type: 'cve', value: c, to_ids: true, warning: null,
      comment: a.exploitedEvidence[c] ? `Exploited in the wild, per MyCERT: ${a.exploitedEvidence[c]}`.slice(0, 1000) : null })
  }
  // one row per value (an event holds a value once: idx_cti_event_value)
  for (const i of a.iocs) {
    if (byValue.has(i.value)) continue
    byValue.set(i.value, { indicator_type: i.type, value: i.value, to_ids: i.toIds, comment: i.comment, warning: warninglistOf(i.type, i.value) })
  }
  const kindLabel = a.kind === 'other' ? null : a.kind[0]!.toUpperCase() + a.kind.slice(1)
  const tags = [...new Set(['MyCERT', ...(kindLabel ? [kindLabel] : []), ...a.tags])].slice(0, 20)
  return {
    event: {
      externalId: a.id,
      title: mycertEventTitle(a),
      description: [a.summary, `Source: MyCERT ${a.id}, ${url}`].filter(Boolean).join('\n\n').slice(0, 5000),
      threatLevel: mycertThreatLevel(a),
      tags,
      attackTechniques: techniques.length ? techniques : null,
      exploitedCves: a.exploitedCves,
      publishedAt: listedAt ?? a.publishedAt ?? now,
      sourceMeta: {
        url, kind: a.kind, rating: a.rating, products: a.products, exploited_evidence: a.exploitedEvidence,
        ioc_count: a.iocs.length, cve_count: a.cves.length,
      },
    },
    attributes: [...byValue.values()],
  }
}

// ── Harvest: fetching MyCERT during a request from Malaysia ──────────
// MyCERT's site (behind Cloudflare) puts a JavaScript challenge in front of requests from outside
// Malaysia and Singapore, and a Worker's own requests count as coming from the country of whoever's
// request is being handled: a visitor's, or the US when nothing is (cron, queue job). Measured on
// 27 Nov 2026 with probe Workers: started by a request from Malaysia, 200 even when placed in
// Virginia; started by a cron, 403 even when placed in Singapore. So the Worker fetches MyCERT while it
// handles a request from MY or SG (an agent's check-in, someone using the dashboard), at most every
// HARVEST_EVERY_MS, keeps the pages in KV, and the nightly step reads them (services/mycert.ts).
export const HARVEST_COUNTRIES: ReadonlySet<string> = new Set(['MY', 'SG'])
export const HARVEST_EVERY_MS = 3 * 3600_000
// Pages fetched longer ago than this are not used: the nightly step fails, saying when MyCERT was last
// fetched, so feed health shows that no request from Malaysia has come in.
export const HARVEST_STALE_MS = 48 * 3600_000
// New advisory pages per harvest (each is one request of the 50 a Worker request may make); MyCERT
// publishes about one a day, so the rest come with the next harvest.
export const HARVEST_PAGES = 10

/** PURE: whether a request from `country` should fetch MyCERT now (`lastAt`: the last harvest, ms). */
export function shouldHarvest(country: string | null | undefined, lastAt: number | null, now: number, force = false): boolean {
  if (!country || !HARVEST_COUNTRIES.has(country.toUpperCase())) return false
  return force || lastAt === null || now - lastAt >= HARVEST_EVERY_MS
}

/** PURE: the advisory pages a harvest fetches: the feed's advisories not stored yet, oldest first. */
export function harvestUrls(items: MycertRssItem[], known: ReadonlySet<string>, max = HARVEST_PAGES): string[] {
  return items.filter((i) => !known.has(i.id)).reverse().slice(0, max).map((i) => i.link || mycertAdvisoryUrl(i.id))
}

/** PURE: the part of an advisory page the parser reads (title, date, kind, keywords, body), to keep KV small. */
export function trimAdvisoryPage(html: string): string {
  const start = html.search(/<h[46][^>]*>\s*MA-\d+\.\d{6}\s*:/i)
  if (start < 0) return html
  const end = html.slice(start).search(/start blog right|class="side-bar"/i)
  return end > 0 ? html.slice(start, start + end) : html.slice(start)
}

/** PURE: why MyCERT could not be read, with when it was last fetched during a request from Malaysia. */
export function harvestProblem(lastAt: number | null, now: number, cause: string): string {
  const when = lastAt === null ? 'never'
    : `${Math.round((now - lastAt) / 3600_000)} hour(s) ago (${new Date(lastAt).toISOString()})`
  return `MyCERT answers only requests from Malaysia or Singapore; its pages were last fetched during one ${when}. Directly: ${cause}`
}
