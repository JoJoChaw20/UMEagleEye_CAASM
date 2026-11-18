/**
 * knowledge.ts - PURE. The curated security knowledge base (src/data/securityKb.json) and its local
 * search. Every entry is paraphrased from an allowed public source and links to it. Searching is
 * keyword and tag scoring in this Worker: no query, and so no company data, ever leaves it.
 */
import KB from '../data/securityKb.json'

export interface KbEntry {
  id: string
  title: string
  tags: string[]
  guidance: string
  source: { name: string; url: string }
  reviewed: string
}

/** The only hosts a knowledge-base source may link to (spec: NIST, CISA, MITRE, CIS, OWASP, FIRST, official vendor docs). */
export const ALLOWED_SOURCE_HOSTS: readonly string[] = [
  'csrc.nist.gov', 'nvlpubs.nist.gov', 'nvd.nist.gov', 'www.nist.gov',
  'www.cisa.gov',
  'attack.mitre.org', 'cwe.mitre.org',
  'www.cisecurity.org',
  'owasp.org', 'cheatsheetseries.owasp.org',
  'www.first.org',
  'learn.microsoft.com', 'msrc.microsoft.com', 'support.microsoft.com',
  'ubuntu.com', 'documentation.ubuntu.com',
  'www.debian.org', 'wiki.debian.org', 'manpages.debian.org',
  'access.redhat.com', 'docs.redhat.com',
  'www.openssh.com', 'httpd.apache.org', 'nginx.org',
]

export const GUIDANCE_MAX = 900
export const SEARCH_MAX = 8

export const KNOWLEDGE: readonly KbEntry[] = KB as KbEntry[]

const STOP = new Set(['the', 'a', 'an', 'and', 'or', 'of', 'to', 'in', 'on', 'for', 'is', 'are', 'how', 'do', 'i', 'we', 'it', 'this', 'that', 'what', 'with', 'my', 'our', 'can', 'should', 'be', 'by', 'from', 'at', 'as', 'not', 'fix', 'about'])

// A port number means its service: "port 22 exposed" finds SSH hardening.
const PORT_WORDS: Record<string, string[]> = {
  '21': ['ftp'], '22': ['ssh'], '23': ['telnet'], '25': ['smtp'], '80': ['http', 'web'], '161': ['snmp'], '443': ['https', 'tls', 'web'],
  '445': ['smb'], '139': ['smb'], '1433': ['mssql', 'database'], '3306': ['mysql', 'database'], '3389': ['rdp'], '5432': ['postgresql', 'database'],
  '5900': ['vnc', 'remote-access'], '6379': ['redis', 'database'], '8080': ['http', 'web'], '27017': ['mongodb', 'database'],
}

function words(text: string): string[] {
  const out: string[] = []
  for (const w of text.toLowerCase().split(/[^a-z0-9.+-]+/)) {
    const t = w.replace(/^[.+-]+|[.+-]+$/g, '')
    if (!t || STOP.has(t)) continue
    out.push(t)
    for (const extra of PORT_WORDS[t] ?? []) out.push(extra)
  }
  return [...new Set(out)]
}

const INDEX = KNOWLEDGE.map(e => ({
  entry: e,
  tags: new Set(e.tags.map(t => t.toLowerCase())),
  title: new Set(words(e.title)),
  body: new Set(words(e.guidance)),
}))

/**
 * The best entries for a query: a tag match scores 3, a title word 2, a guidance word 1, and each
 * requested tag the entry carries adds 5. Ties keep the knowledge-base order, so it is deterministic.
 */
export function searchKnowledge(query: string, tags: string[] = [], limit = 5): KbEntry[] {
  const q = words(query.slice(0, 300))
  const wanted = tags.slice(0, 10).map(t => t.toLowerCase())
  const n = Math.max(1, Math.min(SEARCH_MAX, Math.floor(limit)))
  return INDEX
    .map((x, i) => {
      let score = 0
      for (const w of q) score += (x.tags.has(w) ? 3 : 0) + (x.title.has(w) ? 2 : 0) + (x.body.has(w) ? 1 : 0)
      for (const t of wanted) if (x.tags.has(t)) score += 5
      return { x, i, score }
    })
    .filter(r => r.score > 0)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .slice(0, n)
    .map(r => r.x.entry)
}

/** Why an entry breaks the knowledge-base rules, or null. Used by the schema test. */
export function entryProblems(e: KbEntry): string | null {
  if (!/^kb-\d{3}$/.test(e.id)) return `${e.id}: bad id`
  if (!e.title || e.title.length > 120) return `${e.id}: bad title`
  if (!Array.isArray(e.tags) || e.tags.length === 0 || e.tags.some(t => !/^[a-z0-9.+-]+$/.test(t))) return `${e.id}: bad tags`
  if (!e.guidance || e.guidance.length > GUIDANCE_MAX) return `${e.id}: guidance empty or over ${GUIDANCE_MAX} characters`
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.reviewed)) return `${e.id}: no reviewed date`
  let url: URL
  try { url = new URL(e.source.url) } catch { return `${e.id}: bad source url` }
  if (url.protocol !== 'https:' || !ALLOWED_SOURCE_HOSTS.includes(url.hostname)) return `${e.id}: source ${url.hostname} is not an allowed source`
  if (!e.source.name) return `${e.id}: no source name`
  return null
}
