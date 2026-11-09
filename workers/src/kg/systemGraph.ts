/**
 * kg/systemGraph.ts — pure rules for the shared "system layer" of the knowledge graph (what
 * UMEagleEye's own code, docs and data look like). Used by scripts/kg/build-system-graph.mjs,
 * which bundles it with esbuild. Nothing in the Worker imports it, and it must stay free of
 * Node-only imports so it can be unit tested and bundled either way.
 *
 * Every node it makes has tenant_id NULL, role_group 'analyst' (so a business_owner never sees
 * it) and a key starting with SYSTEM_PREFIX, which is the only thing a rebuild may delete.
 */
import { containsSecret } from './redact'
import type { KgEdge, KgNode, RoleGroup, Visibility } from './extract'

export const SYSTEM_PREFIX = 'system:'

/** Code-hotspot problem rules. Distinct from PLATFORM_RULES, which problems.ts replaces on every refresh. */
export const HOTSPOT_RULES = ['code_hotspot_large_file', 'code_hotspot_shared_module'] as const
export const LARGE_FILE_LINES = 900
export const SHARED_MODULE_IMPORTERS = 12

// ── Files ────────────────────────────────────────────────────────

const base = (p: string) => p.slice(p.lastIndexOf('/') + 1)
const ext = (p: string) => { const b = base(p); const i = b.lastIndexOf('.'); return i < 0 ? '' : b.slice(i + 1).toLowerCase() }
const norm = (p: string) => p.replace(/\\/g, '/')

/** Any .env* file, in any folder. These never enter the graph, not even by name. */
export function isEnvFile(path: string): boolean {
  // Every segment counts: a folder named .env/ or x.env/ holds env files too. The pattern also
  // catches .env, .env.staging, x.env, x.env.example and .envrc is caught by the prefix test.
  return norm(path).toLowerCase().split('/').some(seg => /\.env(\.|$)/.test(seg) || seg.startsWith('.env'))
}

const KEY_EXT = new Set(['pem', 'key', 'p12', 'pfx', 'crt', 'cer', 'jks', 'keystore'])
const BINARY_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'ttf', 'otf', 'woff', 'woff2', 'gz', 'zip', 'pdf', 'tsv', 'csv', 'exe', 'dll', 'bin'])
const CODE_EXT = new Set(['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'py'])
const TEXT_EXT = new Set(['toml', 'yml', 'yaml', 'xml', 'ps1', 'sh', 'iss', 'spec', 'html', 'css', 'txt', 'service', 'cfg', 'ini', 'gitignore', 'gitattributes', 'dockerignore', 'example'])
const TEXT_NAMES = new Set(['dockerfile', '_headers', 'package.json', 'tsconfig.json', 'tsconfig.drizzle.json', 'requirements.txt', 'pyproject.toml'])

export type FileKind =
  | 'route_file' | 'service' | 'queue_file' | 'cron_file' | 'schema' | 'migration' | 'test' | 'page' | 'component' | 'module' | 'script'
  | 'doc' | 'config' | 'lockfile' | 'generated' | 'data' | 'binary' | 'fixture' | 'secret_file'
export interface FileClass { mode: 'skip' | 'name_only' | 'text'; kind: FileKind; area: string }

const areaOf = (p: string) => {
  const top = p.split('/')[0] ?? ''
  return ['workers', 'frontend', 'agent-gui', 'docs'].includes(top) ? top : p.includes('/') ? 'repo-config' : 'root'
}

export function classifyFile(input: string): FileClass {
  const path = norm(input)
  const area = areaOf(path)
  const b = base(path).toLowerCase()
  const e = ext(path)
  if (isEnvFile(path) || KEY_EXT.has(e)) return { mode: 'skip', kind: 'secret_file', area }
  if (b === 'package-lock.json' || b === 'yarn.lock' || b === 'pnpm-lock.yaml' || e === 'lock') return { mode: 'name_only', kind: 'lockfile', area }
  if (/(^|\/)drizzle\/meta\//.test(path) || /\.min\.(js|css)$/.test(path) || /\.webp\.json$/.test(path)) return { mode: 'name_only', kind: 'generated', area }
  if (/(^|\/)tests\/fixtures\//.test(path)) return { mode: 'name_only', kind: 'fixture', area }
  if (/(^|\/)src\/data\//.test(path) || /fingerprints\.json$/.test(path) || e === 'csv' || e === 'tsv') return { mode: 'name_only', kind: 'data', area }
  if (BINARY_EXT.has(e)) return { mode: 'name_only', kind: 'binary', area }
  if (e === 'md') return { mode: 'text', kind: 'doc', area }
  if (e === 'sql') return { mode: 'text', kind: /(^|\/)(drizzle|migrations)\//.test(path) ? 'migration' : 'config', area }
  if (CODE_EXT.has(e)) {
    if (/\.test\.(ts|tsx|js|jsx|mjs)$/.test(b) || /^test_.*\.py$/.test(b) || b === 'conftest.py' || /(^|\/)tests\//.test(path)) return { mode: 'text', kind: 'test', area }
    if (path.startsWith('workers/src/routes/')) return { mode: 'text', kind: 'route_file', area }
    if (path.startsWith('workers/src/services/')) return { mode: 'text', kind: 'service', area }
    if (path.startsWith('workers/src/queues/')) return { mode: 'text', kind: 'queue_file', area }
    if (path.startsWith('workers/src/cron/')) return { mode: 'text', kind: 'cron_file', area }
    if (path === 'workers/src/db/schema.ts') return { mode: 'text', kind: 'schema', area }
    if (path.startsWith('frontend/src/pages/')) return { mode: 'text', kind: 'page', area }
    if (path.startsWith('frontend/src/components/')) return { mode: 'text', kind: 'component', area }
    if (/(^|\/)scripts\//.test(path)) return { mode: 'text', kind: 'script', area }
    return { mode: 'text', kind: 'module', area }
  }
  if (TEXT_NAMES.has(b) || TEXT_EXT.has(e) || e === 'json') {
    // JSON other than the project's own manifests is data or generated.
    if (e === 'json' && !TEXT_NAMES.has(b)) return { mode: 'name_only', kind: 'data', area }
    return { mode: 'text', kind: 'config', area }
  }
  return { mode: 'name_only', kind: 'binary', area }
}

const ALL_STAFF_DOCS = new Set(['PRODUCT.md', 'AGENT_SETUP_GUIDE.md', 'agent-gui/README.md', 'agent-gui/packaging/BEFORE-YOU-INSTALL.txt'])

/**
 * Product docs and how-to knowledge may be read by any signed-in staff; code, tests, migrations and
 * internal docs are for the UMEagleEye team. Every node is 'analyst': a business_owner gets only
 * the status node and the security score, never this layer.
 */
export function visibilityFor(path: string, opts: { reference?: boolean } = {}): { visibility: Visibility; roleGroup: RoleGroup } {
  const open = opts.reference === true || ALL_STAFF_DOCS.has(norm(path))
  return { visibility: open ? 'all_staff' : 'platform', roleGroup: 'analyst' }
}

/** Markdown files whose sections become their own nodes (how-to knowledge people ask about). */
export function isSectionedDoc(path: string): boolean {
  const p = norm(path)
  return ALL_STAFF_DOCS.has(p) || ['README.md', 'DESIGN.md', 'STAGING.md', 'agent-gui/TESTING-VMS.md'].includes(p)
}

// ── Keys ─────────────────────────────────────────────────────────

export function systemKey(type: string, ...parts: string[]): string {
  return `${SYSTEM_PREFIX}${type}:${parts.map(norm).join(' ')}`
}

// ── API path matching (which page calls which route) ─────────────

/** '/events/${id}/status?x=1' and '/api/v1/events/:id/status' both become '/events/:p/status'. */
export function normalizeApiPath(input: string): string {
  let p = input.split('?')[0] ?? ''
  p = p.replace(/\$\{[^}]*\}/g, ':p').replace(/^\/?api\/v1(?=\/|$)/, '')
  if (!p.startsWith('/')) p = `/${p}`
  const segs = p.split('/').filter(Boolean).map(s => (s.startsWith(':') || s.includes(':p') ? ':p' : s))
  return `/${segs.join('/')}`
}

export interface RouteRef { key: string; method: string; path: string }

export function matchRoute(method: string, callPath: string, routes: RouteRef[]): string | null {
  const want = normalizeApiPath(callPath).split('/').filter(Boolean)
  let best: { key: string; statics: number } | null = null
  for (const r of routes) {
    if (r.method !== method.toUpperCase() && r.method !== 'ALL') continue
    const have = normalizeApiPath(r.path).split('/').filter(Boolean)
    if (have.length !== want.length) continue
    let statics = 0
    const ok = have.every((seg, i) => {
      if (seg === ':p' || want[i] === ':p') return true
      if (seg === want[i]) { statics++; return true }
      return false
    })
    if (ok && (!best || statics > best.statics)) best = { key: r.key, statics }
  }
  return best?.key ?? null
}

// ── Imports ──────────────────────────────────────────────────────

function joinPath(from: string, spec: string): string | null {
  const out = norm(from).split('/').slice(0, -1)
  for (const seg of spec.split('/')) {
    if (seg === '.' || seg === '') continue
    if (seg === '..') { if (out.length === 0) return null; out.pop() } else out.push(seg)
  }
  return out.join('/')
}

/** A relative import to a tracked file, or null (packages and missing files). */
export function resolveImport(from: string, spec: string, files: Set<string>): string | null {
  if (!spec.startsWith('.')) return null
  const target = joinPath(from, spec)
  if (target == null) return null
  const tries = [target, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.json'].map(x => target + x), ...['index.ts', 'index.tsx', 'index.js', 'index.jsx'].map(x => `${target}/${x}`)]
  return tries.find(t => files.has(t)) ?? null
}

// ── Markdown ─────────────────────────────────────────────────────

export interface DocChunk { heading: string; body: string }

/** Sections by heading; a long section is cut at paragraph breaks so each piece stays embeddable. */
export function chunkMarkdown(text: string, maxChars = 1500): DocChunk[] {
  const sections: Array<{ heading: string; lines: string[] }> = []
  let fence = false
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence
    const h = !fence ? /^#{1,4}\s+(.+?)\s*#*$/.exec(line) : null
    if (h) sections.push({ heading: h[1] ?? '', lines: [] })
    else (sections[sections.length - 1] ?? (sections[0] = { heading: 'Introduction', lines: [] }, sections[0])).lines.push(line)
  }
  const out: DocChunk[] = []
  for (const s of sections) {
    const paragraphs = s.lines.join('\n').split(/\n{2,}/).map(p => p.trim()).filter(Boolean)
    let cur = ''
    const flush = () => { if (cur.trim()) out.push({ heading: s.heading, body: cur.trim() }); cur = '' }
    for (let p of paragraphs) {
      while (p.length > maxChars) { flush(); out.push({ heading: s.heading, body: p.slice(0, maxChars) }); p = p.slice(maxChars) }
      if (cur && cur.length + p.length + 2 > maxChars) flush()
      cur += (cur ? '\n\n' : '') + p
    }
    flush()
  }
  return out
}

// ── Hotspots ─────────────────────────────────────────────────────

export interface HotspotInput {
  path: string
  kind: FileKind | string
  lines: number
  importers: string[]
  largest?: Array<{ name: string; lines: number }>
}

const HOTSPOT_KINDS = new Set(['route_file', 'service', 'queue_file', 'cron_file', 'schema', 'page', 'component', 'module'])

/** Very large files and heavily depended-on modules, as platform problems with a recommended solution. */
export function hotspotNodes(files: HotspotInput[]): { nodes: KgNode[]; edges: KgEdge[] } {
  const nodes: KgNode[] = []
  const edges: KgEdge[] = []
  const add = (rule: typeof HOTSPOT_RULES[number], f: HotspotInput, severity: string, title: string, detail: string, solution: string, count: number) => {
    const key = systemKey('problem', rule, f.path)
    nodes.push({
      key, tenantId: null, visibility: 'platform', roleGroup: 'analyst', type: 'problem', title,
      body: `Platform problem (${severity}): ${title}. ${detail} Recommended solution: ${solution}`,
      props: { rule, rank: count, severity, count, solution, path: f.path, system: true }, sourceRef: f.path,
    })
    edges.push({ from: key, to: systemKey('file', f.path), relation: 'EVIDENCE', tenantId: null })
  }
  for (const f of files) {
    // A package's __init__.py is imported by every module in it by design; that is not a dependency risk.
    if (!HOTSPOT_KINDS.has(f.kind) || base(norm(f.path)) === '__init__.py') continue
    if (f.lines >= LARGE_FILE_LINES) {
      const big = (f.largest ?? []).slice(0, 3).map(x => `${x.name} (${x.lines} lines)`).join(', ')
      add('code_hotspot_large_file', f, f.lines >= LARGE_FILE_LINES * 1.5 ? 'medium' : 'low',
        `${f.path} is very large (${f.lines} lines)`,
        `Large files are slow to review and easy to break.${big ? ` Largest parts: ${big}.` : ''}`,
        'Split it by responsibility into smaller modules, starting with the largest functions, and move shared helpers out. Keep the public exports unchanged so callers need no edits, and add tests before moving code.',
        f.lines)
    }
    if (f.importers.length >= SHARED_MODULE_IMPORTERS) {
      add('code_hotspot_shared_module', f, 'low',
        `${f.path} is depended on by ${f.importers.length} files`,
        `A change here can affect ${f.importers.length} other files, for example ${f.importers.slice(0, 3).join(', ')}.`,
        'Keep its exported interface small and stable, cover it with unit tests, and avoid adding new responsibilities to it. Split unrelated helpers into their own modules so fewer files depend on each part.',
        f.importers.length)
    }
  }
  return { nodes, edges }
}

// ── Rebuild and screening ────────────────────────────────────────

/** Existing keys that belong to this layer and are not in the new build. Never anything else. */
export function staleKeys(existing: string[], current: Set<string>): string[] {
  return existing.filter(k => k.startsWith(SYSTEM_PREFIX) && !current.has(k))
}

export interface Screened { nodes: KgNode[]; blockedSecret: number; blockedEnv: number; rejected: number; blockedKeys: string[] }

/**
 * The last check before storing. Drops nodes that are not ours (wrong prefix, a tenant, company
 * visibility), that point at an .env* path, or whose text matches a secret pattern. Returns
 * counts and keys only, never the matched text.
 */
export function screenNodes(input: KgNode[]): Screened {
  const out: Screened = { nodes: [], blockedSecret: 0, blockedEnv: 0, rejected: 0, blockedKeys: [] }
  for (const n of input) {
    if (!n.key.startsWith(SYSTEM_PREFIX) || n.tenantId !== null || n.visibility === 'company') { out.rejected++; out.blockedKeys.push(n.key); continue }
    if (isEnvFile(n.key.split(':').slice(2).join(':').split(' ').pop() ?? '') || isEnvFile(n.sourceRef ?? '')) { out.blockedEnv++; out.blockedKeys.push(n.key); continue }
    if (containsSecret(`${n.title}\n${n.body}\n${JSON.stringify(n.props)}`)) { out.blockedSecret++; out.blockedKeys.push(n.key); continue }
    out.nodes.push(n)
  }
  return out
}
