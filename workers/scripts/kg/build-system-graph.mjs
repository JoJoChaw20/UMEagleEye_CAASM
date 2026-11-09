// Builds the shared "system layer" of the knowledge graph from the repository: every git-tracked
// file, parsed (TypeScript compiler API for TS/JS/JSX, Python ast for Python), plus the ATT&CK
// and CWE reference data. Nodes have tenant_id NULL and keys starting with "system:".
//
//   node scripts/kg/build-system-graph.mjs staging --dry-run   # everything except the database
//   node scripts/kg/build-system-graph.mjs staging             # write (staging only)
//
// Only "staging" is accepted: there is no production path. The write uses workers/.env.staging
// through the same DB_TARGET check as the db scripts. Nodes are stored without embeddings; the
// Worker's backfill (kg/store.ts backfillEmbeddings) fills them. A rerun replaces this layer:
// nodes whose key starts with "system:" and are no longer built are deleted, nothing else is.
// Pure rules (classification, visibility, keys, hotspots, screening) are in src/kg/systemGraph.ts.
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build } from 'esbuild'
import ts from 'typescript'
import { loadEnvFile, describe, productionHost } from '../db/lib.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WORKERS = path.resolve(HERE, '../..')
const REPO = path.resolve(WORKERS, '..')
const BATCH = 150
const MIN_NODES_TO_PRUNE = 200
const CWE_GROUP = 20

function fail(msg) {
  console.error(`\nERROR: ${msg}`)
  process.exit(1)
}

// ── arguments: staging only ──────────────────────────────────────
const argv = process.argv.slice(2)
const dryRun = argv.includes('--dry-run')
const target = argv.find(a => !a.startsWith('--'))
const show = argv.find(a => a.startsWith('--show='))?.slice(7) // dry run only: print nodes whose key contains this text
const unknownFlags = argv.filter(a => a.startsWith('--') && a !== '--dry-run' && !a.startsWith('--show='))
if (target !== 'staging' || unknownFlags.length) {
  fail(`usage: node scripts/kg/build-system-graph.mjs staging [--dry-run]. Only "staging" is accepted${target && target !== 'staging' ? ` (got "${target}")` : ''}.`)
}

// ── bundle the pure rules (and the store, for the real write) ────
async function loadLib() {
  const dir = mkdtempSync(path.join(tmpdir(), 'kg-system-'))
  try {
    const out = path.join(dir, 'lib.mjs')
    const src = p => JSON.stringify(path.join(WORKERS, 'src/kg', p).replace(/\\/g, '/'))
    await build({
      stdin: { contents: `export * from ${src('systemGraph.ts')}\nexport { upsertNodes, replaceEdges } from ${src('store.ts')}`, resolveDir: WORKERS, loader: 'ts' },
      bundle: true, platform: 'node', format: 'esm', outfile: out, logLevel: 'error',
      banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
    })
    return await import(pathToFileURL(out).href)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ── python ───────────────────────────────────────────────────────
function findPython() {
  for (const cmd of ['python', 'python3']) {
    const r = spawnSync(cmd, ['-I', '-c', 'import sys; print(sys.version_info[0])'], { encoding: 'utf8' })
    if (!r.error && r.status === 0 && r.stdout.trim() === '3') return cmd
  }
  return null
}

function pythonOutlines(files) {
  if (files.length === 0) return {}
  const py = findPython()
  if (!py) fail('Python 3 is needed to parse the .py files, but neither "python" nor "python3" runs. Install Python 3 and put it on PATH.')
  const result = {}
  for (let i = 0; i < files.length; i += 40) {
    const r = spawnSync(py, ['-I', path.join(HERE, 'py_outline.py'), ...files.slice(i, i + 40)], { cwd: REPO, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    if (r.error || r.status !== 0) fail(`py_outline.py failed (${r.error?.message ?? `exit ${r.status}`}): ${(r.stderr ?? '').split('\n').slice(-3).join(' ').trim()}`)
    Object.assign(result, JSON.parse(r.stdout))
  }
  return result
}

// ── TypeScript / JavaScript analysis ─────────────────────────────
const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all'])
const kindOfScript = p => ({ ts: ts.ScriptKind.TS, tsx: ts.ScriptKind.TSX, jsx: ts.ScriptKind.JSX }[p.split('.').pop()] ?? ts.ScriptKind.JS)

function commentText(raw) {
  return raw.replace(/^\/\*+|\*+\/$/g, '').replace(/^\s*\*\s?/gm, '').replace(/^\s*\/\/\s?/gm, '').replace(/\s+/g, ' ').trim()
}

/** Possible values of a path expression: strings, templates (`${}` for the unknown), a + b, a ? b : c. */
function strVariants(n) {
  if (!n) return []
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return [n.text]
  if (ts.isParenthesizedExpression(n) || ts.isAsExpression(n)) return strVariants(n.expression)
  if (ts.isTemplateExpression(n)) return [n.head.text + n.templateSpans.map(s => '${}' + s.literal.text).join('')]
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = strVariants(n.left)
    const r = strVariants(n.right)
    const L = l.length ? l : ['${}']
    const R = r.length ? r : ['${}']
    return L.flatMap(a => R.map(b => a + b))
  }
  if (ts.isConditionalExpression(n)) return [...strVariants(n.whenTrue), ...strVariants(n.whenFalse)]
  return []
}

function literalTexts(node, out = []) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) out.push(node.text)
  else if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) out.push(node.text)
  ts.forEachChild(node, c => literalTexts(c, out))
  return out
}

function declSizes(sf) {
  const out = []
  const size = n => sf.getLineAndCharacterOfPosition(n.end).line - sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1
  for (const s of sf.statements) {
    if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.name) out.push({ name: s.name.text, lines: size(s) })
    else if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) out.push({ name: d.name.text, lines: size(d) })
      }
    }
  }
  return out.sort((a, b) => b.lines - a.lines)
}

function analyseScript(p, text) {
  const sf = ts.createSourceFile(p, text, ts.ScriptTarget.Latest, true, kindOfScript(p))
  const info = { parseFailed: sf.parseDiagnostics?.length > 0, imports: [], bindings: new Map(), exports: [], routes: [], mounts: [], apiCalls: [], unresolvedApi: 0, header: '', decls: declSizes(sf), idents: new Set(), literals: [] }
  const first = ts.getLeadingCommentRanges(text, 0)?.[0]
  if (first) info.header = commentText(text.slice(first.pos, first.end)).slice(0, 400)

  for (const s of sf.statements) {
    if (ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier)) {
      const spec = s.moduleSpecifier.text
      info.imports.push(spec)
      const c = s.importClause
      if (c?.name) info.bindings.set(c.name.text, spec)
      if (c?.namedBindings) {
        if (ts.isNamespaceImport(c.namedBindings)) info.bindings.set(c.namedBindings.name.text, spec)
        else for (const e of c.namedBindings.elements) info.bindings.set(e.name.text, spec)
      }
    } else if (ts.isExportDeclaration(s)) {
      if (s.moduleSpecifier && ts.isStringLiteral(s.moduleSpecifier)) info.imports.push(s.moduleSpecifier.text)
      if (s.exportClause && ts.isNamedExports(s.exportClause)) info.exports.push(...s.exportClause.elements.map(e => e.name.text))
    } else if (ts.isExportAssignment(s)) info.exports.push('default')
    else if (s.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
      if (s.modifiers.some(m => m.kind === ts.SyntaxKind.DefaultKeyword)) info.exports.push('default')
      if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s) || ts.isEnumDeclaration(s)) && s.name) info.exports.push(s.name.text)
      else if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name)) info.exports.push(d.name.text)
    }
  }

  const visit = n => {
    if (ts.isIdentifier(n)) info.idents.add(n.text)
    if (ts.isCallExpression(n)) {
      const ex = n.expression
      if (ts.isIdentifier(ex) && ex.text === 'require' && n.arguments[0] && ts.isStringLiteral(n.arguments[0])) info.imports.push(n.arguments[0].text)
      if (ex.kind === ts.SyntaxKind.ImportKeyword && n.arguments[0] && ts.isStringLiteral(n.arguments[0])) info.imports.push(n.arguments[0].text)
      if (ts.isPropertyAccessExpression(ex) && ts.isIdentifier(ex.expression)) {
        const obj = ex.expression.text
        const name = ex.name.text
        const arg0 = strVariants(n.arguments[0])[0]
        if (METHODS.has(name) && n.arguments.length >= 2 && arg0 !== undefined && (arg0.startsWith('/') || arg0 === '*')) {
          const handlerIdents = new Set()
          const lits = []
          const collect = c => { if (ts.isIdentifier(c)) handlerIdents.add(c.text); ts.forEachChild(c, collect) }
          n.arguments.forEach((a, i) => { if (i > 0) { collect(a); literalTexts(a, lits) } })
          // Names only: the arguments of a validator call are schemas, not something to store.
          const middleware = n.arguments.slice(1, -1).map(a => (ts.isCallExpression(a) ? `${a.expression.getText(sf)}(...)` : ts.isIdentifier(a) ? a.text : 'inline')).map(x => x.slice(0, 60))
          info.routes.push({ method: name.toUpperCase(), path: arg0, line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1, idents: handlerIdents, literals: lits, middleware, obj })
        } else if (name === 'route' && arg0 !== undefined && n.arguments[1] && ts.isIdentifier(n.arguments[1])) {
          info.mounts.push({ path: arg0, ident: n.arguments[1].text })
        }
        const spec = info.bindings.get(obj)
        if (spec && /(^|\/)api\/client$/.test(spec) && ['get', 'post', 'put', 'patch', 'delete'].includes(name)) {
          const v = strVariants(n.arguments[0]).filter(x => x.includes('/'))
          if (v.length) v.forEach(x => info.apiCalls.push({ method: name.toUpperCase(), path: x }))
          else info.unresolvedApi++
        }
      }
      if (ts.isIdentifier(ex) && ex.text === 'fetch') {
        const v = strVariants(n.arguments[0]).map(x => x.replace(/^\$\{\}/, '')).filter(x => x.startsWith('/'))
        let method = 'GET'
        const opts = n.arguments[1]
        if (opts && ts.isObjectLiteralExpression(opts)) {
          for (const pr of opts.properties) if (ts.isPropertyAssignment(pr) && pr.name.getText(sf) === 'method') method = (strVariants(pr.initializer)[0] ?? 'GET').toUpperCase()
        }
        if (v.length) v.forEach(x => info.apiCalls.push({ method, path: x }))
      }
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  info.literals = literalTexts(sf)
  return info
}

/** Tables from db/schema.ts: variable name -> { table, columns }. */
function schemaTables(text) {
  const sf = ts.createSourceFile('schema.ts', text, ts.ScriptTarget.Latest, true)
  const out = new Map()
  for (const s of sf.statements) {
    if (!ts.isVariableStatement(s)) continue
    for (const d of s.declarationList.declarations) {
      const c = d.initializer
      if (!ts.isIdentifier(d.name) || !c || !ts.isCallExpression(c) || !ts.isIdentifier(c.expression) || c.expression.text !== 'pgTable') continue
      const table = strVariants(c.arguments[0])[0]
      const cols = []
      const obj = c.arguments[1]
      if (table && obj && ts.isObjectLiteralExpression(obj)) {
        for (const pr of obj.properties) {
          if (!ts.isPropertyAssignment(pr)) continue
          const m = /\(\s*['"]([a-z0-9_]+)['"]/.exec(pr.initializer.getText(sf))
          cols.push(m ? m[1] : pr.name.getText(sf))
        }
      }
      if (table) out.set(d.name.text, { table, columns: cols, line: sf.getLineAndCharacterOfPosition(s.getStart(sf)).line + 1 })
    }
  }
  return out
}

// ── small text helpers ───────────────────────────────────────────
const clip = (s, n) => (s.length <= n ? s : `${s.slice(0, n - 3)}...`)
const list = (xs, n = 25) => (xs.length <= n ? xs.join(', ') : `${xs.slice(0, n).join(', ')} and ${xs.length - n} more`)
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'section'

function leadingComments(text) {
  const out = []
  for (const line of text.split(/\r?\n/).slice(0, 40)) {
    const t = line.trim()
    if (t === '' && out.length === 0) continue
    const m = /^(?:#!?|\/\/|--|rem\b|<!--)\s?(.*?)(?:-->)?$/i.exec(t)
    if (!m) break
    if (m[1]) out.push(m[1])
  }
  return out.join(' ').replace(/\s+/g, ' ').trim()
}

function configSummary(p, text) {
  const b = path.posix.basename(p)
  if (b === 'package.json') {
    try {
      const j = JSON.parse(text)
      return `name ${j.name ?? '?'}; scripts: ${list(Object.keys(j.scripts ?? {}), 40)}; dependencies: ${list(Object.keys(j.dependencies ?? {}), 40)}; devDependencies: ${list(Object.keys(j.devDependencies ?? {}), 40)}.`
    } catch { return '' }
  }
  if (b.startsWith('tsconfig')) return 'TypeScript compiler settings.'
  const head = leadingComments(text)
  if (head) return head
  const t = /<title>(.*?)<\/title>/i.exec(text)
  if (t) return `HTML page titled ${t[1]}.`
  return clip(text.split(/\r?\n/).find(l => l.trim()) ?? '', 160)
}

function sqlSummary(text) {
  const head = leadingComments(text)
  const created = [...text.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?/gi)].map(m => m[1].toLowerCase())
  const altered = [...text.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"?([a-z_][a-z0-9_]*)"?/gi)].map(m => m[1].toLowerCase())
  return { head, created: [...new Set(created)], altered: [...new Set(altered)].filter(t => !created.includes(t)) }
}

// ── main ─────────────────────────────────────────────────────────
async function main() {
  const lib = await loadLib()
  const { classifyFile, isEnvFile, isSectionedDoc, visibilityFor, systemKey, resolveImport, matchRoute, chunkMarkdown, hotspotNodes, screenNodes, staleKeys, SYSTEM_PREFIX } = lib

  let tracked
  try {
    tracked = execFileSync('git', ['ls-files', '-z'], { cwd: REPO, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).split('\0').filter(Boolean)
  } catch (err) {
    fail(`git ls-files failed: ${err.message}`)
  }

  // Classify; .env* and key files stop here and are not even named.
  let skippedEnv = 0
  let skippedOther = 0
  let unreadable = 0
  const files = []
  for (const p of tracked) {
    const cls = classifyFile(p)
    if (cls.mode === 'skip') { if (isEnvFile(p)) skippedEnv++; else skippedOther++; continue }
    let text = null
    if (cls.mode === 'text') {
      try {
        text = readFileSync(path.join(REPO, p), 'utf8')
        if (text.length > 2_000_000) { text = null; cls.mode = 'name_only'; cls.kind = 'data' }
      } catch { unreadable++; cls.mode = 'name_only' }
    }
    files.push({ path: p, ...cls, text, lines: text ? text.split('\n').length : 0 })
  }
  const fileSet = new Set(files.map(f => f.path))
  const byPath = new Map(files.map(f => [f.path, f]))
  const ext = p => p.split('.').pop()
  const isScript = f => f.mode === 'text' && ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs'].includes(ext(f.path))
  const isPy = f => f.mode === 'text' && ext(f.path) === 'py'

  // Tables
  const schemaFile = files.find(f => f.path === 'workers/src/db/schema.ts')
  const tableByVar = schemaFile?.text ? schemaTables(schemaFile.text) : new Map()
  const tables = new Map() // name -> { columns, source, line }
  for (const [, t] of tableByVar) tables.set(t.table, { columns: t.columns, source: 'workers/src/db/schema.ts', line: t.line, schema: true })
  const migrationInfo = new Map()
  for (const f of files.filter(f => f.kind === 'migration' && f.text)) {
    const s = sqlSummary(f.text)
    migrationInfo.set(f.path, s)
    for (const t of s.created) if (!tables.has(t)) tables.set(t, { columns: [], source: f.path, line: 0, schema: false })
  }
  const tableNames = new Set(tables.keys())
  const sqlTablesIn = lits => {
    const found = new Set()
    for (const l of lits) for (const m of l.matchAll(/\b(?:from|join|into|update|table)\s+"?([a-z_][a-z0-9_]*)"?/gi)) if (tableNames.has(m[1].toLowerCase())) found.add(m[1].toLowerCase())
    return found
  }

  // Parse code
  const ana = new Map()
  for (const f of files.filter(isScript)) ana.set(f.path, analyseScript(f.path, f.text))
  const pyFiles = files.filter(isPy)
  const py = pythonOutlines(pyFiles.map(f => f.path))
  const pyRoot = 'agent-gui/'
  const resolvePy = (from, mod) => {
    let base
    let rest = mod
    if (mod.startsWith('.')) {
      const dots = /^\.+/.exec(mod)[0].length
      base = from.split('/').slice(0, -1)
      for (let i = 1; i < dots; i++) base.pop()
      rest = mod.slice(dots)
    } else base = pyRoot.replace(/\/$/, '').split('/')
    const target = [...base, ...(rest ? rest.split('.') : [])].join('/')
    return [`${target}.py`, `${target}/__init__.py`].find(c => fileSet.has(c)) ?? null
  }

  const importsOf = new Map() // file path -> resolved local files
  for (const f of files) {
    const out = new Set()
    if (ana.has(f.path)) for (const s of ana.get(f.path).imports) { const r = resolveImport(f.path, s, fileSet); if (r && r !== f.path) out.add(r) }
    if (py[f.path]) for (const s of py[f.path].imports) { const r = resolvePy(f.path, s); if (r && r !== f.path) out.add(r) }
    importsOf.set(f.path, out)
  }

  // Nodes and edges are collected here; screening and endpoint checks come last.
  const nodes = []
  const edges = []
  const addNode = (key, type, title, body, props, sourceRef, ref = {}) => {
    const v = visibilityFor(sourceRef ?? '', ref)
    nodes.push({ key, tenantId: null, visibility: v.visibility, roleGroup: v.roleGroup, type, title: clip(title, 300), body, props, sourceRef })
  }
  const addEdge = (from, to, relation) => edges.push({ from, to, relation, tenantId: null })
  const fileKey = p => systemKey('file', p)

  // Routes (mounts come from src/index.ts)
  const mountOf = new Map() // route file -> prefix
  const indexInfo = ana.get('workers/src/index.ts')
  if (indexInfo) {
    for (const m of indexInfo.mounts) {
      const spec = indexInfo.bindings.get(m.ident)
      const target = spec && resolveImport('workers/src/index.ts', spec, fileSet)
      if (target) mountOf.set(target, `/api/v1${m.path === '/' ? '' : m.path}`)
    }
  }
  const routes = []
  for (const f of files) {
    const a = ana.get(f.path)
    if (!a || !(f.kind === 'route_file' || f.path === 'workers/src/index.ts')) continue
    const prefix = f.kind === 'route_file' ? (mountOf.get(f.path) ?? '') : ''
    for (const r of a.routes) {
      const full = `${prefix}${r.path === '/' && prefix ? '' : r.path}` || '/'
      const tablesUsed = new Set()
      for (const id of r.idents) { const t = tableByVar.get(id); if (t) tablesUsed.add(t.table) }
      for (const t of sqlTablesIn(r.literals)) tablesUsed.add(t)
      const calls = new Set()
      for (const id of r.idents) {
        const spec = a.bindings.get(id)
        const target = spec && resolveImport(f.path, spec, fileSet)
        if (target && target !== 'workers/src/db/schema.ts' && !target.endsWith('/types.ts')) calls.add(target)
      }
      routes.push({ key: systemKey('route', r.method, full), method: r.method, path: full, file: f.path, line: r.line, middleware: r.middleware, tables: [...tablesUsed].sort(), calls: [...calls].sort().slice(0, 12), callers: new Set() })
    }
  }
  const routeRefs = routes.map(r => ({ key: r.key, method: r.method, path: r.path }))

  // Frontend: which API each file calls, and which pages reach it through components
  let unmatchedApi = 0
  let matchedApi = 0
  const directApi = new Map() // frontend file -> Set(route key)
  for (const f of files) {
    const a = ana.get(f.path)
    if (!a || !f.path.startsWith('frontend/src/')) continue
    const keys = new Set()
    for (const c of a.apiCalls) { const k = matchRoute(c.method, c.path, routeRefs); if (k) { keys.add(k); matchedApi++ } else unmatchedApi++ }
    unmatchedApi += a.unresolvedApi
    if (keys.size) directApi.set(f.path, keys)
  }
  const reach = pagePath => {
    const seen = new Set([pagePath])
    const stack = [pagePath]
    const routesHit = new Map() // route -> via file
    while (stack.length) {
      const cur = stack.pop()
      for (const k of directApi.get(cur) ?? []) if (!routesHit.has(k)) routesHit.set(k, cur)
      for (const n of importsOf.get(cur) ?? []) if (n.startsWith('frontend/src/') && !seen.has(n)) { seen.add(n); stack.push(n) }
    }
    return routesHit
  }
  const pageRoutes = new Map()
  for (const f of files.filter(f => f.kind === 'page')) {
    const hit = reach(f.path)
    pageRoutes.set(f.path, hit)
    for (const [k, via] of hit) routes.find(r => r.key === k)?.callers.add(via === f.path ? f.path : `${f.path} (via ${via})`)
  }
  const routeByKey = new Map(routes.map(r => [r.key, r]))

  // Importers for hotspots: distinct non-test source files
  const importers = new Map()
  for (const [from, set] of importsOf) {
    if (byPath.get(from)?.kind === 'test') continue
    for (const to of set) { if (!importers.has(to)) importers.set(to, []); importers.get(to).push(from) }
  }

  // File nodes
  for (const f of files) {
    const a = ana.get(f.path)
    const p = py[f.path]
    const key = fileKey(f.path)
    const local = [...(importsOf.get(f.path) ?? [])]
    const bits = [`${f.kind.replace('_', ' ')} ${f.path} (${f.area}).`]
    let title = f.path
    if (f.mode === 'name_only') {
      bits.push(`Recorded by name only (${f.kind}); its contents are not stored.`)
    } else if (a) {
      if (a.header) bits.push(a.header)
      bits.push(`${f.lines} lines.`)
      if (a.exports.length) bits.push(`Exports: ${list([...new Set(a.exports)], 30)}.`)
      if (a.decls.length) bits.push(`Declares: ${list(a.decls.map(d => d.name), 30)}.`)
      if (local.length) bits.push(`Imports: ${list(local, 20)}.`)
      const used = new Set()
      for (const id of a.idents) { const t = tableByVar.get(id); if (t && a.bindings.has(id)) used.add(t.table) }
      for (const t of sqlTablesIn(a.literals)) used.add(t)
      if (used.size && f.path !== 'workers/src/db/schema.ts') bits.push(`Uses tables: ${list([...used].sort())}.`)
      for (const t of used) if (f.path !== 'workers/src/db/schema.ts') addEdge(key, systemKey('table', t), 'USES_TABLE')
      if (f.kind === 'page') {
        const hit = pageRoutes.get(f.path) ?? new Map()
        if (hit.size) bits.push(`Calls API: ${list([...hit.keys()].map(k => k.replace('system:route:', '')), 30)}.`)
      }
      if (f.kind === 'queue_file' || f.kind === 'cron_file' || f.kind === 'route_file') {
        const rs = routes.filter(r => r.file === f.path)
        if (rs.length) bits.push(`Routes: ${list(rs.map(r => `${r.method} ${r.path}`), 30)}.`)
      }
    } else if (p) {
      if (p.error) bits.push(`Could not be parsed (${p.error}).`)
      if (p.doc) bits.push(p.doc)
      bits.push(`${p.lines || f.lines} lines.`)
      if (p.classes.length) bits.push(`Classes: ${list(p.classes.map(c => c.name), 30)}.`)
      if (p.functions.length) bits.push(`Functions: ${list(p.functions.map(x => x.name), 40)}.`)
      if (local.length) bits.push(`Imports: ${list(local, 20)}.`)
    } else if (f.kind === 'migration') {
      const s = migrationInfo.get(f.path)
      if (s?.head) bits.push(s.head)
      bits.push(`${f.lines} lines.`)
      if (s?.created.length) bits.push(`Creates tables: ${list(s.created)}.`)
      if (s?.altered.length) bits.push(`Alters tables: ${list(s.altered)}.`)
      for (const t of s?.created ?? []) addEdge(key, systemKey('table', t), 'CREATES_TABLE')
      for (const t of s?.altered ?? []) if (tableNames.has(t)) addEdge(key, systemKey('table', t), 'ALTERS_TABLE')
    } else if (f.kind === 'doc') {
      const heads = [...f.text.matchAll(/^#{1,3}\s+(.+?)\s*#*$/gm)].map(m => m[1])
      title = heads[0] ? `${heads[0]} (${f.path})` : f.path
      bits.push(`${f.lines} lines.`)
      if (heads.length) bits.push(`Sections: ${list(heads, 30)}.`)
    } else if (f.mode === 'text') {
      bits.push(`${f.lines} lines.`)
      const s = configSummary(f.path, f.text)
      if (s) bits.push(s)
    }
    const hasTests = f.kind === 'test' ? [...(importsOf.get(f.path) ?? [])].filter(t => byPath.get(t)?.kind !== 'test') : []
    if (hasTests.length) bits.push(`Tests: ${list(hasTests, 10)}.`)
    const type = f.kind === 'page' ? 'page' : 'file'
    addNode(key, type, title, bits.join(' '), { kind: f.kind, area: f.area, lines: f.lines, nameOnly: f.mode === 'name_only' }, f.path)
    for (const t of local) addEdge(key, fileKey(t), 'IMPORTS')
    for (const t of hasTests) addEdge(key, fileKey(t), 'TESTS')
    if (f.kind === 'page') for (const [k] of pageRoutes.get(f.path) ?? []) addEdge(key, k, 'CALLS_API')
    if (f.kind === 'component') for (const k of directApi.get(f.path) ?? []) addEdge(key, k, 'CALLS_API')
  }

  // Route nodes
  for (const r of routes) {
    const callers = [...r.callers].sort()
    addNode(r.key, 'route', `${r.method} ${r.path}`,
      `API route ${r.method} ${r.path}, defined in ${r.file} line ${r.line}. ${r.middleware.length ? `Middleware: ${r.middleware.join(', ')}. ` : ''}${r.tables.length ? `Uses tables: ${list(r.tables)}. ` : ''}${r.calls.length ? `Calls: ${list(r.calls)}. ` : ''}${callers.length ? `Called by frontend: ${list(callers, 12)}.` : 'No frontend file calls this route.'}`,
      { method: r.method, path: r.path, file: r.file, line: r.line }, r.file)
    addEdge(r.key, fileKey(r.file), 'DEFINED_IN')
    for (const t of r.tables) addEdge(r.key, systemKey('table', t), 'USES_TABLE')
    for (const c of r.calls) addEdge(r.key, fileKey(c), 'CALLS')
  }

  // Table nodes
  for (const [name, t] of tables) {
    const used = routes.filter(r => r.tables.includes(name)).map(r => `${r.method} ${r.path}`)
    addNode(systemKey('table', name), 'table', `Table ${name}`,
      `Database table ${name}. ${t.schema ? `Defined in ${t.source}.` : `Created in migration ${t.source}; not mapped in schema.ts.`}${t.columns.length ? ` Columns: ${list(t.columns, 60)}.` : ''}${used.length ? ` Used by routes: ${list(used, 12)}.` : ''}`,
      { table: name, columns: t.columns, mapped: t.schema }, t.source)
    addEdge(systemKey('table', name), fileKey(t.source), 'DEFINED_IN')
  }

  // Queues and cron jobs
  const toml = files.find(f => f.path === 'workers/wrangler.toml')?.text ?? ''
  const queueBindings = new Map()
  const prod = toml.split(/^\[env\./m)[0]
  for (const m of prod.matchAll(/\[\[queues\.producers\]\]\s*queue\s*=\s*"([^"]+)"\s*binding\s*=\s*"([^"]+)"/g)) queueBindings.set(m[2], m[1])
  const consumerFile = 'workers/src/queues/consumer.ts'
  const consumerText = byPath.get(consumerFile)?.text ?? ''
  const jobTypes = [...new Set([...consumerText.matchAll(/job\.type === '([a-z_]+)'/g)].map(m => m[1]))]
  for (const [binding, queue] of queueBindings) {
    const senders = files.filter(f => isScript(f) && f.kind !== 'test' && new RegExp(`\\b${binding}\\b`).test(f.text)).map(f => f.path)
    addNode(systemKey('queue', queue), 'queue', `Queue ${queue}`,
      `Cloudflare queue ${queue} (binding ${binding}), configured in workers/wrangler.toml. Consumed by ${consumerFile}.${queue === 'advisory-queue' && jobTypes.length ? ` Job types handled: ${list(jobTypes)}.` : ''}${senders.length ? ` Messages are sent from: ${list(senders, 15)}.` : ''}`,
      { queue, binding }, 'workers/wrangler.toml')
    if (fileSet.has(consumerFile)) addEdge(systemKey('queue', queue), fileKey(consumerFile), 'CONSUMED_BY')
    for (const s of senders) addEdge(fileKey(s), systemKey('queue', queue), 'SENDS_TO')
  }
  const triggersFile = 'workers/src/cron/triggers.ts'
  const triggersText = byPath.get(triggersFile)?.text ?? ''
  const cronNames = new Map([...triggersText.matchAll(/'([^']+)':\s*'([a-z-]+)'/g)].map(m => [m[1], m[2]]))
  const stepNames = [...new Set([...triggersText.matchAll(/step\(env,\s*'([a-z-]+)'/g)].map(m => m[1]))]
  const cronBlock = /crons\s*=\s*\[([\s\S]*?)\n\]/.exec(prod)?.[1] ?? ''
  for (const m of cronBlock.matchAll(/"([^"]+)"\s*,?\s*(?:#\s*(.*))?/g)) {
    const expr = m[1]
    const handler = cronNames.get(expr)
    addNode(systemKey('cron', expr), 'cron', `Cron ${expr}${handler ? ` (${handler})` : ''}`,
      `Scheduled job with cron expression "${expr}" (UTC)${m[2] ? `: ${m[2].trim()}` : ''}. Handler name: ${handler ?? 'unnamed'}, run by handleCron in ${triggersFile}.${handler === 'drift-audit' && stepNames.length ? ` After the drift audit it also runs the steps: ${list(stepNames)}.` : ''} Crons run on the production worker only; staging has none.`,
      { cron: expr, handler: handler ?? null }, 'workers/wrangler.toml')
    if (fileSet.has(triggersFile)) addEdge(systemKey('cron', expr), fileKey(triggersFile), 'RUNS')
  }
  for (const s of stepNames) {
    addNode(systemKey('cron', `step ${s}`), 'cron', `Cron step ${s}`, `Isolated step "${s}" of the scheduled jobs in ${triggersFile}; a failure in it does not stop the steps after it. Its last result is kept in KV as cron:last:${s}.`, { step: s }, triggersFile)
    addEdge(systemKey('cron', `step ${s}`), fileKey(triggersFile), 'RUNS')
  }

  // Python classes and functions
  for (const f of pyFiles) {
    const p = py[f.path]
    if (!p || p.error) continue
    const fk = fileKey(f.path)
    if (f.kind === 'test') continue // test functions are listed in the file node
    for (const c of p.classes) {
      const k = systemKey('class', `${f.path}#${c.name}`)
      addNode(k, 'class', `${c.name} (class in ${f.path})`,
        `Python class ${c.name}${c.bases.length ? `(${c.bases.join(', ')})` : ''} in ${f.path} line ${c.line}, ${c.lines} lines.${c.doc ? ` ${c.doc}` : ''}${c.methods.length ? ` Methods: ${list(c.methods.map(m => `${m.name}(${m.args.join(', ')})`), 40)}.` : ''}`,
        { path: f.path, line: c.line, methods: c.methods.length }, f.path)
      addEdge(fk, k, 'DEFINES')
    }
    for (const fn of p.functions) {
      const k = systemKey('function', `${f.path}#${fn.name}`)
      addNode(k, 'function', `${fn.name}() in ${f.path}`,
        `Python ${fn.async ? 'async ' : ''}function ${fn.name}(${fn.args.join(', ')}) in ${f.path} line ${fn.line}, ${fn.lines} lines.${fn.doc ? ` ${fn.doc}` : ''}`,
        { path: f.path, line: fn.line }, f.path)
      addEdge(fk, k, 'DEFINES')
    }
  }

  // Doc sections
  for (const f of files.filter(f => f.kind === 'doc' && f.text && isSectionedDoc(f.path))) {
    const chunks = chunkMarkdown(f.text)
    const seen = new Map()
    const docTitle = /^#\s+(.+)$/m.exec(f.text)?.[1] ?? path.posix.basename(f.path)
    for (const c of chunks) {
      const n = (seen.get(c.heading) ?? 0) + 1
      seen.set(c.heading, n)
      const k = systemKey('doc', `${f.path}#${slug(c.heading)}${n > 1 ? `-${n}` : ''}`)
      addNode(k, 'doc', `${docTitle}: ${c.heading}`, c.body, { path: f.path, heading: c.heading, part: n }, f.path)
      addEdge(k, fileKey(f.path), 'PART_OF')
    }
  }

  // Reference knowledge: ATT&CK and CWE (public MITRE data, shared with all staff)
  let attackCount = 0
  let cweCount = 0
  const attackText = byPath.get('workers/src/data/attack.json')
  const cweText = byPath.get('workers/src/data/cwe.json')
  try {
    const attack = JSON.parse(readFileSync(path.join(REPO, 'workers/src/data/attack.json'), 'utf8'))
    const ref = { reference: true }
    for (const [id, slugName, name] of attack.tactics) {
      addNode(systemKey('tactic', id), 'tactic', `ATT&CK tactic ${id}: ${name}`, `MITRE ATT&CK tactic ${id} ${name} (${slugName}). Source: ${attack.source} v${attack.version}.`, { id }, 'workers/src/data/attack.json', ref)
      attackCount++
    }
    const subs = new Map()
    for (const [id, [name]] of Object.entries(attack.techniques)) if (id.includes('.')) { const parent = id.split('.')[0]; if (!subs.has(parent)) subs.set(parent, []); subs.get(parent).push(`${id} ${name}`) }
    for (const [id, [name, tacticIdx]] of Object.entries(attack.techniques)) {
      if (id.includes('.')) continue
      const tacs = tacticIdx.map(i => attack.tactics[i]).filter(Boolean)
      addNode(systemKey('technique', id), 'technique', `ATT&CK technique ${id}: ${name}`,
        `MITRE ATT&CK technique ${id} ${name}. Tactics: ${tacs.map(t => t[2]).join(', ') || 'none listed'}.${subs.get(id)?.length ? ` Sub-techniques: ${list(subs.get(id), 40)}.` : ''} Source: ${attack.source} v${attack.version}.`,
        { id, tactics: tacs.map(t => t[0]) }, 'workers/src/data/attack.json', ref)
      attackCount++
      for (const t of tacs) addEdge(systemKey('technique', id), systemKey('tactic', t[0]), 'IN_TACTIC')
    }
    const cwe = JSON.parse(readFileSync(path.join(REPO, 'workers/src/data/cwe.json'), 'utf8'))
    // 1385 separate nodes would cost 1385 embeddings. Entries are grouped in runs of CWE_GROUP by id
    // instead; a lookup by id or name still works by keyword, and the group is one embedding.
    const entries = Object.entries(cwe.names).filter(([, name]) => !/^DEPRECATED/i.test(name)).map(([id, name]) => [Number(id), name]).sort((a, b) => a[0] - b[0])
    for (let i = 0; i < entries.length; i += CWE_GROUP) {
      const part = entries.slice(i, i + CWE_GROUP)
      const first = part[0][0]
      const last = part[part.length - 1][0]
      addNode(systemKey('cwe', `${first}-${last}`), 'cwe', `CWE-${first} to CWE-${last}`,
        `MITRE CWE entries ${first} to ${last}. ${part.map(([id, name]) => `CWE-${id}: ${name}.`).join(' ')} Source: ${cwe.source} v${cwe.version}.`,
        { first, last, ids: part.map(e => e[0]) }, 'workers/src/data/cwe.json', ref)
      cweCount++
    }
  } catch (err) {
    if (attackText || cweText) fail(`could not read the ATT&CK/CWE reference data: ${err.message}`)
  }

  // Hotspots
  const hotspotInputs = files.filter(f => f.mode === 'text').map(f => ({
    path: f.path, kind: f.kind, lines: f.lines,
    importers: [...new Set(importers.get(f.path) ?? [])],
    largest: ana.get(f.path)?.decls.slice(0, 3) ?? [...(py[f.path]?.functions ?? []), ...(py[f.path]?.classes ?? [])].map(x => ({ name: x.name, lines: x.lines })).sort((a, b) => b.lines - a.lines).slice(0, 3),
  }))
  const hot = hotspotNodes(hotspotInputs)
  nodes.push(...hot.nodes)
  edges.push(...hot.edges)

  // Screen: secret patterns, .env paths, wrong prefix or tenant. Counts only, never the text.
  const screened = screenNodes(nodes)
  const keep = new Set(screened.nodes.map(n => n.key))
  const finalEdges = [...new Map(edges.filter(e => keep.has(e.from) && keep.has(e.to)).map(e => [`${e.from}|${e.to}|${e.relation}`, e])).values()]
  const finalNodes = [...new Map(screened.nodes.map(n => [n.key, n])).values()]
  const danglingEdges = edges.length - finalEdges.length

  // Report
  const byType = {}
  for (const n of finalNodes) byType[n.type] = (byType[n.type] ?? 0) + 1
  const byRel = {}
  for (const e of finalEdges) byRel[e.relation] = (byRel[e.relation] ?? 0) + 1
  const byVis = {}
  for (const n of finalNodes) byVis[n.visibility] = (byVis[n.visibility] ?? 0) + 1
  const envStored = finalNodes.filter(n => isEnvFile(n.sourceRef ?? '') || isEnvFile(n.key.split(/[: ]/).pop() ?? '') || isEnvFile(String(n.props.path ?? ''))).length
  console.log(`\nSystem graph (${dryRun ? 'dry run, database not touched' : 'write'})`)
  console.log(`Tracked files            : ${tracked.length}`)
  console.log(`  .env*/key files skipped: ${skippedEnv + skippedOther} (not named, not stored)`)
  console.log(`  name only              : ${files.filter(f => f.mode === 'name_only').length}`)
  console.log(`  parsed text            : ${files.filter(f => f.mode === 'text').length} (unreadable ${unreadable})`)
  console.log(`Nodes by type:`)
  for (const [t, n] of Object.entries(byType).sort((a, b) => b[1] - a[1])) console.log(`  ${t.padEnd(10)} ${n}`)
  console.log(`Nodes total              : ${finalNodes.length}`)
  console.log(`Nodes by visibility      : ${Object.entries(byVis).map(([k, v]) => `${k} ${v}`).join(', ')}`)
  console.log(`Edges total              : ${finalEdges.length} (${Object.entries(byRel).map(([k, v]) => `${k} ${v}`).join(', ')}; dropped ${danglingEdges} with a missing end)`)
  console.log(`.env* stored             : ${envStored}`)
  console.log(`Secret-pattern blocks    : ${screened.blockedSecret}${screened.blockedSecret ? ` (${screened.blockedKeys.slice(0, 10).join(', ')})` : ''}`)
  console.log(`Other rejects            : ${screened.rejected + screened.blockedEnv}`)
  const parseFailures = [...ana].filter(([, a]) => a.parseFailed).map(([p]) => p).concat(Object.entries(py).filter(([, v]) => v.error).map(([p]) => p))
  console.log(`Parse failures           : ${parseFailures.length}${parseFailures.length ? ` (${parseFailures.slice(0, 10).join(', ')}); their stored children are kept, not pruned` : ''}`)
  console.log(`Hotspot problems         : ${hot.nodes.length}`)
  console.log(`Frontend API calls       : ${matchedApi} matched to a route, ${unmatchedApi} not matched`)
  console.log(`Routes without a mount   : ${routes.filter(r => r.path.startsWith('/') && !r.path.startsWith('/api/v1') && r.file !== 'workers/src/index.ts').length}`)
  console.log(`Reference data           : ${attackCount} ATT&CK nodes, ${cweCount} CWE group nodes`)
  console.log(`To embed (Worker backfill): ${finalNodes.filter(n => lib_embedded.includes(n.type)).length} nodes`)
  if (envStored !== 0) fail('a node refers to an .env* path. Refusing.')

  if (dryRun) {
    if (show) for (const n of finalNodes.filter(n => n.key.includes(show)).slice(0, 5)) console.log(`
[${n.type}/${n.visibility}] ${n.key}
${n.title}
${n.body}`)
    return
  }

  // ── write (staging only) ──
  if (finalNodes.length < MIN_NODES_TO_PRUNE) fail(`only ${finalNodes.length} nodes were built (expected at least ${MIN_NODES_TO_PRUNE}). Nothing was written.`)
  const vars = loadEnvFile('staging')
  const prodHost = productionHost()
  if (!prodHost) console.log('Note: production-host check skipped because the production host is unknown (no .env.production); relying on the DB_TARGET check.')
  else if (new URL(vars.DATABASE_URL).hostname === prodHost) fail('.env.staging points at the production database host. Refusing; nothing was written.')
  console.log(`\nWriting to ${describe(vars.DATABASE_URL)} (staging)`)
  const { neon } = await import('@neondatabase/serverless')
  const sql = neon(vars.DATABASE_URL)
  const q = (text, params = []) => sql(text, params)
  const existing = (await q(`SELECT key FROM kg_nodes WHERE left(key, ${SYSTEM_PREFIX.length}) = $1`, [SYSTEM_PREFIX])).map(r => r.key)
  // A file that failed to parse built no children; keep what is stored for it rather than delete it.
  const protectedPrefixes = []
  for (const f of files) {
    if (py[f.path]?.error) protectedPrefixes.push(systemKey('class', `${f.path}#`), systemKey('function', `${f.path}#`))
    if (ana.get(f.path)?.parseFailed) protectedPrefixes.push(systemKey('route', ''), systemKey('table', ''), systemKey('queue', ''), systemKey('cron', ''))
  }
  const stale = staleKeys(existing, keep).filter(k => !protectedPrefixes.some(p => k.startsWith(p)))
  const edgesFrom = new Map()
  for (const e of finalEdges) { if (!edgesFrom.has(e.from)) edgesFrom.set(e.from, []); edgesFrom.get(e.from).push(e) }
  for (let i = 0; i < finalNodes.length; i += BATCH) {
    const part = finalNodes.slice(i, i + BATCH)
    await lib.upsertNodes(q, {}, part) // no AI binding here: embeddings stay NULL for the Worker to fill
    await lib.replaceEdges(q, part.map(n => n.key), part.flatMap(n => edgesFrom.get(n.key) ?? []))
  }
  for (let i = 0; i < stale.length; i += 500) {
    const part = stale.slice(i, i + 500)
    await q(`DELETE FROM kg_edges WHERE (from_key = ANY($1::text[]) OR to_key = ANY($1::text[])) AND left(from_key, ${SYSTEM_PREFIX.length}) = $2`, [part, SYSTEM_PREFIX])
    await q(`DELETE FROM kg_nodes WHERE key = ANY($1::text[]) AND left(key, ${SYSTEM_PREFIX.length}) = $2`, [part, SYSTEM_PREFIX])
  }
  console.log(`Stored ${finalNodes.length} nodes and ${finalEdges.length} edges; removed ${stale.length} stale node(s).`)
}

// Types the Worker embeds (kg/store.ts EMBEDDED_TYPES), repeated here only for the report.
const lib_embedded = ['asset', 'event', 'advisory', 'problem', 'status', 'posture', 'agent', 'scan', 'cve', 'ti_event', 'doc', 'page', 'route', 'table', 'file', 'chunk', 'technique', 'cwe']

main().catch(err => {
  console.error(`\nERROR: system graph build failed: ${err?.message ?? err}`)
  process.exit(1)
})
