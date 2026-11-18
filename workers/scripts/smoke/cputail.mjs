import fs from 'node:fs'
const txt = fs.readFileSync(process.argv[2], 'utf8')
let depth = 0, start = -1, inStr = false, esc = false
const objs = []
for (let i = 0; i < txt.length; i++) {
  const c = txt[i]
  if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue }
  if (c === '"') { inStr = true; continue }
  if (c === '{') { if (depth === 0) start = i; depth++ }
  else if (c === '}') { depth--; if (depth === 0) { try { objs.push(JSON.parse(txt.slice(start, i + 1))) } catch {} } }
}
const groups = {}
for (const e of objs) {
  const url = e.event?.request?.url ?? (e.event?.cron ? 'cron' : e.event?.queue ? 'queue' : 'other')
  const path = url.replace(/^https?:\/\/[^/]+/, '').replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/g, ':id').replace(/\?.*$/, '')
  const key = `${e.event?.request?.method ?? ''} ${path}`
  ;(groups[key] ??= []).push({ cpu: e.cpuTime, wall: e.wallTime, outcome: e.outcome })
}
const keys = Object.keys(objs[0] ?? {})
console.log('event keys:', keys.join(','))
for (const [k, v] of Object.entries(groups).sort((a, b) => b[1].length - a[1].length)) {
  const cpus = v.map(x => x.cpu).filter(x => typeof x === 'number').sort((a, b) => a - b)
  const bad = v.filter(x => x.outcome !== 'ok').map(x => x.outcome)
  const p = q => cpus.length ? cpus[Math.min(cpus.length - 1, Math.floor(q * cpus.length))] : '-'
  console.log(`${String(v.length).padStart(4)} ${k.padEnd(60)} cpu ms p50=${p(0.5)} p95=${p(0.95)} max=${cpus.at(-1) ?? '-'} ${bad.length ? 'NOT-OK: ' + bad.join(',') : ''}`)
}
