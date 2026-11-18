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
const re = new RegExp(process.argv[3] ?? 'kg-|safety|refused|review|continuation|chatbot|intel', 'i')
for (const e of objs) {
  for (const x of e.logs || []) {
    const m = x.message.map(v => (typeof v === 'string' ? v : JSON.stringify(v))).join(' ')
    if (re.test(m)) console.log(new Date(x.timestamp).toISOString().slice(11, 19), x.level, m.slice(0, 700))
  }
  for (const x of e.exceptions || []) console.log('EXC', x.name, x.message)
  if (e.outcome && e.outcome !== 'ok') console.log('OUTCOME', e.outcome, e.event?.request?.url)
}
console.log('events', objs.length)
