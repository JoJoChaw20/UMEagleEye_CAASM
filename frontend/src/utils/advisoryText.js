// Reads an advisory's recommendedAction text. New advisories use labelled lines
// (see workers/src/lib/advisoryKit.ts); older ones are plain numbered steps or a
// {"a","b"} set, and still parse as steps only.
const LABELS = {
  'why now': 'whyNow', command: 'commands', verify: 'verify', rollback: 'rollback',
  confidence: 'confidence', sources: 'sources', basis: 'basis',
}

const stripNumber = (s) => s.replace(/^\s*\d+[.)]\s*/, '').trim()

function legacySteps(raw) {
  if (raw.startsWith('{') && raw.endsWith('}')) {
    return raw.slice(1, -1).split(/",\s*"/).map((s) => s.replace(/^"+|"+$/g, '').trim()).filter(Boolean).map(stripNumber)
  }
  return raw.split(/\n/).map((s) => s.trim()).filter(Boolean).map(stripNumber)
}

// Only https links from the stored Sources line become anchors.
function parseSources(text) {
  return text.split('|').map((part) => {
    const m = part.trim().match(/^(.*?)\s+(https:\/\/\S+)$/)
    return m ? { label: m[1].trim(), url: m[2] } : null
  }).filter(Boolean)
}

export function parseAdvisory(rawText) {
  const raw = (rawText ?? '').trim()
  const out = { steps: [], whyNow: null, commands: [], verify: null, rollback: null, confidence: null, sources: [], basis: null, structured: false }
  if (!raw) return out

  const stepLines = []
  for (const line of raw.split('\n')) {
    const m = line.match(/^(Why now|Command|Verify|Rollback|Confidence|Sources|Basis):\s*(.*)$/i)
    if (!m) { stepLines.push(line); continue }
    const key = LABELS[m[1].toLowerCase()]
    const value = m[2].trim()
    out.structured = true
    if (key === 'commands') out.commands.push(value)
    else if (key === 'sources') out.sources = parseSources(value)
    else if (key === 'confidence') {
      const c = value.match(/^(High|Medium|Low)\s*-?\s*(.*)$/i)
      out.confidence = c ? { level: c[1][0].toUpperCase() + c[1].slice(1).toLowerCase(), reason: c[2] } : { level: null, reason: value }
    } else out[key] = value
  }
  out.steps = legacySteps(stepLines.join('\n').trim())
  return out
}
