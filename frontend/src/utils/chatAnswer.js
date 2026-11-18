// chatAnswer.js - pure helpers for showing an assistant answer: citations, the confidence line and
// the safe refusal. Model text is only ever split into strings here; it is never turned into HTML.

export const SAFE_REFUSAL = "I can't recommend a safe way to do that from here. Please involve the system owner or the vendor before changing anything."
export const SUPERADMIN_ADVISORY_REFUSAL = 'The Platform Superadmin can view overall statistics and ask general security questions, but cannot debug advisories.'

const CITATION = /\[\s*([SKL]\d+(?:\s*,\s*[SKL]\d+)*)\s*\]/gi

/** Splits text into plain parts and citation groups: [{ type: 'text', text } | { type: 'cite', refs: ['S1', 'K2'] }]. */
export function parseCitations(text) {
  const out = []
  let last = 0
  for (const m of String(text ?? '').matchAll(CITATION)) {
    if (m.index > last) out.push({ type: 'text', text: text.slice(last, m.index) })
    out.push({ type: 'cite', refs: m[1].split(',').map(r => r.trim().toUpperCase()) })
    last = m.index + m[0].length
  }
  if (last < String(text ?? '').length) out.push({ type: 'text', text: String(text).slice(last) })
  return out
}

const CONFIDENCE = /^\s*(?:[-*>]\s*)?(?:\*\*|__)?\s*confidence\s*(?:\*\*|__)?\s*:\s*(?:\*\*|__)?\s*(high|medium|low)\b(?:\*\*|__)?\s*[-–—:,.]?\s*(.*)$/i
const CHECK_WITH = /^\s*(?:[-*>]\s*)?(?:\*\*|__)?\s*check with\s*(?:\*\*|__)?\s*:\s*(.+)$/i

/** The confidence line, as { level: 'High' | 'Medium' | 'Low', reason }, or null. */
export function confidenceOf(line) {
  const m = String(line ?? '').match(CONFIDENCE)
  if (!m) return null
  const level = m[1][0].toUpperCase() + m[1].slice(1).toLowerCase()
  return { level, reason: m[2].replace(/\*\*|__/g, '').trim() }
}

/** The "Check with:" line's value, or null. */
export function checkWithOf(line) {
  const m = String(line ?? '').match(CHECK_WITH)
  return m ? m[1].replace(/\*\*|__/g, '').trim() : null
}

/** True when the whole answer is one of the server's fixed refusals (shown as a warning). */
export function isSafeRefusal(text) {
  const t = String(text ?? '').trim()
  return t === SAFE_REFUSAL || t === SUPERADMIN_ADVISORY_REFUSAL
}

/** A source link the page may open: https only, so a javascript: or data: URL can never be a link. */
export function safeSourceUrl(url) {
  try {
    const u = new URL(String(url ?? ''))
    return u.protocol === 'https:' ? u.href : null
  } catch {
    return null
  }
}

/** Sources by ref (S1, K2, L1), for the citation links. */
export function sourcesByRef(sources) {
  const map = new Map()
  for (const s of Array.isArray(sources) ? sources : []) if (s && typeof s.ref === 'string') map.set(s.ref.toUpperCase(), s)
  return map
}
