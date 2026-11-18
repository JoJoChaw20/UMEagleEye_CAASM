/**
 * continuation.ts - PURE. Joins an answer the model wrote in several parts because it hit its output
 * limit (spec, Project 2: replies are never cut off). When even the continuations run out, the text is
 * cut back to its last complete sentence or line and ends with a fixed note, so it never stops mid-word.
 */

export const LONG_NOTE = 'This answer was too long to finish. Ask about one step at a time.'
export const CONTINUE_PROMPT = 'Continue exactly where you stopped. Do not repeat anything you already wrote, and do not restart the answer.'
/** At most this many continuations, and this many output tokens across all parts. */
export const MAX_CONTINUATIONS = 3
export const MAX_ANSWER_TOKENS = 12_000

const MIN_OVERLAP = 8
const MAX_OVERLAP = 400

/** The next part without the words it repeats from the end of the text so far. */
function withoutOverlap(sofar: string, next: string): string {
  const limit = Math.min(MAX_OVERLAP, sofar.length, next.length)
  for (let k = limit; k >= MIN_OVERLAP; k--) {
    const head = next.slice(0, k)
    if (!sofar.endsWith(head)) continue
    // Only a whole-word overlap counts, so a short coincidence inside a word is kept.
    const before = sofar.charAt(sofar.length - k - 1)
    if (before === '' || /\s/.test(before) || /\s/.test(head.charAt(0))) return next.slice(k)
  }
  return next
}

// A sentence end: . ! or ? with any closing quote, bracket, emphasis or citation, then a space or the end.
const SENTENCE_END = /[.!?]["'’”)\]*_`]*(?:\s*\[[SKL]\d+(?:\s*,\s*[SKL]\d+)*\])?(?=\s|$)/g

/** The text up to its last complete sentence or completed line, without a code block left open. */
function toLastSentence(text: string): string {
  let cut = -1
  for (const m of text.matchAll(SENTENCE_END)) cut = Math.max(cut, (m.index ?? 0) + m[0].length)
  // A line followed by a newline was finished, even a list item with no full stop.
  cut = Math.max(cut, text.lastIndexOf('\n'))
  let out = cut > 0 ? text.slice(0, cut) : ''
  // An odd number of fences means a code block was cut open: drop it from its opening fence.
  const fences = [...out.matchAll(/^\s*(```|~~~)/gm)]
  if (fences.length % 2 === 1) out = out.slice(0, fences[fences.length - 1]!.index ?? 0)
  return out.trimEnd()
}

/** Joins the parts of one answer. `capped`: it still was not finished, so end on a sentence and add the note. */
export function joinContinuation(parts: string[], capped: boolean): string {
  let text = ''
  for (const part of parts) text += text ? withoutOverlap(text, part) : part
  if (!capped) return text.trimEnd()
  const kept = toLastSentence(text)
  return kept ? `${kept}\n\n${LONG_NOTE}` : LONG_NOTE
}
