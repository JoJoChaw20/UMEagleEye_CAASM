// Fix-time figures in words (workers/src/services/fixTime.ts). Plain JS: the Worker builds the report
// PDF with it too (reportPdf.js).

/** Hours as people say them: "45 min", "6 h", "3.5 days". */
export function hoursText(h) {
  if (h == null || Number.isNaN(Number(h))) return '-'
  const n = Number(h)
  if (n < 1) return `${Math.round(n * 60)} min`
  if (n < 48) return `${Math.round(n * 10) / 10} h`
  return `${Math.round(n / 2.4) / 10} days`
}

/** Hands-on WORK (estimated effort), which is not calendar time: always hours, with 8-hour working
 *  days when it is a lot ("156 h (19.5 working days)"). hoursText is for elapsed time. */
export function workText(h) {
  if (h == null || Number.isNaN(Number(h))) return '-'
  const n = Number(h)
  if (n < 1) return `${Math.round(n * 60)} min`
  const hours = `${Math.round(n * 10) / 10} h`
  return n >= 16 ? `${hours} (${Math.round(n / 0.8) / 10} working days)` : hours
}

/** On-time share colour band: 80%+ good, 50%+ fair, below poor; null when nothing was resolved. */
export function onTimeBand(pct) {
  if (pct == null) return null
  return pct >= 80 ? 'good' : pct >= 50 ? 'fair' : 'poor'
}
