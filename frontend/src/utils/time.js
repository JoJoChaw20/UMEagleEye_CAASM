// Relative "time ago" formatter for the inventory First/Last seen column.
// Pure and self-contained (unit-tested in workers/scripts/assets-revision-demo.ts).
//
// Returns { text, title, stale, isNull }:
//   text   — short relative label ("2h ago", "3d ago", "5mo ago", "just now")
//   title  — exact local date+time for a hover tooltip (null when no value)
//   stale  — true when the timestamp is 7 days old or older (tint it amber)
//   isNull — true when there was no value (caller already has its null label)
//
// Edge cases: null/invalid → the caller's nullText (default "—"); a future
// timestamp clamps to "just now"; 7 days exactly counts as stale.
export function formatSeen(value, opts = {}) {
  const nullText = opts.nullText ?? '—'
  if (value == null) return { text: nullText, title: null, stale: false, isNull: true }
  const d = new Date(value)
  if (isNaN(d.getTime())) return { text: nullText, title: null, stale: false, isNull: true }

  const now = opts.now != null ? new Date(opts.now) : new Date()
  const sec = Math.floor((now.getTime() - d.getTime()) / 1000)

  let text
  if (sec <= 0) {
    text = 'just now'                               // future clamps to "just now"
  } else if (sec < 60) {
    text = `${sec}s ago`
  } else if (sec < 3600) {
    text = `${Math.floor(sec / 60)}m ago`
  } else if (sec < 86400) {
    text = `${Math.floor(sec / 3600)}h ago`
  } else {
    const days = Math.floor(sec / 86400)
    if (days < 7)        text = `${days}d ago`
    else if (days < 30)  text = `${Math.floor(days / 7)}w ago`
    else if (days < 365) text = `${Math.floor(days / 30)}mo ago`
    else                 text = `${Math.floor(days / 365)}y ago`
  }

  const SEVEN_DAYS = 7 * 86400
  return { text, title: d.toLocaleString(), stale: sec >= SEVEN_DAYS, isNull: false }
}
