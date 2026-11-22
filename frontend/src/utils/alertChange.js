// What a threat-intel change did to alerts, in words (workers/src/services/iocMatch.ts AlertChange).
// "marked": open CVE alerts that stayed open but gained or lost a threat-intel match: they do not
// show as new or closed on the Alerts page, so they are named apart.
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`

export function alertChangeText(data) {
  const ch = data?.alerts_change
  if (!ch) return data?.alerts_updated ? `${plural(data.alerts_updated, 'alert', 'alerts')} updated.` : ''
  const parts = [
    ch.opened && `${plural(ch.opened, 'alert', 'alerts')} raised`,
    ch.reopened && `${plural(ch.reopened, 'alert', 'alerts')} reopened`,
    ch.resolved && `${plural(ch.resolved, 'alert', 'alerts')} resolved`,
    ch.marked && `${plural(ch.marked, 'open CVE alert', 'open CVE alerts')} gained or lost a threat-intel match`,
  ].filter(Boolean)
  return parts.length ? `${parts.join(' · ')}.` : ''
}
