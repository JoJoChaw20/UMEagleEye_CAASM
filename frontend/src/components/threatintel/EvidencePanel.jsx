// How much of the threat intelligence is used, and how well it works here: the indicators by use (live, GET
// /cti/stats usage), how this organisation's threat-intel alerts ended (live, outcomes_90d), and the limits that
// hold for every deployment. (The lab evaluation results are evidence for the project report, kept in
// C:\FYP\AP2\eval, not on this page: they describe the test machines, not the viewer's network.)
import { ShieldCheck, Database, AlertTriangle } from 'lucide-react'
import { REASON_LABEL, USE_META } from './indicatorUse'
import { Spinner } from '../common/PageParts'

const fmt = (n) => Number(n ?? 0).toLocaleString()

const BLIND = [
  'Encrypted DNS hides lookups on Windows (system DNS over HTTPS) and in any app with its own (browser secure DNS); connections and running programs are still checked.',
  'Device addresses are matched too, but most offices and campuses sit behind one router, so a listed IP is usually caught by an agent\'s connection, not by the address.',
  'A file hash matches only that exact file: a rebuilt or repacked sample is not caught.',
  'Without an agent, a computer is checked only by its address and name.',
]

const KIND_LABEL = { sighting: 'Seen by an agent (sightings)', ioc: 'Address or name listed', malicious_package: 'Malicious package', watchlist: 'Watched software' }

export default function EvidencePanel({ stats }) {
  const u = stats?.usage
  const total = u ? u.agents + u.assets + u.reference : 0
  const pct = (n) => (total ? Math.round((n / total) * 100) : 0)
  const outcomes = Object.entries(stats?.outcomes_90d ?? {})
  return (
    <div className="space-y-4">
      <div className="glass-card p-5 space-y-3">
        <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2"><Database className="w-4 h-4 text-eagle-400" /> What the indicators are used for</h3>
        <p className="text-xs text-dark-400">MyCERT's advisories and the sources' indicators. A source's value that can no longer raise an alert is deleted; reference-only values are kept inside MyCERT's advisories.</p>
        {!u ? <Spinner className="py-8" /> : <>
          <div className="flex h-2.5 gap-px overflow-hidden rounded-full bg-dark-700/50" role="img"
            aria-label={`${fmt(u.agents)} checked by agents, ${fmt(u.assets)} checked against assets, ${fmt(u.reference)} reference only`}>
            <span className="bg-eagle-500" style={{ width: `${pct(u.agents)}%` }} />
            <span className="bg-sky-400" style={{ width: `${pct(u.assets)}%` }} />
            <span className="bg-dark-600" style={{ width: `${pct(u.reference)}%` }} />
          </div>
          <ul className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            {['agents', 'assets', 'reference'].map((k) => (
              <li key={k} className="rounded-md border border-dark-700/50 p-3">
                <p className="text-dark-200 font-medium">{USE_META[k].label}</p>
                <p className="mt-0.5 font-display text-xl text-dark-50 tabular-nums">{fmt(u[k])} <span className="text-xs text-dark-500">({pct(u[k])}%)</span></p>
                <p className="mt-1 text-dark-400">{USE_META[k].help}</p>
                {k === 'reference' && Object.keys(u.reference_reasons).length > 0 && (
                  <ul className="mt-1.5 space-y-0.5 text-dark-500">
                    {Object.entries(u.reference_reasons).sort((a, b) => b[1] - a[1]).map(([r, n]) => <li key={r}>{fmt(n)} {REASON_LABEL[r] ?? r}</li>)}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </>}
      </div>

      <div className="glass-card p-5 space-y-2">
        <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-accent-green" /> How your threat-intel alerts ended (last 90 days)</h3>
        {outcomes.length === 0 ? <p className="text-xs text-dark-400">No threat-intel alert was closed in the last 90 days.</p> : (
          <table className="w-full text-xs">
            <thead><tr className="text-dark-400 border-b border-dark-700/60">
              <th className="py-1.5 text-left font-medium">Kind</th><th className="py-1.5 text-right font-medium">Resolved</th>
              <th className="py-1.5 text-right font-medium">False positive</th><th className="py-1.5 text-right font-medium">Accepted risk</th>
              <th className="py-1.5 text-right font-medium">Not false positive</th>
            </tr></thead>
            <tbody>
              {outcomes.map(([kind, o]) => {
                const n = o.resolved + o.false_positive + o.accepted_risk
                return <tr key={kind} className="border-b border-dark-700/30">
                  <td className="py-1.5 text-dark-200">{KIND_LABEL[kind] ?? kind}</td>
                  <td className="py-1.5 text-right tabular-nums">{fmt(o.resolved)}</td>
                  <td className={`py-1.5 text-right tabular-nums ${o.false_positive ? 'text-amber-400' : ''}`}>{fmt(o.false_positive)}</td>
                  <td className="py-1.5 text-right tabular-nums">{fmt(o.accepted_risk)}</td>
                  <td className="py-1.5 text-right tabular-nums text-dark-100">{n ? `${Math.round(((n - o.false_positive) / n) * 100)}%` : '—'}</td>
                </tr>
              })}
            </tbody>
          </table>
        )}
        <p className="text-[11px] text-dark-500">From how analysts closed them: a false positive is a match that turned out harmless. Alerts closed automatically (the indicator stopped matching) count as resolved.</p>
      </div>

      {/* True of every deployment, so an analyst can read the numbers above for what they are */}
      <div className="glass-card p-5 space-y-2 border border-amber-500/30">
        <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> Limits: what it cannot see</h3>
        <ul className="list-disc pl-5 space-y-0.5 text-xs text-dark-300">
          {BLIND.map((b) => <li key={b}>{b}</li>)}
        </ul>
      </div>
    </div>
  )
}
