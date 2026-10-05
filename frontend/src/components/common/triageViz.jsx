// Visual building blocks shared by the Dashboard and Alerts pages. Every color
// here carries a meaning (severity or urgency) and is always paired with a text
// label, so nothing is readable by color alone.
import { ChevronRight, Clock, CheckCircle2, Globe } from 'lucide-react'
import { SEVERITY_COLORS, TONE, CONCERNS, priorityTier, dueInfo, alertLabel, renderDetail } from './alertMeta'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const cap = (s) => s[0].toUpperCase() + s.slice(1)
export const fmtNum = (n) => (n ?? 0).toLocaleString()

// Horizontal part-to-whole bar of open alerts by severity, with a labelled legend.
export function SeverityStack({ counts, onSelect, height = 10, legend = true }) {
  // Without a click action the parts render as spans, so the bar can sit inside a button
  const Part = onSelect ? 'button' : 'span'
  const total = SEVERITIES.reduce((s, k) => s + (counts?.[k] ?? 0), 0)
  return (
    <div>
      <div className="flex w-full gap-[2px] rounded overflow-hidden bg-dark-700/40" style={{ height }}>
        {total > 0 && SEVERITIES.map(k => {
          const n = counts?.[k] ?? 0
          if (!n) return null
          return (
            <Part key={k} type={onSelect ? 'button' : undefined} onClick={onSelect ? () => onSelect(k) : undefined}
              title={`${cap(k)}: ${fmtNum(n)} (${Math.round((n / total) * 100)}%)`}
              className={`block h-full ${onSelect ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
              style={{ width: `${(n / total) * 100}%`, minWidth: 4, background: SEVERITY_COLORS[k] }} />
          )
        })}
      </div>
      {legend && <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
        {SEVERITIES.map(k => (
          <Part key={k} type={onSelect ? 'button' : undefined} onClick={onSelect ? () => onSelect(k) : undefined}
            className={`flex items-center gap-1.5 text-xs text-dark-300 ${onSelect ? 'hover:text-dark-100' : 'cursor-default'}`}>
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[k] }} />
            {cap(k)} <span className="text-dark-100 font-semibold tabular-nums">{fmtNum(counts?.[k] ?? 0)}</span>
          </Part>
        ))}
      </div>}
    </div>
  )
}

// One "should I worry?" category: count, why it matters, what to do, examples.
export function ConcernCard({ meta, count, examples = [], loading, onOpen, onExample, active }) {
  const Icon = meta.icon
  const clear = !loading && count === 0
  const t = clear ? TONE.good : TONE[meta.tone]
  return (
    <div className={`glass-card w-full p-4 border-l-4 transition-colors flex flex-col
        ${clear ? 'border-l-emerald-500/50 opacity-80' : t.bg}
        ${active ? 'ring-2 ring-eagle-500/60' : 'hover:border-eagle-500/40'}`}
      style={!clear ? { borderLeftColor: t.bar } : undefined}>
      {/* Header area opens the whole category */}
      <button type="button" onClick={onOpen} disabled={clear || loading || !onOpen} className="text-left group"
        title={onOpen && !clear ? `Open all ${fmtNum(count)} alerts in this category` : undefined}>
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${clear ? 'text-emerald-400' : t.text}`} />
          <span className="text-sm font-semibold text-dark-100 group-hover:text-eagle-300">{meta.title}</span>
        </div>
        <div className="flex items-baseline gap-2 mt-2">
          <span className={`text-4xl font-bold leading-none ${clear ? 'text-dark-400' : 'text-dark-50'}`}>{loading ? '…' : fmtNum(count)}</span>
          {clear
            ? <span className="text-xs text-emerald-400 inline-flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" />All clear</span>
            : !loading && <span className={`text-xs font-semibold ${t.text}`}>{meta.action}</span>}
        </div>
        <p className="text-xs text-dark-400 mt-2 leading-relaxed">{meta.why}</p>
      </button>
      {/* Each example opens that specific alert */}
      {!clear && examples.length > 0 && (
        <ul className="mt-3 space-y-0.5 border-t border-dark-700/60 pt-2">
          {examples.map(e => (
            <li key={e.event_id} className="min-w-0">
              <button type="button" onClick={() => onExample?.(e)} disabled={!onExample} title="Open this alert"
                className="w-full text-left text-xs min-w-0 rounded px-1 -mx-1 py-0.5 hover:bg-dark-700/30">
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: SEVERITY_COLORS[e.severity] }} />
                  <span className="text-dark-200 truncate" title={e.asset?.hostname || e.asset?.ip}>{e.asset?.hostname || e.asset?.ip}</span>
                  {e.asset?.internet_facing && <Globe className="w-3 h-3 text-accent-amber flex-shrink-0" title="Internet-facing" />}
                </span>
                <span className="block font-mono text-[11px] text-dark-400 truncate pl-3" title={shortDetail(e)}>{shortDetail(e)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {!clear && !loading && onOpen && (
        <button type="button" onClick={onOpen} className="mt-auto pt-3 text-xs text-eagle-400 hover:underline inline-flex items-center gap-0.5 self-start">
          Review {count === 1 ? 'it' : `all ${fmtNum(count)}`} <ChevronRight className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  )
}

// Compact one-row version of the concern cards, used as quick filters on the
// Alerts page (the Dashboard carries the full explanations).
export function ConcernFilterBar({ counts, loading, active, onPick }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[11px] font-semibold uppercase tracking-wide text-dark-500 mr-1">Quick filters</span>
      {CONCERNS.map(meta => {
        const Icon = meta.icon
        const n = counts?.[meta.id] ?? 0
        const clear = !loading && n === 0
        const t = TONE[meta.tone]
        const on = active === meta.id
        return (
          <button key={meta.id} type="button" onClick={() => onPick(meta.id)} title={`${meta.why} ${meta.action}.`}
            aria-pressed={on}
            className={`inline-flex items-center gap-1.5 pl-2 pr-1 py-1 rounded-lg border text-[13px] transition-colors
              ${on ? 'border-eagle-500 bg-eagle-500/10 text-dark-50' : 'border-dark-700 bg-dark-800/60 text-dark-200 hover:border-dark-500'}`}>
            <Icon className={`w-4 h-4 ${clear ? 'text-emerald-400' : t.text}`} />
            {meta.short ?? meta.title}
            <span className={`text-xs font-bold tabular-nums px-1.5 py-0.5 rounded min-w-[1.75rem] text-center
              ${clear ? 'bg-dark-700/60 text-dark-400' : `${t.bg} ${t.text}`}`}>
              {loading ? '…' : fmtNum(n)}
            </span>
          </button>
        )
      })}
    </div>
  )
}

function shortDetail(e) {
  if (e.event_type === 'new_device') return e.details?.mac ?? 'new'
  if (e.event_type === 'config_change') return alertLabel(e).replace(' Changed', '')
  return renderDetail(e)
}

// Severity × "how long has it been open" grid. Cell shade = count (one hue,
// log scale); cells past the SLA target are flagged with a clock + red outline.
const SLA_PAST = { critical: ['d3_7', 'd7_30', 'gt30'], high: ['d7_30', 'gt30'] }
const BUCKET_LABELS = { lt1d: '< 1 day', d1_3: '1–3 days', d3_7: '3–7 days', d7_30: '7–30 days', gt30: '> 30 days' }

export function AgingHeatmap({ aging, onCell }) {
  const buckets = Object.keys(BUCKET_LABELS)
  const max = Math.max(1, ...SEVERITIES.flatMap(s => buckets.map(b => aging?.[s]?.[b] ?? 0)))
  const shade = (n) => n ? 0.08 + 0.5 * (Math.log1p(n) / Math.log1p(max)) : 0
  const colTotals = buckets.map(b => SEVERITIES.reduce((s, sev) => s + (aging?.[sev]?.[b] ?? 0), 0))
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs border-separate" style={{ borderSpacing: 2 }}>
        <thead>
          <tr>
            <th className="text-left text-dark-500 font-medium pb-1 pr-2">Open for →</th>
            {buckets.map(b => <th key={b} className="text-dark-400 font-medium pb-1 whitespace-nowrap">{BUCKET_LABELS[b]}</th>)}
            <th className="text-dark-400 font-medium pb-1 pl-2 text-right">Total</th>
          </tr>
        </thead>
        <tbody>
          {SEVERITIES.map(sev => {
            const rowTotal = buckets.reduce((s, b) => s + (aging?.[sev]?.[b] ?? 0), 0)
            return (
              <tr key={sev}>
                <th scope="row" className="text-left font-medium pr-2 whitespace-nowrap">
                  <span className="inline-flex items-center gap-1.5 text-dark-200">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[sev] }} />{cap(sev)}
                  </span>
                </th>
                {buckets.map(b => {
                  const n = aging?.[sev]?.[b] ?? 0
                  const late = n > 0 && SLA_PAST[sev]?.includes(b)
                  return (
                    <td key={b} className="p-0">
                      <button type="button" disabled={!n} onClick={() => onCell?.(sev, b)}
                        title={`${fmtNum(n)} ${sev} alert${n === 1 ? '' : 's'} open ${BUCKET_LABELS[b]}${late ? ' — past SLA' : ''}`}
                        className={`w-full h-9 rounded text-center tabular-nums transition-colors
                          ${n ? 'text-dark-50 font-semibold hover:ring-2 hover:ring-eagle-400/60 cursor-pointer' : 'text-dark-600 cursor-default'}
                          ${late ? 'ring-1 ring-inset ring-red-500/70' : ''}`}
                        style={{ background: n ? `rgba(51,147,255,${shade(n)})` : 'rgb(var(--dark-700) / 0.25)' }}>
                        <span className="inline-flex items-center gap-1">
                          {late && <Clock className="w-3 h-3 text-red-400" />}{n ? fmtNum(n) : '·'}
                        </span>
                      </button>
                    </td>
                  )
                })}
                <td className="pl-2 text-right text-dark-200 font-semibold tabular-nums">{fmtNum(rowTotal)}</td>
              </tr>
            )
          })}
          <tr>
            <th className="text-left text-dark-500 font-medium pr-2 pt-1">All</th>
            {colTotals.map((n, i) => <td key={i} className="text-center text-dark-300 tabular-nums pt-1">{fmtNum(n)}</td>)}
            <td />
          </tr>
        </tbody>
      </table>
      <p className="text-[11px] text-dark-500 mt-2 flex items-center gap-3 flex-wrap">
        <span className="inline-flex items-center gap-1"><Clock className="w-3 h-3 text-red-400" />red outline = past SLA (critical &gt; 3 days, high &gt; 7 days)</span>
        <span>Darker = more alerts · click a cell to list them</span>
      </p>
    </div>
  )
}

export function ReasonChips({ reasons, max = 4 }) {
  if (!reasons?.length) return null
  const toneCls = {
    critical: 'border-red-500/40 text-red-300 bg-red-500/10',
    serious:  'border-orange-500/30 text-orange-300 bg-orange-500/10',
    good:     'border-emerald-500/30 text-emerald-300 bg-emerald-500/10',
  }
  return (
    <span className="inline-flex flex-wrap gap-1">
      {reasons.slice(0, max).map(r => (
        <span key={r.label} className={`text-[10px] px-1.5 py-0.5 rounded border whitespace-nowrap ${toneCls[r.tone] ?? toneCls.serious}`}>{r.label}</span>
      ))}
    </span>
  )
}

export function PriorityTier({ score }) {
  const t = priorityTier(score)
  if (!t) return <span className="text-dark-500">—</span>
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border font-semibold whitespace-nowrap ${t.cls}`}
      title={`Priority score ${Math.round(score)} = risk × internet exposure × asset criticality (+ threat intel)`}>
      {t.tier}<span className="font-normal opacity-80">{t.label}</span>
    </span>
  )
}

export function DueLabel({ e }) {
  const d = dueInfo(e)
  if (!d) return null
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium whitespace-nowrap ${d.overdue ? 'text-red-400' : 'text-dark-300'}`}>
      <Clock className="w-3 h-3" />{d.label}
    </span>
  )
}
