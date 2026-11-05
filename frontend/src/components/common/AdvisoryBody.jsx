import { useState } from 'react'
import { Check, Copy, ExternalLink, ShieldCheck, Undo2, Clock } from 'lucide-react'
import { parseAdvisory } from '../../utils/advisoryText'

const CONFIDENCE_STYLE = {
  High: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
  Medium: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
  Low: 'border-dark-600 bg-dark-900 text-dark-300',
}

function CommandLine({ command }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(command); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* clipboard blocked */ }
  }
  return (
    <div className="flex items-center gap-2 rounded-md border border-dark-700 bg-dark-950 py-1.5 pl-3 pr-1.5">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-dark-100">{command}</code>
      <button type="button" onClick={copy} className="btn-ghost flex-shrink-0 px-2 py-1 text-xs" aria-label="Copy command">
        {copied ? <Check className="h-3.5 w-3.5 text-accent-green" /> : <Copy className="h-3.5 w-3.5" />}
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

// Renders a stored advisory: steps, the "why now" window, ready-to-run commands,
// verify and rollback, confidence and clickable sources. Old plain advisories show
// their steps only. compact = the Alerts drawer.
export default function AdvisoryBody({ text, compact = false }) {
  const a = parseAdvisory(text)
  if (!a.steps.length && !a.structured) return <p className="text-sm text-dark-400">No recommended action recorded.</p>
  return (
    <div className="space-y-4">
      {a.whyNow && (
        <div className="flex items-start gap-2.5 rounded-md border border-eagle-500/30 bg-eagle-500/[0.07] px-3 py-2.5 text-sm text-dark-100">
          <Clock className="mt-0.5 h-4 w-4 flex-shrink-0 text-eagle-400" /><span>{a.whyNow}</span>
        </div>
      )}

      <ol className="space-y-2">
        {a.steps.map((step, i) => (
          <li key={i} className="flex items-start gap-3">
            <span className="mt-0.5 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 font-display text-xs font-semibold text-eagle-400">{i + 1}</span>
            <span className={`${compact ? 'text-xs' : 'text-sm'} leading-relaxed text-dark-100`}>{step}</span>
          </li>
        ))}
      </ol>

      {a.commands.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-dark-300">Run</p>
          {a.commands.map((c) => <CommandLine key={c} command={c} />)}
          <p className="text-[11px] text-dark-500">Review before running; take a backup or snapshot first.</p>
        </div>
      )}

      {(a.verify || a.rollback) && (
        <div className={`grid gap-3 ${compact ? '' : 'md:grid-cols-2'}`}>
          {a.verify && (
            <div className="rounded-md border border-dark-700 bg-dark-900 p-3">
              <p className="mb-1 flex items-center gap-1.5 text-xs font-medium text-dark-200"><ShieldCheck className="h-3.5 w-3.5 text-accent-green" />Verify the fix</p>
              <p className="text-xs leading-relaxed text-dark-300">{a.verify}</p>
            </div>
          )}
          {a.rollback && (
            <div className="rounded-md border border-dark-700 bg-dark-900 p-3">
              <p className="mb-1 flex items-center gap-1.5 text-xs font-medium text-dark-200"><Undo2 className="h-3.5 w-3.5 text-dark-400" />If it breaks</p>
              <p className="text-xs leading-relaxed text-dark-300">{a.rollback}</p>
            </div>
          )}
        </div>
      )}

      {(a.confidence || a.sources.length > 0 || a.basis) && (
        <div className="space-y-2 border-t border-dark-700 pt-3">
          {a.sources.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-dark-400">Sources</span>
              {a.sources.map((s) => (
                <a key={s.url} href={s.url} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-md border border-dark-700 bg-dark-900 px-2 py-0.5 text-[11px] text-dark-200 transition-colors hover:border-eagle-500/50 hover:text-eagle-400">
                  {s.label}<ExternalLink className="h-3 w-3" aria-hidden="true" />
                </a>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2 text-[11px] text-dark-400">
            {a.confidence?.level && <span className={`rounded-md border px-2 py-0.5 font-semibold ${CONFIDENCE_STYLE[a.confidence.level] ?? CONFIDENCE_STYLE.Low}`}>{a.confidence.level} confidence</span>}
            {a.confidence?.reason && <span>{a.confidence.reason}</span>}
            {a.basis && <span className="text-dark-500">· {a.basis}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
