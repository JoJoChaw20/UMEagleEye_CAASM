// The computer's security baseline (GET /assets/:id baseline, workers/src/lib/baseline.ts): 30 checks
// after the CIS Benchmarks, the same number for Windows and Linux, against the tenant's target.
// Failed checks first, each with what passes, what the agent found, how to fix it and the CIS reference.
import { useEffect, useState } from 'react'
import { CheckCircle2, ChevronRight, HelpCircle, Lock, MinusCircle, ShieldCheck, XCircle } from 'lucide-react'
import { Section, Empty } from './DetailParts'

const AREAS = {
  updates: 'Updates', accounts: 'Accounts and passwords', firewall: 'Firewall', disk: 'Disk and boot',
  remote: 'Remote access and network', hardening: 'System hardening', integrity: 'Malware and integrity', logging: 'Logging and time',
}
const STATE = {
  fail: { icon: XCircle, cls: 'text-red-400', text: 'Failed' },
  pass: { icon: CheckCircle2, cls: 'text-green-400', text: 'Passed' },
  na: { icon: MinusCircle, cls: 'text-dark-400', text: 'Does not apply' },
  admin: { icon: Lock, cls: 'text-amber-400', text: 'Needs Administrator / root' },
  unknown: { icon: HelpCircle, cls: 'text-dark-400', text: 'Not reported' },
}
const ORDER = { fail: 0, admin: 1, unknown: 2, na: 3, pass: 4 }

function Check({ c }) {
  const [open, setOpen] = useState(false)
  const m = STATE[c.state] ?? STATE.unknown
  const Icon = m.icon
  return (
    <li className="py-1.5">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open}
        className="w-full flex items-start gap-2 text-left">
        <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${m.cls}`} aria-hidden="true" />
        <span className="min-w-0 flex-1">
          <span className="flex items-center justify-between gap-2">
            <span className="text-sm text-dark-100">{c.label}</span>
            <span className={`text-[11px] whitespace-nowrap ${m.cls}`}>{m.text}</span>
          </span>
          {c.found && <span className="block text-[11px] text-dark-400 break-words">Found: {c.found}</span>}
        </span>
        <ChevronRight className={`w-3.5 h-3.5 mt-1 text-dark-500 transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden="true" />
      </button>
      {open && (
        <dl className="ml-6 mt-1 space-y-1 text-[11px]">
          <div><dt className="inline text-dark-500">Passes when: </dt><dd className="inline text-dark-300">{c.expected}</dd></div>
          {c.state !== 'pass' && c.state !== 'na' && <div><dt className="inline text-dark-500">How to fix: </dt><dd className="inline text-dark-300 break-words">{c.fix}</dd></div>}
          <div><dt className="inline text-dark-500">CIS Benchmark: </dt><dd className="inline text-dark-400">{c.cis}</dd></div>
        </dl>
      )}
    </li>
  )
}

export default function BaselineSection({ baseline }) {
  const [showPassed, setShowPassed] = useState(false)
  // Linked from a Below Security Baseline alert (#security-baseline): the router does not scroll to it
  useEffect(() => {
    if (window.location.hash === '#security-baseline') document.getElementById('security-baseline')?.scrollIntoView({ block: 'start' })
  }, [])
  if (!baseline) {
    return (
      <Section icon={ShieldCheck} title="Security baseline" className="xl:col-span-2">
        <Empty>Not reported. The agent sends these checks from the build of 23 November 2026: update it from the Agents page.</Empty>
      </Section>
    )
  }
  const { percent, target, passed, judged, readable, total, assessed, checks, os } = baseline
  const below = assessed && target != null && percent < target
  const pctCls = !assessed ? 'text-dark-400' : below ? (percent < 80 ? 'text-red-400' : 'text-amber-400') : 'text-green-400'
  const shown = checks.filter((c) => showPassed || c.state !== 'pass').sort((a, b) => ORDER[a.state] - ORDER[b.state])
  const byArea = Object.keys(AREAS).map((a) => [a, shown.filter((c) => c.area === a)]).filter(([, l]) => l.length)
  const passedCount = checks.filter((c) => c.state === 'pass').length

  return (
    <section id="security-baseline" className="xl:col-span-2 scroll-mt-4">
      <Section icon={ShieldCheck} title="Security baseline"
        right={
          <span className="text-xs text-right">
            <span className={`font-semibold ${pctCls}`}>{assessed ? `${percent}%` : 'Not assessed'}</span>
            {target != null && <span className="text-dark-400"> · target {target}%</span>}
          </span>
        }>
        {assessed && (
          <div className="mb-3" aria-hidden="true">
            <div className="relative h-2 rounded-full bg-dark-700/60">
              <div className={`h-2 rounded-full ${below ? (percent < 80 ? 'bg-red-500/70' : 'bg-amber-500/70') : 'bg-green-500/70'}`} style={{ width: `${percent}%` }} />
              {target != null && <div className="absolute -top-1 h-4 w-0.5 bg-dark-100" style={{ left: `${target}%` }} title={`Target ${target}%`} />}
            </div>
          </div>
        )}
        <p className="text-[11px] text-dark-400 mb-2">
          {os === 'linux' ? 'Linux' : 'Windows'}: {passed} of {judged} judged checks passed; {readable} of {total} could be read.
          {' '}Checks after the CIS Benchmarks (Level 1): 30 for Windows and 30 for Linux, in the same eight areas. Unreadable checks are left out, never counted as passed.
          {!assessed && ' Too few checks could be read for a score: run the agent as Administrator / root (its service does).'}
        </p>
        <div className="space-y-3">
          {byArea.map(([area, list]) => (
            <div key={area}>
              <p className="text-[11px] uppercase tracking-wide text-dark-500 mb-0.5">{AREAS[area]}</p>
              <ul className="divide-y divide-dark-700/40">{list.map((c) => <Check key={c.id} c={c} />)}</ul>
            </div>
          ))}
        </div>
        {passedCount > 0 && (
          <button type="button" onClick={() => setShowPassed((s) => !s)} className="mt-3 text-xs text-eagle-400 hover:underline">
            {showPassed ? 'Hide passed checks' : `Show passed checks (${passedCount})`}
          </button>
        )}
      </Section>
    </section>
  )
}
