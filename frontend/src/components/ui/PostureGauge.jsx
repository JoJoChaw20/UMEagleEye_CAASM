import { useEffect, useState } from 'react'

// Posture score dial: a 270° arc that sweeps to the score on load, with a ring node
// at its tip (the logo's circuit node). Bands match the dashboard's existing tones:
// below 50 at risk, below 80 needs attention, 80+ good.
export function postureBand(score) {
  if (score == null) return { label: 'No score yet', color: 'rgb(var(--dark-500))', text: 'text-dark-400', chip: 'border-dark-600 bg-dark-900' }
  if (score < 50) return { label: 'At risk', color: 'rgb(var(--sev-critical))', text: 'text-red-400', chip: 'border-red-500/30 bg-red-500/10' }
  if (score < 80) return { label: 'Needs attention', color: 'rgb(var(--sev-medium))', text: 'text-amber-400', chip: 'border-amber-500/30 bg-amber-500/10' }
  return { label: 'Good', color: 'rgb(var(--eagle-400))', text: 'text-eagle-400', chip: 'border-eagle-500/30 bg-eagle-500/10' }
}

const SIZE = 168
const C = SIZE / 2
const R = 66
const CIRC = 2 * Math.PI * R
const ARC = CIRC * 0.75
const START = 135 // degrees; the gap sits at the bottom

export default function PostureGauge({ score, loading = false }) {
  const [shown, setShown] = useState(0)
  useEffect(() => {
    if (score == null) { setShown(0); return undefined }
    const raf = requestAnimationFrame(() => setShown(Math.max(0, Math.min(100, Number(score)))))
    return () => cancelAnimationFrame(raf)
  }, [score])

  const band = postureBand(loading ? null : score)
  const offset = ARC * (1 - shown / 100)
  const tipDeg = START + 270 * (shown / 100)
  const ease = 'cubic-bezier(0.16, 1, 0.3, 1)'

  return (
    <div className="relative mx-auto" style={{ width: SIZE, height: SIZE }}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} width={SIZE} height={SIZE} aria-hidden="true">
        {/* track */}
        <circle cx={C} cy={C} r={R} fill="none" stroke="rgb(var(--dark-700))" strokeWidth="8"
          strokeDasharray={`${ARC} ${CIRC}`} strokeLinecap="round" transform={`rotate(${START} ${C} ${C})`} />
        {/* quarter ticks */}
        {[0, 25, 50, 75, 100].map((t) => {
          const a = ((START + 270 * (t / 100)) * Math.PI) / 180
          const r1 = R + 9
          const r2 = R + 13
          return <line key={t} x1={C + r1 * Math.cos(a)} y1={C + r1 * Math.sin(a)} x2={C + r2 * Math.cos(a)} y2={C + r2 * Math.sin(a)}
            stroke="rgb(var(--dark-600))" strokeWidth="1.5" strokeLinecap="round" />
        })}
        {/* value */}
        {!loading && score != null && (
          <circle cx={C} cy={C} r={R} fill="none" stroke={band.color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={`${ARC} ${CIRC}`} strokeDashoffset={offset} transform={`rotate(${START} ${C} ${C})`}
            style={{ transition: `stroke-dashoffset 1100ms ${ease}, stroke 300ms` }} />
        )}
        {/* tip node */}
        {!loading && score != null && (
          <g style={{ transform: `rotate(${tipDeg}deg)`, transformOrigin: `${C}px ${C}px`, transition: `transform 1100ms ${ease}` }}>
            <circle cx={C + R} cy={C} r="7" fill="rgb(var(--dark-800))" stroke={band.color} strokeWidth="2.5" />
          </g>
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {loading ? <span className="trace-loader" /> : (
          <>
            <span className="font-display text-[44px] font-semibold leading-none tabular-nums text-dark-50">{score ?? '—'}</span>
            <span className="mt-1 text-[11px] text-dark-400">of 100</span>
          </>
        )}
      </div>
    </div>
  )
}
