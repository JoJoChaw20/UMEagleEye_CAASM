import { useId } from 'react'

// A small trend line drawn from real history. `values` are numbers oldest → newest;
// `markIndex` draws a dashed guide at one point (e.g. the comparison point "7 days
// ago"); the newest point ends in a ring node, like the logo's circuit traces.
// The SVG stretches to its container; the node is HTML so it stays round.
export default function Sparkline({
  values = [], height = 32, color = 'rgb(var(--eagle-400))',
  min, max, markIndex = null, label, className = '',
}) {
  const id = useId().replace(/:/g, '')
  const clean = values.map(Number).filter(Number.isFinite)
  if (clean.length < 2) {
    return <span className={`flex items-end text-[11px] text-dark-500 ${className}`} style={{ height }}>Not enough history yet</span>
  }
  const W = 100
  const H = height
  const lo = min ?? Math.min(...clean)
  const hi = max ?? Math.max(...clean)
  const span = hi - lo || 1
  const padY = 4
  const x = (i) => (i / (clean.length - 1)) * W
  const y = (val) => padY + (1 - (val - lo) / span) * (H - padY * 2)
  const line = `M${clean.map((val, i) => `${x(i).toFixed(2)},${y(val).toFixed(2)}`).join(' L')}`
  const area = `${line} L${W},${H} L0,${H} Z`
  const last = clean.length - 1

  return (
    <span className={`relative block ${className}`} style={{ height }} role="img" aria-label={label}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" className="block overflow-visible" aria-hidden="true">
        <defs>
          <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.2" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} fill={`url(#spark-${id})`} />
        {markIndex != null && markIndex >= 0 && markIndex < last && (
          <line x1={x(markIndex)} x2={x(markIndex)} y1={0} y2={H} stroke="rgb(var(--dark-500))" strokeDasharray="2 3" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        )}
        <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      </svg>
      <span aria-hidden="true" className="absolute h-[7px] w-[7px] -translate-x-1/2 -translate-y-1/2 rounded-full border-[1.5px] bg-dark-800"
        style={{ left: '100%', top: `${(y(clean[last]) / H) * 100}%`, borderColor: color }} />
    </span>
  )
}
