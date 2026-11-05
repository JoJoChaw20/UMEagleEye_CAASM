// Authored circuit traces in the logo's grammar: straight runs that break at 45°,
// each ending in a ring node. Light "packets" travel the traces (CSS, so reduced
// motion stops them). Decorative only.
const TRACES = [
  { d: 'M-10 176 H96 L170 250 H300 L336 286', end: [336, 286], delay: 1.4 },
  { d: 'M-10 262 H64 L128 326 H244', end: [244, 326], delay: 2.6 },
  { d: 'M-10 352 H180 L232 404 H420 L470 454', end: [470, 454], delay: 0.7 },
  { d: 'M-10 448 H120 L176 504 H332', end: [332, 504], delay: 3.1 },
  { d: 'M-10 540 H210 L262 592 H392', end: [392, 592], delay: 1.9 },
  { d: 'M-10 636 H88 L150 698 H268 L300 730', end: [300, 730], delay: 4.0 },
  { d: 'M610 214 H540 L490 264 H452', end: [452, 264], delay: 0 },
  { d: 'M610 702 H520 L470 652 H430', end: [430, 652], delay: 3.6 },
]

export default function CircuitField({ className = '' }) {
  return (
    <svg viewBox="0 0 600 800" preserveAspectRatio="xMidYMid slice" aria-hidden="true" className={className}>
      <g fill="none" strokeLinecap="round" strokeLinejoin="round">
        {TRACES.map((t, i) => (
          <g key={i}>
            <path d={t.d} stroke="rgb(var(--brand-blue) / 0.3)" strokeWidth="1.5" />
            <path d={t.d} stroke="rgb(var(--brand-cyan))" strokeWidth="2" pathLength="100"
              className="circuit-packet" style={{ animationDelay: `${t.delay}s` }} />
            <circle cx={t.end[0]} cy={t.end[1]} r="6" stroke="rgb(var(--brand-sky) / 0.75)" strokeWidth="2" fill="rgb(var(--rail))" />
          </g>
        ))}
      </g>
    </svg>
  )
}
