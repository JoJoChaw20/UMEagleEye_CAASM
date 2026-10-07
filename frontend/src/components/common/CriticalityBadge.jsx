import { useState, useRef, useEffect, useCallback, useId } from 'react'
import { createPortal } from 'react-dom'
import client from '../../api/client'

// Shared criticality badge + breakdown tooltip, used by BOTH All Assets and My Assets
// so the two can't drift. The breakdown is fetched lazily from GET /assets/:id/score
// (the same source My Assets already used — server-side computeCriticality, 1 query,
// cached after first open). The tooltip renders in a portal so the table's overflow /
// page edges never clip it, and flips above/below depending on room.
//
// footer:
//   'slider'   → My Assets (has a manual slider): "…Drag slider to override."
//   'computed' → All Assets (no slider):          "…Use Rescore Criticality to refresh."

const FOOTERS = {
  slider:   'Hover score = computed value. Drag slider to override.',
  computed: "Computed from the asset's own data. Use Rescore Criticality to refresh.",
}

function meta(s) {
  if (s >= 9) return { label: 'Critical', cls: 'bg-red-500/20 text-red-400 border-red-500/30' }
  if (s >= 7) return { label: 'High',     cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' }
  if (s >= 4) return { label: 'Medium',   cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' }
  return        { label: 'Low',      cls: 'bg-green-500/20 text-green-400 border-green-500/30' }
}

const TIP_W = 256

export default function CriticalityBadge({ score, assetId, footer = 'slider' }) {
  const s = Number(score)
  const { label, cls } = meta(s)
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState(null)
  const [tip, setTip] = useState(null)
  const [loading, setLoading] = useState(false)
  const anchorRef = useRef(null)
  const tipId = useId()

  const fetchBreakdown = useCallback(async () => {
    if (tip || !assetId) return
    setLoading(true)
    try { const res = await client.get(`/assets/${assetId}/score`); setTip(res.data) }
    catch { /* silent */ } finally { setLoading(false) }
  }, [tip, assetId])

  const place = useCallback(() => {
    const el = anchorRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const m = 8
    const left = Math.min(Math.max(m, r.left), window.innerWidth - TIP_W - m)
    const estH = 190
    const above = r.top - m - estH > 0            // enough room above? else drop below
    setPos({ left, top: above ? r.top - m : r.bottom + m, above })
  }, [])

  const show = useCallback(() => { place(); setOpen(true); fetchBreakdown() }, [place, fetchBreakdown])
  const hide = useCallback(() => setOpen(false), [])

  useEffect(() => {
    if (!open) return
    const onMove = () => place()
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    window.addEventListener('scroll', onMove, true)
    window.addEventListener('resize', onMove)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('scroll', onMove, true)
      window.removeEventListener('resize', onMove)
      window.removeEventListener('keydown', onKey)
    }
  }, [open, place])

  const computed = tip?.score
  const mismatch = tip && computed != null && computed !== s
  const bd = tip?.breakdown

  return (
    <>
      <span
        ref={anchorRef}
        tabIndex={0}
        role="button"
        aria-label={`Criticality ${s} out of 10, ${label}. Show breakdown.`}
        aria-describedby={open ? tipId : undefined}
        className={`inline-block text-xs px-2 py-0.5 rounded-full border font-medium cursor-default select-none outline-none focus-visible:ring-2 focus-visible:ring-eagle-500 ${cls}`}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        onClick={() => (open ? hide() : show())}
      >
        {s}/10 <span className="opacity-70">{label}</span>
      </span>

      {open && pos && createPortal(
        <div
          id={tipId}
          role="tooltip"
          style={{ position: 'fixed', left: pos.left, top: pos.top, width: TIP_W, transform: pos.above ? 'translateY(-100%)' : 'none', zIndex: 1000, pointerEvents: 'none' }}
        >
          <div className="bg-dark-900 border border-dark-600 rounded-xl p-3 shadow-2xl text-xs space-y-2 text-dark-200">
            <p className="font-semibold text-dark-100">Criticality Breakdown</p>
            {loading && <p className="text-dark-300">Loading…</p>}
            {mismatch && (
              <p className="text-dark-300 leading-relaxed">
                Stored score {s}/10, computed {computed}/10: use <span className="text-dark-100">Rescore Criticality</span> to apply.
              </p>
            )}
            {tip && !mismatch && (
              <>
                <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-dark-300">
                  <span>Base (device type)</span><span className="text-right text-dark-100">+{bd?.base}</span>
                  {bd?.internetFacing > 0 && <><span>Internet facing</span><span className="text-right text-yellow-400">+{bd.internetFacing}</span></>}
                  {bd?.portRisk > 0 && <><span>Port risk</span><span className="text-right text-orange-400">+{bd.portRisk}</span></>}
                  {bd?.hostnameHints != null && bd.hostnameHints !== 0 && <><span>Hostname hints</span><span className={`text-right ${bd.hostnameHints > 0 ? 'text-orange-400' : 'text-green-400'}`}>{bd.hostnameHints > 0 ? '+' : ''}{bd.hostnameHints}</span></>}
                </div>
                {tip.factors?.length > 0 && (
                  <ul className="text-dark-300 space-y-0.5 border-t border-dark-700 pt-2">
                    {tip.factors.map((f, i) => <li key={i}>· {f}</li>)}
                  </ul>
                )}
              </>
            )}
            <p className="text-dark-300 border-t border-dark-700 pt-1.5">{FOOTERS[footer] ?? FOOTERS.slider}</p>
          </div>
        </div>,
        document.body,
      )}
    </>
  )
}
