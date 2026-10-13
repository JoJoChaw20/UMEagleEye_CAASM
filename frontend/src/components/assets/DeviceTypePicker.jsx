import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Check, ChevronDown, Loader2, Wand2 } from 'lucide-react'
import client from '../../api/client'
import { DEVICE_TYPE_META } from './assetMeta'

const TYPES = Object.keys(DEVICE_TYPE_META)
const MENU_W = 232

// Who decided the type, as a small marker next to it.
function sourceOf(asset) {
  if (asset.deviceTypeSource === 'manual') return { tag: 'by hand', cls: 'text-eagle-400', text: 'Set by hand' }
  if (asset.deviceTypeSource === 'agent') return { tag: 'agent', cls: 'text-green-400', text: 'Confirmed by agent' }
  const hint = asset.deviceTypeHint
  if (asset.deviceType !== 'unknown' && hint?.auto && hint.type === asset.deviceType) return { tag: 'auto', cls: 'text-dark-400', text: `Inferred from ${hint.evidence}` }
  return { tag: 'auto', cls: 'text-dark-400', text: asset.deviceType === 'unknown' ? 'Not identified yet' : 'Inferred from scans' }
}

// Change a device type in place (Inventory list and asset page), for every asset, not
// only My Assets. A type chosen here is set by hand (scans and agents never change it);
// "Automatic" hands it back to the system, which recomputes it from the stored agent
// and scan facts. The baseline moves with it, so a reclassification is not drift.
// compact: the Inventory row variant (smaller chip, source as a tiny tag).
export default function DeviceTypePicker({ asset, onChanged, compact = false }) {
  const [open, setOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [pos, setPos] = useState(null)
  const [active, setActive] = useState(0)
  const anchorRef = useRef(null)
  const menuRef = useRef(null)
  const menuId = useId()

  const manual = asset.deviceTypeSource === 'manual'
  const meta = DEVICE_TYPE_META[asset.deviceType] ?? DEVICE_TYPE_META.unknown
  const src = sourceOf(asset)
  // Menu rows: Automatic, then the types. The checked row is the current choice.
  const rows = ['auto', ...TYPES]
  const checkedIndex = manual ? rows.indexOf(asset.deviceType) : 0

  const place = useCallback(() => {
    const r = anchorRef.current?.getBoundingClientRect()
    if (!r) return
    const m = 8, estH = 330
    const left = Math.min(Math.max(m, r.left), window.innerWidth - MENU_W - m)
    const below = r.bottom + m + estH < window.innerHeight || r.top - m - estH < 0
    setPos({ left, top: below ? r.bottom + 4 : r.top - 4, below })
  }, [])

  const show = () => { place(); setActive(checkedIndex < 0 ? 0 : checkedIndex); setOpen(true) }
  const close = useCallback((refocus = true) => { setOpen(false); if (refocus) anchorRef.current?.focus() }, [])

  useLayoutEffect(() => { if (open) menuRef.current?.focus() }, [open])

  useEffect(() => {
    if (!open) return
    const onDown = (e) => {
      if (!menuRef.current?.contains(e.target) && !anchorRef.current?.contains(e.target)) close(false)
    }
    const onMove = () => place()
    window.addEventListener('mousedown', onDown)
    window.addEventListener('scroll', onMove, true)
    window.addEventListener('resize', onMove)
    return () => {
      window.removeEventListener('mousedown', onDown)
      window.removeEventListener('scroll', onMove, true)
      window.removeEventListener('resize', onMove)
    }
  }, [open, place, close])

  const choose = async (row) => {
    close()
    if (row === 'auto' ? !manual : manual && row === asset.deviceType) return   // no change
    const body = row === 'auto' ? { device_type_source: 'auto' } : { device_type: row }
    setSaving(true)
    try {
      const res = await client.patch(`/assets/${asset.assetId}`, { ...body, update_baseline: true })
      await onChanged?.(res.data)
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to change the device type')
    } finally {
      setSaving(false)
    }
  }

  const onMenuKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); close() }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => (i + 1) % rows.length) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => (i - 1 + rows.length) % rows.length) }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0) }
    else if (e.key === 'End') { e.preventDefault(); setActive(rows.length - 1) }
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(rows[active]) }
    else if (e.key === 'Tab') close(false)
  }

  const stop = (e) => e.stopPropagation()   // the Inventory row navigates on click

  return (
    <span onClick={stop} className="inline-flex">
      <button
        ref={anchorRef}
        type="button"
        onClick={() => (open ? close() : show())}
        onKeyDown={(e) => { if (e.key === 'ArrowDown' && !open) { e.preventDefault(); show() } }}
        disabled={saving}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Device type: ${meta.label}, ${src.text}. Change`}
        title={`${src.text}. Click to change.`}
        className={`group inline-flex items-center gap-1.5 rounded-md border border-transparent hover:border-dark-600 hover:bg-dark-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-eagle-500 transition-colors ${compact ? 'px-1.5 py-1 -mx-1.5' : 'px-2 py-1 -mx-2'} ${open ? 'border-dark-600 bg-dark-800/60' : ''}`}
      >
        <span className={compact ? 'text-base leading-none' : 'text-lg leading-none'} aria-hidden="true">{meta.icon}</span>
        <span className="text-left leading-tight">
          <span className={`block ${compact ? 'text-xs' : 'text-sm'} text-dark-100`}>{meta.label}</span>
          {compact && <span className={`block text-[10px] ${src.cls}`}>{src.tag}</span>}
        </span>
        {saving
          ? <Loader2 className="w-3.5 h-3.5 text-dark-400 animate-spin" />
          : <ChevronDown className={`w-3.5 h-3.5 text-dark-500 group-hover:text-dark-300 transition-transform ${open ? 'rotate-180' : ''}`} />}
      </button>

      {open && pos && createPortal(
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          tabIndex={-1}
          aria-label="Device type"
          aria-activedescendant={`${menuId}-${active}`}
          onKeyDown={onMenuKey}
          onClick={stop}
          style={{ position: 'fixed', left: pos.left, top: pos.top, width: MENU_W, transform: pos.below ? 'none' : 'translateY(-100%)', zIndex: 1000 }}
          className="bg-dark-900 border border-dark-600 rounded-xl shadow-2xl p-1.5 text-sm outline-none"
        >
          <p className="px-2.5 pt-1 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-dark-400">Device type</p>
          {rows.map((row, i) => {
            const checked = i === checkedIndex
            const isAuto = row === 'auto'
            const m = DEVICE_TYPE_META[row]
            return (
              <div key={row}>
                <div
                  id={`${menuId}-${i}`}
                  role="menuitemradio"
                  aria-checked={checked}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(row)}
                  className={`flex items-start gap-2.5 px-2.5 py-1.5 rounded-lg cursor-pointer ${i === active ? 'bg-dark-800' : ''}`}
                >
                  <span className="w-5 text-center leading-5" aria-hidden="true">
                    {isAuto ? <Wand2 className="w-4 h-4 inline text-eagle-400" /> : m.icon}
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block text-dark-100 leading-5">{isAuto ? 'Automatic' : m.label}</span>
                    {isAuto && (
                      <span className="block text-[11px] text-dark-400 leading-snug">
                        {manual ? 'Let the agent and scans decide' : `Currently ${meta.label.toLowerCase()}: ${src.text.charAt(0).toLowerCase()}${src.text.slice(1)}`}
                      </span>
                    )}
                  </span>
                  {checked && <Check className="w-4 h-4 mt-0.5 text-eagle-400 flex-shrink-0" aria-hidden="true" />}
                </div>
                {isAuto && <div className="my-1 mx-2 border-t border-dark-700" role="separator" />}
              </div>
            )
          })}
          <p className="px-2.5 pt-1.5 pb-1 text-[11px] text-dark-400 leading-snug border-t border-dark-700 mt-1">
            A type you choose is kept: scans and agents never change it.
          </p>
        </div>,
        document.body,
      )}
    </span>
  )
}
