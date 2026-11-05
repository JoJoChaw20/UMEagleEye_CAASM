// Panel heading in the circuit-trace language: a ring node, the title in the display
// face, an optional detail line, and an optional action on the right. Replaces the
// generic icon-chip-plus-title card header.
export default function PanelHeading({ title, detail, action, as: Tag = 'h3', id, className = 'mb-5' }) {
  return (
    <div className={`flex items-start justify-between gap-3 ${className}`}>
      <div className="min-w-0">
        <div className="flex items-center gap-2.5">
          <span aria-hidden="true" className="trace-node" />
          <Tag id={id} className="text-base font-semibold leading-6 text-dark-50">{title}</Tag>
        </div>
        {detail && <p className="mt-1 pl-[17.5px] text-xs text-dark-400">{detail}</p>}
      </div>
      {action && <div className="flex-shrink-0 pt-0.5">{action}</div>}
    </div>
  )
}
