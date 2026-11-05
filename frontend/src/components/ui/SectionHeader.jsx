// Section heading with the logo's circuit trace: title, a 1px trace that runs to the
// actions, ending in a ring node. as="h1" for page titles, h2 for sections.
export default function SectionHeader({ as: Tag = 'h2', id, title, description, actions, className = '' }) {
  const size = Tag === 'h1' ? 'text-[26px] leading-8' : 'text-lg leading-6'
  return (
    <div className={`flex flex-wrap items-end gap-x-4 gap-y-3 ${className}`}>
      <div className="min-w-0">
        <Tag id={id} className={`${size} font-semibold text-dark-50`}>{title}</Tag>
        {description && <p className="mt-1 max-w-3xl text-sm text-dark-400">{description}</p>}
      </div>
      <div aria-hidden="true" className="hidden min-w-[48px] flex-1 items-center self-center pt-1 md:flex">
        <span className="trace-line" />
        <span className="trace-node" />
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
