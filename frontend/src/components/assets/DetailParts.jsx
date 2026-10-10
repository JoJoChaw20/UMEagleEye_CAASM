// Layout pieces shared by the asset detail page and its endpoint-inventory sections.

export function Section({ icon: Icon, title, right, children, className = '' }) {
  return (
    <section className={`glass-card p-5 ${className}`}>
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Icon className="w-4 h-4 text-eagle-400" /> {title}
        </h2>
        {right}
      </div>
      {children}
    </section>
  )
}

export function Field({ label, children }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 border-b border-dark-700/40 last:border-0">
      <dt className="text-xs text-dark-400 whitespace-nowrap pt-0.5">{label}</dt>
      <dd className="text-sm text-dark-100 text-right break-all">{children ?? <span className="text-dark-500">—</span>}</dd>
    </div>
  )
}

export const Empty = ({ children }) => <p className="text-sm text-dark-400">{children}</p>

export const fmtDateTime = (d) => (d ? new Date(d).toLocaleString() : '—')
export const fmtDate = (d) => (d ? new Date(d).toLocaleDateString() : '—')

export function fmtBytes(bytes) {
  if (!bytes) return null
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = Number(bytes)
  let i = 0
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++ }
  return `${value >= 10 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`
}
