import { Link } from 'react-router-dom'
import { ListChecks } from 'lucide-react'
import { checklistItems } from '../../utils/notices'

// The new Tenant Superadmin's security checklist (notice kind owner_checklist). "Done" dismisses it.
export default function OwnerChecklist({ notice, onDone, busy }) {
  const items = checklistItems(notice)
  if (!items.length) return null
  return (
    <div className="rounded-lg border border-eagle-500/30 bg-eagle-500/5 p-4">
      <p id="owner-checklist-title" className="flex items-center gap-2 text-sm font-medium text-dark-50">
        <ListChecks className="h-4 w-4 text-accent-cyan" aria-hidden="true" />
        Security checklist for the new Tenant Superadmin
      </p>
      <ul aria-labelledby="owner-checklist-title" className="mt-2 space-y-1 text-sm text-dark-200">
        {items.map((it) => (
          <li key={it.label} className="flex items-start gap-2">
            <span aria-hidden="true" className="mt-0.5 text-dark-500">&#9744;</span>
            {it.to ? <Link to={it.to} className="text-eagle-400 underline-offset-2 hover:underline">{it.label}</Link> : <span>{it.label}</span>}
          </li>
        ))}
      </ul>
      <button type="button" onClick={onDone} disabled={busy} className="btn-primary mt-3 text-xs py-1.5">Done</button>
    </div>
  )
}
