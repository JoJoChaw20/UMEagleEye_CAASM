// How an EagleEye agent built an SBOM (agents 2.2.6+, sboms raw_data.run): a full run
// (every folder listed) or a daily run (only folders that changed), and the folders it
// could not list this time. A "kept" folder's packages are from its last listing, so its
// CVE alerts stay open; a "missing" folder was never listed, so none of its packages are in.
import { Link } from 'react-router-dom'
import { AlertTriangle, Info } from 'lucide-react'

const folderName = (path) => String(path).split(/[\\/]/).filter(Boolean).pop() || path

function minutes(seconds) {
  const m = Math.round((seconds || 0) / 60)
  return m >= 1 ? `${m} min` : `${seconds || 0} s`
}

function listedAt(iso) {
  if (!iso) return 'an earlier run'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function sbomRunProblems(run) {
  return (run?.kept?.length || 0) + (run?.missing?.length || 0)
}

export default function SbomRunNote({ run, compact = false }) {
  if (!run) return null
  const kept = run.kept || []
  const missing = run.missing || []
  const summary = run.mode === 'quick'
    ? `Daily run: ${run.listed} folder${run.listed === 1 ? '' : 's'} listed, ${run.unchanged} unchanged since their last listing`
    : `Full run: ${run.listed} of ${run.folders} folders listed`

  if (compact) {
    if (!kept.length && !missing.length) return null
    return (
      <p className="mt-3 text-xs text-amber-300 flex items-start gap-1.5">
        <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
        <span>
          The last SBOM could not list {kept.length + missing.length} folder{kept.length + missing.length === 1 ? '' : 's'}
          {kept.length ? `; ${kept.length} kept the packages of an earlier listing` : ''}
          {missing.length ? `; ${missing.length} ${missing.length === 1 ? 'has' : 'have'} no packages yet` : ''}.{' '}
          <Link to="/sbom" className="text-eagle-400 hover:underline">Details in SBOM</Link>
        </span>
      </p>
    )
  }

  return (
    <div className="mb-4 space-y-2 text-xs">
      <p className="text-dark-300 flex items-center gap-1.5">
        <Info className="w-3.5 h-3.5 text-dark-400" />
        {summary} · {minutes(run.seconds)} of listing
      </p>
      {kept.length > 0 && (
        <div className="rounded border border-amber-500/30 bg-amber-500/5 p-2.5">
          <p className="text-amber-300 font-medium mb-1">
            {kept.length} folder{kept.length === 1 ? '' : 's'} not listed this time: {kept.length === 1 ? 'its' : 'their'} packages
            (and CVE alerts) are from {kept.length === 1 ? 'its' : 'their'} last listing
          </p>
          <ul className="space-y-0.5 text-dark-300">
            {kept.map((k) => (
              <li key={k.folder} title={k.folder}>
                <span className="text-dark-100">{folderName(k.folder)}</span>: listed {listedAt(k.listed_at)}. This time: {k.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {missing.length > 0 && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-2.5">
          <p className="text-red-300 font-medium mb-1">
            {missing.length} folder{missing.length === 1 ? '' : 's'} never listed: no packages from {missing.length === 1 ? 'it' : 'them'} are in this SBOM
          </p>
          <ul className="space-y-0.5 text-dark-300">
            {missing.map((m) => (
              <li key={m.folder} title={m.folder}>
                <span className="text-dark-100">{folderName(m.folder)}</span>: {m.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
