import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle2, ExternalLink, Globe, Link2, Hash, Mail, Bug, Package, FileText } from 'lucide-react'
import client from '../../api/client'
import { SevBadge } from '../common/alertMeta'
import { SidePanel, Spinner } from '../common/PageParts'

export const TYPE_META = {
  ip:       { icon: Globe,    label: 'IP' },
  domain:   { icon: Link2,    label: 'Domain' },
  url:      { icon: FileText, label: 'URL' },
  hash:     { icon: Hash,     label: 'Hash' },
  email:    { icon: Mail,     label: 'Email' },
  cve:      { icon: Bug,      label: 'CVE' },
  software: { icon: Package,  label: 'Software' },
}

export function TypeLabel({ type }) {
  const m = TYPE_META[type] ?? { icon: FileText, label: type }
  const Icon = m.icon
  return <span className="inline-flex items-center gap-1.5 text-xs text-dark-300"><Icon className="w-3.5 h-3.5 text-dark-400" />{m.label}</span>
}

const MATCH_KIND = { ioc: 'Listed IOC', watchlist: 'Watched software', address: 'Uses this IP (no alert)' }

// What threat intel knows about one value, and which of our assets it touches.
export default function IndicatorPanel({ value, onClose }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setResult(null)
    setError('')
    client.get('/cti/lookup', { params: { value } })
      .then((r) => setResult(r.data))
      .catch((err) => setError(err?.response?.data?.detail || 'Lookup failed'))
  }, [value])

  const ind = result?.indicator
  const assets = result?.matched_assets ?? []

  return (
    <SidePanel title={<span className="font-mono break-all">{value}</span>} subtitle="Threat-intel lookup" onClose={onClose}>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/40 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}
      {!result && !error && <Spinner />}

      {result && (
        <>
          <div className={`flex items-start gap-3 p-3 rounded-lg border ${result.found
            ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-green-500/10 border-green-500/40 text-green-500'}`}>
            {result.found ? <AlertTriangle className="w-5 h-5 shrink-0" /> : <CheckCircle2 className="w-5 h-5 shrink-0" />}
            <div>
              <p className="font-semibold text-sm">{result.found ? 'Known threat indicator' : 'Not in threat intelligence'}</p>
              <p className="text-xs opacity-80 mt-0.5">
                {result.found
                  ? `Listed by ${ind.source}${ind.event_title ? ` (event “${ind.event_title}”)` : ''}.`
                  : 'This does not mean it is safe: it may not be tracked yet.'}
              </p>
            </div>
          </div>

          {ind && (
            <div className="grid grid-cols-2 gap-2">
              {[
                ['Type', <TypeLabel key="t" type={ind.indicator_type} />],
                ['Confidence', `${((ind.confidence_score ?? 0) * 100).toFixed(0)}%`],
                ['Malware family', ind.malware_family || '—'],
                ['ATT&CK software', ind.attack_software ? `${ind.attack_software_name} (${ind.attack_software})` : '—'],
                ['First seen', new Date(ind.first_seen).toLocaleString()],
                ['Last seen', new Date(ind.last_seen).toLocaleString()],
              ].map(([label, v]) => (
                <div key={label} className="bg-dark-800/60 rounded-lg p-3">
                  <p className="text-xs text-dark-400 mb-0.5">{label}</p>
                  <div className="text-sm text-dark-100 break-words">{v}</div>
                </div>
              ))}
            </div>
          )}

          {ind?.techniques?.length > 0 && (
            <div>
              <p className="text-xs text-dark-400 mb-1.5">
                ATT&CK techniques ({ind.techniques.length}){ind.attack_software ? `, as MITRE documents for ${ind.attack_software_name}` : ', named by the feed'}
              </p>
              <div className="flex flex-wrap gap-1">
                {ind.techniques.map((t) => (
                  <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noreferrer"
                    className="text-[11px] px-1.5 py-0.5 rounded bg-dark-700/60 text-dark-200 hover:text-eagle-400" title={t.name}>
                    <span className="font-mono">{t.id}</span> {t.name}
                  </a>
                ))}
              </div>
            </div>
          )}

          <div>
            <h3 className="text-sm font-semibold text-dark-200 mb-2">Our assets ({assets.length})</h3>
            {assets.length === 0 ? (
              <p className="text-xs text-dark-400 bg-dark-800/40 border border-dark-700/40 rounded-lg p-3">
                <CheckCircle2 className="w-4 h-4 inline mr-1.5 text-green-500" />
                None of your assets matches it.
              </p>
            ) : (
              <ul className="space-y-2">
                {assets.map((a) => (
                  <li key={`${a.asset_id}-${a.event_id ?? 'ip'}`} className="bg-dark-800/60 border border-dark-700/50 rounded-lg p-3 flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <Link to={`/inventory/${a.asset_id}`} className="text-sm font-medium text-eagle-400 hover:underline">{a.hostname || a.ip_address}</Link>
                      <p className="text-xs text-dark-400 mt-0.5">
                        {MATCH_KIND[a.match_kind] ?? 'Match'}{a.observed ? <> · <span className="font-mono">{a.observed}</span></> : null}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {a.severity && <SevBadge sev={a.severity} />}
                      {a.event_id && (
                        <Link to={`/alerts?event=${a.event_id}`} className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-1">
                          Alert <ExternalLink className="w-3 h-3" />
                        </Link>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </SidePanel>
  )
}
