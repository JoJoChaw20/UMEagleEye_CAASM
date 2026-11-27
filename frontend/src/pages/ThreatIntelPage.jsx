import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Globe, Crosshair, BookOpen, Database, CheckCircle2, AlertTriangle, RefreshCw, ArrowLeft, Shield } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TiEventsPanel from '../components/threatintel/TiEventsPanel'
import AttackMatrixPanel from '../components/threatintel/AttackMatrixPanel'
import MatchesPanel from '../components/threatintel/MatchesPanel'
import { TypeLabel, TYPE_META } from '../components/threatintel/IndicatorPanel'
import EvidencePanel from '../components/threatintel/EvidencePanel'
import MycertPanel from '../components/threatintel/MycertPanel'
import { TiPanelProvider } from '../components/threatintel/TiPanel'
import { useTiPanel } from '../components/threatintel/tiPanelContext'
import { SearchBox, day, useSettled } from '../components/threatintel/tiParts'
import { REASON_LABEL, USE_META } from '../components/threatintel/indicatorUse'
import { Tabs, StatTile, Toast, useToast, Spinner, ago } from '../components/common/PageParts'
import { ClearFilters, EmptyState, FilterBar, FilterChip, ListPager, ListTotal, plural } from '../components/common/ListParts'

// Threat Intelligence: which of your devices threat intelligence names. The overview: four tiles that each
// count one thing, the sources with their units, and the tabs MyCERT advisories (the main source),
// Indicators, MITRE ATT&CK and Coverage. Matches and Events are sub-pages (the sidebar). On every view a
// row's details open in the one side panel (components/threatintel/TiPanel.jsx), and every list has the
// same filter bar, total and Previous / Next pager (components/common/ListParts.jsx).

const PAGE_SIZE = 20
const STALE_HOURS = 36       // the sources load nightly: older than this means a run was missed

function ConfBar({ score }) {
  // a threat event's own attributes carry no confidence: show that, not "0%"
  if (score == null) return <span className="text-xs text-dark-500">—</span>
  const pct = (score * 100).toFixed(0)
  const color = score >= 0.8 ? 'rgb(var(--sev-critical))' : score >= 0.6 ? 'rgb(var(--sev-high))' : 'rgb(var(--sev-medium))'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1.5 bg-dark-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs text-dark-400">{pct}%</span>
    </div>
  )
}

// One line per source: its count in its own unit ("89 advisories", "1,805 CVEs"), when it last loaded, and a
// warning when it failed or is old. Production loads them nightly (next_ingest_at); staging has no schedule,
// so there the Platform Superadmin loads them by hand (can_ingest, POST /cti/ingest).
function FeedHealth({ stats, ingesting, onIngest }) {
  const feeds = stats?.feeds ?? []
  const hoursOld = (ts) => (ts ? (Date.now() - new Date(ts).getTime()) / 3600000 : Infinity)
  return (
    <div className="glass-card px-4 py-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
      <span className="text-dark-400 font-medium">Sources</span>
      {feeds.length === 0 && <span className="text-dark-400">Nothing loaded yet.</span>}
      {feeds.map((f) => {
        const failed = f.ok === false
        const stale = !failed && f.last_ok_at && hoursOld(f.last_ok_at) > STALE_HOURS
        const [one, many] = f.unit ?? ['indicator', 'indicators']
        return (
          <span key={f.source} className="inline-flex items-center gap-1.5 text-dark-300"
            title={failed ? 'The last run could not load this source' : f.last_ok_at ? `Loaded ${new Date(f.last_ok_at).toLocaleString()}` : 'Not loaded since source health was recorded'}>
            {failed || stale
              ? <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              : <CheckCircle2 className={`w-3.5 h-3.5 ${f.last_ok_at ? 'text-accent-green' : 'text-dark-500'}`} />}
            <span className="text-dark-100">{f.source}</span>
            <span className="tabular-nums">{plural(f.count, one, many)}</span>
            <span className={failed || stale ? 'text-amber-400' : 'text-dark-500'}>
              {failed ? `failed${f.last_ok_at ? `, last loaded ${ago(f.last_ok_at)}` : ''}` : `updated ${ago(f.last_ok_at, 'unknown')}`}
            </span>
          </span>
        )
      })}
      <span className="ml-auto flex items-center gap-3 text-dark-500">
        {stats?.next_ingest_at && <span>Next update {new Date(stats.next_ingest_at).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })}</span>}
        {stats && !stats.next_ingest_at && <span>No schedule on this server</span>}
        {stats?.can_ingest && (
          <button onClick={onIngest} disabled={ingesting} className="btn-secondary text-xs py-1 px-2.5 inline-flex items-center gap-1.5 disabled:opacity-60"
            title="Load all sources now, for every tenant (staging has no nightly schedule)">
            <RefreshCw className={`w-3.5 h-3.5 ${ingesting ? 'animate-spin' : ''}`} />
            {ingesting ? 'Updating…' : 'Update sources now'}
          </button>
        )}
      </span>
    </div>
  )
}

// The Indicators tab: the indicators in use by default; "Show reference-only too" adds the ones kept for
// lookups and inside MyCERT's advisories. The type chips' counts follow the other filters, so they add up
// to the total shown (GET /cti/indicators by_type).
function IndicatorsTab({ sources, showToast }) {
  const panel = useTiPanel()
  const [q, setQ] = useState('')
  const search = useSettled(q.trim())
  const [type, setType] = useState('')
  const [source, setSource] = useState('')
  const [all, setAll] = useState(false)
  const [matchedOnly, setMatchedOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [data, setData] = useState(null)

  useEffect(() => { setPage(1) }, [search, type, source, all, matchedOnly])
  useEffect(() => {
    const params = { page, limit: PAGE_SIZE, ...(all ? {} : { use: 'in_use' }) }
    if (search) params.q = search
    if (type) params.indicator_type = type
    if (source) params.source = source
    if (matchedOnly) params.matched = 'true'
    client.get('/cti/indicators', { params })
      .then((res) => setData(res.data))
      .catch((err) => { showToast(err?.response?.data?.detail || 'Failed to load indicators', 'error'); setData({ items: [], total: 0, by_type: {}, reference: 0 }) })
  }, [page, search, type, source, all, matchedOnly, panel.version, showToast])

  const byType = data?.by_type ?? {}
  const sum = Object.values(byType).reduce((n, v) => n + v, 0)
  const filtered = !!(search || type || source || matchedOnly)
  const clear = () => { setQ(''); setType(''); setSource(''); setMatchedOnly(false) }
  const open = (ind) => panel.open({ kind: 'indicator', value: ind.value, label: ind.value })

  return (
    <div className="space-y-3">
      <FilterBar>
        <SearchBox value={q} onChange={setQ} placeholder="Search values" label="Search indicator values" />
        <FilterChip pressed={!type} onClick={() => setType('')} count={sum}>All</FilterChip>
        {Object.keys(TYPE_META).filter((t) => byType[t] || type === t).map((t) => {
          const Icon = TYPE_META[t].icon
          return <FilterChip key={t} pressed={type === t} onClick={() => setType(t)} icon={Icon} count={byType[t] ?? 0}>{TYPE_META[t].label}</FilterChip>
        })}
        <select value={source} onChange={(e) => setSource(e.target.value)} className="input-field w-40 py-1.5 text-sm" aria-label="Source">
          <option value="">All sources</option>
          {sources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <label className="inline-flex items-center gap-1.5 text-xs text-dark-300">
          <input type="checkbox" checked={matchedOnly} onChange={(e) => setMatchedOnly(e.target.checked)} className="accent-eagle-500" /> Matching our devices only
        </label>
        <label className="inline-flex items-center gap-1.5 text-xs text-dark-300" title="Values kept for lookups and inside MyCERT's advisories that never raise an alert">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} className="accent-eagle-500" />
          Show reference-only too{data ? <span className="tabular-nums text-dark-500">({(data.reference ?? 0).toLocaleString()})</span> : null}
        </label>
        {filtered && <ClearFilters onClick={clear} />}
        {data && <ListTotal><b>{data.total.toLocaleString()}</b> {data.total === 1 ? 'indicator' : 'indicators'}{all ? '' : ' in use'}</ListTotal>}
      </FilterBar>

      <div className="glass-card overflow-hidden">
        {!data ? <Spinner className="py-20" /> : data.items.length === 0 ? (
          <EmptyState icon={Globe} title="No indicators" filtered={filtered} onClear={clear}>The sources load every morning.</EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>Type</th><th>Value</th><th>Used for</th><th>Source</th><th>Confidence</th><th>Malware family</th><th>ATT&CK</th><th>Last listed</th></tr>
                </thead>
                <tbody>
                  {data.items.map((ind) => (
                    <tr key={ind.indicator_id} className="cursor-pointer hover:bg-dark-700/30" onClick={() => open(ind)}
                      tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') open(ind) }}>
                      <td><TypeLabel type={ind.indicator_type} /></td>
                      <td className="max-w-xs truncate font-mono text-xs text-accent-cyan" title={ind.value}>{ind.value}</td>
                      <td>
                        {ind.used_for && (
                          <span className={`whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] ${USE_META[ind.used_for]?.cls ?? ''}`}
                            title={ind.reference_reason ? `Reference only: ${REASON_LABEL[ind.reference_reason] ?? ind.reference_reason}` : USE_META[ind.used_for]?.help}>
                            {USE_META[ind.used_for]?.short}{ind.reference_reason === 'expired' ? ' · expired' : ''}
                          </span>
                        )}
                      </td>
                      <td className="text-xs text-dark-300">{ind.source}</td>
                      <td><ConfBar score={ind.confidence_score} /></td>
                      <td className="max-w-[10rem] truncate text-xs text-dark-300" title={ind.malware_family || ''}>{ind.malware_family || '—'}</td>
                      <td className="text-xs">
                        {ind.technique_count > 0 ? (
                          <span className="text-accent-purple" title={ind.attack_software ? `${ind.attack_software_name} (${ind.attack_software}) in MITRE ATT&CK` : 'Techniques named by the source'}>
                            {ind.attack_software ? <span className="font-mono">{ind.attack_software}</span> : 'Named'} · {plural(ind.technique_count, 'technique')}
                          </span>
                        ) : <span className="text-dark-500">—</span>}
                      </td>
                      <td className="whitespace-nowrap text-xs text-dark-400">{day(ind.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ListPager page={data.page ?? page} pageSize={PAGE_SIZE} total={data.total} one="indicator" onChange={setPage} />
          </>
        )}
      </div>
    </div>
  )
}

// view: the sub-pages under Threat Intel in the sidebar: 'matches' (/threat-intel/matches) and 'events'
// (/threat-intel/events); none: the overview.
const SUB_PAGES = {
  matches: { title: 'Matches', listLabel: 'Matches', lead: 'Open threat-intel matches on your devices: an indicator an agent saw, or one listed on a device\'s own address, name or software.' },
  events: { title: 'Threat-intel events', listLabel: 'Events', lead: 'Your organisation\'s own threat-intel events and the ones other tenants share with you. MyCERT\'s advisories are under Threat Intelligence → MyCERT advisories.' },
}

export default function ThreatIntelPage(props) {
  const { toast, show: showToast } = useToast()
  return (
    <TiPanelProvider showToast={showToast}>
      <Toast toast={toast} />
      <ThreatIntelContent {...props} showToast={showToast} />
    </TiPanelProvider>
  )
}

function ThreatIntelContent({ view, showToast }) {
  const { can } = useAuth()
  const navigate = useNavigate()
  const panel = useTiPanel()
  // Matches are alerts (GET /events: alert.view) and Events are threat events (GET /cti/events:
  // ti_event.view); this page only needs cti.view, so each sub-page shows with its own action.
  const canMatches = can('alert.view')
  const canEvents = can('ti_event.view')
  const [stats, setStats] = useState(null)
  const [mycert, setMycert] = useState(null)
  const [ingesting, setIngesting] = useState(false)
  const [tab, setTab] = useState('mycert')
  const [mycertPreset, setMycertPreset] = useState(0)
  const [subTab, setSubTab] = useState('list')       // a sub-page: its list, or its ATT&CK view
  useEffect(() => { setSubTab('list') }, [view])
  const [lookupInput, setLookupInput] = useState('')

  const loadStats = useCallback(async () => {
    const [s, m] = await Promise.allSettled([client.get('/cti/stats'), client.get('/cti/mycert', { params: { page_size: 1 } })])
    if (s.status === 'fulfilled') setStats(s.value.data)
    if (m.status === 'fulfilled') setMycert(m.value.data.summary)
  }, [])
  useEffect(() => { if (!view) loadStats() }, [view, loadStats, panel.version])

  // Staging only (stats.can_ingest): the run takes a minute or two, one source per queue job
  const ingest = async () => {
    setIngesting(true)
    try {
      const res = await client.post('/cti/ingest')
      if (res.data?.queued === false) {
        showToast('An update is already running or ran in the last hour.', 'info')
        setIngesting(false)
      } else {
        showToast('Update queued. The counts refresh in about a minute.', 'success')
        setTimeout(() => { loadStats(); panel.changed(); setIngesting(false) }, 60000)
      }
    } catch (err) {
      showToast(err?.response?.data?.detail ?? 'Failed to queue the update', 'error')
      setIngesting(false)
    }
  }

  const lookup = (e) => {
    e?.preventDefault()
    const v = lookupInput.trim()
    if (v) panel.open({ kind: 'indicator', value: v, label: v })
  }

  const m = stats?.matches
  const ev = stats?.ti_events
  const sources = (stats?.feeds ?? []).map((f) => f.source)
  const sub = view ? SUB_PAGES[view] : null

  const lookupForm = (
    <form onSubmit={lookup} className="flex w-full gap-2 sm:w-auto" role="search">
      <div className="flex-1 sm:w-80 [&_input]:w-full">
        <SearchBox value={lookupInput} onChange={setLookupInput} placeholder="Look up an IP, domain, hash or CVE…" label="Look up a value in threat intelligence" />
      </div>
      <button type="submit" disabled={!lookupInput.trim()} className="btn-primary text-sm disabled:opacity-50">Look up</button>
    </form>
  )

  // A sub-page: one back link, its title and lead, the list and its ATT&CK view
  if (sub) {
    return (
      <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            {/* a block of its own: .page-title is inline-flex and would sit beside it */}
            <Link to="/threat-intel" className="flex w-fit items-center gap-1 text-xs text-dark-400 hover:text-eagle-400"><ArrowLeft className="h-3.5 w-3.5" /> Threat Intelligence</Link>
            <h1 className="page-title mt-1">{sub.title}</h1>
            <p className="mt-1 max-w-2xl text-sm text-dark-400">{sub.lead}</p>
          </div>
          {lookupForm}
        </div>
        <Tabs label={`${sub.title} views`} active={subTab} onChange={setSubTab} tabs={[
          { id: 'list', label: sub.listLabel },
          { id: 'attack', label: 'MITRE ATT&CK' },
        ]} />
        {subTab === 'attack'
          ? <AttackMatrixPanel key={view} fixedScope={view === 'matches' ? 'matched' : 'events'} />
          : view === 'matches' ? <MatchesPanel showToast={showToast} /> : <TiEventsPanel showToast={showToast} />}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header + lookup */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="mt-1 max-w-2xl text-sm text-dark-400">Which of your devices threat intelligence names: MyCERT's advisories for Malaysia first, then your own threat-intel events and the global sources behind them.</p>
        </div>
        {lookupForm}
      </div>

      {/* Four tiles, each counting one thing and saying what */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Matches on our devices" icon={Crosshair} tone={m?.open > 0 ? 'danger' : 'good'}
          value={m ? <>{m.open.toLocaleString()}<span className="ml-1.5 text-sm font-medium text-dark-400">on {plural(m.assets, 'device')}</span></> : '—'}
          sub={m ? (m.open > 0 ? `${m.high} critical or high · open alerts` : 'nothing matched') : ' '}
          onClick={canMatches ? () => navigate('/threat-intel/matches') : undefined} />
        <StatTile label="MyCERT advisories touching our devices" icon={Shield} tone={mycert?.affecting > 0 ? 'warning' : 'muted'}
          value={mycert ? <>{mycert.affecting.toLocaleString()}<span className="ml-1.5 text-sm font-medium text-dark-400">of {mycert.total.toLocaleString()}</span></> : '—'}
          sub={mycert ? `${mycert.exploited_affecting} with a CVE exploited in the wild` : ' '}
          onClick={() => { setTab('mycert'); setMycertPreset((n) => n + 1); panel.close() }} />
        <StatTile label="Our threat-intel events" icon={BookOpen}
          value={ev ? ev.ours.toLocaleString() : '—'}
          sub={ev ? `${ev.ours_published} published · ${ev.shared} shared with us` : ' '}
          onClick={canEvents ? () => navigate('/threat-intel/events') : undefined} />
        {/* what is actually matched, not everything stored (workers/src/services/threatIntel.ts indicatorUseSql) */}
        <StatTile label="Indicators in use" icon={Database}
          value={stats?.usage ? (stats.usage.agents + stats.usage.assets).toLocaleString() : '—'}
          sub={stats?.usage ? `${stats.usage.agents.toLocaleString()} checked by agents · ${stats.usage.assets.toLocaleString()} against devices` : ' '}
          onClick={() => setTab('indicators')} />
      </div>

      <FeedHealth stats={stats} ingesting={ingesting} onIngest={ingest} />

      {/* Matches and Events are sub-pages (sidebar, under Threat Intel). MyCERT, the main source, comes first. */}
      <Tabs label="Threat intelligence views" active={tab} onChange={setTab} tabs={[
        { id: 'mycert', label: 'MyCERT advisories' },
        { id: 'indicators', label: 'Indicators' },
        { id: 'matrix', label: 'MITRE ATT&CK' },
        { id: 'evidence', label: 'Coverage' },
      ]} />

      {/* the tile opens the list on what it counts: a new key starts it with "Touching our devices" on */}
      {tab === 'mycert' ? <MycertPanel key={mycertPreset} startAffecting={mycertPreset > 0} showToast={showToast} />
        : tab === 'matrix' ? <AttackMatrixPanel fixedScope="feeds" />
        : tab === 'evidence' ? <EvidencePanel stats={stats} />
        : <IndicatorsTab sources={sources} showToast={showToast} />}
    </div>
  )
}
