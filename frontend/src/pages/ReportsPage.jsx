import { useState, useEffect } from 'react'
import { FileText, Download, RefreshCw, Clock, ChevronDown, Loader2, Trash2 } from 'lucide-react'
import { jsPDF } from 'jspdf'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'

const REPORT_TYPES = [
  { value: 'executive', label: 'Executive Briefing' },
  { value: 'weekly',    label: 'Weekly Summary' },
  { value: 'monthly',   label: 'Monthly Report' },
]

// ── Helpers ───────────────────────────────────────────────────────
const safe  = s => String(s ?? '').replace(/[^\x20-\x7E]/g, ' ').trim()
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v))

// ── jsPDF report builder ──────────────────────────────────────────
function buildPdf(data, reportType) {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const W = 210, H = 297, ml = 14, mr = 14, cw = W - ml - mr
  const typeName = REPORT_TYPES.find(t => t.value === reportType)?.label ?? reportType

  const score      = data.posture_score ?? 0
  const trend      = data.score_trend
  const scoreRgb   = score >= 70 ? [22,163,74] : score >= 40 ? [217,119,6] : [220,38,38]
  const scoreLabel = score >= 70 ? 'GOOD' : score >= 40 ? 'FAIR' : 'CRITICAL'
  const now        = new Date(data.generated_at)
  const nowStr     = safe(now.toLocaleString('en-US', { timeZone: 'Asia/Kuala_Lumpur' }) + ' MYT')

  // ── Page 1 ────────────────────────────────────────────────────────

  // Header
  doc.setFillColor(11,17,32)
  doc.rect(0, 0, W, 30, 'F')
  doc.setFont('helvetica','bold'); doc.setFontSize(17); doc.setTextColor(255,255,255)
  doc.text('UMEagleEye CAASM', ml, 12)
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(147,197,253)
  doc.text(safe(`${typeName} — Security Posture Report`), ml, 19)
  doc.setTextColor(148,163,184); doc.setFontSize(7.5)
  doc.text(nowStr, W - mr, 19, { align:'right' })
  doc.text('Confidential — University of Malaya', W - mr, 25, { align:'right' })

  let y = 38

  // ── Section helper ───────────────────────────────────────────────
  const sectionTitle = (title) => {
    doc.setFont('helvetica','bold'); doc.setFontSize(7); doc.setTextColor(100,116,139)
    doc.text(title, ml, y)
    doc.setDrawColor(226,232,240); doc.line(ml, y+1.5, ml+cw, y+1.5)
    y += 6
  }

  // ── 1. Posture Score ─────────────────────────────────────────────
  sectionTitle('SECURITY POSTURE SCORE')
  doc.setFillColor(248,250,252); doc.setDrawColor(226,232,240)
  doc.roundedRect(ml, y, cw, 24, 2, 2, 'FD')

  doc.setFont('helvetica','bold'); doc.setFontSize(30); doc.setTextColor(...scoreRgb)
  doc.text(String(score), ml+6, y+17)
  doc.setFontSize(9); doc.setTextColor(100,116,139)
  doc.text('/ 100', ml+24, y+17)
  doc.setFontSize(11); doc.setTextColor(...scoreRgb)
  doc.text(scoreLabel, ml+40, y+13)
  if (trend !== null) {
    const tSign = trend > 0 ? '+' : ''
    const tColor = trend > 0 ? [22,163,74] : trend < 0 ? [220,38,38] : [100,116,139]
    doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(...tColor)
    doc.text(safe(`${tSign}${trend} since last snapshot`), ml+40, y+19)
  }

  // Progress bar
  const barX = ml+82, barY = y+9, barW = cw-86, barH = 4
  doc.setFillColor(226,232,240); doc.roundedRect(barX, barY, barW, barH, 1,1,'F')
  doc.setFillColor(...scoreRgb); doc.roundedRect(barX, barY, clamp(barW*(score/100),0,barW), barH, 1,1,'F')
  doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(100,116,139)
  const desc = score>=70 ? 'Posture is healthy. Continue monitoring for changes.'
    : score>=40 ? 'Posture needs attention. Address open advisories promptly.'
    : 'Critical risk detected. Immediate remediation required.'
  doc.text(safe(desc), barX, y+18)
  y += 30

  // ── 2. Key Metrics ───────────────────────────────────────────────
  sectionTitle('KEY METRICS')
  const stats = [
    { label:'Total Assets',       value: String(data.total_assets??0),     color:[30,64,175]  },
    { label:'Critical Assets',    value: String(data.critical_assets??0),  color:[220,38,38]  },
    { label:'Internet-Facing',    value: String(data.internet_facing??0),  color:[220,38,38]  },
    { label:'Critical Events',    value: String(data.critical_events??0),  color:[220,38,38]  },
    { label:'High Events',        value: String(data.high_events??0),      color:[217,119,6]  },
    { label:'Open Advisories',    value: String((data.open_advisories??[]).length), color:[217,119,6] },
    { label:'SLA Breaches >72h',  value: String(data.sla_breaches??0),    color: (data.sla_breaches??0)>0?[220,38,38]:[22,163,74] },
    { label:'CTI Indicators',     value: String((data.cti_summary??[]).reduce((a,r)=>a+(r.count??0),0)), color:[124,58,237] },
  ]
  const bw = (cw-14)/4, bh = 14
  stats.forEach((s,i) => {
    const row = Math.floor(i/4), col = i%4
    const bx = ml + col*(bw+4), by = y + row*(bh+3)
    doc.setFillColor(248,250,252); doc.setDrawColor(226,232,240)
    doc.roundedRect(bx, by, bw, bh, 1.5,1.5,'FD')
    doc.setFont('helvetica','bold'); doc.setFontSize(14); doc.setTextColor(...s.color)
    doc.text(s.value, bx+4, by+9)
    doc.setFont('helvetica','normal'); doc.setFontSize(6); doc.setTextColor(100,116,139)
    doc.text(s.label, bx+4, by+12.5)
  })
  y += 34

  // ── 3. Asset Distribution ────────────────────────────────────────
  sectionTitle('ASSET DISTRIBUTION BY TYPE')
  const typeColors = { server:[30,64,175], workstation:[22,163,74], network:[124,58,237], iot:[217,119,6], unknown:[100,116,139] }
  const byType = data.asset_by_type ?? []
  const total  = byType.reduce((a,r)=>a+(r.count??0),0)||1
  let tx = ml
  byType.forEach(r => {
    const pct = Math.round(((r.count??0)/total)*100)
    const col = typeColors[r.deviceType] ?? [100,116,139]
    const bw2 = clamp((cw*(pct/100))-2, 2, cw)
    doc.setFillColor(...col); doc.roundedRect(tx, y, bw2, 6, 1,1,'F')
    tx += bw2 + 2
  })
  y += 9
  // Legend
  let lx = ml
  byType.forEach(r => {
    const col = typeColors[r.deviceType] ?? [100,116,139]
    doc.setFillColor(...col); doc.rect(lx, y, 3, 3, 'F')
    doc.setFont('helvetica','normal'); doc.setFontSize(6.5); doc.setTextColor(71,85,105)
    doc.text(safe(`${r.deviceType} (${r.count})`), lx+4.5, y+2.5)
    lx += 30
  })
  y += 8

  // ── 4. Event Breakdown ───────────────────────────────────────────
  sectionTitle('EVENT BREAKDOWN')
  const evTypes = data.event_by_type ?? []
  const sevData = [
    { label:'Critical', count: data.critical_events??0, color:[220,38,38] },
    { label:'High',     count: data.high_events??0,     color:[217,119,6] },
    { label:'Medium',   count: data.medium_events??0,   color:[234,179,8] },
  ]
  // Severity pills
  sevData.forEach((s,i) => {
    const px = ml + i*38
    doc.setFillColor(...s.color); doc.setDrawColor(...s.color)
    doc.roundedRect(px, y, 35, 10, 1.5,1.5,'FD')
    doc.setFont('helvetica','bold'); doc.setFontSize(13); doc.setTextColor(...s.color)
    doc.text(String(s.count), px+4, y+7.5)
    doc.setFont('helvetica','normal'); doc.setFontSize(6.5); doc.setTextColor(100,116,139)
    doc.text(s.label, px+4, y+13)
  })
  // Top event types (right side)
  if (evTypes.length > 0) {
    const ex = ml+120
    doc.setFont('helvetica','bold'); doc.setFontSize(6.5); doc.setTextColor(100,116,139)
    doc.text('TOP EVENT TYPES', ex, y+2)
    evTypes.slice(0,4).forEach((e,i) => {
      doc.setFont('helvetica','normal'); doc.setTextColor(30,41,59)
      doc.text(safe(e.eventType?.replace(/_/g,' ')||''), ex, y+6+(i*4))
      doc.setTextColor(100,116,139)
      doc.text(String(e.count), ml+cw, y+6+(i*4), { align:'right' })
    })
  }
  y += 20

  // ── 5. Threat Intelligence ───────────────────────────────────────
  const ctiTotal = (data.cti_summary??[]).reduce((a,r)=>a+(r.count??0),0)
  if (ctiTotal > 0) {
    sectionTitle('THREAT INTELLIGENCE')
    doc.setFillColor(245,243,255); doc.setDrawColor(167,139,250)
    doc.roundedRect(ml, y, cw, 12, 1.5,1.5,'FD')
    doc.setFont('helvetica','bold'); doc.setFontSize(11); doc.setTextColor(124,58,237)
    doc.text(String(ctiTotal), ml+5, y+8.5)
    doc.setFont('helvetica','normal'); doc.setFontSize(7.5); doc.setTextColor(71,85,105)
    doc.text('Total IoC indicators ingested from threat intelligence feeds', ml+18, y+7)
    let cx2 = ml+18
    ;(data.cti_summary??[]).forEach(r => {
      doc.setFontSize(6.5); doc.setTextColor(100,116,139)
      doc.text(safe(`${r.source}: ${r.count}`), cx2, y+11)
      cx2 += 50
    })
    y += 17
  }

  // ── 6. SBOM & Last Scan ──────────────────────────────────────────
  sectionTitle('SCAN & SBOM COVERAGE')
  const ls = data.last_scan
  doc.setFont('helvetica','normal'); doc.setFontSize(7.5); doc.setTextColor(30,41,59)
  doc.text(safe(`SBOMs generated: ${data.sbom_count??0}`), ml, y)
  if (ls) {
    doc.text(safe(`Last scan: ${new Date(ls.startedAt).toLocaleString('en-US')} (${ls.scanType}, ${ls.hostsDiscovered} hosts)`), ml+50, y)
  }
  y += 8

  // ── Page 2 ────────────────────────────────────────────────────────
  doc.addPage()
  y = 20

  // Page 2 header strip
  doc.setFillColor(11,17,32); doc.rect(0,0,W,12,'F')
  doc.setFont('helvetica','bold'); doc.setFontSize(9); doc.setTextColor(255,255,255)
  doc.text('UMEagleEye CAASM — Security Posture Report (continued)', ml, 8)
  doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(148,163,184)
  doc.text(nowStr, W-mr, 8, { align:'right' })

  // ── 7. Top CVE Vulnerabilities ───────────────────────────────────
  const cves = data.top_cves ?? []
  if (cves.length > 0) {
    sectionTitle('TOP CVE VULNERABILITIES BY RISK SCORE')
    // Table header
    doc.setFillColor(241,245,249); doc.rect(ml, y-2, cw, 6,'F')
    doc.setFont('helvetica','bold'); doc.setFontSize(6.5); doc.setTextColor(100,116,139)
    doc.text('CVE ID',       ml+2,       y+2)
    doc.text('PACKAGE',      ml+45,      y+2)
    doc.text('CVSS',         ml+110,     y+2)
    doc.text('RISK SCORE',   ml+130,     y+2)
    doc.text('DATE',         ml+cw-2,    y+2, { align:'right' })
    y += 7

    cves.forEach(ev => {
      if (y > H-25) return
      const d    = ev.details ?? {}
      const risk = ev.compositeRiskScore ? Number(ev.compositeRiskScore).toFixed(1) : '—'
      const cvss = d.cvss_base_score ? Number(d.cvss_base_score).toFixed(1) : '—'
      const riskNum = parseFloat(risk)||0
      const rColor = riskNum>=70?[220,38,38]:riskNum>=40?[217,119,6]:[22,163,74]

      doc.setFont('helvetica','bold'); doc.setFontSize(7); doc.setTextColor(30,64,175)
      doc.text(safe(d.cve_id||'Unknown'), ml+2, y+2)

      doc.setFont('helvetica','normal'); doc.setTextColor(30,41,59)
      doc.text(safe((d.package_name||'').slice(0,28)), ml+45, y+2)
      doc.text(safe(cvss), ml+110, y+2)

      doc.setFont('helvetica','bold'); doc.setTextColor(...rColor)
      doc.text(safe(risk), ml+130, y+2)

      doc.setFont('helvetica','normal'); doc.setTextColor(148,163,184)
      doc.text(safe(new Date(ev.timestamp).toLocaleDateString('en-US')), ml+cw-2, y+2, { align:'right' })

      doc.setDrawColor(241,245,249); doc.line(ml, y+4, ml+cw, y+4)
      y += 7
    })
    y += 4
  }

  // ── 8. Open Advisories ───────────────────────────────────────────
  const advRows = data.open_advisories ?? []
  if (advRows.length > 0) {
    sectionTitle('OPEN ADVISORIES')
    doc.setFillColor(241,245,249); doc.rect(ml, y-2, cw, 6,'F')
    doc.setFont('helvetica','bold'); doc.setFontSize(6.5); doc.setTextColor(100,116,139)
    doc.text('STATUS',   ml+2,       y+2)
    doc.text('SUMMARY',  ml+28,      y+2)
    doc.text('DATE',     ml+cw-2,    y+2, { align:'right' })
    y += 7

    advRows.forEach(adv => {
      if (y > H-25) return
      const sc = adv.status==='open'?[220,38,38]:[217,119,6]
      doc.setFont('helvetica','bold'); doc.setFontSize(6.5); doc.setTextColor(...sc)
      doc.text(safe((adv.status||'').toUpperCase()), ml+2, y+2)
      doc.setFont('helvetica','normal'); doc.setTextColor(30,41,59)
      const sum = safe(adv.summary||'').slice(0,90)
      doc.text(sum+(safe(adv.summary||'').length>90?'...':''), ml+28, y+2)
      doc.setTextColor(148,163,184)
      doc.text(safe(new Date(adv.createdAt).toLocaleDateString('en-US')), ml+cw-2, y+2, { align:'right' })
      doc.setDrawColor(241,245,249); doc.line(ml, y+4, ml+cw, y+4)
      y += 7
    })
    y += 4
  }

  // ── 9. Top Assets ────────────────────────────────────────────────
  if (y < H-50) {
    sectionTitle('TOP ASSETS BY CRITICALITY')
    doc.setFillColor(241,245,249); doc.rect(ml, y-2, cw, 6,'F')
    doc.setFont('helvetica','bold'); doc.setFontSize(6.5); doc.setTextColor(100,116,139)
    doc.text('#',          ml+2,     y+2)
    doc.text('HOSTNAME/IP',ml+9,     y+2)
    doc.text('TYPE',       ml+80,    y+2)
    doc.text('OWNER',      ml+105,   y+2)
    doc.text('SCORE',      ml+145,   y+2)
    doc.text('WAN',        ml+cw-2,  y+2, { align:'right' })
    y += 7

    ;(data.top_assets??[]).forEach((a,i) => {
      if (y > H-20) return
      const s  = a.criticalityScore??0
      const sc = s>=8?[220,38,38]:s>=5?[217,119,6]:[22,163,74]
      doc.setFont('helvetica','normal'); doc.setFontSize(6.5)

      doc.setTextColor(100,116,139); doc.text(String(i+1), ml+2, y+2)

      doc.setTextColor(30,41,59)
      doc.text(safe(a.hostname||a.ipAddress||''), ml+9, y+2)
      if (a.hostname) { doc.setTextColor(148,163,184); doc.text(safe(a.ipAddress||''), ml+9, y+5.5) }

      doc.setTextColor(100,116,139)
      doc.text(safe(a.deviceType||''), ml+80, y+2)
      doc.text(safe((a.owner||'—').slice(0,20)), ml+105, y+2)

      doc.setFont('helvetica','bold'); doc.setTextColor(...sc)
      doc.text(`${s}/10`, ml+145, y+2)

      doc.setFont('helvetica','normal')
      doc.setTextColor(...(a.isInternetFacing ? [220,38,38] : [22,163,74]))
      doc.text(a.isInternetFacing?'Yes':'No', ml+cw-2, y+2, { align:'right' })

      doc.setDrawColor(241,245,249); doc.line(ml, y+(a.hostname?7:4), ml+cw, y+(a.hostname?7:4))
      y += a.hostname ? 9 : 6
    })
  }

  // ── Footers (both pages) ─────────────────────────────────────────
  [1,2].forEach(pg => {
    doc.setPage(pg)
    doc.setDrawColor(226,232,240); doc.line(ml, H-10, W-mr, H-10)
    doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(148,163,184)
    doc.text('UMEagleEye CAASM - Confidential - University of Malaya', ml, H-5)
    doc.text(`Page ${pg} of 2`, W-mr, H-5, { align:'right' })
  })

  return doc
}

// ── Page component ────────────────────────────────────────────────
export default function ReportsPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const [reports,     setReports]     = useState([])
  const [tenantFilter, setTenantFilter] = useState('')
  const [listLoading, setListLoading] = useState(true)
  const [generating,  setGenerating]  = useState(false)
  const [downloading, setDownloading] = useState(null)
  const [deleting,    setDeleting]    = useState(null)
  const [reportType,  setReportType]  = useState('executive')

  useEffect(() => { loadReports() }, [])

  const loadReports = async () => {
    setListLoading(true)
    try {
      const res = await client.get('/reports/list')
      setReports(res.data.reports || [])
    } catch (err) { console.error(err) }
    finally { setListLoading(false) }
  }

  const generateReport = async () => {
    setGenerating(true)
    try {
      const res  = await client.get('/reports/data', { params: { type: reportType } })
      const doc  = buildPdf(res.data, reportType)
      const blob = doc.output('blob')

      const form = new FormData()
      form.append('pdf', blob, `report_${reportType}.pdf`)
      form.append('report_type', reportType)
      await client.post('/reports/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      await loadReports()
    } catch (err) {
      console.error('[ReportsPage] generation failed:', err?.message ?? err)
      alert(`Failed to generate report: ${err?.message ?? 'Unknown error'}. Check browser console for details.`)
    } finally {
      setGenerating(false)
    }
  }

  const downloadReport = async (filename) => {
    setDownloading(filename)
    try {
      const res = await client.get(`/reports/download/${filename}`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a   = document.createElement('a')
      a.href = url; a.download = filename
      document.body.appendChild(a); a.click()
      document.body.removeChild(a); URL.revokeObjectURL(url)
    } catch (err) { console.error('Download failed:', err) }
    finally { setDownloading(null) }
  }

  const deleteReport = async (filename) => {
    if (!window.confirm(`Delete "${filename}"? This cannot be undone.`)) return
    setDeleting(filename)
    try {
      await client.delete(`/reports/delete/${filename}`)
      setReports(prev => prev.filter(r => r.filename !== filename))
    } catch (err) {
      console.error('Delete failed:', err)
      alert('Failed to delete report.')
    } finally {
      setDeleting(null)
    }
  }

  const triggerSnapshot = async () => {
    try { await client.post('/reports/snapshot'); alert('Posture snapshot saved.') }
    catch (err) { console.error(err) }
  }

  const filteredReports = tenantFilter
    ? reports.filter(r => r.tenant_id === tenantFilter)
    : reports

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-dark-400 text-sm mt-1">Generate and download security posture reports as PDF</p>
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          <TenantSelector value={tenantFilter} onChange={setTenantFilter} />
          {!isSuperadmin && !isBusinessOwner && (
            <button onClick={triggerSnapshot} className="btn-secondary flex items-center gap-2 text-sm">
              <Clock className="w-4 h-4" /> Snapshot Now
            </button>
          )}
          {!isSuperadmin && !isBusinessOwner && (
            <div className="flex items-stretch">
              <div className="relative">
                <select value={reportType} onChange={e => setReportType(e.target.value)}
                  className="input-field text-sm py-2 pl-3 pr-8 rounded-r-none border-r-0 appearance-none">
                  {REPORT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-400 pointer-events-none" />
              </div>
              <button onClick={generateReport} disabled={generating}
                className="btn-primary flex items-center gap-2 rounded-l-none">
                {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                {generating ? 'Generating...' : 'Generate PDF'}
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        {listLoading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : filteredReports.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>Report Name</th><th>Type</th><th>Generated</th><th>Actions</th></tr></thead>
            <tbody>
              {filteredReports.map(r => (
                <tr key={r.filename}>
                  <td className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-accent-red flex-shrink-0" />
                    <span className="font-medium text-white text-sm">{r.filename}</span>
                  </td>
                  <td className="text-dark-300 text-sm capitalize">{r.report_type?.replace('_',' ')??'—'}</td>
                  <td className="text-dark-400 text-xs">{r.created_at ? new Date(r.created_at).toLocaleString() : '—'}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <button onClick={() => downloadReport(r.filename)} disabled={downloading===r.filename}
                        className="btn-secondary text-xs flex items-center gap-1 py-1 px-2">
                        {downloading===r.filename ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                        Download
                      </button>
                      <button onClick={() => deleteReport(r.filename)} disabled={deleting===r.filename}
                        className="text-xs flex items-center gap-1 py-1 px-2 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50">
                        {deleting===r.filename ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No reports yet</p>
            {!isSuperadmin && !isBusinessOwner && (
              <>
                <p className="text-sm mb-4">Select a report type and click Generate PDF</p>
                <button onClick={generateReport} disabled={generating} className="btn-primary">
                  {generating ? 'Generating...' : 'Generate PDF'}
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
