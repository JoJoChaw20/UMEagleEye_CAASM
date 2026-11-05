// Security posture report (PDF, built in the browser with jsPDF from GET /reports/data).
//
// Storyline, in the order an IT security admin decides in:
//   Page 1  Situation: the verdict in one sentence and the numbers behind it,
//           1. Decisions for this period, 2. Do these first (ranked fixes with asset,
//           reason, deadline and owner).
//   Page 2  3. Where the risk is (hotspot assets) · 4. What changed this period ·
//           5. Remediation progress (advisories, SLA breaches, unowned alerts) ·
//           6. Coverage and blind spots.
//   Then    Appendix (weekly and monthly reports): highest-risk CVEs, open advisories,
//           inventory by type, threat-intel feeds, last scan.
// jsPDF's standard fonts are Latin-1 only, so every string goes through safe().
import { jsPDF } from 'jspdf'

const TYPE_NAMES = { executive: 'Executive Briefing', weekly: 'Weekly Summary', monthly: 'Monthly Report' }

const C = {
  navy: [11, 22, 45], navySub: [148, 170, 205], eagle: [11, 111, 240], ink: [15, 23, 42], body: [51, 65, 85],
  muted: [100, 116, 139], line: [226, 232, 240], zebra: [247, 249, 252], white: [255, 255, 255],
  red: [200, 30, 45], redBg: [254, 236, 238], amber: [180, 100, 0], amberBg: [255, 246, 225],
  green: [4, 128, 84], greenBg: [228, 247, 238], blueBg: [234, 243, 255],
}
const LEVEL = {
  critical: { label: 'ACT NOW', fg: C.red, bg: C.redBg },
  elevated: { label: 'NEEDS ATTENTION', fg: C.amber, bg: C.amberBg },
  stable: { label: 'STABLE', fg: C.green, bg: C.greenBg },
}
const SEV = { critical: C.red, high: [200, 90, 10], medium: C.amber, low: C.muted }

const safe = (s) => String(s ?? '')
  .replace(/[–—]/g, '-').replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/…/g, '...')
  .replace(/[^\x20-\x7E\xA0-\xFF]/g, ' ').replace(/\s+/g, ' ').trim()
const fmtDate = (d) => new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Kuala_Lumpur' })
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

export function buildPdf(data, reportType) {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const W = 210, H = 297, M = 14, CW = W - M * 2, BOTTOM = H - 16
  const story = data.story ?? {}
  const risk = story.risk ?? {}
  const level = LEVEL[story.verdict?.level] ?? LEVEL.stable
  const days = story.period_days ?? 30
  const now = new Date(data.generated_at ?? Date.now())
  const from = new Date(now.getTime() - days * 86400000)
  const typeName = TYPE_NAMES[reportType] ?? 'Security Report'
  let y = 0

  const font = (size, style = 'normal', color = C.body) => { doc.setFont('helvetica', style); doc.setFontSize(size); doc.setTextColor(...color) }
  const fill = (c) => doc.setFillColor(...c)
  const stroke = (c) => doc.setDrawColor(...c)

  // ── page frame ──
  const runningHeader = () => {
    fill(C.navy); doc.rect(0, 0, W, 10, 'F')
    font(7.5, 'bold', C.white); doc.text('UMEagleEye CAASM', M, 6.5)
    font(7.5, 'normal', C.navySub); doc.text(safe(`${typeName} - ${fmtDate(from)} to ${fmtDate(now)}`), W - M, 6.5, { align: 'right' })
    y = 18
  }
  const newPage = () => { doc.addPage(); runningHeader() }
  const ensure = (h) => { if (y + h > BOTTOM) newPage() }

  const sectionTitle = (num, title, note) => {
    ensure(16)
    font(12, 'bold', C.ink); doc.text(safe(num ? `${num}. ${title}` : title), M, y)
    if (note) { font(8, 'normal', C.muted); doc.text(safe(note), W - M, y, { align: 'right' }) }
    y += 2
    stroke(C.eagle); doc.setLineWidth(0.5); doc.line(M, y, M + 18, y)
    stroke(C.line); doc.setLineWidth(0.2); doc.line(M + 18, y, W - M, y)
    y += 5
  }

  const paragraph = (text, size = 9, color = C.body, width = CW) => {
    font(size, 'normal', color)
    const lines = doc.splitTextToSize(safe(text), width)
    ensure(lines.length * size * 0.42 + 1)
    doc.text(lines, M, y)
    y += lines.length * size * 0.42 + 1.5
  }

  // A table with wrapped cells; repeats its header on a new page.
  const table = (cols, rows, { empty = 'Nothing to show.', size = 8 } = {}) => {
    const lh = size * 0.42
    const head = () => {
      fill(C.zebra); doc.rect(M, y - 3.6, CW, 6, 'F')
      font(7, 'bold', C.muted)
      let x = M
      for (const col of cols) {
        doc.text(safe(col.label).toUpperCase(), col.align === 'right' ? x + col.w - 2 : x + 2, y, { align: col.align === 'right' ? 'right' : 'left' })
        x += col.w
      }
      y += 4.5
    }
    ensure(14); head()
    if (rows.length === 0) { paragraph(empty, 8.5, C.muted); y += 2; return }
    for (const row of rows) {
      const cells = cols.map(col => {
        const v = typeof col.get === 'function' ? col.get(row) : row[col.key]
        const text = Array.isArray(v) ? v.map(safe).join('; ') : safe(v)
        return doc.splitTextToSize(text || '-', col.w - 4)
      })
      const rowH = Math.max(...cells.map(c => c.length)) * lh + 2.6
      if (y + rowH > BOTTOM) { newPage(); head() }
      let x = M
      cols.forEach((col, ci) => {
        const color = col.color ? col.color(row) : C.body
        font(size, col.bold ? 'bold' : 'normal', color)
        doc.text(cells[ci], col.align === 'right' ? x + col.w - 2 : x + 2, y + 0.6, { align: col.align === 'right' ? 'right' : 'left' })
        x += col.w
      })
      y += rowH
      stroke(C.line); doc.setLineWidth(0.15); doc.line(M, y - 3, W - M, y - 3)
    }
    y += 2
  }

  // A row of number tiles.
  const tiles = (items, h = 17) => {
    ensure(h + 4)
    const gap = 3, w = (CW - gap * (items.length - 1)) / items.length
    items.forEach((t, i) => {
      const x = M + i * (w + gap)
      fill(t.bg ?? C.zebra); stroke(C.line); doc.setLineWidth(0.2); doc.roundedRect(x, y, w, h, 1.5, 1.5, 'FD')
      font(15, 'bold', t.color ?? C.ink); doc.text(safe(t.value), x + 3, y + 7.5)
      font(6.8, 'normal', C.muted); doc.text(doc.splitTextToSize(safe(t.label), w - 5), x + 3, y + 11.5)
    })
    y += h + 5
  }

  // ════ Page 1: situation ════
  fill(C.navy); doc.rect(0, 0, W, 30, 'F')
  font(9, 'bold', C.navySub); doc.text('UMEagleEye CAASM', M, 10)
  font(16, 'bold', C.white); doc.text(safe(`${typeName}: Security Posture Report`), M, 18.5)
  font(8.5, 'normal', C.navySub)
  doc.text(safe(`Period ${fmtDate(from)} to ${fmtDate(now)} (${days} days)`), M, 25)
  doc.text(safe(`Generated ${now.toLocaleString('en-GB', { timeZone: 'Asia/Kuala_Lumpur' })} MYT`), W - M, 25, { align: 'right' })
  y = 38

  // the verdict
  const headline = safe(story.verdict?.headline ?? 'No data.')
  font(10.5, 'bold', C.ink)
  const hl = doc.splitTextToSize(headline, CW - 10)
  font(8, 'normal', C.body)
  const blind = story.verdict?.blind_spot ? doc.splitTextToSize(safe(story.verdict.blind_spot), CW - 10) : []
  const vh = 10 + hl.length * 4.6 + (blind.length ? blind.length * 3.8 + 2 : 0)
  fill(level.bg); doc.roundedRect(M, y, CW, vh, 2, 2, 'F')
  font(8, 'bold', level.fg); doc.text(`SITUATION: ${level.label}`, M + 5, y + 6)
  font(10.5, 'bold', C.ink); doc.text(hl, M + 5, y + 11.5)
  if (blind.length) { font(8, 'normal', C.body); doc.text(blind, M + 5, y + 11.5 + hl.length * 4.6 + 1) }
  y += vh + 6

  const score = data.posture_score ?? 0
  const trend = data.score_trend
  tiles([
    { value: `${score}/100`, label: `Posture score${trend == null ? '' : ` (${trend > 0 ? '+' : ''}${trend} since last snapshot)`}`,
      color: score >= 80 ? C.green : score >= 50 ? C.amber : C.red },
    { value: String(risk.critical ?? 0), label: 'Open critical alerts', color: risk.critical ? C.red : C.ink },
    { value: String(risk.high ?? 0), label: 'Open high alerts', color: risk.high ? SEV.high : C.ink },
    { value: String((risk.kev ?? 0) + (risk.threat_intel ?? 0)), label: 'Exploited (KEV) or threat-intel matches', color: (risk.kev || risk.threat_intel) ? C.red : C.ink },
    { value: String(risk.exposed_assets ?? 0), label: 'Internet-facing assets with critical/high', color: risk.exposed_assets ? C.red : C.ink },
    { value: String(data.sla_breaches ?? 0), label: 'Advisories past the 72h SLA', color: data.sla_breaches ? C.amber : C.ink },
  ])

  const ch = story.changes ?? {}
  const pr = story.progress ?? {}
  const cv = story.coverage ?? {}
  // decisions, from the facts above
  const decisions = []
  const urgent = (story.actions ?? []).filter(a => a.due === 'within 72 hours').length
  if (urgent) decisions.push(`Fix the ${plural(urgent, 'action')} due in 72 hours (section 2): they involve exploited or threat-intel-named weaknesses.`)
  if (risk.exposed_assets) decisions.push(`Reduce exposure on ${plural(risk.exposed_assets, 'internet-facing asset')} with critical or high alerts: patch, or restrict access until patched.`)
  if (pr.unassigned_critical) decisions.push(`Assign an owner to the ${plural(pr.unassigned_critical, 'critical alert')} nobody is working on (Alerts page, filter Critical).`)
  if (data.sla_breaches) decisions.push(`Escalate the ${plural(data.sla_breaches, 'advisory', 'advisories')} past the 72-hour SLA, or record why they wait.`)
  if (ch.new_devices) decisions.push(`Review the ${plural(ch.new_devices, 'new device')} found this period: add the known ones to My Assets with an owner, isolate the unknown.`)
  if (cv.total && cv.cve_checked < cv.total) decisions.push(`Deploy the EagleEye agent on the computers among the ${cv.total - cv.cve_checked} assets that are not CVE-checked.`)
  if (cv.no_owner) decisions.push(`Give owners to ${plural(cv.no_owner, 'asset')} so alerts reach someone.`)
  if (!decisions.length) decisions.push('No decision is needed this period: keep the scan and SBOM schedules running.')
  sectionTitle(1, 'Decisions for this period', 'What the facts below call for')
  decisions.forEach((d, i) => {
    font(9, 'normal', C.body)
    const lines = doc.splitTextToSize(safe(d), CW - 9)
    ensure(lines.length * 3.9 + 2)
    fill(C.eagle); doc.circle(M + 2.2, y - 1.1, 2.2, 'F')
    font(7, 'bold', C.white); doc.text(String(i + 1), M + 2.2, y - 0.1, { align: 'center' })
    font(9, 'normal', C.body); doc.text(lines, M + 7, y)
    y += lines.length * 3.9 + 2.2
  })

  y += 2
  sectionTitle(2, 'Do these first', 'Ranked like the Alerts page: exploited, threat intel, risk, exposure')
  table([
    { label: '#', w: 7, get: r => r.rank, bold: true },
    { label: 'Action', w: 58, get: r => r.action, bold: true, color: () => C.ink },
    { label: 'Asset', w: 33, get: r => (r.ip ? `${r.asset} (${r.ip})` : r.asset) },
    { label: 'Why', w: 44, get: r => r.why },
    { label: 'Due', w: 20, get: r => ({ 'within 72 hours': '72 hours', 'within 7 days': '7 days' }[r.due] ?? 'Next window'),
      color: r => (r.due === 'within 72 hours' ? C.red : r.due === 'within 7 days' ? C.amber : C.body), bold: true },
    { label: 'Owner', w: 20, get: r => r.owner ?? (r.assigned ? 'Assigned' : 'Unassigned'), color: r => (r.owner || r.assigned ? C.body : C.amber) },
  ], story.actions ?? [], { empty: 'No open alerts: nothing needs fixing now.' })

  // ════ Page 2: the picture behind it ════
  newPage()
  sectionTitle(3, 'Where the risk is', 'Assets with the most exploited, critical and high alerts')
  table([
    { label: 'Asset', w: 42, get: r => (r.ip ? `${r.asset} (${r.ip})` : r.asset), bold: true, color: () => C.ink },
    { label: 'Type', w: 22, get: r => r.device_type },
    { label: 'Exposure', w: 22, get: r => (r.internet_facing ? 'Internet-facing' : 'Internal'), color: r => (r.internet_facing ? C.red : C.body) },
    { label: 'Critical', w: 15, align: 'right', get: r => r.critical, color: r => (r.critical ? C.red : C.muted) },
    { label: 'High', w: 13, align: 'right', get: r => r.high, color: r => (r.high ? SEV.high : C.muted) },
    { label: 'KEV', w: 11, align: 'right', get: r => r.kev, color: r => (r.kev ? C.red : C.muted) },
    { label: 'CVE-checked', w: 20, get: r => (r.cve_checked ? 'Yes' : 'No (no SBOM)'), color: r => (r.cve_checked ? C.body : C.amber) },
    { label: 'Owner', w: 37, get: r => r.owner ?? 'none' },
  ], story.hotspots ?? [], { empty: 'No asset has open alerts.' })

  sectionTitle(4, `What changed in the last ${days} days`)
  tiles([
    { value: String(ch.opened ?? 0), label: 'New alerts' },
    { value: String(ch.closed ?? 0), label: 'Alerts closed' },
    { value: String(ch.new_critical ?? 0), label: 'New critical alerts', color: ch.new_critical ? C.red : C.ink },
    { value: String(ch.new_devices ?? 0), label: 'New devices found', color: ch.new_devices ? C.amber : C.ink },
    { value: String(ch.new_ports ?? 0), label: 'New open ports', color: ch.new_ports ? C.amber : C.ink },
  ], 15)
  const net = (ch.opened ?? 0) - (ch.closed ?? 0)
  paragraph(net > 0
    ? `The backlog grew by ${plural(net, 'alert')}: ${ch.opened ?? 0} opened against ${ch.closed ?? 0} closed.`
    : net < 0 ? `The backlog shrank by ${plural(-net, 'alert')}: ${ch.closed ?? 0} closed against ${ch.opened ?? 0} opened.`
      : 'As many alerts were closed as were opened.')
  y += 2

  sectionTitle(5, 'Remediation progress')
  tiles([
    { value: String(pr.open ?? 0), label: 'Advisories open' },
    { value: String(pr.in_progress ?? 0), label: 'In progress' },
    { value: String(pr.acknowledged ?? 0), label: 'Acknowledged' },
    { value: String(pr.resolved_in_period ?? 0), label: `Resolved in ${days} days`, color: pr.resolved_in_period ? C.green : C.ink },
    { value: String(pr.unassigned_critical ?? 0), label: 'Critical alerts with no assignee', color: pr.unassigned_critical ? C.red : C.ink },
  ], 15)
  if ((pr.sla_breaches ?? []).length) {
    font(8.5, 'bold', C.ink); ensure(8); doc.text('Oldest advisories past the 72-hour SLA', M, y); y += 4
    table([
      { label: 'Age', w: 18, get: r => `${r.age_days} days`, color: () => C.red, bold: true },
      { label: 'Advisory', w: 140, get: r => ((r.summary ?? '').length > 200 ? `${r.summary.slice(0, 200).replace(/\s+\S*$/, '')}...` : r.summary) },
      { label: 'Assigned', w: 24, get: r => (r.assigned ? 'Yes' : 'No'), color: r => (r.assigned ? C.body : C.amber) },
    ], pr.sla_breaches)
  }

  const pct = cv.total ? Math.round((cv.cve_checked / cv.total) * 100) : 0
  sectionTitle(6, 'Coverage and blind spots', 'What these numbers cannot see')
  tiles([
    { value: String(cv.total ?? 0), label: 'Assets known' },
    { value: `${cv.cve_checked ?? 0} (${pct}%)`, label: 'CVE-checked (agent + SBOM)', color: pct < 50 ? C.amber : C.ink },
    { value: String(cv.with_agent ?? 0), label: 'Running the EagleEye agent' },
    { value: String(cv.not_seen_recently ?? 0), label: 'Not seen in 14 days', color: cv.not_seen_recently ? C.amber : C.ink },
    { value: String(cv.no_owner ?? 0), label: 'Without an owner', color: cv.no_owner ? C.amber : C.ink },
  ], 15)
  paragraph('Printers, routers, IoT and phones are discovered and watched for changes but cannot be CVE-checked; only computers running the agent are.', 8, C.muted)
  y += 2

  // ════ Appendix (weekly / monthly) ════
  if (reportType !== 'executive') {
    newPage()
    sectionTitle('A', 'Highest-risk CVE alerts', 'By composite risk score')
    table([
      { label: 'CVE', w: 34, get: r => r.details?.cve_id ?? 'unknown', bold: true, color: () => C.ink },
      { label: 'Package', w: 52, get: r => `${r.details?.package_name ?? ''} ${r.details?.package_version ?? ''}` },
      { label: 'CVSS', w: 16, align: 'right', get: r => r.details?.cvss_base_score ?? '-' },
      { label: 'KEV', w: 12, get: r => (r.details?.kev ? 'Yes' : 'No'), color: r => (r.details?.kev ? C.red : C.muted) },
      { label: 'Risk', w: 16, align: 'right', get: r => (r.compositeRiskScore == null ? '-' : Number(r.compositeRiskScore).toFixed(1)) },
      { label: 'Fixed in', w: 30, get: r => (Array.isArray(r.details?.fix_versions) ? r.details.fix_versions.slice(0, 2).join(', ') : '-') },
      { label: 'Since', w: 22, get: r => fmtDate(r.timestamp) },
    ], data.top_cves ?? [], { empty: 'No open CVE alerts.' })

    sectionTitle('B', 'Open advisories', 'Newest first')
    table([
      { label: 'Status', w: 24, get: r => (r.status ?? '').replace('_', ' '), color: r => (r.status === 'open' ? C.red : C.amber), bold: true },
      { label: 'Summary', w: 136, get: r => ((r.summary ?? '').length > 240 ? `${r.summary.slice(0, 240).replace(/\s+\S*$/, '')}...` : r.summary) },
      { label: 'Created', w: 22, get: r => fmtDate(r.createdAt) },
    ], data.open_advisories ?? [], { empty: 'No open advisories.' })

    sectionTitle('C', 'Inventory and sources')
    const byType = (data.asset_by_type ?? []).map(r => `${r.deviceType} ${r.count}`).join(', ')
    paragraph(`Assets by type: ${byType || 'none'}. Internet-facing: ${data.internet_facing ?? 0}. SBOMs: ${data.sbom_count ?? 0}.`)
    const feeds = (data.cti_summary ?? []).map(r => `${r.source} ${r.count}`).join(', ')
    paragraph(`Threat-intelligence indicators by feed: ${feeds || 'none'}.`)
    const ls = data.last_scan
    paragraph(ls ? `Last network scan: ${new Date(ls.startedAt).toLocaleString('en-GB', { timeZone: 'Asia/Kuala_Lumpur' })} MYT (${ls.scanType}, ${ls.hostsDiscovered} hosts).` : 'No network scan recorded.')
  }

  // footer on every page
  const pages = doc.getNumberOfPages()
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    stroke(C.line); doc.setLineWidth(0.2); doc.line(M, H - 10, W - M, H - 10)
    font(7, 'normal', C.muted)
    doc.text('UMEagleEye CAASM - Confidential - University of Malaya', M, H - 6)
    doc.text(`Page ${p} of ${pages}`, W - M, H - 6, { align: 'right' })
  }
  return doc
}
