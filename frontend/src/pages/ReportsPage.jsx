import { useState, useEffect } from 'react'
import { FileText, Download, RefreshCw, Clock, ChevronDown, Loader2, Trash2 } from 'lucide-react'
import { buildPdf } from '../utils/reportPdf'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'

const REPORT_TYPES = [
  { value: 'executive', label: 'Executive Briefing' },
  { value: 'weekly',    label: 'Weekly Summary' },
  { value: 'monthly',   label: 'Monthly Report' },
]

// ── Helpers ───────────────────────────────────────────────────────

// The PDF itself (storyline and layout): utils/reportPdf.js

export default function ReportsPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const canDeleteReports = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
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
          <h1 className="page-title">Reports</h1>
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
                    <span className="font-medium text-dark-50 text-sm">{r.filename}</span>
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
                      {canDeleteReports && (
                        <button onClick={() => deleteReport(r.filename)} disabled={deleting===r.filename}
                          className="text-xs flex items-center gap-1 py-1 px-2 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50">
                          {deleting===r.filename ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
                          Delete
                        </button>
                      )}
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
