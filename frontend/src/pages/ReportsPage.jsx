import { useState, useEffect } from 'react'
import { FileText, Download, RefreshCw, Clock, ChevronDown } from 'lucide-react'
import client from '../api/client'

const REPORT_TYPES = [
  { value: 'weekly', label: 'Weekly Summary' },
  { value: 'monthly', label: 'Monthly Report' },
  { value: 'executive', label: 'Executive Briefing' },
  { value: 'posture_snapshot', label: 'Posture Snapshot' },
]

export default function ReportsPage() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [reportType, setReportType] = useState('weekly')
  const [downloading, setDownloading] = useState(null)

  useEffect(() => { loadReports() }, [])

  const loadReports = async () => {
    setLoading(true)
    try {
      const res = await client.get('/reports/list')
      setReports(res.data.reports || [])
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }

  const generateReport = async () => {
    setGenerating(true)
    try {
      await client.post('/reports/generate', null, { params: { report_type: reportType } })
      // Poll for the new report every 3 seconds, up to 5 times
      let attempts = 0
      const poll = setInterval(async () => {
        attempts++
        await loadReports()
        if (attempts >= 5) { clearInterval(poll); setGenerating(false) }
      }, 3000)
    } catch { setGenerating(false) }
  }

  const triggerSnapshot = async () => {
    try {
      await client.post('/reports/snapshot')
      setTimeout(loadReports, 2000)
    } catch (err) { console.error(err) }
  }

  const downloadReport = async (filename) => {
    setDownloading(filename)
    try {
      const res = await client.get(`/reports/download/${filename}`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Download failed:', err)
    } finally {
      setDownloading(null)
    }
  }

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1048576).toFixed(1)} MB`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-dark-400 text-sm mt-1">Security posture reports and executive summaries</p>
        </div>
        <div className="flex gap-2 items-center">
          <button onClick={triggerSnapshot} className="btn-secondary flex items-center gap-2 text-sm">
            <Clock className="w-4 h-4" />
            Snapshot Now
          </button>

          {/* Report type selector + generate */}
          <div className="flex items-stretch">
            <div className="relative">
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="input-field text-sm py-2 pl-3 pr-8 rounded-r-none border-r-0 appearance-none"
              >
                {REPORT_TYPES.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-400 pointer-events-none" />
            </div>
            <button
              onClick={generateReport}
              disabled={generating}
              className="btn-primary flex items-center gap-2 rounded-l-none"
            >
              {generating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
              {generating ? 'Generating...' : 'Generate'}
            </button>
          </div>
        </div>
      </div>

      {/* Report list */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : reports.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Report Name</th>
                <th>Size</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.filename}>
                  <td className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-accent-red flex-shrink-0" />
                    <span className="font-medium text-white text-sm">{r.filename}</span>
                  </td>
                  <td className="text-dark-300 text-sm">{formatSize(r.size_bytes)}</td>
                  <td className="text-dark-400 text-xs">{new Date(r.created * 1000).toLocaleString()}</td>
                  <td>
                    <button
                      onClick={() => downloadReport(r.filename)}
                      disabled={downloading === r.filename}
                      className="btn-secondary text-xs flex items-center gap-1 py-1 px-2"
                    >
                      {downloading === r.filename
                        ? <RefreshCw className="w-3 h-3 animate-spin" />
                        : <Download className="w-3 h-3" />}
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No reports generated yet</p>
            <p className="text-sm mb-4">Select a report type and click Generate</p>
            <button onClick={generateReport} disabled={generating} className="btn-primary">
              {generating ? 'Generating...' : 'Generate Report'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
