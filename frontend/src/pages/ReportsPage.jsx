import { useState, useEffect } from 'react'
import { FileText, Download, RefreshCw, Clock } from 'lucide-react'
import client from '../api/client'

export default function ReportsPage() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)

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
      await client.post('/reports/generate', null, { params: { report_type: 'weekly' } })
      setTimeout(() => { loadReports(); setGenerating(false) }, 8000)
    } catch { setGenerating(false) }
  }

  const triggerSnapshot = async () => {
    try {
      await client.post('/reports/snapshot')
    } catch (err) { console.error(err) }
  }

  const downloadReport = (filename) => {
    const token = localStorage.getItem('access_token')
    window.open(
      `/api/v1/reports/download/${filename}?token=${token}`,
      '_blank'
    )
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
        <div className="flex gap-2">
          <button onClick={triggerSnapshot} className="btn-secondary flex items-center gap-2">
            <Clock className="w-4 h-4" />
            Snapshot Now
          </button>
          <button onClick={generateReport} disabled={generating} className="btn-primary flex items-center gap-2">
            {generating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Report cards */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : reports.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>Report Name</th><th>Size</th><th>Created</th><th>Action</th></tr></thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.filename}>
                  <td className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-accent-red" />
                    <span className="font-medium text-white text-sm">{r.filename}</span>
                  </td>
                  <td className="text-dark-300 text-sm">{formatSize(r.size_bytes)}</td>
                  <td className="text-dark-400 text-xs">{new Date(r.created * 1000).toLocaleString()}</td>
                  <td>
                    <button onClick={() => downloadReport(r.filename)} className="btn-secondary text-xs flex items-center gap-1 py-1 px-2">
                      <Download className="w-3 h-3" /> Download
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
            <p className="text-sm mb-4">Generate your first posture report</p>
            <button onClick={generateReport} className="btn-primary">Generate Report</button>
          </div>
        )}
      </div>
    </div>
  )
}
