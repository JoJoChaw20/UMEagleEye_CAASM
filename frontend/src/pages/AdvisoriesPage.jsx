import { useState, useEffect } from 'react'
import { FileSearch } from 'lucide-react'
import client from '../api/client'

export default function AdvisoriesPage() {
  const [advisories, setAdvisories] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    client.get('/advisories', { params: { page_size: 50 } })
      .then(res => setAdvisories(res.data.items || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const statusBadge = (s) => {
    const map = { open:'badge-open', acknowledged:'badge-medium', in_progress:'badge-in-progress', resolved:'badge-resolved' }
    return map[s] || 'badge-open'
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">AI Advisories</h1>
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
        ) : advisories.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>Summary</th><th>Status</th><th>Created</th><th>Resolved</th></tr></thead>
            <tbody>
              {advisories.map(a => (
                <tr key={a.advisory_id}>
                  <td className="max-w-md truncate text-dark-200">{a.summary}</td>
                  <td><span className={statusBadge(a.status)}>{a.status}</span></td>
                  <td className="text-dark-400 text-xs">{new Date(a.created_at).toLocaleString()}</td>
                  <td className="text-dark-400 text-xs">{a.resolved_at ? new Date(a.resolved_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <FileSearch className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No advisories generated yet. The AI advisory engine activates when threats are detected.</p>
          </div>
        )}
      </div>
    </div>
  )
}
