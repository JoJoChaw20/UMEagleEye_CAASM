import { useState, useEffect } from 'react'
import { FileSearch, X, CheckCircle, ShieldAlert, UserPlus } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function AdvisoriesPage() {
  const { user } = useAuth()
  const [advisories, setAdvisories] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedAdvisory, setSelectedAdvisory] = useState(null)

  useEffect(() => {
    fetchAdvisories()
  }, [])

  const fetchAdvisories = () => {
    client.get('/advisories', { params: { page_size: 50 } })
      .then(res => setAdvisories(res.data.items || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  const handleResolve = async (id) => {
    try {
      await client.patch(`/advisories/${id}/status`, { status: 'resolved' })
      setSelectedAdvisory(null)
      fetchAdvisories()
    } catch (err) {
      console.error(err)
    }
  }

  const handleAssignToMe = async (id) => {
    try {
      await client.patch(`/advisories/${id}/status`, { 
        status: 'in_progress', 
        assigned_to: user.user_id 
      })
      setSelectedAdvisory(null)
      fetchAdvisories()
    } catch (err) {
      console.error(err)
    }
  }

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
                <tr 
                  key={a.advisory_id} 
                  onClick={() => setSelectedAdvisory(a)}
                  className="cursor-pointer hover:bg-white/5 transition-colors"
                >
                  <td className="max-w-md truncate text-dark-200 font-medium">{a.summary}</td>
                  <td><span className={statusBadge(a.status)}>{a.status.replace('_', ' ')}</span></td>
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

      {/* Advisory Detail Modal */}
      {selectedAdvisory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col">
            
            {/* Header */}
            <div className="p-6 border-b border-dark-600 flex justify-between items-start bg-dark-900/50 rounded-t-xl">
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-8 h-8 text-eagle-500" />
                <div>
                  <h2 className="text-xl font-bold text-white">Advisory Details</h2>
                  <p className="text-sm text-dark-400 mt-1">
                    Generated on {new Date(selectedAdvisory.created_at).toLocaleString()}
                  </p>
                </div>
              </div>
              <button onClick={() => setSelectedAdvisory(null)} className="text-dark-400 hover:text-white transition-colors">
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto custom-scrollbar flex-1 space-y-6">
              
              <div>
                <h3 className="text-sm font-semibold text-eagle-400 uppercase tracking-wider mb-2">Summary</h3>
                <div className="bg-dark-900 p-4 rounded-lg border border-dark-700 text-dark-100">
                  {selectedAdvisory.summary}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-eagle-400 uppercase tracking-wider mb-2">Recommended Action</h3>
                <div className="bg-dark-900 p-4 rounded-lg border border-dark-700 text-dark-100 whitespace-pre-wrap font-mono text-sm leading-relaxed">
                  {selectedAdvisory.recommended_action}
                </div>
              </div>

            </div>

            {/* Footer */}
            <div className="p-6 border-t border-dark-600 bg-dark-900/50 rounded-b-xl flex justify-between items-center">
              <div>
                <span className={`px-3 py-1 text-xs uppercase tracking-wider font-bold rounded-full border ${
                  selectedAdvisory.status === 'resolved' 
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                    : selectedAdvisory.status === 'in_progress'
                    ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                }`}>
                  Status: {selectedAdvisory.status.replace('_', ' ')}
                </span>
                {selectedAdvisory.assigned_to && (
                  <span className="ml-3 text-xs text-dark-400">
                    Assigned
                  </span>
                )}
              </div>
              
              <div className="flex gap-3">
                <button onClick={() => setSelectedAdvisory(null)} className="btn-secondary">
                  Close
                </button>
                {selectedAdvisory.status === 'open' && (
                  <button 
                    onClick={() => handleAssignToMe(selectedAdvisory.advisory_id)}
                    className="btn-primary flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
                  >
                    <UserPlus className="w-4 h-4" />
                    Assign to Me
                  </button>
                )}
                {selectedAdvisory.status !== 'resolved' && (
                  <button 
                    onClick={() => handleResolve(selectedAdvisory.advisory_id)}
                    className="btn-primary flex items-center gap-2"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Mark as Resolved
                  </button>
                )}
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  )
}
