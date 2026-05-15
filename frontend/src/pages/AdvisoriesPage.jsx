import { useState, useEffect, useCallback } from 'react'
import { FileSearch, X, CheckCircle, ShieldAlert, UserPlus, Filter } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

const STATUS_OPTIONS = ['all', 'open', 'in_progress', 'acknowledged', 'resolved']

export default function AdvisoriesPage() {
  const { user } = useAuth()
  const [advisories, setAdvisories] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedAdvisory, setSelectedAdvisory] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')

  const fetchAdvisories = useCallback(() => {
    setLoading(true)
    const params = { page_size: 100 }
    if (statusFilter !== 'all') params.status = statusFilter
    client.get('/advisories', { params })
      .then(res => setAdvisories(res.data.items || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [statusFilter])

  useEffect(() => { fetchAdvisories() }, [fetchAdvisories])

  const handleStatus = async (id, status) => {
    try {
      await client.patch(`/advisories/${id}/status`, { status })
      setSelectedAdvisory(null)
      fetchAdvisories()
    } catch (err) { console.error(err) }
  }

  const handleAssignToMe = async (id) => {
    try {
      await client.patch(`/advisories/${id}/status`, {
        status: 'in_progress',
        assigned_to: user.user_id,
      })
      setSelectedAdvisory(null)
      fetchAdvisories()
    } catch (err) { console.error(err) }
  }

  const statusBadgeClass = (s) => {
    const map = {
      open:         'bg-red-500/20 text-red-400 border-red-500/30',
      acknowledged: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      in_progress:  'bg-blue-500/20 text-blue-400 border-blue-500/30',
      resolved:     'bg-green-500/20 text-green-400 border-green-500/30',
    }
    return `text-xs px-2 py-0.5 rounded-full border font-medium ${map[s] || 'bg-dark-600/40 text-dark-400 border-dark-500/30'}`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">AI Advisories</h1>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-dark-400" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input-field text-sm py-1.5 w-40"
          >
            {STATUS_OPTIONS.map(s => (
              <option key={s} value={s}>{s === 'all' ? 'All Statuses' : s.replace('_', ' ')}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : advisories.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Summary</th>
                <th>Status</th>
                <th>Assigned</th>
                <th>Created</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {advisories.map(a => (
                <tr
                  key={a.advisoryId}
                  onClick={() => setSelectedAdvisory(a)}
                  className="cursor-pointer hover:bg-white/5 transition-colors"
                >
                  <td className="max-w-md truncate text-dark-200 font-medium">{a.summary}</td>
                  <td><span className={statusBadgeClass(a.status)}>{a.status?.replace('_', ' ')}</span></td>
                  <td className="text-dark-400 text-xs">{a.assignedTo ? a.assignedTo.slice(0, 8) + '...' : '—'}</td>
                  <td className="text-dark-400 text-xs">{new Date(a.createdAt).toLocaleString()}</td>
                  <td className="text-dark-400 text-xs">{a.resolvedAt ? new Date(a.resolvedAt).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <FileSearch className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No advisories{statusFilter !== 'all' ? ` with status "${statusFilter}"` : ''} yet.</p>
          </div>
        )}
      </div>

      {selectedAdvisory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col">

            <div className="p-6 border-b border-dark-600 flex justify-between items-start bg-dark-900/50 rounded-t-xl">
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-8 h-8 text-eagle-500" />
                <div>
                  <h2 className="text-xl font-bold text-white">Advisory Details</h2>
                  <p className="text-sm text-dark-400 mt-1">
                    Generated {new Date(selectedAdvisory.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>
              <button onClick={() => setSelectedAdvisory(null)} className="text-dark-400 hover:text-white transition-colors">
                <X className="w-6 h-6" />
              </button>
            </div>

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
                  {selectedAdvisory.recommendedAction}
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-dark-600 bg-dark-900/50 rounded-b-xl flex justify-between items-center">
              <div className="space-y-1">
                <span className={statusBadgeClass(selectedAdvisory.status)}>
                  {selectedAdvisory.status?.replace('_', ' ')}
                </span>
                {selectedAdvisory.assignedTo && (
                  <p className="text-xs text-dark-400 mt-1">
                    Assigned to: <span className="font-mono">{selectedAdvisory.assignedTo.slice(0, 16)}...</span>
                  </p>
                )}
              </div>

              <div className="flex gap-3">
                <button onClick={() => setSelectedAdvisory(null)} className="btn-secondary">Close</button>
                {selectedAdvisory.status === 'open' && (
                  <button
                    onClick={() => handleAssignToMe(selectedAdvisory.advisoryId)}
                    className="btn-primary flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
                  >
                    <UserPlus className="w-4 h-4" />
                    Assign to Me
                  </button>
                )}
                {selectedAdvisory.status !== 'resolved' && (
                  <button
                    onClick={() => handleStatus(selectedAdvisory.advisoryId, 'resolved')}
                    className="btn-primary flex items-center gap-2"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Mark Resolved
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
