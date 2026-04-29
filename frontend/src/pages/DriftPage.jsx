import { useState, useEffect } from 'react'
import { AlertTriangle, RefreshCw, Zap } from 'lucide-react'
import client from '../api/client'

export default function DriftPage() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadDrifts() }, [])
  
  const loadDrifts = () => {
    setLoading(true)
    client.get('/events', { params: { page_size: 50 } })
      .then(res => {
        const driftTypes = ['port_opened','port_closed','version_downgrade','config_change','new_package','removed_package']
        setEvents((res.data.items || []).filter(e => driftTypes.includes(e.event_type)))
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  const triggerAudit = async () => {
    try {
      await client.post('/scans/drift-audit')
      alert('Drift audit triggered.')
      setTimeout(loadDrifts, 2000)
    } catch (err) { alert('Failed to trigger audit.') }
  }

  const triggerAdvisory = async (eventId) => {
    try {
      await client.post(`/events/${eventId}/advisory`)
      alert('AI Advisory generation queued. Check Advisories page in a moment.')
    } catch (err) {
      console.error(err)
      alert('Failed to trigger advisory generation.')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Drift Detection</h1>
          <p className="text-dark-400 text-sm">Deviations from Golden Image baselines</p>
        </div>
        <button onClick={triggerAudit} className="btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Run Drift Audit
        </button>
      </div>
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
        ) : events.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>Event Type</th><th>Severity</th><th>Changed Attribute</th><th>Previous</th><th>New</th><th>Time</th><th>Actions</th></tr></thead>
            <tbody>
              {events.map(e => (
                <tr key={e.event_id}>
                  <td className="font-mono text-xs">{e.event_type}</td>
                  <td><span className={`badge-${e.severity}`}>{e.severity}</span></td>
                  <td className="text-dark-300">{e.details?.changed_attribute || '—'}</td>
                  <td className="font-mono text-xs text-accent-red">{JSON.stringify(e.details?.previous_value) || '—'}</td>
                  <td className="font-mono text-xs text-accent-green">{JSON.stringify(e.details?.new_value) || '—'}</td>
                  <td className="text-dark-400 text-xs">{new Date(e.timestamp).toLocaleString()}</td>
                  <td>
                    <button
                      onClick={() => triggerAdvisory(e.event_id)}
                      className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors"
                      title="Generate AI Advisory"
                    >
                      <Zap className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <AlertTriangle className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No drift events detected. Set baselines on assets to enable drift auditing.</p>
          </div>
        )}
      </div>
    </div>
  )
}
