import { useState, useEffect } from 'react'
import { Shield, Zap } from 'lucide-react'
import client from '../api/client'

export default function VulnerabilitiesPage() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadEvents() }, [])

  const loadEvents = () => {
    setLoading(true)
    client.get('/events', { params: { event_type: 'cve_detected', page_size: 50 } })
      .then(res => setEvents(res.data.items || []))
      .catch(console.error)
      .finally(() => setLoading(false))
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
      <h1 className="text-2xl font-bold text-white">Vulnerabilities</h1>
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
        ) : events.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>CVSS</th><th>Risk Score</th><th>Time</th><th>Actions</th></tr></thead>
            <tbody>
              {events.map(e => (
                <tr key={e.event_id}>
                  <td className="font-mono text-sm text-accent-cyan">{e.details?.cve_id || '—'}</td>
                  <td><span className={`badge-${e.severity}`}>{e.severity}</span></td>
                  <td className="text-dark-300 text-sm">{e.details?.package_name} {e.details?.package_version}</td>
                  <td className="font-mono">{e.details?.cvss_base_score ?? '—'}</td>
                  <td className="font-mono">{e.composite_risk_score ?? '—'}</td>
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
            <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No vulnerabilities detected yet. Generate SBOMs to start CVE correlation.</p>
          </div>
        )}
      </div>
    </div>
  )
}
