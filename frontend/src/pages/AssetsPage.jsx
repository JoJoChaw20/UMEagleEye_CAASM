import { useState, useEffect } from 'react'
import { Server, Search, RefreshCw, Wifi } from 'lucide-react'
import client from '../api/client'

export default function AssetsPage() {
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)

  useEffect(() => { loadAssets() }, [page, search])

  const loadAssets = async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 25 }
      if (search) params.search = search
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }

  const triggerScan = async () => {
    setScanning(true)
    try {
      await client.post('/scans/active', { scan_type: 'nmap' })
      setTimeout(() => { loadAssets(); setScanning(false) }, 5000)
    } catch (err) { setScanning(false) }
  }

  const icon = (t) => ({ server:'🖥️', workstation:'💻', network:'🌐', iot:'📡' }[t] || '❓')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
          <p className="text-dark-400 text-sm mt-1">{total} assets discovered</p>
        </div>
        <button onClick={triggerScan} disabled={scanning} className="btn-primary flex items-center gap-2" id="scan-btn">
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />}
          {scanning ? 'Scanning...' : 'Active Scan'}
        </button>
      </div>
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
        <input type="text" placeholder="Search by hostname or IP..." value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1) }}
          className="input-field w-full pl-10" id="asset-search" />
      </div>
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : assets.length > 0 ? (
          <table className="data-table">
            <thead><tr><th>Type</th><th>Hostname</th><th>IP Address</th><th>Vendor</th><th>Criticality</th><th>Baseline</th><th>Last Scanned</th></tr></thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.asset_id}>
                  <td>{icon(a.device_type)}</td>
                  <td className="font-medium text-white">{a.hostname || '—'}</td>
                  <td className="font-mono text-sm text-accent-cyan">{a.ip_address}</td>
                  <td className="text-dark-300 text-sm">{a.hardware_vendor || '—'}</td>
                  <td><span className="text-xs">{a.criticality_score}/10</span></td>
                  <td>{a.baseline_state ? <span className="badge-resolved">Set</span> : <span className="text-dark-500 text-xs">No</span>}</td>
                  <td className="text-dark-400 text-xs">{a.last_scanned ? new Date(a.last_scanned).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Server className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p>No assets yet. Run a scan to start.</p>
            <button onClick={triggerScan} className="btn-primary mt-4">Start Scan</button>
          </div>
        )}
      </div>
    </div>
  )
}
