import { useState, useEffect } from 'react'
import { Server, Search, RefreshCw, Wifi, Shield, Bookmark, GitBranch, Target } from 'lucide-react'
import client from '../api/client'
import AssetGraph from '../components/common/AssetGraph'
import BlastRadiusModal from '../components/common/BlastRadiusModal'

export default function AssetsPage() {
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [activeTab, setActiveTab] = useState('inventory') // 'inventory' | 'graph'
  const [blastRadiusAssetId, setBlastRadiusAssetId] = useState(null)
  const [graphBlastId, setGraphBlastId] = useState(null)

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

  const triggerSbomScan = async (assetId) => {
    const target = prompt("Enter scan target (e.g. image:ubuntu:22.04, image:nginx:alpine, dir:/app):", "image:nginx:alpine");
    if (!target) return;
    try {
      await client.post(`/assets/${assetId}/scan-sbom`, { target })
      alert('SBOM Scan queued. Check Alerts page in a few minutes.')
    } catch (err) {
      console.error(err)
      alert('Failed to trigger SBOM scan.')
    }
  }

  const triggerSetBaseline = async (assetId) => {
    if (!confirm('Set current state as Golden Image baseline? This will overwrite any existing baseline.')) return
    try {
      await client.post(`/assets/${assetId}/baseline`, { confirm: true })
      alert('Baseline set successfully.')
      loadAssets()
    } catch (err) {
      console.error(err)
      alert('Failed to set baseline.')
    }
  }

  const handleGraphAssetSelect = (assetId) => {
    setGraphBlastId(prev => prev === assetId ? null : assetId)
  }

  const icon = (t) => ({ server: '🖥️', workstation: '💻', network: '🌐', iot: '📡' }[t] || '❓')

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

      {/* Tab Toggle */}
      <div className="flex items-center gap-1 p-1 bg-dark-800/60 rounded-xl w-fit border border-dark-700/50" id="asset-view-toggle">
        <button
          onClick={() => setActiveTab('inventory')}
          className={`tab-toggle ${activeTab === 'inventory' ? 'active' : ''}`}
          id="tab-inventory"
        >
          <Server className="w-4 h-4" />
          Inventory
        </button>
        <button
          onClick={() => setActiveTab('graph')}
          className={`tab-toggle ${activeTab === 'graph' ? 'active' : ''}`}
          id="tab-graph"
        >
          <GitBranch className="w-4 h-4" />
          Relationship Graph
        </button>
      </div>

      {/* Inventory View */}
      {activeTab === 'inventory' && (
        <>
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
                <thead><tr><th>Type</th><th>Hostname</th><th>IP Address</th><th>Vendor</th><th>Criticality</th><th>Baseline</th><th>Last Scanned</th><th>Actions</th></tr></thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.assetId}>
                      <td>{icon(a.deviceType)}</td>
                      <td className="font-medium text-white">{a.hostname || '—'}</td>
                      <td className="font-mono text-sm text-accent-cyan">{a.ipAddress}</td>
                      <td className="text-dark-300 text-sm">{a.hardwareVendor || '—'}</td>
                      <td><span className="text-xs">{a.criticalityScore}/10</span></td>
                      <td>{a.baselineState ? <span className="badge-resolved">Set</span> : <span className="text-dark-500 text-xs">No</span>}</td>
                      <td className="text-dark-400 text-xs">{a.lastScanned ? new Date(a.lastScanned).toLocaleString() : '—'}</td>
                      <td>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => triggerSbomScan(a.assetId)}
                            className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors"
                            title="Scan SBOM"
                          >
                            <Shield className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => triggerSetBaseline(a.assetId)}
                            className={`p-1.5 rounded transition-colors ${a.baselineState ? 'text-eagle-500 hover:bg-eagle-500/10' : 'text-dark-400 hover:bg-dark-500/20'}`}
                            title="Set Baseline"
                          >
                            <Bookmark className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => setBlastRadiusAssetId(a.assetId)}
                            className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                            title="Blast Radius"
                          >
                            <Target className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
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
        </>
      )}

      {/* Graph View */}
      {activeTab === 'graph' && (
        <div className="glass-card p-5">
          <AssetGraph
            onSelectAsset={handleGraphAssetSelect}
            blastRadiusId={graphBlastId}
          />
        </div>
      )}

      {/* Blast Radius Modal */}
      {blastRadiusAssetId && (
        <BlastRadiusModal
          assetId={blastRadiusAssetId}
          onClose={() => setBlastRadiusAssetId(null)}
        />
      )}
    </div>
  )
}
