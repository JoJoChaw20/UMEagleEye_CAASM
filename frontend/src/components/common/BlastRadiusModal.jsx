import { useState, useEffect } from 'react'
import { X, AlertTriangle, Shield, ChevronRight } from 'lucide-react'
import client from '../../api/client'

const DEPTH_COLORS = ['#ff5252', '#ff9800', '#ffc400', '#00e676']

export default function BlastRadiusModal({ assetId, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [assetInfo, setAssetInfo] = useState(null)

  useEffect(() => {
    if (!assetId) return
    const fetchData = async () => {
      setLoading(true)
      try {
        const [blastRes, assetRes] = await Promise.all([
          client.get(`/relationships/blast-radius/${assetId}?max_depth=3`),
          client.get(`/assets/${assetId}`),
        ])
        setData(blastRes.data)
        setAssetInfo(assetRes.data)
      } catch (err) {
        console.error('Blast radius load error:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [assetId])

  if (!assetId) return null

  // Group affected by depth
  const byDepth = {}
  if (data?.affected_assets) {
    data.affected_assets.forEach(a => {
      if (!byDepth[a.depth]) byDepth[a.depth] = []
      byDepth[a.depth].push(a)
    })
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center" id="blast-radius-modal">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-2xl mx-4 bg-dark-900 border border-dark-700 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-700">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Blast Radius Analysis</h2>
              {assetInfo && (
                <p className="text-sm text-dark-400">
                  Origin: <span className="text-accent-cyan font-mono">{assetInfo.hostname || assetInfo.ip_address}</span>
                </p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-dark-700 rounded-lg transition-colors" id="blast-close-btn">
            <X className="w-5 h-5 text-dark-400" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-5 max-h-[60vh] overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
            </div>
          ) : data?.total_affected === 0 ? (
            <div className="text-center py-12 text-dark-400">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-lg font-medium">No downstream impact</p>
              <p className="text-sm mt-1">This asset has no connected assets in the relationship graph.</p>
            </div>
          ) : (
            <div className="space-y-5">
              {/* Summary cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="glass-card p-4 text-center">
                  <p className="text-2xl font-bold text-red-400">{data.total_affected}</p>
                  <p className="text-xs text-dark-400 mt-1">Affected Assets</p>
                </div>
                <div className="glass-card p-4 text-center">
                  <p className="text-2xl font-bold text-amber-400">{data.max_depth}</p>
                  <p className="text-xs text-dark-400 mt-1">Max Depth</p>
                </div>
                <div className="glass-card p-4 text-center">
                  <p className="text-2xl font-bold text-white">{Object.keys(byDepth).length}</p>
                  <p className="text-xs text-dark-400 mt-1">Hop Levels</p>
                </div>
              </div>

              {/* Depth tree */}
              {Object.entries(byDepth).sort(([a],[b]) => a - b).map(([depth, assets]) => (
                <div key={depth} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full"
                      style={{ background: DEPTH_COLORS[depth - 1] || DEPTH_COLORS[3] }}
                    />
                    <h3 className="text-sm font-semibold text-dark-200">
                      Depth {depth}
                      <span className="text-dark-500 font-normal ml-2">
                        {assets.length} asset{assets.length !== 1 ? 's' : ''}
                      </span>
                    </h3>
                  </div>

                  <div className="space-y-1.5 ml-5">
                    {assets.map((a, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between py-2 px-3 rounded-lg bg-dark-800/50 border border-dark-700/30 hover:border-dark-600 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-lg">
                            {a.device_type === 'server' ? '🖥️' : a.device_type === 'workstation' ? '💻' : a.device_type === 'network' ? '🌐' : '❓'}
                          </span>
                          <div>
                            <p className="text-sm font-medium text-white">{a.hostname || '—'}</p>
                            <p className="text-xs font-mono text-accent-cyan">{a.ip_address}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {a.criticality_score >= 8 && (
                            <span className="badge-critical">Critical</span>
                          )}
                          <div className="flex items-center gap-0.5 text-dark-500 text-[10px]">
                            {a.path?.slice(-3).map((p, pi) => (
                              <span key={pi} className="flex items-center">
                                {pi > 0 && <ChevronRight className="w-3 h-3" />}
                                <span className="font-mono">{p.slice(0, 8)}</span>
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-dark-700 flex justify-end">
          <button onClick={onClose} className="btn-secondary text-sm" id="blast-done-btn">Done</button>
        </div>
      </div>
    </div>
  )
}
