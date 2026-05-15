import { useState, useEffect, useCallback } from 'react'
import { Globe, Network, GitBranch, Wifi, Monitor, RefreshCw, ChevronRight, ChevronDown, Cpu } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Node icon by type ─────────────────────────────────────────────
function NodeIcon({ type, className = 'w-4 h-4' }) {
  switch (type) {
    case 'gateway': return <Globe className={className} />
    case 'router': return <Network className={className} />
    case 'switch': return <GitBranch className={className} />
    case 'access_point': return <Wifi className={className} />
    default: return <Monitor className={className} />
  }
}

// ── Node type badge colors ─────────────────────────────────────────
const NODE_COLORS = {
  gateway: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  router: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  switch: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  access_point: 'bg-green-500/20 text-green-400 border-green-500/30',
  host: 'bg-dark-600/40 text-dark-300 border-dark-500/30',
}

// ── Recursive tree node component ─────────────────────────────────
function TopologyNode({ node, depth = 0 }) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children && node.children.length > 0

  return (
    <div className="relative">
      {/* Connector line from parent */}
      {depth > 0 && (
        <div
          className="absolute left-0 top-0 bottom-0 border-l border-dark-600/50"
          style={{ left: `${(depth - 1) * 24 + 12}px` }}
        />
      )}

      <div
        className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-dark-700/40 transition-colors cursor-pointer group"
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {/* Horizontal connector */}
        {depth > 0 && (
          <div
            className="absolute border-t border-dark-600/50"
            style={{ left: `${(depth - 1) * 24 + 12}px`, width: '12px', top: '50%' }}
          />
        )}

        {/* Expand/collapse toggle */}
        {hasChildren ? (
          expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
            : <ChevronRight className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
        ) : (
          <span className="w-3.5 h-3.5 flex-shrink-0" />
        )}

        {/* Node icon */}
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 border ${NODE_COLORS[node.node_type] || NODE_COLORS.host}`}>
          <NodeIcon type={node.node_type} className="w-3.5 h-3.5" />
        </div>

        {/* Node label */}
        <span className="text-sm text-dark-200 font-medium min-w-0 truncate">
          {node.label || node.node_id?.slice(0, 8)}
        </span>

        {/* Layer badge */}
        <span className="text-xs text-dark-500 ml-1">L{node.layer}</span>

        {/* Node type badge */}
        <span className={`ml-auto text-xs px-2 py-0.5 rounded-full border flex-shrink-0 ${NODE_COLORS[node.node_type] || NODE_COLORS.host}`}>
          {node.node_type?.replace('_', ' ')}
        </span>

        {/* Children count when collapsed */}
        {hasChildren && !expanded && (
          <span className="text-xs text-dark-500 flex-shrink-0">
            {node.children.length} child{node.children.length !== 1 ? 'ren' : ''}
          </span>
        )}
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div className="relative">
          {node.children.map((child) => (
            <TopologyNode key={child.node_id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Loading skeleton ──────────────────────────────────────────────
function SkeletonNode({ depth = 0, withChildren = false }) {
  return (
    <div>
      <div
        className="flex items-center gap-2 py-1.5 px-2 rounded-lg"
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
      >
        <span className="w-3.5 h-3.5" />
        <div className="w-7 h-7 rounded-lg bg-dark-700 animate-pulse flex-shrink-0" />
        <div className="h-4 bg-dark-700 rounded animate-pulse" style={{ width: `${80 + Math.random() * 80}px` }} />
        <div className="ml-auto h-4 w-16 bg-dark-700 rounded animate-pulse" />
      </div>
      {withChildren && (
        <>
          <SkeletonNode depth={depth + 1} />
          <SkeletonNode depth={depth + 1} />
        </>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function TopologyPage() {
  const { user } = useAuth()
  const [tree, setTree] = useState([])
  const [loading, setLoading] = useState(true)
  const [inferring, setInferring] = useState(false)
  const [error, setError] = useState(null)

  const canInfer = ['ops_lead', 'security_engineer', 'superadmin'].includes(user?.role)

  const loadTopology = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await client.get('/topology')
      setTree(res.data.tree || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load topology')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadTopology() }, [loadTopology])

  const handleInfer = async () => {
    if (!confirm('Infer topology from asset relationships? This will rebuild the topology tree.')) return
    setInferring(true)
    try {
      const res = await client.post('/topology/infer')
      alert(`Topology inferred: ${res.data.nodes_created} nodes created.`)
      await loadTopology()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to infer topology')
    } finally {
      setInferring(false)
    }
  }

  // Count total nodes in tree
  function countNodes(nodes) {
    return nodes.reduce((acc, n) => acc + 1 + countNodes(n.children || []), 0)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Topology</h1>
          <p className="text-dark-400 text-sm mt-1">
            {loading ? 'Loading...' : `${countNodes(tree)} nodes in topology tree`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadTopology}
            disabled={loading}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {canInfer && (
            <button
              onClick={handleInfer}
              disabled={inferring}
              className="btn-primary flex items-center gap-2"
            >
              <Cpu className={`w-4 h-4 ${inferring ? 'animate-spin' : ''}`} />
              {inferring ? 'Inferring...' : 'Infer Topology'}
            </button>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 flex-wrap">
        {Object.entries(NODE_COLORS).map(([type, cls]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className={`w-5 h-5 rounded flex items-center justify-center border ${cls}`}>
              <NodeIcon type={type} className="w-3 h-3" />
            </div>
            <span className="text-xs text-dark-400 capitalize">{type.replace('_', ' ')}</span>
          </div>
        ))}
      </div>

      {/* Error state */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadTopology} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Tree panel */}
      <div className="glass-card p-5">
        {loading ? (
          <div className="space-y-0.5">
            <SkeletonNode withChildren />
            <SkeletonNode depth={1} />
            <SkeletonNode depth={1} withChildren />
            <SkeletonNode depth={2} />
            <SkeletonNode depth={2} />
          </div>
        ) : tree.length > 0 ? (
          <div className="space-y-0.5">
            {tree.map((node) => (
              <TopologyNode key={node.node_id} node={node} depth={0} />
            ))}
          </div>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Network className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No topology data</p>
            <p className="text-sm mb-4">
              No network topology has been defined yet.
            </p>
            {canInfer && (
              <button onClick={handleInfer} disabled={inferring} className="btn-primary">
                <Cpu className="w-4 h-4 mr-2" />
                Infer from Assets
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
