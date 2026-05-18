import { useState, useEffect, useCallback } from 'react'
import { Globe, Network, GitBranch, Wifi, Monitor, RefreshCw, ChevronRight, ChevronDown, Cpu, Building2, AlertTriangle } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Node icon by type ─────────────────────────────────────────────
function NodeIcon({ type, className = 'w-4 h-4' }) {
  switch (type) {
    case 'gateway':      return <Globe      className={className} />
    case 'router':       return <Network    className={className} />
    case 'switch':       return <GitBranch  className={className} />
    case 'access_point': return <Wifi       className={className} />
    default:             return <Monitor    className={className} />
  }
}

const NODE_COLORS = {
  gateway:      'bg-purple-500/20 text-purple-400 border-purple-500/30',
  router:       'bg-blue-500/20 text-blue-400 border-blue-500/30',
  switch:       'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  access_point: 'bg-green-500/20 text-green-400 border-green-500/30',
  host:         'bg-dark-600/40 text-dark-300 border-dark-500/30',
}

// Criticality dot: only shown for score >= 8
function CritDot({ score }) {
  if (!score || score < 8) return null
  const color = score >= 10 ? 'bg-red-500' : score >= 9 ? 'bg-orange-500' : 'bg-yellow-500'
  return <span title={`Criticality ${score}`} className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />
}

// ── Recursive tree node ───────────────────────────────────────────
function TopologyNode({ node, depth = 0 }) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children && node.children.length > 0
  const meta = node.metadata ?? {}
  const ip = meta.ip_address
  const crit = meta.criticality_score
  const dmz = meta.is_internet_facing

  return (
    <div className="relative">
      {depth > 0 && (
        <div
          className="absolute top-0 bottom-0 border-l border-dark-600/40"
          style={{ left: `${(depth - 1) * 24 + 12}px` }}
        />
      )}

      <div
        className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-dark-700/40 transition-colors group"
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {depth > 0 && (
          <div
            className="absolute border-t border-dark-600/40"
            style={{ left: `${(depth - 1) * 24 + 12}px`, width: '12px', top: '50%' }}
          />
        )}

        {/* Expand toggle */}
        {hasChildren ? (
          expanded
            ? <ChevronDown  className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 cursor-pointer" />
            : <ChevronRight className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 cursor-pointer" />
        ) : (
          <span className="w-3.5 h-3.5 flex-shrink-0" />
        )}

        {/* Icon */}
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 border ${NODE_COLORS[node.node_type] || NODE_COLORS.host}`}>
          <NodeIcon type={node.node_type} className="w-3.5 h-3.5" />
        </div>

        {/* Label + IP */}
        <span className="text-sm text-dark-200 font-medium truncate min-w-0">
          {node.label || node.node_id?.slice(0, 8)}
        </span>
        {ip && (
          <span className="text-xs text-dark-500 font-mono flex-shrink-0">{ip}</span>
        )}

        {/* Internet-facing badge */}
        {dmz && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/25 flex-shrink-0">
            DMZ
          </span>
        )}

        {/* Criticality dot */}
        <CritDot score={crit} />

        {/* Layer + type badge on right */}
        <div className="ml-auto flex items-center gap-2 flex-shrink-0">
          <span className="text-xs text-dark-500">L{node.layer}</span>
          <span className={`text-xs px-2 py-0.5 rounded-full border ${NODE_COLORS[node.node_type] || NODE_COLORS.host}`}>
            {node.node_type?.replace('_', ' ')}
          </span>
          {hasChildren && !expanded && (
            <span className="text-xs text-dark-500">{node.children.length} child{node.children.length !== 1 ? 'ren' : ''}</span>
          )}
        </div>
      </div>

      {expanded && hasChildren && (
        <div className="relative">
          {node.children.map(child => (
            <TopologyNode key={child.node_id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Tenant section (superadmin all-tenant view) ───────────────────
function TenantSection({ tenantTree }) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="glass-card overflow-hidden">
      <button
        onClick={() => setCollapsed(c => !c)}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-dark-700/30 transition-colors text-left border-b border-dark-700/50"
      >
        {collapsed
          ? <ChevronRight className="w-4 h-4 text-dark-400 flex-shrink-0" />
          : <ChevronDown  className="w-4 h-4 text-dark-400 flex-shrink-0" />}
        <Building2 className="w-4 h-4 text-accent-400 flex-shrink-0" />
        <span className="font-semibold text-white">{tenantTree.tenant_name}</span>
        <span className="text-xs text-dark-400 ml-1">{tenantTree.node_count} node{tenantTree.node_count !== 1 ? 's' : ''}</span>
      </button>
      {!collapsed && (
        <div className="p-5 space-y-0.5">
          {tenantTree.tree.map(node => (
            <TopologyNode key={node.node_id} node={node} depth={0} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Skeleton ──────────────────────────────────────────────────────
function SkeletonNode({ depth = 0, withChildren = false }) {
  return (
    <div>
      <div className="flex items-center gap-2 py-1.5 px-2 rounded-lg" style={{ paddingLeft: `${depth * 24 + 8}px` }}>
        <span className="w-3.5 h-3.5" />
        <div className="w-7 h-7 rounded-lg bg-dark-700 animate-pulse flex-shrink-0" />
        <div className="h-4 bg-dark-700 rounded animate-pulse flex-grow max-w-[140px]" />
        <div className="h-3 bg-dark-700 rounded animate-pulse w-24 ml-2" />
        <div className="ml-auto h-4 w-14 bg-dark-700 rounded animate-pulse" />
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
  const [tenantTrees, setTenantTrees] = useState([])   // superadmin all-tenant view
  const [tenants, setTenants] = useState([])
  const [tenantFilter, setTenantFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [inferring, setInferring] = useState(false)
  const [error, setError] = useState(null)

  const isSuperadmin = user?.role === 'superadmin'
  const canInfer = ['ops_lead', 'security_engineer', 'superadmin'].includes(user?.role)

  // Fetch tenant list for filter dropdown
  useEffect(() => {
    if (!isSuperadmin) return
    client.get('/tenants').then(res => setTenants(res.data.tenants || [])).catch(() => {})
  }, [isSuperadmin])

  const loadTopology = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = tenantFilter ? { tenant_id: tenantFilter } : {}
      const res = await client.get('/topology', { params })
      if (res.data.tenant_trees) {
        setTenantTrees(res.data.tenant_trees)
        setTree([])
      } else {
        setTree(res.data.tree || [])
        setTenantTrees([])
      }
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load topology')
    } finally {
      setLoading(false)
    }
  }, [tenantFilter])

  useEffect(() => { loadTopology() }, [loadTopology])

  const handleInfer = async () => {
    if (!confirm('Rebuild topology from current asset inventory? Existing topology will be replaced.')) return
    setInferring(true)
    try {
      const res = await client.post('/topology/infer')
      alert(res.data.message || `Topology inferred: ${res.data.nodes_created} nodes created.`)
      await loadTopology()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to infer topology')
    } finally {
      setInferring(false)
    }
  }

  function countNodes(nodes) {
    return nodes.reduce((acc, n) => acc + 1 + countNodes(n.children || []), 0)
  }

  const totalCount = tenantTrees.length > 0
    ? tenantTrees.reduce((s, t) => s + t.node_count, 0)
    : countNodes(tree)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Topology</h1>
          <p className="text-dark-400 text-sm mt-1">
            {loading ? 'Loading...' : `${totalCount} node${totalCount !== 1 ? 's' : ''} in topology tree`}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Tenant filter — superadmin only */}
          {isSuperadmin && tenants.length > 0 && (
            <div className="relative">
              <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400 pointer-events-none" />
              <select
                value={tenantFilter}
                onChange={e => setTenantFilter(e.target.value)}
                className="input-field pl-9 pr-8 text-sm appearance-none min-w-[180px]"
              >
                <option value="">All Tenants</option>
                {tenants.map(t => (
                  <option key={t.tenant_id} value={t.tenant_id}>{t.name}</option>
                ))}
              </select>
            </div>
          )}

          <button onClick={loadTopology} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {canInfer && (
            <button onClick={handleInfer} disabled={inferring} className="btn-primary flex items-center gap-2">
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
        <div className="flex items-center gap-1.5">
          <span className="text-xs px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/25">DMZ</span>
          <span className="text-xs text-dark-400">Internet-facing</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
          <span className="text-xs text-dark-400">Critical (≥8)</span>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadTopology} className="btn-secondary text-sm ml-auto">Retry</button>
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="glass-card p-5 space-y-0.5">
          <SkeletonNode withChildren />
          <SkeletonNode depth={1} />
          <SkeletonNode depth={1} withChildren />
          <SkeletonNode depth={2} />
          <SkeletonNode depth={2} />
        </div>
      ) : tenantTrees.length > 0 ? (
        // Superadmin all-tenant view: one card per tenant
        <div className="space-y-4">
          {tenantTrees.map(t => (
            <TenantSection key={t.tenant_id} tenantTree={t} />
          ))}
        </div>
      ) : tree.length > 0 ? (
        <div className="glass-card p-5 space-y-0.5">
          {tree.map(node => (
            <TopologyNode key={node.node_id} node={node} depth={0} />
          ))}
        </div>
      ) : (
        <div className="glass-card text-center py-20 text-dark-400">
          <Network className="w-16 h-16 mx-auto mb-4 opacity-20" />
          <p className="text-lg font-medium mb-2">No topology data</p>
          <p className="text-sm mb-4">
            {canInfer
              ? 'Run "Infer Topology" to automatically build the network tree from your asset inventory.'
              : 'No topology has been defined for this tenant yet.'}
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
  )
}
