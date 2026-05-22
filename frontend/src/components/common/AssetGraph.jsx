import { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import client from '../../api/client'

const TYPE_COLORS = {
  server:      '#3393ff',
  workstation: '#00e5ff',
  network:     '#ffc400',
  iot:         '#ff9800',
  unknown:     '#7b7f87',
}
const EDGE_GRAPH_COLORS = {
  same_subnet:      '#ffffff',
  connects_to:      '#3393ff',
  depends_on:       '#00e676',
  authenticates_to: '#ffc400',
  exposes_service:  '#ff5252',
}
const EDGE_FILTER_COLORS = {
  same_subnet:      '#9aa0a6',
  connects_to:      '#3393ff',
  depends_on:       '#00e676',
  authenticates_to: '#ffc400',
  exposes_service:  '#ff5252',
}
const EDGE_LABELS = {
  same_subnet:      'Subnet',
  connects_to:      'Connects',
  depends_on:       'Depends',
  authenticates_to: 'Auth',
  exposes_service:  'Exposes',
}

const ALL_TYPES    = ['server', 'workstation', 'network', 'iot']
const ALL_REL_TYPES = ['same_subnet', 'connects_to', 'depends_on', 'authenticates_to', 'exposes_service']

/* ── Force simulation ──────────────────────────────────────────── */
function forceSimulation(nodes, edges, W, H) {
  nodes.forEach(n => {
    n.x = W / 2 + (Math.random() - 0.5) * W * 0.6
    n.y = H / 2 + (Math.random() - 0.5) * H * 0.6
    n.vx = 0; n.vy = 0
  })

  const nodeMap = {}
  nodes.forEach(n => { nodeMap[n.asset_id] = n })

  const seenPairs = new Set()
  const uniqueEdges = []
  edges.forEach(e => {
    const key = e.source < e.target ? `${e.source}-${e.target}` : `${e.target}-${e.source}`
    if (!seenPairs.has(key)) { seenPairs.add(key); uniqueEdges.push(e) }
  })

  const repulsion = 12000, attraction = 0.015, damping = 0.85
  const centerGravity = 0.005, idealLength = 180, collisionRadius = 40

  for (let iter = 0; iter < 200; iter++) {
    const temp = 1 - iter / 200
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j]
        const dx = b.x - a.x, dy = b.y - a.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (repulsion * temp) / (dist * dist)
        const fx = (dx / dist) * force, fy = (dy / dist) * force
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy
        if (dist < collisionRadius * 2) {
          const overlap = (collisionRadius * 2 - dist) * 0.5
          a.x += (dx / dist) * overlap; a.y += (dy / dist) * overlap
          b.x -= (dx / dist) * overlap; b.y -= (dy / dist) * overlap
        }
      }
    }
    uniqueEdges.forEach(e => {
      const a = nodeMap[e.source], b = nodeMap[e.target]
      if (!a || !b) return
      const dx = b.x - a.x, dy = b.y - a.y
      const dist = Math.sqrt(dx * dx + dy * dy) || 1
      if (dist > idealLength) {
        const force = (dist - idealLength) * attraction * temp
        const fx = (dx / dist) * force, fy = (dy / dist) * force
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy
      }
    })
    nodes.forEach(n => {
      n.vx += (W / 2 - n.x) * centerGravity; n.vy += (H / 2 - n.y) * centerGravity
      n.vx *= damping; n.vy *= damping
      n.x += n.vx * temp; n.y += n.vy * temp
      n.x = Math.max(40, Math.min(W - 40, n.x))
      n.y = Math.max(40, Math.min(H - 40, n.y))
    })
  }
  return nodes
}

/* ── Main component ────────────────────────────────────────────── */
export default function AssetGraph({ onSelectAsset, blastRadiusId, tenantFilter = '' }) {
  const canvasRef  = useRef(null)
  const drawRef    = useRef(null)
  const hoveredRef = useRef(null)
  const blastRef   = useRef(null)

  // Filter refs — updated alongside state so draw() always sees latest
  const activeTypesRef    = useRef(new Set(ALL_TYPES))
  const activeRelTypesRef = useRef(new Set(ALL_REL_TYPES))

  const [graphData, setGraphData]       = useState({ nodes: [], edges: [] })
  const [blastData, setBlastData]       = useState(null)
  const [tooltip,   setTooltip]         = useState(null)
  const [loading,   setLoading]         = useState(true)
  const [inferring, setInferring]       = useState(false)
  const [activeTypes,    setActiveTypes]    = useState(new Set(ALL_TYPES))
  const [activeRelTypes, setActiveRelTypes] = useState(new Set(ALL_REL_TYPES))

  const stateRef = useRef({ zoom: 1, offsetX: 0, offsetY: 0, dragging: false, dragNode: null })

  /* Load graph data ─────────────────────────────────────────────── */
  const loadGraph = useCallback(async () => {
    setLoading(true)
    try {
      const params = tenantFilter ? { tenant_id: tenantFilter } : {}
      const res = await client.get('/relationships/graph', { params })
      setGraphData(res.data ?? { nodes: [], edges: [] })
    } catch (err) { console.error('Graph load error:', err) }
    finally { setLoading(false) }
  }, [tenantFilter])

  useEffect(() => { loadGraph() }, [loadGraph])

  /* Load blast radius (only update ref + redraw, no re-layout) ──── */
  useEffect(() => {
    if (!blastRadiusId) {
      blastRef.current = null
      setBlastData(null)
      drawRef.current?.()
      return
    }
    client.get(`/relationships/blast-radius/${blastRadiusId}?max_depth=3`)
      .then(res => {
        blastRef.current = res.data
        setBlastData(res.data)
        drawRef.current?.()
      })
      .catch(err => console.error('Blast radius error:', err))
  }, [blastRadiusId])

  /* Filter toggles ─────────────────────────────────────────────── */
  const toggleType = (type) => {
    const next = new Set(activeTypes)
    if (next.has(type)) next.delete(type); else next.add(type)
    setActiveTypes(next)
    activeTypesRef.current = next
    drawRef.current?.()
  }

  const toggleRelType = (type) => {
    const next = new Set(activeRelTypes)
    if (next.has(type)) next.delete(type); else next.add(type)
    setActiveRelTypes(next)
    activeRelTypesRef.current = next
    drawRef.current?.()
  }

  /* Layout + render effect — only reruns when graphData changes ──── */
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    // Reset view on data reload
    stateRef.current.zoom = 1; stateRef.current.offsetX = 0; stateRef.current.offsetY = 0

    const ctx = canvas.getContext('2d')
    const rect = canvas.parentElement?.getBoundingClientRect()
    const W = (rect?.width || 800)
    const H = 500
    canvas.width  = W * window.devicePixelRatio
    canvas.height = H * window.devicePixelRatio
    canvas.style.width  = W + 'px'
    canvas.style.height = H + 'px'
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0)

    const nodes = graphData.nodes.map(n => ({ ...n }))
    const edges = [...(graphData.edges ?? [])]

    if (nodes.length > 0) forceSimulation(nodes, edges, W, H)

    stateRef.current.nodes = nodes
    stateRef.current.edges = edges

    /* ── Draw function ──────────────────────────────────────────── */
    function draw() {
      const blast        = blastRef.current
      const hovered      = hoveredRef.current
      const activeTypes  = activeTypesRef.current
      const activeRels   = activeRelTypesRef.current
      const { zoom, offsetX, offsetY } = stateRef.current

      ctx.clearRect(0, 0, W, H)
      ctx.fillStyle = '#0d0e13'
      ctx.fillRect(0, 0, W, H)

      // Grid
      ctx.strokeStyle = '#14161d'; ctx.lineWidth = 0.5
      const gs = 40 * zoom
      const sx = (offsetX % gs) - gs, sy = (offsetY % gs) - gs
      for (let x = sx; x < W; x += gs) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke() }
      for (let y = sy; y < H; y += gs) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke() }

      ctx.save()
      ctx.translate(offsetX, offsetY)
      ctx.scale(zoom, zoom)

      const nodeMap = {}
      nodes.forEach(n => { nodeMap[n.asset_id] = n })

      const blastSet = new Set()
      if (blast?.affected_assets) {
        blast.affected_assets.forEach(a => blastSet.add(a.asset_id))
        if (blast.origin_asset_id) blastSet.add(blast.origin_asset_id)
      }

      // Edges
      edges.forEach(e => {
        const a = nodeMap[e.source], b = nodeMap[e.target]
        if (!a || !b) return
        if (!activeTypes.has(a.device_type) || !activeTypes.has(b.device_type)) return
        if (!activeRels.has(e.relationship_type)) return

        const isBlast = blastSet.size > 0 && blastSet.has(e.source) && blastSet.has(e.target)
        ctx.beginPath()
        ctx.strokeStyle = isBlast ? '#ff5252' : (EDGE_GRAPH_COLORS[e.relationship_type] || '#3e4047')
        ctx.lineWidth   = isBlast ? 2.5 : 1.2
        ctx.globalAlpha = isBlast ? 1 : (blastSet.size > 0 ? 0.15 : 0.6)
        if (e.relationship_type === 'same_subnet') ctx.setLineDash([4, 4])
        else ctx.setLineDash([])
        ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
        ctx.setLineDash([]); ctx.globalAlpha = 1

        if (zoom > 0.6) {
          const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2
          ctx.font = `${9 / zoom}px Inter,sans-serif`
          ctx.fillStyle = isBlast ? '#ff8a80' : '#60646d'
          ctx.globalAlpha = isBlast ? 0.9 : 0.5
          ctx.textAlign = 'center'
          ctx.fillText(EDGE_LABELS[e.relationship_type] || e.relationship_type, mx, my - 4)
          ctx.globalAlpha = 1
        }
      })

      // Nodes
      nodes.forEach(n => {
        if (!activeTypes.has(n.device_type)) return

        const isBlast  = blastSet.has(n.asset_id)
        const isOrigin = blast?.origin_asset_id === n.asset_id
        const isHover  = hovered === n.asset_id
        const dimmed   = blastSet.size > 0 && !isBlast
        const color    = TYPE_COLORS[n.device_type] || TYPE_COLORS.unknown
        const radius   = Math.max(10, 6 + (n.edge_count ?? 0) * 2)

        if ((n.is_internet_facing || isOrigin) && !dimmed) {
          const glow = ctx.createRadialGradient(n.x, n.y, radius, n.x, n.y, radius * 3)
          glow.addColorStop(0, isOrigin ? 'rgba(255,82,82,0.35)' : 'rgba(51,147,255,0.2)')
          glow.addColorStop(1, 'rgba(0,0,0,0)')
          ctx.fillStyle = glow
          ctx.beginPath(); ctx.arc(n.x, n.y, radius * 3, 0, Math.PI * 2); ctx.fill()
        }

        ctx.beginPath(); ctx.arc(n.x, n.y, radius, 0, Math.PI * 2)
        ctx.globalAlpha = dimmed ? 0.15 : 1
        ctx.fillStyle   = isOrigin ? '#ff5252' : color; ctx.fill()
        ctx.strokeStyle = isHover ? '#ffffff' : (isBlast ? '#ff8a80' : '#1e2028')
        ctx.lineWidth   = isHover ? 2.5 : 1.5; ctx.stroke()
        ctx.globalAlpha = 1

        if (n.criticality_score >= 8 && !dimmed) {
          ctx.beginPath(); ctx.arc(n.x, n.y, radius + 4, 0, Math.PI * 2)
          ctx.strokeStyle = '#ff5252'; ctx.lineWidth = 1.5
          ctx.setLineDash([3, 3]); ctx.stroke(); ctx.setLineDash([])
        }

        if (zoom > 0.5 && !dimmed) {
          const label = n.hostname || n.ip_address
          ctx.font = `bold ${10 / zoom}px Inter,sans-serif`
          ctx.fillStyle = isOrigin ? '#ff8a80' : '#e2e3e5'
          ctx.textAlign = 'center'
          ctx.fillText(label, n.x, n.y + radius + 14)
          if (n.hostname) {
            ctx.font = `${8 / zoom}px Inter,sans-serif`; ctx.fillStyle = '#7b7f87'
            ctx.fillText(n.ip_address, n.x, n.y + radius + 24)
          }
        }
      })

      ctx.restore()

      // Legend
      const lx = 16, ly = H - 120
      ctx.fillStyle = 'rgba(13,14,19,0.85)'; ctx.fillRect(lx, ly, 150, 110)
      ctx.strokeStyle = '#1e2028'; ctx.strokeRect(lx, ly, 150, 110)
      ctx.font = '10px Inter,sans-serif'; ctx.fillStyle = '#7b7f87'; ctx.textAlign = 'left'
      ctx.fillText('RELATIONSHIP TYPES', lx + 8, ly + 14)
      let ly2 = ly + 28
      Object.entries(EDGE_GRAPH_COLORS).forEach(([type, color]) => {
        const active = activeRelTypesRef.current.has(type)
        ctx.globalAlpha = active ? 1 : 0.25
        ctx.fillStyle = color; ctx.fillRect(lx + 8, ly2 - 4, 12, 3)
        ctx.fillStyle = '#a0a3a8'; ctx.font = '9px Inter,sans-serif'
        ctx.fillText(EDGE_LABELS[type] || type, lx + 26, ly2)
        ctx.globalAlpha = 1
        ly2 += 16
      })
    }

    drawRef.current = draw
    draw()

    /* ── Event handlers ──────────────────────────────────────────── */
    const getNodeAt = (mx, my) => {
      const { zoom, offsetX, offsetY } = stateRef.current
      const gx = (mx - offsetX) / zoom, gy = (my - offsetY) / zoom
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i]
        if (!activeTypesRef.current.has(n.device_type)) continue
        const r = Math.max(10, 6 + (n.edge_count ?? 0) * 2)
        const dx = gx - n.x, dy = gy - n.y
        if (dx * dx + dy * dy < r * r) return n
      }
      return null
    }

    const handleMouseMove = (e) => {
      const r = canvas.getBoundingClientRect()
      const mx = e.clientX - r.left, my = e.clientY - r.top
      const s = stateRef.current

      if (s.dragNode) { s.dragNode.x = (mx - s.offsetX) / s.zoom; s.dragNode.y = (my - s.offsetY) / s.zoom; draw(); return }
      if (s.dragging) { s.offsetX += e.movementX; s.offsetY += e.movementY; draw(); return }

      const node = getNodeAt(mx, my)
      if (node) {
        canvas.style.cursor = 'pointer'
        hoveredRef.current = node.asset_id
        setTooltip({ x: mx + 15, y: my - 10, node })
      } else {
        canvas.style.cursor = 'grab'
        hoveredRef.current = null
        setTooltip(null)
      }
      draw()
    }

    const handleMouseDown = (e) => {
      const r = canvas.getBoundingClientRect()
      const node = getNodeAt(e.clientX - r.left, e.clientY - r.top)
      if (node) { stateRef.current.dragNode = node; canvas.style.cursor = 'grabbing' }
      else       { stateRef.current.dragging = true; canvas.style.cursor = 'grabbing' }
    }

    const handleMouseUp = () => {
      if (stateRef.current.dragNode) draw()
      stateRef.current.dragging = false; stateRef.current.dragNode = null
      canvas.style.cursor = 'grab'
    }

    const handleClick = (e) => {
      const r = canvas.getBoundingClientRect()
      const node = getNodeAt(e.clientX - r.left, e.clientY - r.top)
      if (node && onSelectAsset) onSelectAsset(node.asset_id)
    }

    const handleWheel = (e) => {
      e.preventDefault()
      const s = stateRef.current
      const r = canvas.getBoundingClientRect()
      const mx = e.clientX - r.left, my = e.clientY - r.top
      const delta = e.deltaY > 0 ? 0.9 : 1.1
      const newZoom = Math.max(0.2, Math.min(3, s.zoom * delta))
      s.offsetX = mx - (mx - s.offsetX) * (newZoom / s.zoom)
      s.offsetY = my - (my - s.offsetY) * (newZoom / s.zoom)
      s.zoom = newZoom
      draw()
    }

    canvas.addEventListener('mousemove',  handleMouseMove)
    canvas.addEventListener('mousedown',  handleMouseDown)
    canvas.addEventListener('mouseup',    handleMouseUp)
    canvas.addEventListener('mouseleave', handleMouseUp)
    canvas.addEventListener('click',      handleClick)
    canvas.addEventListener('wheel',      handleWheel, { passive: false })

    return () => {
      canvas.removeEventListener('mousemove',  handleMouseMove)
      canvas.removeEventListener('mousedown',  handleMouseDown)
      canvas.removeEventListener('mouseup',    handleMouseUp)
      canvas.removeEventListener('mouseleave', handleMouseUp)
      canvas.removeEventListener('click',      handleClick)
      canvas.removeEventListener('wheel',      handleWheel)
    }
  }, [graphData, onSelectAsset])

  /* Infer relationships ─────────────────────────────────────────── */
  const triggerInference = async () => {
    setInferring(true)
    try {
      const res = await client.post('/relationships/infer')
      await loadGraph()
      alert(res.data?.message || 'Relationships inferred.')
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to infer relationships')
    } finally {
      setInferring(false)
    }
  }

  /* Zoom controls ───────────────────────────────────────────────── */
  const adjustZoom = (factor) => {
    stateRef.current.zoom = Math.max(0.2, Math.min(3, stateRef.current.zoom * factor))
    drawRef.current?.()
  }

  const resetView = () => {
    stateRef.current.zoom = 1; stateRef.current.offsetX = 0; stateRef.current.offsetY = 0
    drawRef.current?.()
  }

  // Compute visible counts for filter pills
  const typeCounts = {}
  ALL_TYPES.forEach(t => { typeCounts[t] = graphData.nodes?.filter(n => n.device_type === t).length ?? 0 })
  const relTypeCounts = {}
  ALL_REL_TYPES.forEach(t => { relTypeCounts[t] = graphData.edges?.filter(e => e.relationship_type === t).length ?? 0 })

  return (
    <div className="space-y-3">
      {/* Top controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-dark-300">
            {graphData.total_nodes ?? graphData.nodes?.length ?? 0} nodes &middot; {graphData.total_edges ?? graphData.edges?.length ?? 0} edges
          </span>
          {blastData && (
            <span className="badge-critical">Blast Radius: {blastData.total_affected} affected</span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => adjustZoom(1.3)} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Zoom In">
            <ZoomIn className="w-4 h-4" />
          </button>
          <button onClick={() => adjustZoom(0.7)} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Zoom Out">
            <ZoomOut className="w-4 h-4" />
          </button>
          <button onClick={resetView} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Reset View">
            <Maximize2 className="w-4 h-4" />
          </button>
          <div className="w-px h-5 bg-dark-700 mx-1" />
          <button onClick={triggerInference} disabled={inferring} className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3">
            <RefreshCw className={`w-3.5 h-3.5 ${inferring ? 'animate-spin' : ''}`} />
            {inferring ? 'Inferring...' : 'Infer Relationships'}
          </button>
        </div>
      </div>

      {/* Filter pills */}
      <div className="flex items-center gap-3 flex-wrap text-xs border-t border-dark-700/50 pt-3">
        <span className="text-dark-500 text-[11px] uppercase tracking-wide">Filter:</span>

        {/* Device type pills */}
        {ALL_TYPES.map(type => {
          const active = activeTypes.has(type)
          const count  = typeCounts[type]
          return (
            <button
              key={type}
              onClick={() => toggleType(type)}
              title={`${active ? 'Hide' : 'Show'} ${type}`}
              className={`flex items-center gap-1 px-2 py-0.5 rounded-full border transition-all ${
                active ? 'border-current' : 'border-dark-600 opacity-30 grayscale'
              }`}
              style={{ color: active ? TYPE_COLORS[type] : undefined }}
            >
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: TYPE_COLORS[type] }} />
              <span className="capitalize">{type}</span>
              {count > 0 && <span className="text-[10px] opacity-70">({count})</span>}
            </button>
          )
        })}

        <div className="w-px h-4 bg-dark-700" />

        {/* Relationship type pills */}
        {ALL_REL_TYPES.map(type => {
          const active = activeRelTypes.has(type)
          const count  = relTypeCounts[type]
          const color  = EDGE_FILTER_COLORS[type]
          return (
            <button
              key={type}
              onClick={() => toggleRelType(type)}
              title={`${active ? 'Hide' : 'Show'} ${EDGE_LABELS[type]} edges`}
              className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border transition-all ${
                active ? 'border-current' : 'border-dark-600 opacity-30 grayscale'
              }`}
              style={{ color: active ? color : undefined }}
            >
              <span className="inline-block w-3 h-0.5 flex-shrink-0 rounded" style={{ background: color }} />
              {EDGE_LABELS[type]}
              {count > 0 && <span className="text-[10px] opacity-70">({count})</span>}
            </button>
          )
        })}
      </div>

      {/* Canvas area */}
      <div className="graph-container relative">
        {loading ? (
          <div className="flex items-center justify-center" style={{ height: 500 }}>
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : !graphData.nodes?.length ? (
          <div className="flex flex-col items-center justify-center text-dark-400" style={{ height: 500 }}>
            <svg className="w-16 h-16 mb-4 opacity-20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="6" cy="6" r="3" /><circle cx="18" cy="6" r="3" /><circle cx="12" cy="18" r="3" />
              <line x1="8.5" y1="7.5" x2="10.5" y2="16" /><line x1="15.5" y1="7.5" x2="13.5" y2="16" />
            </svg>
            <p className="text-lg font-medium mb-1">No relationships found</p>
            <p className="text-sm mb-4">Click "Infer Relationships" to auto-generate from asset inventory</p>
            <button onClick={triggerInference} disabled={inferring} className="btn-primary text-sm">
              <RefreshCw className={`w-4 h-4 mr-2 ${inferring ? 'animate-spin' : ''}`} />
              Infer Relationships
            </button>
          </div>
        ) : (
          <canvas ref={canvasRef} style={{ cursor: 'grab', display: 'block' }} />
        )}

        {/* Tooltip */}
        {tooltip && (
          <div className="absolute pointer-events-none z-50" style={{ left: tooltip.x, top: tooltip.y }}>
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-3 shadow-xl text-xs min-w-[180px]">
              <div className="flex items-center gap-2 mb-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: TYPE_COLORS[tooltip.node.device_type] || TYPE_COLORS.unknown }} />
                <span className="font-semibold text-white text-sm">{tooltip.node.hostname || tooltip.node.ip_address}</span>
              </div>
              <div className="space-y-1 text-dark-300">
                <div className="flex justify-between"><span>IP</span><span className="font-mono text-accent-cyan">{tooltip.node.ip_address}</span></div>
                <div className="flex justify-between"><span>Type</span><span className="capitalize">{tooltip.node.device_type}</span></div>
                <div className="flex justify-between">
                  <span>Criticality</span>
                  <span className={tooltip.node.criticality_score >= 8 ? 'text-accent-red' : ''}>{tooltip.node.criticality_score}/10</span>
                </div>
                <div className="flex justify-between"><span>Connections</span><span>{tooltip.node.edge_count ?? 0}</span></div>
                {tooltip.node.is_internet_facing && <div className="text-accent-amber mt-1">Internet Facing</div>}
              </div>
              <div className="text-dark-500 mt-2 text-[10px]">Click for blast radius</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
