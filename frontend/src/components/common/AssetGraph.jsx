import { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import client from '../../api/client'

/* ───────── colour palette ───────── */
const TYPE_COLORS = {
  server: '#3393ff',
  workstation: '#00e5ff',
  network: '#ffc400',
  iot: '#ff9800',
  unknown: '#7b7f87',
}
const EDGE_COLORS = {
  same_subnet: '#3e4047',
  connects_to: '#3393ff',
  depends_on: '#00e676',
  authenticates_to: '#ffc400',
  exposes_service: '#ff5252',
}
const EDGE_LABELS = {
  same_subnet: 'Subnet',
  connects_to: 'Connects',
  depends_on: 'Depends',
  authenticates_to: 'Auth',
  exposes_service: 'Exposes',
}

/* ───────── simple force simulation ───────── */
function forceSimulation(nodes, edges, width, height) {
  // Assign random positions
  nodes.forEach((n, i) => {
    n.x = width / 2 + (Math.random() - 0.5) * width * 0.6
    n.y = height / 2 + (Math.random() - 0.5) * height * 0.6
    n.vx = 0
    n.vy = 0
  })

  // Build edge index
  const edgeIndex = {}
  edges.forEach(e => {
    if (!edgeIndex[e.source]) edgeIndex[e.source] = []
    if (!edgeIndex[e.target]) edgeIndex[e.target] = []
    edgeIndex[e.source].push(e.target)
    edgeIndex[e.target].push(e.source)
  })

  const nodeMap = {}
  nodes.forEach(n => { nodeMap[n.asset_id] = n })

  // Run iterations
  const iterations = 200 // Increased slightly for more settling time
  const repulsion = 12000 // Increased from 5000 to push nodes further apart
  const attraction = 0.015
  const damping = 0.85
  const centerGravity = 0.005 // Lowered from 0.02 to stop crushing the graph into the center
  const idealLength = 180 // Increased from 80 to give long hostnames room to breathe
  const collisionRadius = 40 // New: Define a physical boundary to prevent overlap

  // Group edges to avoid multiplying attraction for multiple edges between same nodes
  const uniqueEdges = []
  const seenPairs = new Set()
  edges.forEach(e => {
    const minStr = e.source < e.target ? e.source : e.target
    const maxStr = e.source > e.target ? e.source : e.target
    const pairId = `${minStr}-${maxStr}`
    if (!seenPairs.has(pairId)) {
      seenPairs.add(pairId)
      uniqueEdges.push({ source: e.source, target: e.target })
    }
  })

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 1 - iter / iterations

    // Repulsion (all pairs) + Collision Detection
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j]
        let dx = b.x - a.x, dy = b.y - a.y
        let dist = Math.sqrt(dx * dx + dy * dy) || 1

        // 1. Standard Electrostatic Repulsion
        const force = (repulsion * temp) / (dist * dist)
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        a.vx -= fx; a.vy -= fy
        b.vx += fx; b.vy += fy

        // 2. Hard Collision Detection (Prevents exact overlap)
        const minDistance = collisionRadius * 2
        if (dist < minDistance) {
          // If nodes are crossing boundaries, instantly push them apart
          const overlap = minDistance - dist
          const pushX = (dx / dist) * overlap * 0.5
          const pushY = (dy / dist) * overlap * 0.5

          // Apply position correction directly rather than relying solely on velocity
          a.x += pushX; a.y += pushY
          b.x -= pushX; b.y -= pushY
        }
      }
    }

    // Attraction (unique edges)
    uniqueEdges.forEach(e => {
      const a = nodeMap[e.source], b = nodeMap[e.target]
      if (!a || !b) return
      let dx = b.x - a.x, dy = b.y - a.y
      let dist = Math.sqrt(dx * dx + dy * dy) || 1
      // Only attract if they are further than ideal length
      if (dist > idealLength) {
        const force = (dist - idealLength) * attraction * temp
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        a.vx += fx; a.vy += fy
        b.vx -= fx; b.vy -= fy
      }
    })

    // Center gravity
    nodes.forEach(n => {
      n.vx += (width / 2 - n.x) * centerGravity
      n.vy += (height / 2 - n.y) * centerGravity
    })

    // Apply velocities
    nodes.forEach(n => {
      n.vx *= damping
      n.vy *= damping
      n.x += n.vx * temp
      n.y += n.vy * temp
      // Bounds
      n.x = Math.max(40, Math.min(width - 40, n.x))
      n.y = Math.max(40, Math.min(height - 40, n.y))
    })
  }

  return nodes
}

/* ───────── main component ───────── */
export default function AssetGraph({ onSelectAsset, blastRadiusId }) {
  const canvasRef = useRef(null)
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] })
  const [blastData, setBlastData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [inferring, setInferring] = useState(false)
  const [hoveredNode, setHoveredNode] = useState(null)
  const [tooltip, setTooltip] = useState(null)

  // Transform & interaction state
  const stateRef = useRef({
    zoom: 1,
    offsetX: 0,
    offsetY: 0,
    dragging: false,
    dragStart: { x: 0, y: 0 },
    dragNode: null,
    nodes: [],
    edges: [],
  })

  const loadGraph = useCallback(async () => {
    setLoading(true)
    try {
      const res = await client.get('/relationships/graph')
      setGraphData(res.data)
    } catch (err) { console.error('Graph load error:', err) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { loadGraph() }, [loadGraph])

  // Load blast radius when requested
  useEffect(() => {
    if (!blastRadiusId) { setBlastData(null); return }
    const fetchBlast = async () => {
      try {
        const res = await client.get(`/relationships/blast-radius/${blastRadiusId}?max_depth=3`)
        setBlastData(res.data)
      } catch (err) { console.error('Blast radius error:', err) }
    }
    fetchBlast()
  }, [blastRadiusId])

  const triggerInference = async () => {
    setInferring(true)
    try {
      await client.post('/relationships/infer')
      // Wait for inference to complete, then reload
      setTimeout(() => { loadGraph(); setInferring(false) }, 5000)
    } catch (err) {
      console.error('Inference error:', err)
      setInferring(false)
    }
  }

  // Run layout & render
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const rect = canvas.parentElement.getBoundingClientRect()
    const W = rect.width || 800
    const H = 500
    canvas.width = W * window.devicePixelRatio
    canvas.height = H * window.devicePixelRatio
    canvas.style.width = W + 'px'
    canvas.style.height = H + 'px'
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0)

    // Deep clone nodes for layout
    const nodes = graphData.nodes.map(n => ({ ...n }))
    const edges = [...graphData.edges]

    if (nodes.length > 0) {
      forceSimulation(nodes, edges, W, H)
    }

    stateRef.current.nodes = nodes
    stateRef.current.edges = edges

    // Blast radius set of affected IDs
    const blastSet = new Set()
    if (blastData?.affected_assets) {
      blastData.affected_assets.forEach(a => blastSet.add(a.asset_id))
      blastSet.add(blastData.origin_asset_id)
    }

    const draw = () => {
      const { zoom, offsetX, offsetY } = stateRef.current
      ctx.clearRect(0, 0, W, H)

      // Background
      ctx.fillStyle = '#0d0e13'
      ctx.fillRect(0, 0, W, H)

      // Grid pattern
      ctx.strokeStyle = '#14161d'
      ctx.lineWidth = 0.5
      const gridSize = 40 * zoom
      const startX = (offsetX % gridSize) - gridSize
      const startY = (offsetY % gridSize) - gridSize
      for (let x = startX; x < W; x += gridSize) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke()
      }
      for (let y = startY; y < H; y += gridSize) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke()
      }

      ctx.save()
      ctx.translate(offsetX, offsetY)
      ctx.scale(zoom, zoom)

      const nodeMap = {}
      nodes.forEach(n => { nodeMap[n.asset_id] = n })

      // Draw edges
      edges.forEach(e => {
        const a = nodeMap[e.source], b = nodeMap[e.target]
        if (!a || !b) return

        const isBlastEdge = blastSet.size > 0 && blastSet.has(e.source) && blastSet.has(e.target)
        const color = isBlastEdge ? '#ff5252' : (EDGE_COLORS[e.relationship_type] || '#3e4047')
        const isDashed = e.relationship_type === 'same_subnet'

        ctx.beginPath()
        ctx.strokeStyle = color
        ctx.lineWidth = isBlastEdge ? 2.5 : 1.2
        ctx.globalAlpha = isBlastEdge ? 1 : (blastSet.size > 0 ? 0.15 : 0.6)
        if (isDashed) ctx.setLineDash([4, 4])
        else ctx.setLineDash([])
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
        ctx.setLineDash([])
        ctx.globalAlpha = 1

        // Edge label
        if (zoom > 0.6) {
          const mx = (a.x + b.x) / 2
          const my = (a.y + b.y) / 2
          ctx.font = `${9 / zoom}px Inter, sans-serif`
          ctx.fillStyle = isBlastEdge ? '#ff8a80' : '#60646d'
          ctx.globalAlpha = isBlastEdge ? 0.9 : 0.5
          ctx.textAlign = 'center'
          ctx.fillText(EDGE_LABELS[e.relationship_type] || e.relationship_type, mx, my - 4)
          ctx.globalAlpha = 1
        }
      })

      // Draw nodes
      nodes.forEach(n => {
        const isBlastNode = blastSet.has(n.asset_id)
        const isOrigin = blastData?.origin_asset_id === n.asset_id
        const isHovered = hoveredNode === n.asset_id
        const baseColor = TYPE_COLORS[n.device_type] || TYPE_COLORS.unknown
        const radius = Math.max(10, 6 + n.edge_count * 2)

        // Dim non-blast nodes when blast radius is active
        const dimmed = blastSet.size > 0 && !isBlastNode

        // Glow for internet-facing or blast origin
        if ((n.is_internet_facing || isOrigin) && !dimmed) {
          const glow = ctx.createRadialGradient(n.x, n.y, radius, n.x, n.y, radius * 3)
          glow.addColorStop(0, isOrigin ? 'rgba(255,82,82,0.35)' : 'rgba(51,147,255,0.2)')
          glow.addColorStop(1, 'rgba(0,0,0,0)')
          ctx.fillStyle = glow
          ctx.beginPath()
          ctx.arc(n.x, n.y, radius * 3, 0, Math.PI * 2)
          ctx.fill()
        }

        // Node circle
        ctx.beginPath()
        ctx.arc(n.x, n.y, radius, 0, Math.PI * 2)
        ctx.globalAlpha = dimmed ? 0.15 : 1
        ctx.fillStyle = isOrigin ? '#ff5252' : baseColor
        ctx.fill()
        ctx.strokeStyle = isHovered ? '#ffffff' : (isBlastNode ? '#ff8a80' : '#1e2028')
        ctx.lineWidth = isHovered ? 2.5 : 1.5
        ctx.stroke()
        ctx.globalAlpha = 1

        // Criticality ring (for score >= 8)
        if (n.criticality_score >= 8 && !dimmed) {
          ctx.beginPath()
          ctx.arc(n.x, n.y, radius + 4, 0, Math.PI * 2)
          ctx.strokeStyle = '#ff5252'
          ctx.lineWidth = 1.5
          ctx.setLineDash([3, 3])
          ctx.stroke()
          ctx.setLineDash([])
        }

        // Label
        if (zoom > 0.5 && !dimmed) {
          const label = n.hostname || n.ip_address
          ctx.font = `bold ${10 / zoom}px Inter, sans-serif`
          ctx.fillStyle = isOrigin ? '#ff8a80' : '#e2e3e5'
          ctx.textAlign = 'center'
          ctx.fillText(label, n.x, n.y + radius + 14)

          // IP underneath hostname
          if (n.hostname) {
            ctx.font = `${8 / zoom}px Inter, sans-serif`
            ctx.fillStyle = '#7b7f87'
            ctx.fillText(n.ip_address, n.x, n.y + radius + 24)
          }
        }
      })

      ctx.restore()

      // Legend
      const legendX = 16, legendY = H - 120
      ctx.fillStyle = 'rgba(13,14,19,0.85)'
      ctx.fillRect(legendX, legendY, 150, 110)
      ctx.strokeStyle = '#1e2028'
      ctx.strokeRect(legendX, legendY, 150, 110)
      ctx.font = '10px Inter, sans-serif'
      ctx.fillStyle = '#7b7f87'
      ctx.textAlign = 'left'
      ctx.fillText('RELATIONSHIP TYPES', legendX + 8, legendY + 14)

      let ly = legendY + 28
      Object.entries(EDGE_COLORS).forEach(([type, color]) => {
        ctx.fillStyle = color
        ctx.fillRect(legendX + 8, ly - 4, 12, 3)
        ctx.fillStyle = '#a0a3a8'
        ctx.font = '9px Inter, sans-serif'
        ctx.fillText(EDGE_LABELS[type] || type, legendX + 26, ly)
        ly += 16
      })
    }

    draw()

    // Mouse interaction handlers
    const getNodeAt = (mx, my) => {
      const { zoom, offsetX, offsetY } = stateRef.current
      const gx = (mx - offsetX) / zoom
      const gy = (my - offsetY) / zoom
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i]
        const r = Math.max(10, 6 + n.edge_count * 2)
        const dx = gx - n.x, dy = gy - n.y
        if (dx * dx + dy * dy < r * r) return n
      }
      return null
    }

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      const state = stateRef.current

      if (state.dragNode) {
        // Dragging a node
        const gx = (mx - state.offsetX) / state.zoom
        const gy = (my - state.offsetY) / state.zoom
        state.dragNode.x = gx
        state.dragNode.y = gy
        draw()
        return
      }

      if (state.dragging) {
        // Panning
        state.offsetX += e.movementX
        state.offsetY += e.movementY
        draw()
        return
      }

      const node = getNodeAt(mx, my)
      if (node) {
        canvas.style.cursor = 'pointer'
        setHoveredNode(node.asset_id)
        setTooltip({
          x: mx + 15,
          y: my - 10,
          node: node,
        })
      } else {
        canvas.style.cursor = 'grab'
        setHoveredNode(null)
        setTooltip(null)
      }
    }

    const handleMouseDown = (e) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      const node = getNodeAt(mx, my)

      if (node) {
        stateRef.current.dragNode = node
        canvas.style.cursor = 'grabbing'
      } else {
        stateRef.current.dragging = true
        canvas.style.cursor = 'grabbing'
      }
    }

    const handleMouseUp = (e) => {
      if (stateRef.current.dragNode) {
        draw()
      }
      stateRef.current.dragging = false
      stateRef.current.dragNode = null
      canvas.style.cursor = 'grab'
    }

    const handleClick = (e) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      const node = getNodeAt(mx, my)
      if (node && onSelectAsset) {
        onSelectAsset(node.asset_id)
      }
    }

    const handleWheel = (e) => {
      e.preventDefault()
      const state = stateRef.current
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top

      const delta = e.deltaY > 0 ? 0.9 : 1.1
      const newZoom = Math.max(0.2, Math.min(3, state.zoom * delta))

      // Zoom towards cursor
      state.offsetX = mx - (mx - state.offsetX) * (newZoom / state.zoom)
      state.offsetY = my - (my - state.offsetY) * (newZoom / state.zoom)
      state.zoom = newZoom
      draw()
    }

    canvas.addEventListener('mousemove', handleMouseMove)
    canvas.addEventListener('mousedown', handleMouseDown)
    canvas.addEventListener('mouseup', handleMouseUp)
    canvas.addEventListener('mouseleave', handleMouseUp)
    canvas.addEventListener('click', handleClick)
    canvas.addEventListener('wheel', handleWheel, { passive: false })

    return () => {
      canvas.removeEventListener('mousemove', handleMouseMove)
      canvas.removeEventListener('mousedown', handleMouseDown)
      canvas.removeEventListener('mouseup', handleMouseUp)
      canvas.removeEventListener('mouseleave', handleMouseUp)
      canvas.removeEventListener('click', handleClick)
      canvas.removeEventListener('wheel', handleWheel)
    }
  }, [graphData, blastData, hoveredNode, onSelectAsset])

  const resetView = () => {
    stateRef.current.zoom = 1
    stateRef.current.offsetX = 0
    stateRef.current.offsetY = 0
    // Re-trigger render
    setGraphData(prev => ({ ...prev }))
  }

  const zoomIn = () => {
    stateRef.current.zoom = Math.min(3, stateRef.current.zoom * 1.3)
    setGraphData(prev => ({ ...prev }))
  }

  const zoomOut = () => {
    stateRef.current.zoom = Math.max(0.2, stateRef.current.zoom * 0.7)
    setGraphData(prev => ({ ...prev }))
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-dark-300">
            {graphData.total_nodes || 0} nodes &middot; {graphData.total_edges || 0} edges
          </span>
          {blastData && (
            <span className="badge-critical">
              Blast Radius: {blastData.total_affected} affected
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={zoomIn} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Zoom In" id="graph-zoom-in">
            <ZoomIn className="w-4 h-4" />
          </button>
          <button onClick={zoomOut} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Zoom Out" id="graph-zoom-out">
            <ZoomOut className="w-4 h-4" />
          </button>
          <button onClick={resetView} className="p-1.5 rounded hover:bg-dark-700 text-dark-300 transition-colors" title="Reset View" id="graph-reset">
            <Maximize2 className="w-4 h-4" />
          </button>
          <div className="w-px h-5 bg-dark-700 mx-1" />
          <button
            onClick={triggerInference}
            disabled={inferring}
            className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
            id="graph-infer-btn"
          >
            {inferring ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            {inferring ? 'Inferring...' : 'Infer Relationships'}
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div className="graph-container relative" id="asset-graph-canvas">
        {loading ? (
          <div className="flex items-center justify-center" style={{ height: 500 }}>
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : graphData.nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-dark-400" style={{ height: 500 }}>
            <svg className="w-16 h-16 mb-4 opacity-20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="6" cy="6" r="3" /><circle cx="18" cy="6" r="3" /><circle cx="12" cy="18" r="3" />
              <line x1="8.5" y1="7.5" x2="10.5" y2="16" /><line x1="15.5" y1="7.5" x2="13.5" y2="16" />
            </svg>
            <p className="text-lg font-medium mb-1">No relationships found</p>
            <p className="text-sm mb-4">Run a scan and infer relationships to see the graph</p>
            <button onClick={triggerInference} className="btn-primary text-sm" id="graph-first-infer">
              Infer Relationships
            </button>
          </div>
        ) : (
          <canvas ref={canvasRef} style={{ cursor: 'grab' }} />
        )}

        {/* Tooltip */}
        {tooltip && (
          <div
            className="absolute pointer-events-none z-50"
            style={{ left: tooltip.x, top: tooltip.y }}
          >
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-3 shadow-xl text-xs min-w-[180px]">
              <div className="flex items-center gap-2 mb-2">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ background: TYPE_COLORS[tooltip.node.device_type] || TYPE_COLORS.unknown }}
                />
                <span className="font-semibold text-white text-sm">
                  {tooltip.node.hostname || tooltip.node.ip_address}
                </span>
              </div>
              <div className="space-y-1 text-dark-300">
                <div className="flex justify-between">
                  <span>IP</span>
                  <span className="font-mono text-accent-cyan">{tooltip.node.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span>Type</span>
                  <span className="capitalize">{tooltip.node.device_type}</span>
                </div>
                <div className="flex justify-between">
                  <span>Criticality</span>
                  <span className={tooltip.node.criticality_score >= 8 ? 'text-accent-red' : ''}>{tooltip.node.criticality_score}/10</span>
                </div>
                <div className="flex justify-between">
                  <span>Connections</span>
                  <span>{tooltip.node.edge_count}</span>
                </div>
                {tooltip.node.is_internet_facing && (
                  <div className="text-accent-amber mt-1">⚠ Internet Facing</div>
                )}
              </div>
              <div className="text-dark-500 mt-2 text-[10px]">Click for blast radius</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
