import { useMemo, useRef, useState } from 'react'

const severityRank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
const typeOrder = ['external_source', 'source', 'endpoint', 'host', 'attack', 'event_group', 'ioc', 'user', 'alert', 'evidence', 'mitre', 'response', 'web_server', 'target', 'incident']

function layoutNodes(nodes, mode) {
  const width = 1000
  const height = 600
  if (mode === 'incident') {
    const root = nodes.find((item) => item.type === 'incident')
    const positions = {}
    if (root) positions[root.id] = { x: 560, y: height / 2 }
    const columns = [
      { x: 85, types: ['source', 'ioc', 'user', 'host'] },
      { x: 310, types: ['alert'] },
      { x: 765, types: ['mitre'] },
      { x: 920, types: ['event_group', 'evidence', 'response'] },
    ]
    const assigned = new Set(root ? [root.id] : [])
    columns.forEach((column) => {
      const items = nodes.filter((item) => column.types.includes(item.type))
      items.forEach((item, index) => {
        positions[item.id] = { x: column.x, y: 34 + (index + 1) * (525 / (items.length + 1)) }
        assigned.add(item.id)
      })
    })
    const remaining = nodes.filter((item) => !assigned.has(item.id))
    remaining.forEach((item, index) => { positions[item.id] = { x: 560, y: 55 + index * 54 } })
    return { positions, width, height }
  }
  const groups = new Map()
  nodes.forEach((node) => {
    const rank = Math.max(0, typeOrder.indexOf(node.type))
    const existing = groups.get(rank) || []
    existing.push(node)
    groups.set(rank, existing)
  })
  const ranks = [...groups.keys()].sort((a, b) => a - b)
  const positions = {}
  ranks.forEach((rank, columnIndex) => {
    const items = groups.get(rank)
    const x = 90 + columnIndex * (820 / Math.max(ranks.length - 1, 1))
    items.forEach((item, itemIndex) => {
      positions[item.id] = { x, y: 55 + (itemIndex + 1) * (500 / (items.length + 1)) }
    })
  })
  return { positions, width, height }
}

function displayValue(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (Array.isArray(value)) {
    if (!value.length) return '—'
    if (typeof value[0] === 'object') return value.map((item) => item.provider || item.summary || 'record').join(', ')
    return value.join(', ')
  }
  if (typeof value === 'object') return JSON.stringify(value)
  if (typeof value === 'boolean') return value ? 'YES' : 'NO'
  return String(value)
}

export default function GraphCanvas({ nodes = [], edges = [], mode = 'network', title, subtitle, onNavigate }) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [nodeType, setNodeType] = useState('')
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [selected, setSelected] = useState(null)
  const [scale, setScale] = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const drag = useRef(null)

  const nodeTypes = useMemo(() => [...new Set(nodes.map((item) => item.type))].sort(), [nodes])
  const visibleNodes = useMemo(() => nodes.filter((item) => {
    const text = `${item.label} ${item.type} ${item.status} ${item.severity}`.toLowerCase()
    const suspicious = ['SUSPICIOUS', 'DETECTED', 'LIKELY_ATTACK', 'CONFIRMED_ATTACK', 'UNDER_ATTACK', 'HIGH_RISK'].includes(item.status)
      || severityRank[item.severity] >= severityRank.HIGH
    return (!search || text.includes(search.toLowerCase()))
      && (!severity || item.severity === severity)
      && (!nodeType || item.type === nodeType)
      && (!suspiciousOnly || suspicious)
  }), [nodes, search, severity, nodeType, suspiciousOnly])
  const visibleIds = useMemo(() => new Set(visibleNodes.map((item) => item.id)), [visibleNodes])
  const visibleEdges = useMemo(() => edges.filter((item) => visibleIds.has(item.source) && visibleIds.has(item.target)), [edges, visibleIds])
  const layout = useMemo(() => layoutNodes(visibleNodes, mode), [visibleNodes, mode])

  const zoom = (next) => setScale(Math.min(2.2, Math.max(0.55, next)))
  const reset = () => { setScale(1); setOffset({ x: 0, y: 0 }); setSelected(null) }
  const pointerDown = (event) => {
    if (event.target.dataset.canvas !== 'true') return
    drag.current = { x: event.clientX, y: event.clientY, offset }
    event.currentTarget.setPointerCapture(event.pointerId)
  }
  const pointerMove = (event) => {
    if (!drag.current) return
    setOffset({ x: drag.current.offset.x + event.clientX - drag.current.x, y: drag.current.offset.y + event.clientY - drag.current.y })
  }
  const selectNode = (node) => setSelected({ kind: 'node', item: node })
  const selectEdge = (edge) => setSelected({ kind: 'edge', item: edge })

  return <section className="graph-workspace panel">
    <header className="graph-header"><div><p className="eyebrow">RELATIONSHIP VIEW</p><h2>{title}</h2><p>{subtitle}</p></div><div className="graph-summary"><span>{visibleNodes.length} nodes</span><span>{visibleEdges.length} relationships</span></div></header>
    <div className="graph-toolbar">
      <input aria-label="Search graph nodes" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search nodes" />
      <select aria-label="Graph severity filter" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((item) => <option key={item}>{item}</option>)}</select>
      <select aria-label="Graph node type filter" value={nodeType} onChange={(event) => setNodeType(event.target.value)}><option value="">All node types</option>{nodeTypes.map((item) => <option key={item} value={item}>{item.replaceAll('_', ' ')}</option>)}</select>
      <label><input type="checkbox" checked={suspiciousOnly} onChange={(event) => setSuspiciousOnly(event.target.checked)} /> Suspicious only</label>
      <div className="zoom-controls"><button onClick={() => zoom(scale - 0.15)} aria-label="Zoom out">−</button><span>{Math.round(scale * 100)}%</span><button onClick={() => zoom(scale + 0.15)} aria-label="Zoom in">+</button><button onClick={reset}>Fit view</button></div>
    </div>
    <div className="graph-body">
      <div className="graph-canvas" onWheel={(event) => { event.preventDefault(); zoom(scale + (event.deltaY < 0 ? 0.1 : -0.1)) }}>
        {visibleNodes.length ? <svg viewBox={`0 0 ${layout.width} ${layout.height}`} role="img" aria-label={title} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }}>
          <rect data-canvas="true" width={layout.width} height={layout.height} className="graph-background" />
          <g transform={`translate(${offset.x} ${offset.y}) scale(${scale})`}>
            {visibleEdges.map((edge) => {
              const source = layout.positions[edge.source]; const target = layout.positions[edge.target]
              if (!source || !target) return null
              return <g key={edge.id} className={`graph-edge severity-${String(edge.severity || 'INFO').toLowerCase()}`} onClick={(event) => { event.stopPropagation(); selectEdge(edge) }} onKeyDown={(event) => { if (event.key === 'Enter') selectEdge(edge) }} tabIndex="0" role="button" aria-label={`Inspect ${edge.relationship || edge.protocol || 'connection'}`}>
                <line className="edge-hit" x1={source.x} y1={source.y} x2={target.x} y2={target.y} />
                <line className="edge-line" x1={source.x} y1={source.y} x2={target.x} y2={target.y} />
                {(visibleEdges.length <= 20 || selected?.kind === 'edge' && selected.item.id === edge.id) && <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 5}>{edge.event_count || 1} · {edge.relationship || edge.protocol || 'connection'}</text>}
                <title>{edge.event_count || 1} · {edge.relationship || edge.protocol || 'connection'}</title>
              </g>
            })}
            {visibleNodes.map((node) => {
              const position = layout.positions[node.id]
              return <g key={node.id} transform={`translate(${position.x - 66} ${position.y - 22})`} className={`graph-node type-${node.type} severity-${String(node.severity || 'INFO').toLowerCase()} ${selected?.kind === 'node' && selected.item.id === node.id ? 'selected' : ''}`} onClick={(event) => { event.stopPropagation(); selectNode(node) }} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectNode(node) } }} tabIndex="0" role="button" aria-label={`Inspect ${node.label}`}>
                <rect width="132" height="44" rx="3" />
                <text className="node-label" x="10" y="18">{node.label.length > 19 ? `${node.label.slice(0, 18)}…` : node.label}</text>
                <text className="node-meta" x="10" y="34">{node.type.replaceAll('_', ' ')} · {node.status}</text>
                <title>{node.label} — {node.type} — {node.status}</title>
              </g>
            })}
          </g>
        </svg> : <div className="empty"><b>NO GRAPH DATA</b><p>No nodes match the selected filters.</p></div>}
      </div>
      <aside className="graph-detail">
        {selected ? <><header><p className="eyebrow">{selected.kind === 'node' ? 'NODE DETAILS' : 'CONNECTION DETAILS'}</p><h3>{selected.kind === 'node' ? selected.item.label : `${selected.item.source} → ${selected.item.target}`}</h3></header><dl>{Object.entries(selected.item).filter(([key]) => !['id', 'details'].includes(key)).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{displayValue(value)}</dd></div>)}{selected.item.details && Object.entries(selected.item.details).map(([key, value]) => <div key={`detail-${key}`}><dt>{key.replaceAll('_', ' ')}</dt><dd>{displayValue(value)}</dd></div>)}</dl>{onNavigate && selected.item.incident_ids?.length > 0 && <button className="primary" onClick={() => onNavigate('Incidents', selected.item.incident_ids[0])}>Open related incident</button>}</> : <div className="empty"><b>SELECT A NODE OR EDGE</b><p>Inspect activity, risk, relationships, and related incidents.</p></div>}
      </aside>
    </div>
  </section>
}
