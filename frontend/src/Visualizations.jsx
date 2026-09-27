import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import GraphCanvas from './GraphCanvas.jsx'

function GraphLoading({ label }) {
  return <section className="loading-state" aria-live="polite" aria-busy="true"><header><span>LOADING</span><b>{label}</b></header><div className="loading-lines"><i /><i /><i /></div></section>
}

function GraphError({ message, retry }) {
  return <section className="component-error"><div><b>VISUALIZATION UNAVAILABLE</b><p>{message}</p></div><button onClick={retry}>Retry</button></section>
}

export function NetworkMode({ token, onNavigate }) {
  const [range, setRange] = useState('24h')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const refreshTimer = useRef(null)
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setData(await api(`/visualizations/network?range=${range}`, { token })) } catch (err) { setError(`Network topology: ${err.message}`) } finally { setLoading(false) }
  }, [token, range])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    const stream = new EventSource('/api/v1/live/stream', { withCredentials: true })
    const schedule = () => { clearTimeout(refreshTimer.current); refreshTimer.current = setTimeout(load, 500) }
    stream.addEventListener('web_request', schedule); stream.addEventListener('attack', schedule); stream.addEventListener('demo_reset', schedule)
    return () => { clearTimeout(refreshTimer.current); stream.close() }
  }, [load])
  if (loading && !data) return <GraphLoading label="Building network topology from persisted telemetry…" />
  if (error && !data) return <GraphError message={error} retry={load} />
  return <div className="visualization-mode"><div className="visualization-command"><div><p className="eyebrow">NETWORK MODE</p><h2>Infrastructure communication</h2><p>Aggregated from normalized web and network telemetry. No synthetic topology nodes are added.</p></div><label>Time range<select value={range} onChange={(event) => setRange(event.target.value)}><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="24h">24 hours</option><option value="7d">7 days</option></select></label></div>{error && <GraphError message={error} retry={load} />}<section className="topology-summary">{[['Nodes', data.summary.nodes], ['Connections', data.summary.connections], ['Suspicious', data.summary.suspicious_connections], ['Events', data.summary.events]].map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</section><GraphCanvas nodes={data.nodes} edges={data.edges} mode="network" title="Network topology" subtitle="Select a node or connection to inspect actual traffic, risk, and incident relationships." onNavigate={onNavigate} /></div>
}

export function AttackGraphPanel({ token, incidentId = null, onNavigate, compact = false }) {
  const [range, setRange] = useState('24h')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const timer = useRef(null)
  const load = useCallback(async () => {
    try {
      const incident = incidentId ? `&incident_id=${encodeURIComponent(incidentId)}` : ''
      setData(await api(`/visualizations/attack-graph?range=${range}${incident}`, { token }))
      setError('')
    } catch (err) { setError(`Attack graph: ${err.message}`) }
  }, [token, range, incidentId])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    const stream = new EventSource('/api/v1/live/stream', { withCredentials: true })
    const schedule = () => { clearTimeout(timer.current); timer.current = setTimeout(load, 400) }
    stream.addEventListener('attack', schedule); stream.addEventListener('demo_reset', schedule)
    return () => { clearTimeout(timer.current); stream.close() }
  }, [load])
  if (!data && !error) return <GraphLoading label="Building attack relationships…" />
  if (!data) return <GraphError message={error} retry={load} />
  return <div className={compact ? 'graph-compact' : ''}><div className="graph-range"><label>Relationship window<select value={range} onChange={(event) => setRange(event.target.value)}><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="24h">24 hours</option><option value="7d">7 days</option></select></label></div>{error && <GraphError message={error} retry={load} />}<GraphCanvas nodes={data.nodes} edges={data.edges} mode="attack" title={incidentId ? 'Incident attack path' : 'Live attack relationship graph'} subtitle="Aggregated source, attack, endpoint, target, and incident relationships." onNavigate={onNavigate} /></div>
}

export function IncidentRelationshipGraph({ incidentId, token, onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { setData(await api(`/visualizations/incidents/${incidentId}`, { token })); setError('') } catch (err) { setError(`Incident graph: ${err.message}`) }
  }, [incidentId, token])
  useEffect(() => { load() }, [load])
  if (!data && !error) return <GraphLoading label="Mapping incident relationships…" />
  if (!data) return <GraphError message={error} retry={load} />
  return <GraphCanvas nodes={data.nodes} edges={data.edges} mode="incident" title="Incident relationship graph" subtitle="Click any source, alert, IOC, host, evidence, MITRE, event group, or response node." onNavigate={onNavigate} />
}
