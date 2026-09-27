import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api.js'

const seriesColors = { events: '#5b8fc2', attacks: '#e35869', incidents: '#d9a441', responses: '#38bda9' }

function TrendChart({ rows }) {
  const [hover, setHover] = useState(null)
  const width = 760; const height = 250; const pad = { left: 38, right: 12, top: 18, bottom: 30 }
  const keys = ['events', 'attacks', 'incidents', 'responses']
  const maximum = Math.max(1, ...rows.flatMap((item) => keys.map((key) => item[key])))
  const x = (index) => pad.left + index * ((width - pad.left - pad.right) / Math.max(rows.length - 1, 1))
  const y = (value) => height - pad.bottom - value * ((height - pad.top - pad.bottom) / maximum)
  const path = (key) => rows.map((item, index) => `${index ? 'L' : 'M'} ${x(index)} ${y(item[key])}`).join(' ')
  return <div className="trend-chart"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Events, attacks, incidents, and responses over time">
    {[0, .25, .5, .75, 1].map((ratio) => <g key={ratio}><line x1={pad.left} x2={width - pad.right} y1={y(maximum * ratio)} y2={y(maximum * ratio)} className="chart-grid" /><text x={pad.left - 7} y={y(maximum * ratio) + 3} textAnchor="end">{Math.round(maximum * ratio)}</text></g>)}
    {keys.map((key) => <path key={key} d={path(key)} fill="none" stroke={seriesColors[key]} strokeWidth="2" />)}
    {rows.map((item, index) => <rect key={item.timestamp} x={Math.max(pad.left, x(index) - 8)} y={pad.top} width="16" height={height - pad.top - pad.bottom} fill="transparent" onMouseEnter={() => setHover({ ...item, index })} onMouseLeave={() => setHover(null)}><title>{new Date(item.timestamp).toLocaleString()} — {keys.map((key) => `${key}: ${item[key]}`).join(', ')}</title></rect>)}
    <text x={pad.left} y={height - 8}>{rows[0] ? new Date(rows[0].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}</text><text x={width - pad.right} y={height - 8} textAnchor="end">{rows.length ? new Date(rows.at(-1).timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}</text>
  </svg>{hover && <div className="chart-tooltip" style={{ left: `${Math.min(85, Math.max(8, hover.index / Math.max(rows.length - 1, 1) * 100))}%` }}><b>{new Date(hover.timestamp).toLocaleTimeString()}</b>{keys.map((key) => <span key={key}><i style={{ background: seriesColors[key] }} />{key}: {hover[key]}</span>)}</div>}<div className="chart-legend">{keys.map((key) => <span key={key}><i style={{ background: seriesColors[key] }} />{key}</span>)}</div></div>
}

function Distribution({ title, rows, color = '#5b8fc2' }) {
  const maximum = Math.max(1, ...rows.map((item) => item.value))
  return <section className="distribution"><h3>{title}</h3>{rows.length ? rows.slice(0, 6).map((item) => <div key={item.label}><header><span>{item.label}</span><b>{item.value}</b></header><i><b style={{ width: `${item.value / maximum * 100}%`, background: item.color || color }} /></i></div>) : <p>NO DATA IN SELECTED WINDOW</p>}</section>
}

export default function SOCAnalytics({ token }) {
  const [range, setRange] = useState('24h')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const timer = useRef(null)
  const load = useCallback(async () => {
    try { setData(await api(`/visualizations/trends?range=${range}`, { token })); setError('') } catch (err) { setError(`Security analytics: ${err.message}`) }
  }, [token, range])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    const stream = new EventSource('/api/v1/live/stream', { withCredentials: true })
    const schedule = () => { clearTimeout(timer.current); timer.current = setTimeout(load, 600) }
    stream.addEventListener('attack', schedule); stream.addEventListener('demo_complete', schedule); stream.addEventListener('demo_reset', schedule)
    return () => { clearTimeout(timer.current); stream.close() }
  }, [load])
  const severityRows = useMemo(() => Object.entries(data?.severity_distribution || {}).map(([label, value]) => ({ label, value, color: label === 'CRITICAL' ? '#e35869' : label === 'HIGH' ? '#d66b53' : label === 'MEDIUM' ? '#d9a441' : '#5b8fc2' })), [data])
  const responseRows = useMemo(() => Object.entries(data?.response_distribution || {}).map(([label, value]) => ({ label, value, color: label === 'SUCCESS' ? '#38b783' : label === 'FAILED' ? '#e35869' : '#5b8fc2' })), [data])
  const confidenceRows = useMemo(() => Object.entries(data?.confidence_distribution || {}).map(([label, value]) => ({ label, value, color: label === 'HIGH' ? '#e35869' : label === 'MEDIUM' ? '#d9a441' : '#5b8fc2' })), [data])
  return <section className="analytics-panel panel"><div className="panel-head"><div><p className="eyebrow">SOC ANALYTICS</p><h2>Security activity over time</h2></div><label>Time range<select value={range} onChange={(event) => setRange(event.target.value)}><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="24h">24 hours</option><option value="7d">7 days</option></select></label></div>{error && <div className="component-error"><div><b>ANALYTICS UNAVAILABLE</b><p>{error}</p></div><button onClick={load}>Retry</button></div>}{data ? <div className="analytics-grid"><TrendChart rows={data.series} /><div className="analytics-side"><Distribution title="Severity" rows={severityRows} /><Distribution title="Top attack types" rows={data.attack_type_distribution || []} color="#d66b53" /><Distribution title="Detection confidence" rows={confidenceRows} /><Distribution title="Response actions" rows={responseRows} color="#38bda9" /></div></div> : <div className="loading-state"><header><span>LOADING</span><b>Loading backend-derived trends…</b></header><div className="loading-lines"><i /><i /><i /></div></div>}</section>
}
