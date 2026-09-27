import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api.js'
import { AttackGraphPanel } from './Visualizations.jsx'

const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }
const rangeMilliseconds = { '15m': 15 * 60_000, '1h': 60 * 60_000, '24h': 24 * 60 * 60_000 }

function withinRange(timestamp, range) {
  return range === 'all' || new Date(timestamp).getTime() >= Date.now() - rangeMilliseconds[range]
}

function sortRecords(rows, mode, timestampField, severityOf, confidenceOf) {
  return [...rows].sort((left, right) => {
    if (mode === 'oldest') return new Date(left[timestampField]) - new Date(right[timestampField])
    if (mode === 'severity') return severityOrder[severityOf(right)] - severityOrder[severityOf(left)]
    if (mode === 'confidence') return confidenceOf(right) - confidenceOf(left)
    return new Date(right[timestampField]) - new Date(left[timestampField])
  })
}

function MetricStrip({ summary }) {
  const metrics = summary?.metrics || {}
  const items = [
    ['Requests/sec', metrics.requests_per_sec ?? 0, 'Current 60-second window'],
    ['Events/sec', metrics.events_per_sec ?? 0, 'Normalized event throughput'],
    ['Detections', metrics.attacks ?? 0, 'Aggregates in 24 hours'],
    ['Detection rate', `${metrics.detection_rate ?? 0}%`, 'Detected requests / requests'],
    ['Confirmed blocks', metrics.blocked_confirmed ?? 0, 'Verified real actions only'],
    ['Simulated responses', metrics.responses_simulated ?? 0, 'Dry-run actions'],
  ]
  return <section className="soc-metric-strip">{items.map(([label, value, note]) => <div key={label}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>)}</section>
}

function StreamStatus({ state, mode }) {
  return <div className={`stream-status ${state.toLowerCase()}`}><i /><span>{state === 'LIVE' ? 'STREAM CONNECTED' : state}</span><b>{mode || 'WAITING'}</b></div>
}

function Filters({ filters, setFilters, attackTypes = [] }) {
  const update = (key, value) => setFilters((current) => ({ ...current, [key]: value }))
  return <div className="filter-bar">
    <input aria-label="Search live records" value={filters.search} onChange={(event) => update('search', event.target.value)} placeholder="Search source, target, endpoint or detection" />
    <select aria-label="Severity filter" value={filters.severity} onChange={(event) => update('severity', event.target.value)}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((item) => <option key={item}>{item}</option>)}</select>
    <select aria-label="Attack type filter" value={filters.attackType} onChange={(event) => update('attackType', event.target.value)}><option value="">All attack types</option>{attackTypes.map((item) => <option key={item}>{item}</option>)}</select>
    <input aria-label="Source filter" value={filters.source} onChange={(event) => update('source', event.target.value)} placeholder="Source IP" />
    <input aria-label="Endpoint filter" value={filters.endpoint} onChange={(event) => update('endpoint', event.target.value)} placeholder="Endpoint" />
    <select aria-label="Time range" value={filters.timeRange} onChange={(event) => update('timeRange', event.target.value)}><option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="all">All retained</option></select>
    <select aria-label="Sort records" value={filters.sort} onChange={(event) => update('sort', event.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="severity">Highest severity</option><option value="confidence">Highest confidence</option></select>
    <button onClick={() => setFilters({ search: '', severity: '', attackType: '', source: '', endpoint: '', timeRange: '24h', sort: 'newest' })}>Reset filters</button>
  </div>
}

function LiveTable({ requests, attacksByEvent, Badge, onSelect }) {
  if (!requests.length) return <div className="empty"><b>WAITING FOR EVENTS</b><p>No authorized web traffic matches the current filters.</p></div>
  return <div className="table-wrap live-table"><table><thead><tr><th>Time</th><th>Result</th><th>Request</th><th>Source</th><th>Target</th><th>Detection</th><th>Status</th></tr></thead><tbody>{requests.map((request) => {
    const attack = attacksByEvent.get(request.security_event_id)
    return <tr key={request.id} onClick={() => onSelect(request)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(request) } }} tabIndex="0" role="button" aria-label={`Open ${request.method} ${request.path} request details`}>
      <td>{new Date(request.timestamp).toLocaleTimeString()}</td>
      <td>{attack ? <Badge>{attack.severity}</Badge> : <Badge tone="info">INFO</Badge>}</td>
      <td><b>{request.method} {request.path}</b><small>{request.query_string || `HTTP ${request.status_code}`}</small></td>
      <td><code>{request.source_ip}</code></td>
      <td>{request.target_host}</td>
      <td>{attack ? <><b>{attack.attack_type}</b><small>{attack.rule_id} · {Math.round(attack.confidence * 100)}%</small></> : <span className="muted">No detection</span>}</td>
      <td><Badge tone={attack ? attack.classification.toLowerCase() : 'info'}>{attack?.classification || 'OBSERVED'}</Badge></td>
    </tr>
  })}</tbody></table></div>
}

function AttackTable({ attacks, Badge, onSelect }) {
  if (!attacks.length) return <div className="empty"><b>NO DETECTIONS</b><p>No attack detections match the selected filters.</p></div>
  return <div className="table-wrap attack-table"><table><thead><tr><th>Last seen</th><th>Severity</th><th>Attack</th><th>Source</th><th>Target endpoint</th><th>Requests</th><th>Confidence</th><th>Response</th></tr></thead><tbody>{attacks.map((attack) => <tr key={attack.id} onClick={() => onSelect(attack)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(attack) } }} tabIndex="0" role="button" aria-label={`Open ${attack.attack_type} investigation`}>
    <td>{new Date(attack.last_seen).toLocaleTimeString()}</td>
    <td><Badge>{attack.severity}</Badge></td>
    <td><b>{attack.attack_type}</b><small>{attack.family.replaceAll('_', ' ')} · {attack.rule_id}</small></td>
    <td><code>{attack.source_ip}</code></td>
    <td><b>{attack.target_host}</b><small>{attack.endpoint}</small></td>
    <td>{attack.request_count}</td>
    <td>{Math.round(attack.confidence * 100)}%<small>{attack.classification.replaceAll('_', ' ')}</small></td>
    <td><Badge tone={attack.response_status.toLowerCase()}>{attack.response_status}</Badge></td>
  </tr>)}</tbody></table></div>
}

function Pagination({ total, page, setPage, pageSize = 25 }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  if (total <= pageSize) return null
  return <nav className="table-pagination" aria-label="Table pagination"><span>{page * pageSize + 1}–{Math.min(total, (page + 1) * pageSize)} of {total}</span><div><button onClick={() => setPage((value) => Math.max(0, value - 1))} disabled={page === 0}>Previous</button><b>Page {page + 1} / {pages}</b><button onClick={() => setPage((value) => Math.min(pages - 1, value + 1))} disabled={page >= pages - 1}>Next</button></div></nav>
}

function TopList({ title, rows, empty = 'NO DATA' }) {
  return <section className="rank-list"><h3>{title}</h3>{rows?.length ? rows.map((row, index) => <div key={`${row.value}-${index}`}><span>{index + 1}</span><b title={row.value}>{row.value}</b><strong>{row.count}</strong></div>) : <p>{empty}</p>}</section>
}

function RequestDrawer({ request, onClose, Badge }) {
  if (!request) return null
  return <aside className="detail-drawer"><header><div><p className="eyebrow">WEB REQUEST</p><h2>{request.method} {request.path}</h2></div><button onClick={onClose} aria-label="Close request details">×</button></header><dl className="fact-grid">
    <div><dt>Source</dt><dd><code>{request.source_ip}</code></dd></div><div><dt>Target</dt><dd>{request.target_host}</dd></div><div><dt>Status</dt><dd><Badge tone="info">HTTP {request.status_code}</Badge></dd></div><div><dt>Latency</dt><dd>{request.latency_ms ?? '—'} ms</dd></div><div><dt>Time</dt><dd>{new Date(request.timestamp).toLocaleString()}</dd></div><div><dt>Request ID</dt><dd><code>{request.request_id}</code></dd></div>
  </dl><section><h3>Normalized request</h3><pre>{JSON.stringify({ query: request.query_string, user_agent: request.user_agent, safe_headers: request.safe_headers, metadata: request.request_metadata }, null, 2)}</pre></section></aside>
}

function AttackDrawer({ detail, loading, onClose, onUpdate, Badge }) {
  if (!detail && !loading) return null
  const attack = detail?.attack
  return <aside className="detail-drawer attack-detail"><header><div><p className="eyebrow">ATTACK INVESTIGATION</p><h2>{attack?.attack_type || 'Loading detection…'}</h2></div><button onClick={onClose} aria-label="Close attack investigation">×</button></header>{loading ? <div className="loading">Loading correlated evidence…</div> : <>
    <div className="attack-headline"><Badge>{attack.severity}</Badge><strong>{Math.round(attack.confidence * 100)}% confidence</strong><Badge tone={attack.classification.toLowerCase()}>{attack.classification.replaceAll('_', ' ')}</Badge></div>
    <div className="analyst-actions"><button onClick={() => onUpdate(attack.id, { status: 'INVESTIGATING' })}>Start investigation</button><button onClick={() => onUpdate(attack.id, { classification: 'FALSE_POSITIVE' })}>Mark false positive</button></div>
    <div className="response-flow"><span className="done">DETECTED</span><i>›</i><span className="done">ANALYZED</span><i>›</i><span className={detail.incident?.responses.length ? 'done' : ''}>POLICY CHECK</span><i>›</i><span className={attack.response_status === 'DRY_RUN' ? 'simulated' : ''}>{attack.response_status === 'DRY_RUN' ? 'SIMULATED' : 'AWAITING ACTION'}</span></div>
    <dl className="fact-grid"><div><dt>Source</dt><dd><code>{attack.source_ip}</code></dd></div><div><dt>Target</dt><dd>{attack.target_host}</dd></div><div><dt>Endpoint</dt><dd>{attack.endpoint}</dd></div><div><dt>Requests</dt><dd>{attack.request_count}</dd></div><div><dt>Rule</dt><dd>{attack.rule_id}</dd></div><div><dt>Response</dt><dd>{attack.response_status}</dd></div></dl>
    <section><h3>Detection evidence</h3><div className="evidence-list">{attack.evidence.map((item, index) => <div key={index}><Badge tone="info">{item.source}</Badge><p>{item.reason}</p>{item.signal && <code>{item.signal}</code>}</div>)}</div></section>
    <section><h3>MITRE ATT&CK</h3><div className="pill-row">{attack.mitre_techniques.map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div></section>
    {detail.incident?.iocs.length > 0 && <section><h3>Indicators and threat intelligence</h3><div className="request-mini-list">{detail.incident.iocs.map((item) => <div key={item.id}><Badge tone="info">{item.type}</Badge><code>{item.value}</code><span>{item.verdict}</span>{item.enrichment?.map((result, index) => <small key={index}>{result.provider}: {result.summary} {result.mock ? '(SIMULATED)' : ''}</small>)}</div>)}</div></section>}
    {detail.incident && <section><h3>Correlated incident</h3><div className="incident-summary-line"><div><b>{detail.incident.title}</b><small>{detail.incident.status} · {detail.incident.severity}</small></div><strong>{detail.incident.risk_score}<small>{detail.incident.risk_level} RISK</small></strong></div><ul>{detail.incident.risk_reasons.map((item) => <li key={item}>{item}</li>)}</ul></section>}
    <section><h3>Response history</h3>{detail.incident?.responses.length ? detail.incident.responses.map((item) => <div className="response-record" key={item.id}><Badge tone={item.status.toLowerCase()}>{item.status}</Badge><b>{item.action_type}</b><span>{item.target}</span><small>{item.dry_run ? 'SIMULATED — no external change' : 'REAL ADAPTER'}</small></div>) : <p className="muted">No response requested.</p>}</section>
    <section><h3>Attack replay</h3><div className="compact-timeline">{detail.incident?.timeline.map((item) => <div key={item.id}><time>{new Date(item.timestamp).toLocaleTimeString()}</time><b>{item.type.replaceAll('_', ' ')}</b><p>{item.summary}</p></div>)}</div></section>
    <section><h3>Audit trail</h3>{detail.audit.length ? <div className="request-mini-list">{detail.audit.map((item) => <div key={item.id}><time>{new Date(item.timestamp).toLocaleTimeString()}</time><b>{item.action}</b><Badge>{item.result}</Badge></div>)}</div> : <p className="muted">No directly related audit records.</p>}</section>
    <section><h3>Related requests</h3><div className="request-mini-list">{detail.requests.map((item) => <div key={item.id}><code>{item.source_ip}</code><b>{item.method} {item.path}</b><span>HTTP {item.status_code}</span></div>)}</div></section>
  </>}</aside>
}

export default function LiveSecurity({ page, token, Badge, focusId, onNavigate }) {
  const [requests, setRequests] = useState([])
  const [attacks, setAttacks] = useState([])
  const [summary, setSummary] = useState(null)
  const [catalog, setCatalog] = useState(null)
  const [streamState, setStreamState] = useState('CONNECTING')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [demoRunning, setDemoRunning] = useState(false)
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [selectedAttack, setSelectedAttack] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [filters, setFilters] = useState({ search: '', severity: '', attackType: '', source: '', endpoint: '', timeRange: '24h', sort: 'newest' })
  const [replay, setReplay] = useState([])
  const [attackView, setAttackView] = useState('table')
  const [tablePage, setTablePage] = useState(0)
  const summaryTimer = useRef(null)

  const refreshSummary = useCallback(async () => {
    try { setSummary(await api('/web/summary', { token })) } catch (err) { setError(err.message) }
  }, [token])
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [summaryData, requestData, attackData, catalogData, replayData] = await Promise.all([
        api('/web/summary', { token }), api('/web/requests?limit=150', { token }), api('/web/attacks?limit=150', { token }), api('/web/attack-catalog', { token }), api('/web/replay', { token }),
      ])
      setSummary(summaryData); setRequests(requestData); setAttacks(attackData); setCatalog(catalogData); setReplay(replayData.events)
    } catch (err) { setError(err.message) } finally { setLoading(false) }
  }, [token])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const stream = new EventSource('/api/v1/live/stream', { withCredentials: true })
    const scheduleSummary = () => {
      clearTimeout(summaryTimer.current)
      summaryTimer.current = setTimeout(refreshSummary, 500)
    }
    const onConnected = () => setStreamState('LIVE')
    const onRequest = (event) => { const message = JSON.parse(event.data); setRequests((rows) => [message.data, ...rows.filter((item) => item.id !== message.data.id)].slice(0, 200)); scheduleSummary() }
    const onAttack = (event) => { const message = JSON.parse(event.data); setAttacks((rows) => [message.data, ...rows.filter((item) => item.id !== message.data.id)].sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]).slice(0, 200)); scheduleSummary() }
    const onReplay = (event) => { const message = JSON.parse(event.data); setReplay((rows) => [...rows, message.data].slice(-50)) }
    const onComplete = (event) => { const message = JSON.parse(event.data); setNotice(`Controlled replay completed: ${message.data.requests} requests, ${message.data.attacks} detections, response ${message.data.response_status}.`); load() }
    const onReset = () => { setReplay([]); setNotice('Controlled web demo reset completed.'); load() }
    stream.addEventListener('connected', onConnected); stream.addEventListener('web_request', onRequest); stream.addEventListener('attack', onAttack); stream.addEventListener('replay_step', onReplay); stream.addEventListener('demo_complete', onComplete); stream.addEventListener('demo_reset', onReset)
    stream.onopen = () => setStreamState('LIVE')
    stream.onerror = () => setStreamState('RECONNECTING')
    return () => { clearTimeout(summaryTimer.current); stream.close() }
  }, [load, refreshSummary])

  const attacksByEvent = useMemo(() => {
    const map = new Map()
    attacks.forEach((attack) => attack.related_event_ids.forEach((id) => map.set(id, attack)))
    return map
  }, [attacks])
  const attackTypes = useMemo(() => [...new Set(attacks.map((item) => item.attack_type))].sort(), [attacks])
  const filteredAttacks = useMemo(() => {
    const search = filters.search.toLowerCase()
    const rows = attacks.filter((item) => (!filters.severity || item.severity === filters.severity)
      && (!filters.attackType || item.attack_type === filters.attackType)
      && (!filters.source || item.source_ip.includes(filters.source))
      && (!filters.endpoint || item.endpoint.toLowerCase().includes(filters.endpoint.toLowerCase()))
      && withinRange(item.last_seen, filters.timeRange)
      && (!search || `${item.attack_type} ${item.source_ip} ${item.target_host} ${item.endpoint} ${item.rule_id}`.toLowerCase().includes(search)))
    return sortRecords(rows, filters.sort, 'last_seen', (item) => item.severity, (item) => item.confidence)
  }, [attacks, filters])
  const filteredRequests = useMemo(() => {
    const search = filters.search.toLowerCase()
    const rows = requests.filter((item) => {
      const attack = attacksByEvent.get(item.security_event_id)
      return (!filters.severity || attack?.severity === filters.severity)
        && (!filters.attackType || attack?.attack_type === filters.attackType)
        && (!filters.source || item.source_ip.includes(filters.source))
        && (!filters.endpoint || item.path.toLowerCase().includes(filters.endpoint.toLowerCase()))
        && withinRange(item.timestamp, filters.timeRange)
        && (!search || `${item.method} ${item.path} ${item.source_ip} ${item.target_host} ${attack?.attack_type || ''}`.toLowerCase().includes(search))
    })
    return sortRecords(rows, filters.sort, 'timestamp', (item) => attacksByEvent.get(item.security_event_id)?.severity || 'INFO', (item) => attacksByEvent.get(item.security_event_id)?.confidence || 0)
  }, [requests, attacksByEvent, filters])
  useEffect(() => { setTablePage(0) }, [filters, page, attackView])
  const pagedRequests = filteredRequests.slice(tablePage * 25, tablePage * 25 + 25)
  const pagedAttacks = filteredAttacks.slice(tablePage * 25, tablePage * 25 + 25)

  const openAttack = async (attack) => {
    setSelectedRequest(null); setSelectedAttack(attack); setDetail(null); setDetailLoading(true)
    try { setDetail(await api(`/web/attacks/${attack.id}`, { token })) } catch (err) { setError(err.message) } finally { setDetailLoading(false) }
  }
  useEffect(() => {
    if (!focusId) return
    let active = true
    setSelectedRequest(null); setSelectedAttack({ id: focusId }); setDetail(null); setDetailLoading(true)
    api(`/web/attacks/${focusId}`, { token }).then((item) => { if (active) setDetail(item) }).catch((err) => { if (active) setError(err.message) }).finally(() => { if (active) setDetailLoading(false) })
    return () => { active = false }
  }, [focusId, token])
  const updateAttack = async (attackId, changes) => {
    setError('')
    try {
      await api(`/web/attacks/${attackId}`, { token, method: 'PATCH', body: changes })
      setDetail(await api(`/web/attacks/${attackId}`, { token }))
      await load()
    } catch (err) { setError(err.message) }
  }
  const runDemo = async () => {
    setNotice(''); setError(''); setReplay([]); setDemoRunning(true)
    try { await api('/demo/web-run', { token, method: 'POST' }) } catch (err) { setError(err.message) } finally { setDemoRunning(false) }
  }
  const resetDemo = async () => {
    setNotice(''); setError(''); setDemoRunning(true)
    try { await api('/demo/web-reset', { token, method: 'POST' }) } catch (err) { setError(err.message) } finally { setDemoRunning(false) }
  }

  if (loading && !summary) return <section className="loading-state" aria-live="polite" aria-busy="true"><header><span>LOADING</span><b>Loading persisted SOC telemetry…</b></header><div className="loading-grid"><i /><i /><i /><i /></div><div className="loading-lines"><i /><i /><i /></div></section>
  return <div className="live-security">
    <div className="operational-bar"><StreamStatus state={streamState} mode={summary?.mode} /><div className="operator-actions"><button onClick={resetDemo} disabled={demoRunning}>Reset web demo</button><button className="primary" onClick={runDemo} disabled={demoRunning}>{demoRunning ? 'Replay in progress…' : 'Start controlled web demo'}</button></div></div>
    {error && <div className="error-box">{error}</div>}{notice && <div className="success-box">{notice}</div>}
    <MetricStrip summary={summary} />
    {(page === 'Live Monitor' || (page === 'Attacks' && attackView === 'table')) && <Filters filters={filters} setFilters={setFilters} attackTypes={attackTypes} />}
    {page === 'Live Monitor' && <section className="panel soc-panel"><div className="panel-head"><div><p className="eyebrow">SERVER-SENT EVENTS</p><h2>Live security activity</h2></div><span>{filteredRequests.length} matching records</span></div><LiveTable requests={pagedRequests} attacksByEvent={attacksByEvent} Badge={Badge} onSelect={(item) => { setSelectedAttack(null); setSelectedRequest(item) }} /><Pagination total={filteredRequests.length} page={tablePage} setPage={setTablePage} /></section>}
    {page === 'Attacks' && <><div className="view-switch"><div><p className="eyebrow">ATTACK MODE</p><span>{filteredAttacks.length} correlated aggregates</span></div><div><button className={attackView === 'table' ? 'active' : ''} onClick={() => setAttackView('table')}>Table</button><button className={attackView === 'graph' ? 'active' : ''} onClick={() => setAttackView('graph')}>Relationship graph</button></div></div>{attackView === 'table' ? <section className="panel soc-panel"><div className="panel-head"><div><p className="eyebrow">CORRELATED DETECTIONS</p><h2>Attack monitoring</h2></div><span>{filteredAttacks.length} aggregates</span></div><AttackTable attacks={pagedAttacks} Badge={Badge} onSelect={openAttack} /><Pagination total={filteredAttacks.length} page={tablePage} setPage={setTablePage} /></section> : <AttackGraphPanel token={token} onNavigate={onNavigate} />}</>}
    {page === 'Web Security' && <>
      <section className="web-operations-grid"><div className="panel"><div className="panel-head"><div><p className="eyebrow">ATTACK SURFACE</p><h2>Web security operations</h2></div><Badge tone="info">{catalog?.total || 0} CATEGORIES</Badge></div><div className="severity-summary">{['CRITICAL', 'HIGH', 'MEDIUM'].map((severity) => <div key={severity}><Badge>{severity}</Badge><strong>{summary?.severity_distribution?.[severity] || 0}</strong><span>detections</span></div>)}</div><p className="truth-note">Context-dependent detections require explicit application or WAF evidence. Signature matches begin as suspicious and escalate with repetition.</p></div>
      <div className="top-grid"><TopList title="Top attacking sources" rows={summary?.top_sources} /><TopList title="Top attack types" rows={summary?.top_attack_types} /><TopList title="Top targeted endpoints" rows={summary?.top_targets} /></div></section>
      <section className="system-posture"><div className="panel"><p className="eyebrow">RISK DISTRIBUTION</p>{Object.entries(summary?.risk_distribution || {}).length ? Object.entries(summary.risk_distribution).map(([key, value]) => <div className="posture-row" key={key}><Badge>{key}</Badge><strong>{value}</strong></div>) : <p className="muted">NO INCIDENT RISK DATA</p>}</div><div className="panel"><p className="eyebrow">CONNECTOR HEALTH</p>{Object.entries(summary?.connector_health || {}).map(([key, value]) => <div className="posture-row" key={key}><Badge>{key}</Badge><strong>{value}</strong></div>)}</div><div className="panel"><p className="eyebrow">SYSTEM HEALTH</p>{Object.entries(summary?.system_health || {}).map(([key, value]) => <div className="posture-row" key={key}><span>{key.toUpperCase()}</span><Badge>{value}</Badge></div>)}</div></section>
      <section className="split-grid web-split"><div className="panel"><div className="panel-head"><div><p className="eyebrow">RECENT DETECTIONS</p><h2>Web attacks</h2></div></div><AttackTable attacks={attacks.slice(0, 10)} Badge={Badge} onSelect={openAttack} /></div><div className="panel"><div className="panel-head"><div><p className="eyebrow">REPLAY</p><h2>Response timeline</h2></div></div>{replay.length ? <div className="replay-list">{replay.map((item, index) => <div key={`${item.sequence}-${index}`}><time>00:{String(index).padStart(2, '0')}</time><i /><div><b>{item.label}</b><small>{item.attacks?.join(', ') || item.type?.replaceAll('_', ' ') || 'Observed request'} · {item.simulated === false ? 'RECORDED' : 'SIMULATED'}</small></div></div>)}</div> : <div className="empty"><b>NO REPLAY DATA</b><p>Start the controlled web demo to watch the workflow.</p></div>}</div></section>
      <section className="panel soc-panel"><div className="panel-head"><div><p className="eyebrow">NORMALIZED ACCESS LOGS</p><h2>Recent web requests</h2></div></div><LiveTable requests={requests.slice(0, 20)} attacksByEvent={attacksByEvent} Badge={Badge} onSelect={(item) => setSelectedRequest(item)} /></section>
    </>}
    <RequestDrawer request={selectedRequest} onClose={() => setSelectedRequest(null)} Badge={Badge} />
    <AttackDrawer detail={detail} loading={detailLoading} onUpdate={updateAttack} onClose={() => { setSelectedAttack(null); setDetail(null) }} Badge={Badge} />
    {(selectedRequest || selectedAttack) && <button aria-label="Close details" className="drawer-backdrop" onClick={() => { setSelectedRequest(null); setSelectedAttack(null); setDetail(null) }} />}
  </div>
}
