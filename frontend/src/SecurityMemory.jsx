import { useMemo, useState } from 'react'
import { api } from './api.js'
import './security-memory.css'

const FILTERS = [
  ['all', 'All recalled experience'],
  ['lesson', 'Lessons'],
  ['failure', 'Previous failures'],
  ['success', 'Successful approaches'],
]

function values(items) {
  return Array.isArray(items) ? items.filter(Boolean) : []
}

function MemoryCard({ item, onOpenIncident }) {
  if (!item.experience) {
    return <article className="security-memory-card">
      <header><div><p className="eyebrow">RECALLED FROM HINDSIGHT · {item.type || 'MEMORY'}</p>
        <h3>{values(item.recalled_facts)[0] || item.context || 'Hindsight memory'}</h3>
        {item.context && <small>{item.context}</small>}</div>
        <span>No linked GhostSOC incident</span>
      </header>
      {values(item.recalled_facts).length > 1 && <ul>{values(item.recalled_facts).slice(1).map((fact, index) => <li key={index}>{fact}</li>)}</ul>}
    </article>
  }
  const experience = item.experience || {}
  const incident = experience.incident || {}
  const investigation = experience.investigation || {}
  const response = experience.response || {}
  const feedback = values(experience.analyst_feedback)
  const lessons = values(experience.lessons)
  const worked = [...values(investigation.successful_paths), ...values(response.successful_actions).map((action) => action.type)]
  const failed = [...values(investigation.failed_paths), ...values(response.failed_actions).map((action) => action.type)]
  return <article className="security-memory-card">
    <header><div><p className="eyebrow">RECALLED FROM HINDSIGHT</p><h3>{incident.title || 'Security incident experience'}</h3></div>
      {item.source_incident_id && <button type="button" className="source-link" onClick={() => onOpenIncident(item.source_incident_id)}>
        Source incident <code>{item.source_incident_id?.slice(0, 8) || 'unknown'}</code>
      </button>}</header>
    <div className="memory-card-grid">
      <section><h4>What worked</h4>{worked.length ? <ul>{worked.map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul> : <p>Not recorded</p>}</section>
      <section className="memory-failure"><h4>What failed</h4>{failed.length ? <ul>{failed.map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul> : <p>No failed path recorded</p>}</section>
      <section className="memory-lesson"><h4>Lessons learned</h4>{lessons.length ? <ul>{lessons.map((lesson, index) => <li key={`${lesson.lesson}-${index}`}>{lesson.lesson}</li>)}</ul> : <p>No lesson recorded</p>}</section>
      {values(response.side_effects).length > 0 && <section><h4>Side effects</h4><ul>{values(response.side_effects).map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul></section>}
    </div>
    {feedback.length > 0 && <details className="memory-provenance"><summary>Analyst decisions and recalled facts</summary>
      {feedback.map((decision, index) => <p key={`${decision.decision}-${index}`}><strong>{decision.decision}:</strong> {decision.reason}</p>)}
      {values(item.recalled_facts).length > 0 && <ul>{values(item.recalled_facts).map((fact, index) => <li key={index}>{fact}</li>)}</ul>}
    </details>}
    {feedback.length === 0 && values(item.recalled_facts).length > 0 && <details className="memory-provenance"><summary>Facts returned by Hindsight</summary>
      <ul>{values(item.recalled_facts).map((fact, index) => <li key={index}>{fact}</li>)}</ul>
    </details>}
  </article>
}

export default function SecurityMemory({ token, onNavigate }) {
  const [query, setQuery] = useState('')
  const [activeQuery, setActiveQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    const normalized = query.trim()
    if (normalized.length < 2) return
    setActiveQuery(normalized); setLoading(true); setError(''); setResult(null)
    try {
      setResult(await api('/memory/search', { token, method: 'POST', body: { query: normalized, limit: 20 } }))
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  const matches = useMemo(() => (result?.matches || []).filter((item) => {
    if (filter === 'all') return true
    const experience = item.experience || {}
    const failed = values(experience.investigation?.failed_paths).length > 0 || values(experience.response?.failed_actions).length > 0
    const worked = values(experience.investigation?.successful_paths).length > 0 || values(experience.response?.successful_actions).length > 0
    if (filter === 'failure') return failed
    if (filter === 'success') return worked
    return values(experience.lessons).length > 0
  }), [result, filter])

  return <div className="security-memory-page">
    <section className="memory-intro panel"><div><p className="eyebrow">ORGANIZATIONAL EXPERIENCE · POWERED BY HINDSIGHT</p>
      <h2>Security Memory</h2><p>Search prior incident experience so the next investigation can build on what analysts learned.</p></div>
      <div className="memory-loop" aria-label="Incident, learn, recall, investigate"><span>Incident</span><i>→</i><span>Learn</span><i>→</i><span>Recall</span><i>→</i><span>Investigate</span></div>
    </section>
    <section className="panel memory-search-panel"><form onSubmit={submit}>
      <label htmlFor="memory-query">Search Hindsight memory</label>
      <div className="memory-search-row"><input id="memory-query" value={query} onChange={(event) => setQuery(event.target.value)}
        placeholder="Try: previous failed containment, credential access…" minLength={2} maxLength={1000} required />
        <button className="primary" type="submit" disabled={loading || query.trim().length < 2}>{loading ? 'Searching…' : 'Search memory'}</button></div>
    </form>
    <p className="memory-search-note">Results include Hindsight facts and experiences. A source incident link appears only when a result matches a retained GhostSOC record.</p>
    </section>
    <section className="panel memory-results-panel" aria-live="polite">
      <div className="panel-head"><div><p className="eyebrow">RETRIEVED HINDSIGHT MEMORY</p><h3>{activeQuery ? `Results for “${activeQuery}”` : 'Search to recall past experience'}</h3></div>
        {result?.status === 'available' && <span>{result.matches.length} recalled memor{result.matches.length === 1 ? 'y' : 'ies'}</span>}</div>
      {result?.status === 'unavailable' && <div className="component-warning">Hindsight is unavailable. Search again after the memory provider recovers.</div>}
      {error && <div className="component-warning">Search failed: {error}</div>}
      {loading && <p role="status">Asking Hindsight to recall relevant security experience…</p>}
      {result?.status === 'available' && result.matches.length > 0 && <>
        <div className="memory-filters" role="group" aria-label="Filter recalled experiences">{FILTERS.map(([value, label]) => <button type="button" key={value} className={filter === value ? 'active' : ''} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div>
        {matches.length ? <div className="security-memory-list">{matches.map((item) => <MemoryCard key={item.memory_id || item.fact_id || item.document_id} item={item} onOpenIncident={(id) => onNavigate('Incidents', id)} />)}</div>
          : <p>No recalled sources match this filter.</p>}
      </>}
      {result?.status === 'available' && result.matches.length === 0 && <p>No relevant Hindsight memories found for this search.</p>}
    </section>
  </div>
}
