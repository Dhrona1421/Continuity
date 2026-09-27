import { useEffect, useState } from 'react'
import { api } from './api.js'
import './incident-memory.css'

const EMPTY = 'No relevant historical experience found.'

export default function IncidentMemory({ incidentId, token }) {
  const [memory, setMemory] = useState(null)
  const [experience, setExperience] = useState(null)
  const [experienceError, setExperienceError] = useState('')
  const [recommendation, setRecommendation] = useState(null)
  const [memoryError, setMemoryError] = useState('')
  const [agentError, setAgentError] = useState('')
  const [decision, setDecision] = useState('')
  const [reason, setReason] = useState('')
  const [modification, setModification] = useState('')
  const [outcome, setOutcome] = useState('')
  const [lesson, setLesson] = useState('')
  const [lessonCondition, setLessonCondition] = useState('')
  const [lessonBehavior, setLessonBehavior] = useState('')
  const [feedbackState, setFeedbackState] = useState('')
  const [saving, setSaving] = useState(false)
  const [withoutMemory, setWithoutMemory] = useState(false)

  useEffect(() => {
    let active = true
    setMemory(null); setMemoryError(''); setExperience(null); setExperienceError('')
    api(`/incidents/${incidentId}/experience`, { token })
      .then((result) => { if (active) setExperience(result) })
      .catch(() => { if (active) setExperienceError('Current incident experience unavailable') })
    api('/memory/recall', { token, method: 'POST', body: { incident_id: incidentId } })
      .then((result) => { if (active) setMemory(result) })
      .catch(() => { if (active) setMemoryError('Security Memory unavailable') })
    return () => { active = false }
  }, [incidentId, token, feedbackState])

  useEffect(() => {
    let active = true
    setRecommendation(null); setAgentError('')
    api(`/incidents/${incidentId}/recommendation${withoutMemory ? '?without_memory=true' : ''}`,
      { token, method: 'POST' })
      .then((result) => { if (active) setRecommendation(result) })
      .catch(() => { if (active) setAgentError('AI Recommendation unavailable. Use the existing investigation tools.') })
    return () => { active = false }
  }, [incidentId, token, withoutMemory])

  const saveLearning = async () => {
    if (!decision || reason.trim().length < 3 || (decision === 'modified' && !modification.trim()) ||
      (lesson.trim() && lesson.trim().length < 3)) {
      setFeedbackState('Choose a decision and provide a reason (and your modification if applicable).')
      return
    }
    setSaving(true); setFeedbackState('')
    try {
      const result = await api('/memory/learn', { token, method: 'POST', body: {
        incident_id: incidentId, recommendation_id: recommendation?.recommendation_id || undefined,
        decision, reason: reason.trim(), modification: decision === 'modified' ? modification.trim() : undefined,
        outcome: outcome.trim() || undefined,
        lesson: lesson.trim() ? {
          lesson: lesson.trim(), condition: lessonCondition.trim(),
          recommended_behavior: lessonBehavior.trim(),
        } : undefined,
      } })
      setFeedbackState(result.status === 'retained'
        ? 'Analyst decision saved to Hindsight. It can inform future incidents.'
        : 'Decision recorded locally, but Security Memory unavailable. Re-submit after Hindsight recovers.')
      if (result.status === 'retained') {
        setDecision(''); setReason(''); setModification(''); setOutcome('')
        setLesson(''); setLessonCondition(''); setLessonBehavior('')
      }
    } catch (error) { setFeedbackState(`Feedback not saved: ${error.message}`) }
    finally { setSaving(false) }
  }

  const matches = memory?.matches || []
  return <div className="memory-workspace">
    <section className="panel" aria-label="Security Memory">
      <div className="panel-head"><div><p className="eyebrow">INSTITUTIONAL EXPERIENCE · POWERED BY HINDSIGHT</p><h3>Security Memory</h3></div>
        <span>{memory?.status === 'available' ? `${matches.length} related historical incidents` : ''}</span></div>
      {!memory && !memoryError && <p role="status">Recalling historical experience…</p>}
      {(memoryError || memory?.status === 'unavailable') && <div className="component-warning">Security Memory unavailable. Investigation remains available.</div>}
      {memory?.status === 'available' && (matches.length ? <div className="cards-list">{matches.map((item) => {
        const e = item.experience
        const reportedSuccesses = e.analyst_feedback.filter((f) => f.decision === 'accepted' && f.outcome)
          .map((f) => `Analyst-reported: ${f.outcome}`).join('; ')
        return <article key={item.memory_id}><b>{e.incident.title}</b><small>Source incident {item.source_incident_id}</small>
          <p><strong>Worked:</strong> {e.investigation.successful_paths.join('; ') || e.response.successful_actions.map((a) => a.type).join('; ') || reportedSuccesses || 'Not recorded'}</p>
          <p><strong>Failed:</strong> {e.investigation.failed_paths.join('; ') || e.response.failed_actions.map((a) => a.type).join('; ') || 'Not recorded'}</p>
          {e.response.side_effects.length > 0 && <p><strong>Side effects:</strong> {e.response.side_effects.join('; ')}</p>}
          <p><strong>Lesson:</strong> {e.lessons.map((l) => l.lesson).join('; ') || 'Not recorded'}</p>
          {e.analyst_feedback.length > 0 && <p><strong>Analyst decisions:</strong> {e.analyst_feedback.map((f) => `${f.decision}: ${f.reason}`).join('; ')}</p>}
        </article>
      })}</div> : <p>{EMPTY}</p>)}
      {experienceError && <p role="status">{experienceError}</p>}
      {experience?.status === 'recorded' && <article className="current-experience">
        <h4>This incident’s recorded experience <small>· current case, not recalled history</small></h4>
        <p>Hindsight retain: <strong>{experience.provider_status}</strong>
          {experience.provider_status !== 'retained' && ' · not available as historical memory until retained'}</p>
        <p><strong>Reported outcome:</strong> {experience.experience.incident.outcome || 'Not recorded'}</p>
        <p><strong>Failed investigation path:</strong> {experience.experience.investigation.failed_paths.join('; ') || 'Not recorded'}</p>
        <p><strong>Reported side effects:</strong> {experience.experience.response.side_effects.join('; ') || 'Not recorded'}</p>
        <p><strong>Lessons:</strong> {experience.experience.lessons.map((item) => item.lesson).join('; ') || 'Not recorded'}</p>
      </article>}
    </section>
    <section className="panel" aria-label="AI Recommendation">
      <div className="panel-head"><div><p className="eyebrow">INVESTIGATION ONLY · HUMAN CONTROL</p><h3>AI Recommendation</h3></div>
        <label><input type="checkbox" checked={withoutMemory} onChange={(event) => setWithoutMemory(event.target.checked)} /> Without memory comparison</label></div>
      {!recommendation && !agentError && <p role="status">Analyzing current incident and recalled experience…</p>}
      {(agentError || recommendation?.status === 'unavailable') && <div className="component-warning">
        {agentError || recommendation?.error || 'AI Recommendation unavailable'}. Continue with existing incident tools.</div>}
      {recommendation?.status === 'ready' && <>
        <p>{withoutMemory ? 'Current evidence only · memory bypassed' : `Memory: ${recommendation.memory_status}`}</p>
        {recommendation.memory_note && <p>{recommendation.memory_note}</p>}
        <ol>{recommendation.steps.map((step, index) => <li key={index}>{step}</li>)}</ol>
        <p>Confidence: {Math.round(recommendation.confidence * 100)}%</p>
        <details><summary>Why? · reasoning &amp; historical citations</summary>
          <p>{recommendation.reasoning}</p>
          {recommendation.conflict_reasoning && <p><strong>Conflicting experience:</strong> {recommendation.conflict_reasoning}</p>}
          {recommendation.historical_evidence.map((item) => <article key={item.memory_id}>
            <strong>{item.title}</strong> · source incident <code>{item.source_incident_id}</code>
            <p>Lessons: {item.lessons.map((l) => l.lesson).join('; ') || 'None recorded'}</p>
          </article>)}
          <p><strong>Next steps:</strong> {recommendation.suggested_next_steps.join('; ')}</p>
        </details>
        <p>{recommendation.advisory}</p>
        <div className="action-list">{['accepted', 'modified', 'rejected'].map((value) => <button
          key={value} type="button" aria-pressed={decision === value} onClick={() => setDecision(value)}>
          {value === 'accepted' ? 'Accept' : value === 'modified' ? 'Modify' : 'Reject'}</button>)}</div>
      </>}
    </section>
    <section className="panel" aria-label="Analyst Feedback">
      <p className="eyebrow">CLOSE THE LEARNING LOOP</p><h3>Analyst Feedback</h3>
      <p>Decision: {decision || 'Choose Accept, Modify or Reject above.'}</p>
      <label>Reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={2000} /></label>
      {decision === 'modified' && <label>What would you change?<textarea value={modification} onChange={(event) => setModification(event.target.value)} maxLength={2000} /></label>}
      <label>Observed outcome (optional, analyst-reported; not automatically verified)<textarea value={outcome} onChange={(event) => setOutcome(event.target.value)} maxLength={2000} /></label>
      <label>Lesson learned (optional)<textarea value={lesson} onChange={(event) => setLesson(event.target.value)} maxLength={1000} /></label>
      {lesson.trim() && <>
        <label>When does this lesson apply?<input value={lessonCondition} onChange={(event) => setLessonCondition(event.target.value)} maxLength={1000} /></label>
        <label>Recommended behavior<input value={lessonBehavior} onChange={(event) => setLessonBehavior(event.target.value)} maxLength={1000} /></label>
      </>}
      <button className="primary" type="button" disabled={saving || !decision} onClick={saveLearning}>{saving ? 'Saving…' : 'Save Learning'}</button>
      {feedbackState && <p role="status">{feedbackState}</p>}
      {experience?.experience?.analyst_feedback?.length > 0 && <div className="feedback-history">
        <h4>Recorded decisions for this incident</h4>
        {experience.experience.analyst_feedback.map((item, index) => <article key={`${item.recommendation_id || 'manual'}-${index}`}>
          <strong>{item.decision}</strong> · {item.reason}
          {item.modification && <p>Modification: {item.modification}</p>}
          {item.outcome && <p>Analyst-reported outcome: {item.outcome}</p>}
          {item.lesson && <p>Lesson: {item.lesson.lesson}</p>}
        </article>)}
      </div>}
      <p>To request a response action, use the existing Response &amp; audit tab. Approval requirements are unchanged.</p>
    </section>
  </div>
}
