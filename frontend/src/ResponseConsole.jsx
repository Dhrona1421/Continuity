import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api.js'

function ResponseState({ action, Badge }) {
  const execution = action.execution_status
  const result = action.execution_result || {}
  const states = [
    ['Requested', true, 'Request recorded'],
    ['Policy', true, action.approval_required ? 'Approval policy applied' : 'Pre-approved'],
    ['Approval', action.approval_status !== 'PENDING', action.approval_status],
    ['Execution', !['PENDING', 'RUNNING'].includes(execution), execution],
    ['Verification', execution === 'SUCCESS' || execution === 'DRY_RUN', result.verified ? 'VERIFIED' : execution],
  ]
  return <div className="response-state-line">{states.map(([label, complete, value], index) => <div key={label} className={complete ? execution === 'DRY_RUN' && index >= 3 ? 'simulated' : 'complete' : ''}><i /><span>{label}</span><b>{value}</b></div>)}</div>
}

function ActionHistory({ actions, Badge }) {
  if (!actions.length) return <div className="empty"><b>NO RESPONSE ACTIONS</b><p>No policy-controlled action has been requested.</p></div>
  return <div className="response-history">{actions.map((action) => <article key={action.id}><header><div><Badge>{action.execution_status}</Badge><b>{action.action_type.replaceAll('_', ' ')}</b></div><time>{new Date(action.requested_at).toLocaleString()}</time></header><dl><div><dt>Target</dt><dd>{action.target}</dd></div><div><dt>Approval</dt><dd>{action.approval_status}</dd></div><div><dt>Mode</dt><dd>{action.dry_run ? 'SIMULATED' : 'REAL ADAPTER'}</dd></div><div><dt>Requested by</dt><dd>{action.requested_by.slice(0, 8)}</dd></div></dl><ResponseState action={action} Badge={Badge} />{action.execution_result && <p className={action.dry_run ? 'simulation-result' : action.execution_status === 'SUCCESS' ? 'verified-result' : 'failed-result'}>{action.execution_result.message || action.execution_result.error || JSON.stringify(action.execution_result)}</p>}</article>)}</div>
}

export default function ResponseConsole({ incident, token, onRefresh, Badge }) {
  const [context, setContext] = useState(null)
  const [selectedType, setSelectedType] = useState('')
  const [target, setTarget] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [working, setWorking] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [reasons, setReasons] = useState({})

  const load = useCallback(async () => {
    try {
      const data = await api(`/incidents/${incident.id}/response-context`, { token })
      setContext(data); setError('')
      const first = data.actions.find((item) => item.enabled)
      setSelectedType((current) => current && data.actions.some((item) => item.action_type === current && item.enabled) ? current : first?.action_type || '')
    } catch (err) { setError(`Response context: ${err.message}`) }
  }, [incident.id, token])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    const stream = new EventSource('/api/v1/live/stream', { withCredentials: true })
    const update = (event) => { const message = JSON.parse(event.data); if (message.data.incident_id === incident.id) { load(); onRefresh() } }
    stream.addEventListener('response', update)
    return () => stream.close()
  }, [incident.id, load, onRefresh])

  const selected = useMemo(() => context?.actions.find((item) => item.action_type === selectedType), [context, selectedType])
  useEffect(() => { setTarget(selected?.targets[0]?.value || ''); setConfirmed(false) }, [selected])

  const requestAction = async () => {
    if (!selected || !target || !confirmed) return
    setWorking(true); setError(''); setNotice('')
    try {
      const action = await api('/response-actions', {
        token,
        method: 'POST',
        body: {
          incident_id: incident.id,
          action_type: selected.action_type,
          target,
          idempotency_key: `ui:${incident.id}:${selected.action_type}:${crypto.randomUUID()}`,
          policy_id: context.policy.id,
        },
      })
      setNotice(action.approval_status === 'PENDING' ? 'Response request recorded and awaiting analyst approval.' : `Policy evaluated. Action result: ${action.execution_status}.`)
      setConfirmed(false); await load(); await onRefresh()
    } catch (err) { setError(err.message) } finally { setWorking(false) }
  }
  const decide = async (action, decision) => {
    const reason = (reasons[action.id] || '').trim()
    if (reason.length < 3) { setError('Approval or denial requires a reason of at least three characters.'); return }
    setWorking(true); setError(''); setNotice('')
    try {
      const result = await api(`/response-actions/${action.id}/approval`, { token, method: 'POST', body: { decision, reason } })
      setNotice(`${decision === 'APPROVED' ? 'Approval' : 'Denial'} recorded. Execution state: ${result.execution_status}.`)
      await load(); await onRefresh()
    } catch (err) { setError(err.message) } finally { setWorking(false) }
  }

  if (!context && !error) return <section className="loading-state"><header><span>LOADING</span><b>Evaluating response policy and authorized targets…</b></header><div className="loading-lines"><i /><i /><i /></div></section>
  return <div className="response-console">
    {error && <div className="error-box">{error}</div>}{notice && <div className="success-box">{notice}</div>}
    {context && <><section className="response-policy-bar"><div><p className="eyebrow">ACTIVE POLICY</p><h3>{context.policy.name}</h3><span>Minimum risk: {context.policy.min_risk_level} · Incident risk: {context.incident.risk_level}</span></div><Badge tone={context.mode.toLowerCase()}>{context.mode}</Badge></section>
    <section className="guardrail-grid">{context.guardrails.map((item) => <div key={item.name}><span>{item.name}</span><Badge>{item.status}</Badge><small>{item.detail}</small></div>)}</section>
    <section className="response-request panel"><div className="section-heading"><div><p className="eyebrow">NEW RESPONSE REQUEST</p><h3>Policy-controlled defensive action</h3></div></div><div className="response-form"><label>Action<select value={selectedType} onChange={(event) => setSelectedType(event.target.value)} disabled={!context.permissions.can_request || working}>{context.actions.map((item) => <option key={item.action_type} value={item.action_type} disabled={!item.enabled}>{item.label}{item.enabled ? '' : ' — unavailable'}</option>)}</select></label><label>Validated target<select value={target} onChange={(event) => setTarget(event.target.value)} disabled={!selected?.enabled || working}>{selected?.targets.map((item) => <option key={`${item.type}-${item.value}`} value={item.value}>{item.label} · {item.type}</option>)}</select></label></div>{selected && <div className={`action-assessment impact-${selected.impact.toLowerCase()}`}><div><Badge>{selected.impact} IMPACT</Badge><b>{selected.label}</b><p>{selected.description}</p></div><dl><div><dt>Approval</dt><dd>{selected.approval_required ? 'REQUIRED' : selected.preapproved ? 'PRE-APPROVED' : 'POLICY CONTROLLED'}</dd></div><div><dt>Targets</dt><dd>{selected.targets.length}</dd></div><div><dt>Mode</dt><dd>{context.mode}</dd></div></dl></div>}{selected && !selected.enabled && <div className="component-warning"><b>ACTION UNAVAILABLE</b><span>{selected.disabled_reason}</span></div>}<label className="response-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} disabled={!selected?.enabled || working} /><span>I confirm this typed action and server-validated target. I understand that DRY_RUN makes no external change.</span></label><button className="request-action" onClick={requestAction} disabled={!context.permissions.can_request || !selected?.enabled || !target || !confirmed || working}>{working ? 'Processing policy…' : selected?.approval_required ? 'Request analyst approval' : 'Evaluate and execute policy'}</button><p className="truth-note">{context.truth_note}</p></section>
    {context.response_actions.some((item) => item.approval_status === 'PENDING') && <section className="approval-queue panel"><div className="section-heading"><div><p className="eyebrow">APPROVAL QUEUE</p><h3>Actions requiring a decision</h3></div></div>{context.response_actions.filter((item) => item.approval_status === 'PENDING').map((action) => <article key={action.id}><header><Badge>{action.action_type.replaceAll('_', ' ')}</Badge><b>{action.target}</b><span>Requested {new Date(action.requested_at).toLocaleString()}</span></header><label>Decision reason<textarea value={reasons[action.id] || ''} onChange={(event) => setReasons((current) => ({ ...current, [action.id]: event.target.value }))} placeholder="Document the evidence and reason for this decision" maxLength="500" /></label><div><button className="deny-action" onClick={() => decide(action, 'DENIED')} disabled={!context.permissions.can_approve || working}>Deny</button><button className="approve-action" onClick={() => decide(action, 'APPROVED')} disabled={!context.permissions.can_approve || working}>Approve {context.mode === 'DRY_RUN' ? 'simulation' : 'action'}</button></div></article>)}</section>}
    <section className="panel response-history-panel"><div className="section-heading"><div><p className="eyebrow">RESPONSE HISTORY</p><h3>Execution and verification</h3></div><span>{context.response_actions.length}</span></div><ActionHistory actions={context.response_actions} Badge={Badge} /></section></>}
  </div>
}
