const API_ROOT = '/api/v1'

export async function api(path, { token, method = 'GET', body } = {}) {
  const headers = { 'X-Correlation-ID': crypto.randomUUID() }
  // Arena's browser preview proxy may reserve/strip Authorization; the API also
  // accepts this same-origin dashboard JWT header while retaining Bearer support.
  if (token) headers['X-GhostSOC-Token'] = token
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const response = await fetch(`${API_ROOT}${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('application/json') ? await response.json() : await response.text()
  if (!response.ok) {
    const message = payload?.error?.message || payload?.detail || `Request failed (${response.status})`
    throw new Error(message)
  }
  return payload
}

export async function login(email, password) {
  return api('/auth/login', { method: 'POST', body: { email, password } })
}
