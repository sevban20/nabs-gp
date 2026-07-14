// Minimal API client. Token kept in memory (not localStorage) by design.
let _token = null

export function setToken(t) { _token = t }
export function isAuthenticated() { return !!_token }

// Faz 6: rol-duyarlı arayüz — JWT payload'ından rol okunur (yalnızca UI
// ipucu; asıl yetki kontrolü her zaman API tarafında).
const ROLE_LEVEL = { viewer: 0, operator: 1, approver: 2, admin: 3 }
export function getRole() {
  if (!_token) return 'viewer'
  try {
    return JSON.parse(atob(_token.split('.')[1])).role || 'viewer'
  } catch { return 'viewer' }
}
export function hasRole(minimum) {
  return (ROLE_LEVEL[getRole()] ?? 0) >= (ROLE_LEVEL[minimum] ?? 99)
}

const json = (body) => ({
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const res = await fetch(`/api/v1${path}`, { ...options, headers })
  if (res.status === 401) { _token = null; throw new Error('Oturum süresi doldu, tekrar giriş yapın.') }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `HTTP ${res.status}`)
  }
  return res.status === 204 ? null : res.json()
}

export async function login(username, password, otp) {
  const params = { username, password }
  if (otp) params.otp = otp
  const res = await fetch('/api/v1/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  })
  if (!res.ok) throw new Error('Kullanıcı adı veya parola hatalı.')
  const data = await res.json()
  _token = data.access_token
  return data
}

export const getAssets = (opts = {}) => {
  const p = new URLSearchParams()
  if (opts.q) p.set('q', opts.q)
  if (opts.status && opts.status !== 'all') p.set('status', opts.status)
  if (opts.limit) p.set('limit', opts.limit)
  if (opts.offset) p.set('offset', opts.offset)
  const qs = p.toString()
  return request(`/assets${qs ? `?${qs}` : ''}`)
}
// Faz 6: tam CRUD ve yönetim uçları
export const createAsset = (data) => request('/assets', { method: 'POST', ...json(data) })
export const deleteAsset = (id) => request(`/assets/${id}`, { method: 'DELETE' })
export const getBackupHistory = (assetId) => request(`/assets/${assetId}/backups`)
export const getCredentials = () => request('/credentials')
export const createCredential = (data) => request('/credentials', { method: 'POST', ...json(data) })
export const deleteCredential = (id) => request(`/credentials/${id}`, { method: 'DELETE' })
export const createUser = (data) => request('/auth/users', { method: 'POST', ...json(data) })
export const getUsers = () => request('/users')
export const patchUser = (id, data) => request(`/users/${id}`, { method: 'PATCH', ...json(data) })
export const resetUserPassword = (id, newPassword) =>
  request(`/users/${id}/reset-password`, { method: 'POST', ...json({ new_password: newPassword }) })
export const deleteUser = (id) => request(`/users/${id}`, { method: 'DELETE' })
export const getSecretStatus = () => request('/system/secret-status')
export const getTlsStatus = (host, port) =>
  request(`/system/tls-status${host ? `?host=${encodeURIComponent(host)}${port ? `&port=${port}` : ''}` : ''}`)
export const ldapTest = (username, password) =>
  request('/system/ldap-test', { method: 'POST', ...json({ username: username || null, password: password || null }) })
export const getInstalledCert = () => request('/system/tls-certificate')
export const uploadCert = (certificate, privateKey) =>
  request('/system/tls-certificate', { method: 'POST', ...json({ certificate, private_key: privateKey }) })
export const enrollMfa = () => request('/auth/mfa/enroll', { method: 'POST' })
export const silenceAdvisory = (id) => request(`/advisories/${id}/silence`, { method: 'POST' })
export const createRemediation = (data) => request('/remediations', { method: 'POST', ...json(data) })
export const generateRemediation = (advisoryId) =>
  request(`/ai/advisories/${advisoryId}/generate-remediation`, { method: 'POST' })
export const indexBenchmark = (source, text) =>
  request('/ai/index-benchmark', { method: 'POST', ...json({ source, text }) })
export const getDashboardSummary = () => request('/dashboard/summary')
export const getRecentJobs = (status) =>
  request(`/jobs/recent${status ? `?status=${status}` : ''}`)
export const getJobCounts = () => request('/jobs/counts')
export const getSettings = () => request('/settings')
export const updateSettings = (values) => request('/settings', { method: 'PUT', ...json({ values }) })
export const getApiKeys = () => request('/apikeys')
export const createApiKey = (name, role) => request('/apikeys', { method: 'POST', ...json({ name, role }) })
export const revokeApiKey = (id) => request(`/apikeys/${id}`, { method: 'DELETE' })
export const getAdvisories = (assetId) =>
  request(`/advisories${assetId ? `?asset_id=${assetId}` : ''}`)
export const getRemediations = () => request('/remediations')
export const transitionRemediation = (id, status) =>
  request(`/remediations/${id}/transition?new_status=${status}`, { method: 'POST' })
export const resolveAdvisory = (id) => request(`/advisories/${id}/resolve`, { method: 'POST' })
export const triggerBackup = (assetId) => request(`/assets/${assetId}/backup`, { method: 'POST' })
export const getConfigHistory = (assetId) => request(`/assets/${assetId}/config/history`)
export const getConfigDiff = (assetId, a, b) =>
  request(`/assets/${assetId}/config/diff?commit_a=${a}&commit_b=${b}`)
export const getConfigContent = (assetId, commit) =>
  request(`/assets/${assetId}/config/content${commit ? `?commit=${commit}` : ''}`)

export function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
export const startDiscovery = (cidr, community) =>
  request('/discovery/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cidr, snmp_community: community || 'public' }),
  })
export const getDiscoveryResults = (taskId) => request(`/discovery/results/${taskId}`)
export const setBaseline = (assetId, note) =>
  request(`/assets/${assetId}/baseline`, { method: 'POST', ...json({ note: note || null }) })
export const getDrift = (assetId) => request(`/assets/${assetId}/drift`)
export const getFleetDrift = () => request('/compliance/drift')
export const triggerSweep = () => request('/compliance/sweep', { method: 'POST' })
export const getTopologyGraph = (includeEndpoints) =>
  request(`/topology/graph${includeEndpoints ? '?include_endpoints=true' : ''}`)
export const collectTopology = (assetId) =>
  request(`/topology/collect/${assetId}`, { method: 'POST' })
export const collectL2 = (assetId) => request(`/assets/${assetId}/collect-l2`, { method: 'POST' })
export const getDiscoveredHosts = (q) =>
  request(`/discovery/hosts?only_unmanaged=true${q ? `&q=${encodeURIComponent(q)}` : ''}`)
export const sshProbe = (ipAddress, credentialId) =>
  request('/discovery/ssh-probe', { method: 'POST', ...json({ ip_address: ipAddress, credential_id: credentialId }) })
export const onboardHost = (hostId, data) =>
  request(`/discovery/hosts/${hostId}/onboard`, { method: 'POST', ...json(data) })
export const getAiStatus = () => request('/ai/status')
export const chatWithNetwork = (question) =>
  request('/ai/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  })
export const summarizeChange = (assetId, a, b) =>
  request(`/ai/assets/${assetId}/summarize-change?commit_a=${a}&commit_b=${b}`)

export async function downloadRiskReport() {
  const res = await fetch('/api/v1/reports/risk.pdf', {
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  })
  if (!res.ok) throw new Error(`Rapor alınamadı (HTTP ${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'nabs-risk-report.pdf'
  link.click()
  URL.revokeObjectURL(url)
}
