import { useEffect, useState } from 'react'
import { createApiKey, getApiKeys, revokeApiKey } from '../api.js'

const API_BASE = `${window.location.origin}/api/v1`

export default function Integrations() {
  const [keys, setKeys] = useState([])
  const [name, setName] = useState('')
  const [role, setRole] = useState('viewer')
  const [created, setCreated] = useState(null)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  const load = () => getApiKeys().then(setKeys).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault(); setError(null); setCreated(null)
    try {
      const res = await createApiKey(name, role)
      setCreated(res); setName(''); load()
    } catch (err) { setError(err.message) }
  }

  const revoke = async (k) => {
    if (!confirm(`'${k.name}' anahtarı iptal edilsin mi? Bu anahtarı kullanan entegrasyonlar çalışmayı durdurur.`)) return
    try { await revokeApiKey(k.id); load() } catch (e) { setError(e.message) }
  }

  const copy = (text) => {
    navigator.clipboard?.writeText(text)
    setCopied(true); setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div>
      <div className="page-head"><h2>Entegrasyonlar & API</h2></div>
      <p className="hint">Harici sistemler (SIEM, otomasyon, CMDB) NABS-GP API'sini
        bir API anahtarıyla kullanabilir. Anahtar, isteklerde <code>X-API-Key</code>
        başlığında gönderilir ve seçtiğiniz rolün yetkileriyle sınırlıdır.</p>

      <div className="card">
        <h3>Yeni API Anahtarı</h3>
        {error && <div className="error">{error}</div>}
        <form onSubmit={submit} className="inline-form">
          <input placeholder="Ad (örn. Splunk entegrasyonu)" value={name}
            onChange={(e) => setName(e.target.value)} required />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {['viewer', 'operator', 'approver', 'admin'].map((r) =>
              <option key={r} value={r}>{r}</option>)}
          </select>
          <button>Oluştur</button>
        </form>
        {created && (
          <div className="info key-reveal">
            <strong>Anahtar oluşturuldu — yalnızca şimdi görünür:</strong>
            <div className="key-box">
              <code>{created.api_key}</code>
              <button className="secondary" onClick={() => copy(created.api_key)}>
                {copied ? 'Kopyalandı ✓' : 'Kopyala'}</button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Mevcut Anahtarlar</h3>
        <table className="flat">
          <thead><tr><th>Ad</th><th>Önek</th><th>Rol</th><th>Durum</th>
            <th>Son kullanım</th><th></th></tr></thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id} style={{ opacity: k.is_active ? 1 : 0.5 }}>
                <td>{k.name}</td>
                <td><code>{k.prefix}…</code></td>
                <td>{k.role}</td>
                <td>{k.is_active
                  ? <span className="badge risk-ok">aktif</span>
                  : <span className="badge risk-bad">iptal</span>}</td>
                <td className="muted">{k.last_used_at
                  ? new Date(k.last_used_at).toLocaleString('tr-TR') : 'hiç'}</td>
                <td>{k.is_active &&
                  <button className="danger" onClick={() => revoke(k)}>İptal</button>}</td>
              </tr>
            ))}
            {keys.length === 0 &&
              <tr><td colSpan="6" className="empty">Henüz API anahtarı yok.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Hızlı Başlangıç</h3>
        <p className="hint">Örnek: cihaz envanterini API anahtarıyla çekme.</p>
        <pre className="code-sample">{`curl -H "X-API-Key: <ANAHTAR>" \\
  ${API_BASE}/assets`}</pre>
        <p className="hint">Etkileşimli API dokümanı (OpenAPI): <a href="/api/docs"
          target="_blank" rel="noreferrer">/api/docs</a> · Şema: <a href="/api/openapi.json"
          target="_blank" rel="noreferrer">/api/openapi.json</a></p>
      </div>
    </div>
  )
}
