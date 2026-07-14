import { useEffect, useState } from 'react'
import {
  getInstalledCert, getSecretStatus, getSettings, getTlsStatus, ldapTest,
  updateSettings, uploadCert,
} from '../api.js'

function certBadge(info) {
  if (info.expired) return <div className="drift-banner bad">⚠ SÜRESİ DOLMUŞ</div>
  if (info.expiring_soon) return <div className="drift-banner bad">⚠ {info.days_remaining} gün içinde doluyor</div>
  return <div className="drift-banner ok">✓ Geçerli · {info.days_remaining} gün kaldı</div>
}

function CertUploadCard() {
  const [installed, setInstalled] = useState(null)
  const [cert, setCert] = useState('')
  const [key, setKey] = useState('')
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => getInstalledCert().then(setInstalled).catch(() => setInstalled(null))
  useEffect(() => { load() }, [])

  const readFile = (setter) => (e) => {
    const f = e.target.files?.[0]
    if (!f) return
    const r = new FileReader()
    r.onload = () => setter(r.result)
    r.readAsText(f)
  }

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setError(null); setMsg(null)
    try {
      const info = await uploadCert(cert, key)
      setMsg(`Sertifika yüklendi · ${info.days_remaining} gün geçerli. Web sunucu (Caddy) `
        + 'dosya değişince otomatik yeniler.')
      setCert(''); setKey(''); load()
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="card">
      <h3>Web Sunucu TLS Sertifikası (GUI erişimi)</h3>
      <p className="hint">GUI'ye HTTPS erişiminde kullanılan sertifikayı yükleyin/güncelleyin.
        Backend doğrular (anahtar-sertifika eşleşmesi, süre) ve reverse-proxy'ye yazar; özel
        anahtar asla geri döndürülmez. (docker-compose.tls.yml + Caddyfile.uploaded gerekir.)</p>
      {installed?.installed && !installed.error && (
        <div style={{ marginBottom: 12 }}>
          {certBadge(installed)}
          <div className="hint" style={{ marginTop: 6 }}>
            Kurulu · Konu: {installed.subject} · Veren: {installed.issuer}
            {installed.self_signed ? ' (self-signed)' : ''} · Bitiş:
            {' '}{new Date(installed.not_after).toLocaleString('tr-TR')}
          </div>
        </div>
      )}
      {installed && !installed.installed &&
        <div className="hint" style={{ marginBottom: 10 }}>Henüz yüklenmiş sertifika yok.</div>}
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <form onSubmit={submit}>
        <label className="hint">Sertifika (PEM, fullchain önerilir)
          <input type="file" accept=".pem,.crt,.cer" onChange={readFile(setCert)} />
        </label>
        <textarea rows={4} placeholder="-----BEGIN CERTIFICATE----- …" value={cert}
          onChange={(e) => setCert(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
        <label className="hint">Özel anahtar (PEM)
          <input type="file" accept=".pem,.key" onChange={readFile(setKey)} />
        </label>
        <textarea rows={4} placeholder="-----BEGIN PRIVATE KEY----- …" value={key}
          onChange={(e) => setKey(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
        <div className="actions">
          <button disabled={busy || !cert || !key}>{busy ? 'Yükleniyor…' : 'Sertifikayı Yükle'}</button>
        </div>
      </form>
    </div>
  )
}

function SecretStatusCard() {
  const [st, setSt] = useState(null)
  useEffect(() => { getSecretStatus().then(setSt).catch(() => setSt({ error: true })) }, [])
  if (!st) return null
  return (
    <div className="card">
      <h3>Secret Kaynağı (Vault / env)</h3>
      <p className="hint">Bootstrap secret'ları: {st.vault_enabled
        ? (st.vault_reachable ? 'Vault aktif ve erişilebilir.' : 'Vault yapılandırılmış ama erişilemiyor!')
        : 'Vault kapalı — env kullanılıyor.'}</p>
      {st.error && <div className="error">Vault: {st.error}</div>}
      <table className="flat">
        <thead><tr><th>Secret</th><th>Durum</th><th>Kaynak</th></tr></thead>
        <tbody>
          {(st.secrets || []).map((s) => (
            <tr key={s.name}>
              <td><code>{s.name}</code></td>
              <td>{s.is_set
                ? <span className="badge risk-ok">ayarlı</span>
                : <span className="badge risk-bad">eksik</span>}</td>
              <td><span className={`src-tag src-${s.source === 'vault' ? 'db' : s.source === 'env' ? 'env' : 'default'}`}>
                {s.source}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TlsStatusCard() {
  const [host, setHost] = useState('')
  const [st, setSt] = useState(null)
  const [error, setError] = useState(null)
  const check = async () => {
    setError(null); setSt(null)
    try { setSt(await getTlsStatus(host || undefined)) }
    catch (e) { setError(e.message) }
  }
  return (
    <div className="card">
      <h3>TLS Sertifika Durumu</h3>
      <p className="hint">Platform (ya da verilen host) TLS sertifikasını canlı okur.
        Boş bırakırsan NABS_DOMAIN kullanılır.</p>
      <div className="inline-form">
        <input placeholder="host (örn. nabs.sirket.local)" value={host}
          onChange={(e) => setHost(e.target.value)} />
        <button onClick={check}>Kontrol Et</button>
      </div>
      {error && <div className="error">{error}</div>}
      {st && !st.reachable && <div className="error">Erişilemedi: {st.error}</div>}
      {st && st.reachable && !st.error && (
        <div className={`drift-banner ${st.expired ? 'bad' : st.expiring_soon ? 'bad' : 'ok'}`}
          style={{ marginTop: 10 }}>
          {st.expired ? '⚠ SÜRESİ DOLMUŞ' : st.expiring_soon
            ? `⚠ ${st.days_remaining} gün içinde doluyor` : `✓ Geçerli · ${st.days_remaining} gün kaldı`}
          <div className="hint" style={{ marginTop: 6 }}>
            Konu: {st.subject}<br />Veren: {st.issuer}
            {st.self_signed ? ' (self-signed)' : ''}<br />
            Bitiş: {new Date(st.not_after).toLocaleString('tr-TR')}
            {st.san?.length ? ` · SAN: ${st.san.join(', ')}` : ''}
          </div>
        </div>
      )}
    </div>
  )
}

function LdapTestCard() {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [res, setRes] = useState(null)
  const [error, setError] = useState(null)
  const test = async () => {
    setError(null); setRes(null)
    try { setRes(await ldapTest(u, p)) } catch (e) { setError(e.message) }
  }
  return (
    <div className="card">
      <h3>LDAP Bağlantı Testi</h3>
      <p className="hint">Ayarlar → LDAP altındaki yapılandırmayı test eder. Kullanıcı/parola
        verirsen bind denenir; boşsa yalnızca sunucu erişimi kontrol edilir.</p>
      <div className="inline-form">
        <input placeholder="test kullanıcı (opsiyonel)" value={u} onChange={(e) => setU(e.target.value)} />
        <input type="password" placeholder="parola (opsiyonel)" value={p}
          onChange={(e) => setP(e.target.value)} />
        <button onClick={test}>Test Et</button>
      </div>
      {error && <div className="error">{error}</div>}
      {res && <div className={res.ok ? 'info' : 'error'}>{res.ok ? '✓ ' : '✗ '}{res.reason}</div>}
    </div>
  )
}

export default function Settings() {
  const [items, setItems] = useState([])
  const [edits, setEdits] = useState({})
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => getSettings()
    .then((r) => { setItems(r.settings); setEdits({}) })
    .catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const setVal = (key, v) => setEdits({ ...edits, [key]: v })

  const save = async () => {
    if (Object.keys(edits).length === 0) return
    setBusy(true); setError(null); setMsg(null)
    try {
      const res = await updateSettings(edits)
      setMsg(`${res.changed} ayar güncellendi.`); load()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  const groups = [...new Set(items.map((s) => s.group))]

  const field = (s) => {
    const editing = s.key in edits
    const val = editing ? edits[s.key] : (s.secret ? '' : (s.value ?? ''))
    if (s.type === 'enum') {
      return (
        <select value={editing ? edits[s.key] : (s.value ?? '')}
          onChange={(e) => setVal(s.key, e.target.value)}>
          {s.options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      )
    }
    return (
      <input type={s.secret ? 'password' : (s.type === 'int' ? 'number' : 'text')}
        value={val}
        placeholder={s.secret ? (s.is_set ? '•••••• (ayarlı — değiştirmek için yazın)' : 'ayarlı değil') : ''}
        onChange={(e) => setVal(s.key, e.target.value)} />
    )
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Ayarlar</h2>
          <span className="hint">Operasyonel ayarlar. Master key, JWT ve DB parolası gibi
            bootstrap secret'ları güvenlik gereği burada YÖNETİLMEZ (env/Vault).</span>
        </div>
        <div className="actions">
          <button disabled={busy || Object.keys(edits).length === 0} onClick={save}>
            {busy ? 'Kaydediliyor…' : `Kaydet${Object.keys(edits).length ? ` (${Object.keys(edits).length})` : ''}`}
          </button>
          <button className="secondary" onClick={load}>Sıfırla</button>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}

      {groups.map((g) => (
        <div key={g} className="card">
          <h3>{g}</h3>
          <div className="settings-grid">
            {items.filter((s) => s.group === g).map((s) => (
              <div key={s.key} className="setting-row">
                <div className="setting-label">
                  {s.label}
                  <span className={`src-tag src-${s.source}`}>{s.source}</span>
                  {s.help && <div className="setting-help">{s.help}</div>}
                </div>
                {field(s)}
              </div>
            ))}
          </div>
        </div>
      ))}
      <p className="hint">Kaynak etiketi: <b>db</b> = admin override, <b>env</b> = ortam değişkeni,
        <b> default</b> = varsayılan. Bir alanı boşaltıp kaydedersek override silinir (env/default'a döner).</p>

      <h2 style={{ marginTop: 28 }}>Sistem Durumu & Testler</h2>
      <SecretStatusCard />
      <CertUploadCard />
      <TlsStatusCard />
      <LdapTestCard />
    </div>
  )
}
