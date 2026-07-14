import { useEffect, useState } from 'react'
import {
  createCredential, createUser, deleteCredential, deleteUser, enrollMfa,
  getCredentials, getUsers, hasRole, indexBenchmark, patchUser, resetUserPassword,
} from '../api.js'

const ROLES = ['viewer', 'operator', 'approver', 'admin']

function Credentials() {
  const [rows, setRows] = useState([])
  const [form, setForm] = useState({ name: '', username: '', password: '', secret: '' })
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)

  const load = () => getCredentials().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const submit = async (e) => {
    e.preventDefault(); setError(null)
    try {
      const payload = { ...form }
      if (!payload.secret) delete payload.secret
      await createCredential(payload)
      setForm({ name: '', username: '', password: '', secret: '' })
      setMsg('Kimlik bilgisi kasaya şifreli olarak eklendi.'); load()
    } catch (err) { setError(err.message) }
  }

  const remove = async (c) => {
    if (!confirm(`'${c.name}' silinsin mi?`)) return
    try { await deleteCredential(c.id); load() } catch (e) { setError(e.message) }
  }

  return (
    <div className="panel-form">
      <h3>Kimlik Bilgisi Kasası</h3>
      <p className="hint">Parolalar AES-256-GCM ile şifrelenir; bir daha görüntülenemez.</p>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <form onSubmit={submit} className="form-grid">
        <label>Ad*<input required value={form.name} onChange={set('name')} /></label>
        <label>Kullanıcı adı*<input required value={form.username} onChange={set('username')} /></label>
        <label>Parola*<input required type="password" value={form.password} onChange={set('password')} /></label>
        <label>Enable secret<input type="password" value={form.secret} onChange={set('secret')} /></label>
        <div className="actions"><button>Ekle</button></div>
      </form>
      <table>
        <thead><tr><th>Ad</th><th>Kullanıcı</th><th>Oluşturulma</th><th></th></tr></thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td><td>{c.username}</td>
              <td>{new Date(c.created_at).toLocaleDateString('tr-TR')}</td>
              <td>{hasRole('admin') &&
                <button className="danger" onClick={() => remove(c)}>Sil</button>}</td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan="4" className="empty">Kayıt yok.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

function Users() {
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const load = () => getUsers().then(setUsers).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault(); setError(null)
    try {
      const res = await createUser(form)
      setMsg(`Kullanıcı '${res.username}' (${res.role}) oluşturuldu.`)
      setForm({ username: '', password: '', role: 'viewer' })
      load()
    } catch (err) { setError(err.message) }
  }

  const changeRole = async (u, role) => {
    try { await patchUser(u.id, { role }); setMsg(`${u.username} → ${role}`); load() }
    catch (e) { setError(e.message) }
  }
  const toggleActive = async (u) => {
    try { await patchUser(u.id, { is_active: !u.is_active }); load() }
    catch (e) { setError(e.message) }
  }
  const resetPw = async (u) => {
    const pw = prompt(`${u.username} için yeni parola (min 8):`)
    if (!pw) return
    try { await resetUserPassword(u.id, pw); setMsg(`${u.username} parolası sıfırlandı.`) }
    catch (e) { setError(e.message) }
  }
  const remove = async (u) => {
    if (!confirm(`${u.username} silinsin mi?`)) return
    try { await deleteUser(u.id); load() } catch (e) { setError(e.message) }
  }

  return (
    <div className="panel-form">
      <h3>Kullanıcı Yönetimi</h3>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <form onSubmit={submit} className="inline-form" style={{ marginBottom: 12 }}>
        <input required minLength={3} placeholder="Kullanıcı adı" value={form.username}
          onChange={set('username')} />
        <input required minLength={8} type="password" placeholder="Parola (min 8)"
          value={form.password} onChange={set('password')} />
        <select value={form.role} onChange={set('role')}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <button>Oluştur</button>
      </form>
      <table>
        <thead><tr><th>Kullanıcı</th><th>Rol</th><th>Durum</th><th>MFA</th><th></th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} style={{ opacity: u.is_active ? 1 : 0.5 }}>
              <td>{u.username}</td>
              <td>
                <select value={u.role} onChange={(e) => changeRole(u, e.target.value)}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </td>
              <td>{u.is_active
                ? <span className="badge risk-ok">aktif</span>
                : <span className="badge risk-bad">pasif</span>}</td>
              <td>{u.mfa_enabled
                ? <span className="badge risk-ok">açık</span>
                : <span className="badge sev-info">kapalı</span>}</td>
              <td className="actions">
                <button className="secondary" onClick={() => toggleActive(u)}>
                  {u.is_active ? 'Pasifleştir' : 'Aktifleştir'}</button>
                <button className="secondary" onClick={() => resetPw(u)}>Parola</button>
                <button className="danger" onClick={() => remove(u)}>Sil</button>
              </td>
            </tr>
          ))}
          {users.length === 0 && <tr><td colSpan="5" className="empty">Kullanıcı yok.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

function Mfa() {
  const [uri, setUri] = useState(null)
  const [error, setError] = useState(null)
  const enroll = async () => {
    if (!confirm('Hesabınızda TOTP MFA etkinleştirilsin mi? Sonraki girişlerde OTP kodu zorunlu olur.')) return
    try { setUri((await enrollMfa()).otpauth_uri) } catch (e) { setError(e.message) }
  }
  return (
    <div className="panel-form">
      <h3>MFA (TOTP)</h3>
      {error && <div className="error">{error}</div>}
      {uri ? (
        <>
          <div className="info">MFA etkinleştirildi. Bu URI'yi authenticator uygulamanıza ekleyin
            (bir daha gösterilmez):</div>
          <pre>{uri}</pre>
        </>
      ) : <button onClick={enroll}>Hesabımda MFA Etkinleştir</button>}
    </div>
  )
}

function Benchmark() {
  const [source, setSource] = useState('')
  const [text, setText] = useState('')
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setError(null); setMsg(null)
    try {
      const res = await indexBenchmark(source, text)
      setMsg(`'${res.source}' indekslendi: ${res.chunks_indexed} chunk.`)
      setSource(''); setText('')
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="panel-form">
      <h3>Benchmark İndeksle (RAG)</h3>
      <p className="hint">CIS benchmark vb. metinleri AI Chat bağlamına ekler.
        Ollama embedding servisi gerektirir.</p>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <form onSubmit={submit}>
        <input placeholder="Kaynak adı (örn. CIS Cisco IOS 17 v2.0)" value={source}
          onChange={(e) => setSource(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
        <textarea rows={6} placeholder="Benchmark metnini yapıştırın…" value={text}
          onChange={(e) => setText(e.target.value)} style={{ width: '100%' }} />
        <div className="actions" style={{ marginTop: 8 }}>
          <button disabled={busy || !source || !text}>{busy ? 'İndeksleniyor…' : 'İndeksle'}</button>
        </div>
      </form>
    </div>
  )
}

export default function Admin() {
  return (
    <section>
      <h2>Yönetim</h2>
      {hasRole('operator') ? <Credentials /> :
        <p className="hint">Kimlik bilgisi kasası için operator rolü gerekir.</p>}
      {hasRole('admin') && <Users />}
      <Mfa />
      {hasRole('operator') && <Benchmark />}
    </section>
  )
}
