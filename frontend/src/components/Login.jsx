import { useState } from 'react'
import { login } from '../api.js'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [showOtp, setShowOtp] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try { await login(username, password, otp || undefined); onLogin() }
    catch (err) {
      if (err.mfaRequired) setShowOtp(true)
      setError(err.message)
    }
    finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="logo-mark">N</div>
        <h1>NABS-GP</h1>
        <p>Ağ Varlık, Yedekleme ve Güvenlik Yönetim Platformu</p>
        <input placeholder="Kullanıcı adı" value={username}
          onChange={(e) => setUsername(e.target.value)} autoFocus />
        <input type="password" placeholder="Parola" value={password}
          onChange={(e) => setPassword(e.target.value)} />
        {showOtp && <input placeholder="MFA kodu (6 haneli)" value={otp} maxLength={6}
          inputMode="numeric" onChange={(e) => setOtp(e.target.value)} autoFocus />}
        {error && <div className="error">{error}</div>}
        <button disabled={busy || !username || !password}>
          {busy ? 'Giriş yapılıyor…' : 'Giriş Yap'}
        </button>
      </form>
    </div>
  )
}
