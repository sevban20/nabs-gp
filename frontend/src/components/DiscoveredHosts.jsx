import { useEffect, useState } from 'react'
import {
  getCredentials, getDiscoveredHosts, hasRole, onboardHost, sshProbe,
} from '../api.js'

const VENDORS = [
  ['cisco_ios', 'Cisco IOS'], ['fortinet', 'Fortinet'], ['fortiswitch', 'FortiSwitch'],
  ['paloalto', 'Palo Alto'], ['juniper_junos', 'Juniper'], ['huawei_vrp', 'Huawei'],
  ['aruba_aoscx', 'Aruba OS-CX'], ['aruba_procurve', 'Aruba ProCurve'],
  ['mikrotik', 'MikroTik'], ['openwrt', 'OpenWrt'], ['linux', 'Linux'],
]

function OnboardForm({ host, credentials, onDone, onCancel }) {
  const [form, setForm] = useState({
    hostname: '', vendor: 'cisco_ios', backup_method: 'ACTIVE_SSH', credential_id: '',
  })
  const [error, setError] = useState(null)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const submit = async (e) => {
    e.preventDefault(); setError(null)
    try {
      const payload = { ...form }
      if (!payload.credential_id) delete payload.credential_id
      await onboardHost(host.id, payload)
      onDone()
    } catch (err) { setError(err.message) }
  }

  return (
    <form className="panel-form" onSubmit={submit}>
      <h3>Envantere Ekle — {host.ip_address} ({host.oui_vendor})</h3>
      {error && <div className="error">{error}</div>}
      <div className="form-grid">
        <label>Hostname*<input required value={form.hostname} onChange={set('hostname')}
          placeholder="örn. ACCESS-SW-05" /></label>
        <label>Vendor*<select value={form.vendor} onChange={set('vendor')}>
          {VENDORS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label>Yöntem<select value={form.backup_method} onChange={set('backup_method')}>
          {['ACTIVE_SSH', 'ACTIVE_API', 'PASSIVE_SFTP', 'PASSIVE_TFTP'].map((m) =>
            <option key={m} value={m}>{m}</option>)}</select></label>
        <label>Kimlik bilgisi<select value={form.credential_id} onChange={set('credential_id')}>
          <option value="">— seçilmedi —</option>
          {credentials.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select></label>
      </div>
      <div className="actions">
        <button>Ekle</button>
        <button type="button" className="secondary" onClick={onCancel}>Vazgeç</button>
      </div>
    </form>
  )
}

export default function DiscoveredHosts() {
  const [hosts, setHosts] = useState([])
  const [credentials, setCredentials] = useState([])
  const [query, setQuery] = useState('')
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const [onboarding, setOnboarding] = useState(null)
  const [probeCred, setProbeCred] = useState('')

  const load = () => getDiscoveredHosts(query).then(setHosts).catch((e) => setError(e.message))
  useEffect(() => {
    if (hasRole('operator')) getCredentials().then(setCredentials).catch(() => {})
  }, [])
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [query])

  const probe = async (host) => {
    if (!probeCred) { setError('Önce SSH denemesi için bir kimlik bilgisi seçin.'); return }
    setMsg(`${host.ip_address} deneniyor…`); setError(null)
    try {
      const res = await sshProbe(host.ip_address, probeCred)
      setMsg(res.success
        ? `✓ ${host.ip_address}: SSH başarılı (tahmini: ${res.vendor_guess})`
        : `✗ ${host.ip_address}: ${res.reason}`)
    } catch (e) { setMsg(null); setError(e.message) }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Keşfedilen Cihazlar</h2>
          <span className="hint">ARP + MAC tablosu + komşuluktan bulunan, envanterde olmayan
            uç cihazlar. Cihazlar sekmesinde bir switch için "L2 Envanteri Topla" çalıştırın.</span>
        </div>
        <button className="secondary" onClick={load}>Yenile</button>
      </div>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}

      <div className="toolbar">
        <input className="search" placeholder="MAC, IP, üretici veya cihaz ara…"
          value={query} onChange={(e) => setQuery(e.target.value)} />
        {hasRole('operator') && (
          <label className="probe-cred">SSH denemesi kimliği:
            <select value={probeCred} onChange={(e) => setProbeCred(e.target.value)}>
              <option value="">— seç —</option>
              {credentials.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
        )}
      </div>

      {onboarding && <OnboardForm host={onboarding} credentials={credentials}
        onCancel={() => setOnboarding(null)}
        onDone={() => { setOnboarding(null); setMsg('Cihaz envantere eklendi.'); load() }} />}

      <table>
        <thead><tr><th>MAC</th><th>Üretici (OUI)</th><th>IP</th><th>Görüldüğü Cihaz</th>
          <th>Port</th><th>VLAN</th><th>Kaynak</th><th></th></tr></thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td><code>{h.mac}</code></td>
              <td>{h.oui_vendor || 'unknown'}</td>
              <td>{h.ip_address || '—'}</td>
              <td>{h.seen_on_device}</td>
              <td>{h.seen_on_interface || '—'}</td>
              <td>{h.vlan || '—'}</td>
              <td><span className={`badge src-${(h.source || '').toLowerCase()}`}>{h.source}</span></td>
              <td className="actions">
                {hasRole('operator') && h.ip_address &&
                  <button className="secondary" onClick={() => probe(h)}>SSH Dene</button>}
                {hasRole('operator') && h.ip_address &&
                  <button onClick={() => setOnboarding(h)}>Onboard</button>}
              </td>
            </tr>
          ))}
          {hosts.length === 0 &&
            <tr><td colSpan="8" className="empty">Keşfedilen cihaz yok.
              Bir switch'te "L2 Envanteri Topla" çalıştırın.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
