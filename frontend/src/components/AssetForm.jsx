import { useEffect, useState } from 'react'
import { createAsset, getCredentials, hasRole } from '../api.js'

const VENDORS = [
  ['cisco_ios', 'Cisco IOS/IOS-XE'],
  ['fortinet', 'Fortinet FortiGate'],
  ['fortiswitch', 'Fortinet FortiSwitch'],
  ['paloalto', 'Palo Alto PAN-OS'],
  ['juniper_junos', 'Juniper Junos'],
  ['huawei_vrp', 'Huawei VRP'],
  ['aruba_aoscx', 'Aruba OS-CX'],
  ['aruba_procurve', 'Aruba/HP ProCurve'],
  ['mikrotik', 'MikroTik RouterOS'],
  ['openwrt', 'OpenWrt (Linux/UCI)'],
  ['linux', 'Genel Linux'],
]
const METHODS = ['ACTIVE_SSH', 'ACTIVE_API', 'PASSIVE_SFTP', 'PASSIVE_TFTP']
const EMPTY = {
  hostname: '', ip_address: '', vendor: 'cisco_ios', model: '', os_version: '',
  serial_number: '', backup_method: 'ACTIVE_SSH', credential_id: '',
  cron_schedule: '0 2 * * *',
}

export default function AssetForm({ onCreated, onCancel }) {
  const [form, setForm] = useState(EMPTY)
  const [credentials, setCredentials] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (hasRole('operator')) getCredentials().then(setCredentials).catch(() => {})
  }, [])

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value })

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      const payload = { ...form }
      for (const k of ['model', 'os_version', 'serial_number', 'credential_id'])
        if (!payload[k]) delete payload[k]
      await createAsset(payload)
      onCreated()
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return (
    <form className="panel-form" onSubmit={submit}>
      <h3>Yeni Varlık</h3>
      {error && <div className="error">{error}</div>}
      <div className="form-grid">
        <label>Hostname*<input required value={form.hostname} onChange={set('hostname')} /></label>
        <label>IP adresi*<input required value={form.ip_address} onChange={set('ip_address')}
          placeholder="10.1.1.1" /></label>
        <label>Vendor*<select value={form.vendor} onChange={set('vendor')}>
          {VENDORS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label>Yedekleme yöntemi*<select value={form.backup_method} onChange={set('backup_method')}>
          {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}</select></label>
        <label>Model<input value={form.model} onChange={set('model')} /></label>
        <label>OS sürümü<input value={form.os_version} onChange={set('os_version')}
          placeholder="17.6.4 (CVE eşleme için)" /></label>
        <label>Seri no<input value={form.serial_number} onChange={set('serial_number')} /></label>
        <label>Cron zamanlaması<input value={form.cron_schedule} onChange={set('cron_schedule')} /></label>
        <label>Kimlik bilgisi
          <select value={form.credential_id} onChange={set('credential_id')}>
            <option value="">— seçilmedi —</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>{c.name} ({c.username})</option>
            ))}
          </select>
        </label>
      </div>
      <div className="actions">
        <button disabled={busy}>{busy ? 'Ekleniyor…' : 'Varlığı Ekle'}</button>
        <button type="button" className="secondary" onClick={onCancel}>Vazgeç</button>
      </div>
    </form>
  )
}
