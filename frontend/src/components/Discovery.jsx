import { useEffect, useRef, useState } from 'react'
import { getDiscoveryResults, startDiscovery } from '../api.js'
import DiscoveredHosts from './DiscoveredHosts.jsx'

export default function Discovery() {
  const [cidr, setCidr] = useState('')
  const [community, setCommunity] = useState('public')
  const [taskId, setTaskId] = useState(null)
  const [state, setState] = useState(null)
  const [hosts, setHosts] = useState(null)
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const scan = async () => {
    setError(null); setHosts(null)
    try {
      const res = await startDiscovery(cidr, community)
      setTaskId(res.task_id); setState('PENDING')
    } catch (e) { setError(e.message) }
  }

  useEffect(() => {
    if (!taskId) return
    timer.current = setInterval(async () => {
      try {
        const res = await getDiscoveryResults(taskId)
        setState(res.state)
        if (res.state === 'SUCCESS') { setHosts(res.hosts); clearInterval(timer.current) }
        if (res.state === 'FAILURE') { setError('Tarama başarısız.'); clearInterval(timer.current) }
      } catch (e) { setError(e.message); clearInterval(timer.current) }
    }, 3000)
    return () => clearInterval(timer.current)
  }, [taskId])

  return (
    <section>
      <h2>Ağ Keşfi</h2>
      <p className="hint">TCP erişilebilirlik probu (22/443/8443) + SNMP sysDescr kimliklendirme.
        Celery worker'ının çalışıyor olması gerekir.</p>
      <div className="actions" style={{ gap: 8 }}>
        <input placeholder="CIDR (örn. 10.1.0.0/24)" value={cidr}
          onChange={(e) => setCidr(e.target.value)} />
        <input placeholder="SNMP community" value={community}
          onChange={(e) => setCommunity(e.target.value)} />
        <button disabled={!cidr} onClick={scan}>Taramayı Başlat</button>
      </div>
      {error && <div className="error">{error}</div>}
      {state && !hosts && !error && <p className="hint">Durum: {state}…</p>}
      {hosts && (
        <table>
          <thead><tr><th>IP</th><th>Açık Portlar</th><th>Vendor</th><th>OS</th><th>Keşif Kaynağı</th></tr></thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.ip_address}>
                <td>{h.ip_address}</td>
                <td>{h.open_ports.join(', ')}</td>
                <td>{h.vendor}</td>
                <td>{h.os_version || '—'}</td>
                <td><span className={`badge src-${(h.discovery_source || '').toLowerCase()}`}>
                  {h.discovery_source || 'TCP_PROBE'}</span></td>
              </tr>
            ))}
            {hosts.length === 0 &&
              <tr><td colSpan="5" className="empty">Canlı cihaz bulunamadı.</td></tr>}
          </tbody>
        </table>
      )}

      <hr className="section-sep" />
      <DiscoveredHosts />
    </section>
  )
}
