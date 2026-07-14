import { useEffect, useState } from 'react'
import { getDashboardSummary } from '../api.js'
import { BarList, Donut } from './charts.jsx'

const VENDOR_LABELS = {
  cisco_ios: 'Cisco IOS', fortinet: 'Fortinet',
  paloalto: 'Palo Alto', juniper_junos: 'Juniper',
}
const SEV_COLOR = {
  CRITICAL: 'var(--bad)', HIGH: '#fb923c', MEDIUM: 'var(--warn)',
  LOW: 'var(--muted)', INFO: 'var(--muted)',
}

function Kpi({ label, value, sub, tone }) {
  return (
    <div className={`kpi ${tone || ''}`}>
      <div className="kpi-value">{value}</div>
      <div className="kpi-label">{label}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  )
}

export default function Overview({ onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const load = () => getDashboardSummary().then(setData).catch((e) => setError(e.message))
  useEffect(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [])

  if (error) return <div className="error">{error}</div>
  if (!data) return <div className="hint">Panel yükleniyor…</div>

  const a = data.assets
  const b = data.backups_24h
  const adv = data.advisories

  return (
    <div className="overview">
      <div className="page-head">
        <div>
          <h2>Genel Bakış</h2>
          <span className="hint">Son güncelleme: {new Date(data.generated_at).toLocaleTimeString('tr-TR')} · 30 sn'de bir yenilenir</span>
        </div>
      </div>

      <div className="kpi-grid">
        <Kpi label="Toplam Cihaz" value={a.total} sub={`${a.active} aktif`} />
        <Kpi label="Erişilebilir (up)" value={a.up} tone="ok"
          sub={a.unknown ? `${a.unknown} bilinmiyor` : null} />
        <Kpi label="Erişilemeyen (down)" value={a.down} tone={a.down ? 'bad' : 'ok'} />
        <Kpi label="Ortalama Risk" value={data.risk.average}
          tone={data.risk.average >= 80 ? 'ok' : data.risk.average >= 50 ? 'warn' : 'bad'}
          sub="100 = sıkılaştırılmış" />
        <Kpi label="Kritik + Yüksek Bulgu" value={adv.critical + adv.high}
          tone={adv.critical + adv.high ? 'bad' : 'ok'} sub={`${adv.total} toplam açık`} />
        <Kpi label="Onay Bekleyen" value={data.pending_remediations}
          tone={data.pending_remediations ? 'warn' : 'ok'} sub="düzeltme" />
        <Kpi label="Config Drift" value={data.drifted_assets ?? 0}
          tone={data.drifted_assets ? 'bad' : 'ok'} sub="golden'dan sapan cihaz" />
      </div>

      <div className="grid-3">
        <div className="card">
          <h3>Cihaz Durumu</h3>
          <Donut size={150} centerLabel={a.total} centerSub="cihaz"
            segments={[
              { label: 'Up', value: a.up, color: 'var(--ok)' },
              { label: 'Down', value: a.down, color: 'var(--bad)' },
              { label: 'Bilinmiyor', value: a.unknown, color: 'var(--border)' },
            ]} />
        </div>
        <div className="card">
          <h3>Risk Dağılımı</h3>
          <Donut size={150} centerLabel={data.risk.average} centerSub="ort. risk"
            segments={[
              { label: 'İyi (80+)', value: data.risk.bands.good, color: 'var(--ok)' },
              { label: 'Orta (50-79)', value: data.risk.bands.warn, color: 'var(--warn)' },
              { label: 'Riskli (<50)', value: data.risk.bands.bad, color: 'var(--bad)' },
            ]} />
        </div>
        <div className="card">
          <h3>Yedekleme (24s)</h3>
          <BarList items={[
            { label: 'Başarılı', value: b.success, color: 'var(--ok)' },
            { label: 'Hatalı', value: b.failed, color: 'var(--bad)' },
            { label: 'Sürüyor', value: b.in_progress, color: 'var(--accent)' },
            { label: 'Bayat (>24s)', value: b.stale_assets, color: 'var(--warn)' },
          ]} />
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-head">
            <h3>En Riskli Cihazlar</h3>
            <button className="link" onClick={() => onNavigate('assets')}>Tümü →</button>
          </div>
          <table className="flat">
            <thead><tr><th>Cihaz</th><th>IP</th><th>Durum</th><th>Risk</th></tr></thead>
            <tbody>
              {data.top_risk_assets.map((d) => (
                <tr key={d.id}>
                  <td>{d.hostname}</td>
                  <td className="muted">{d.ip_address}</td>
                  <td>{d.is_reachable === true ? <span className="dot-ok" title="up" />
                    : d.is_reachable === false ? <span className="dot-bad" title="down" />
                      : <span className="dot-unk" title="bilinmiyor" />}</td>
                  <td><RiskPill score={d.risk_score} /></td>
                </tr>
              ))}
              {data.top_risk_assets.length === 0 &&
                <tr><td colSpan="4" className="empty">Cihaz yok.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-head">
            <h3>Son Güvenlik Bulguları</h3>
            <button className="link" onClick={() => onNavigate('advisories')}>Tümü →</button>
          </div>
          <div className="feed">
            {data.recent_advisories.map((f) => (
              <div key={f.id} className="feed-row">
                <span className="badge sev" style={{ color: SEV_COLOR[f.severity] }}>{f.severity}</span>
                <div className="feed-body">
                  <div className="feed-title">{f.title}</div>
                  <div className="feed-meta">{f.hostname} · {f.rule_id}</div>
                </div>
              </div>
            ))}
            {data.recent_advisories.length === 0 &&
              <p className="empty">Açık bulgu yok — tebrikler.</p>}
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Vendor Dağılımı</h3>
        <BarList items={Object.entries(data.vendors).map(([v, n]) => ({
          label: VENDOR_LABELS[v] || v, value: n,
        }))} unit=" cihaz" />
      </div>
    </div>
  )
}

function RiskPill({ score }) {
  const cls = score >= 80 ? 'risk-ok' : score >= 50 ? 'risk-warn' : 'risk-bad'
  return <span className={`badge ${cls}`}>{score}</span>
}
