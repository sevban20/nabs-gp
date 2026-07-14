import { useEffect, useRef, useState } from 'react'
import { getJobCounts, getRecentJobs } from '../api.js'

const STATUS_CLASS = {
  QUEUED: 'status-queued', IN_PROGRESS: 'status-run',
  SUCCESS: 'risk-ok', FAILED: 'risk-bad', TIMEOUT: 'risk-bad',
}
const STATUS_LABEL = {
  QUEUED: 'kuyrukta', IN_PROGRESS: 'çalışıyor',
  SUCCESS: 'başarılı', FAILED: 'hata', TIMEOUT: 'zaman aşımı',
}

export default function Jobs() {
  const [jobs, setJobs] = useState([])
  const [counts, setCounts] = useState(null)
  const [filter, setFilter] = useState('')
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const load = () => {
    getRecentJobs(filter).then(setJobs).catch((e) => setError(e.message))
    getJobCounts().then(setCounts).catch(() => {})
  }
  useEffect(() => {
    load()
    timer.current = setInterval(load, 5000)  // canlı takip
    return () => clearInterval(timer.current)
  }, [filter])

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>İşlem Geçmişi</h2>
          <span className="hint">Yedekleme işleri — kuyruk, çalışan ve tamamlanan.
            5 sn'de bir otomatik yenilenir.</span>
        </div>
        <button className="secondary" onClick={load}>Yenile</button>
      </div>

      {counts && (
        <div className="kpi-grid">
          <div className="kpi"><div className="kpi-value">{counts.queued}</div>
            <div className="kpi-label">Kuyrukta</div></div>
          <div className="kpi"><div className="kpi-value">{counts.in_progress}</div>
            <div className="kpi-label">Çalışıyor</div></div>
          <div className="kpi ok"><div className="kpi-value">{counts.success}</div>
            <div className="kpi-label">Başarılı</div></div>
          <div className={`kpi ${counts.failed ? 'bad' : ''}`}>
            <div className="kpi-value">{counts.failed}</div>
            <div className="kpi-label">Hatalı</div></div>
        </div>
      )}

      <div className="toolbar">
        <div className="filter-chips">
          {[['', 'Tümü'], ['QUEUED', 'Kuyrukta'], ['IN_PROGRESS', 'Çalışıyor'],
            ['SUCCESS', 'Başarılı'], ['FAILED', 'Hatalı']].map(([k, l]) => (
            <button key={k} className={`chip ${filter === k ? 'active' : ''}`}
              onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      <table>
        <thead><tr><th>Cihaz</th><th>Durum</th><th>Yöntem</th><th>Tetikleyen</th>
          <th>Başlangıç</th><th>Bitiş</th><th>Sonuç</th></tr></thead>
        <tbody>
          {jobs.map((j) => (
            <tr key={j.id}>
              <td>{j.hostname}</td>
              <td><span className={`badge ${STATUS_CLASS[j.status] || ''}`}>
                {STATUS_LABEL[j.status] || j.status}</span></td>
              <td>{j.method_used}</td>
              <td className="muted">{j.triggered_by}</td>
              <td>{j.triggered_at ? new Date(j.triggered_at).toLocaleString('tr-TR') : '—'}</td>
              <td>{j.completed_at ? new Date(j.completed_at).toLocaleString('tr-TR') : '—'}</td>
              <td>{j.status === 'SUCCESS'
                ? <code>{j.commit_hash ? j.commit_hash.slice(0, 10) : 'değişiklik yok'}</code>
                : j.error_log
                  ? <span className="err-text" title={j.error_log}>{j.error_log.slice(0, 60)}…</span>
                  : '—'}</td>
            </tr>
          ))}
          {jobs.length === 0 &&
            <tr><td colSpan="7" className="empty">Henüz işlem yok.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
