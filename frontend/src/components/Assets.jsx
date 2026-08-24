import { useEffect, useState } from 'react'
import {
  collectL2, collectTopology, deleteAsset, getAssets, getBackupHistory, hasRole,
  setBaseline, triggerBackup,
} from '../api.js'
import AssetForm from './AssetForm.jsx'
import DiffView from './DiffView.jsx'
import DriftView from './DriftView.jsx'

function riskClass(score) {
  if (score >= 80) return 'risk-ok'
  if (score >= 50) return 'risk-warn'
  return 'risk-bad'
}

function BackupHistory({ assetId }) {
  const [rows, setRows] = useState(null)
  useEffect(() => { getBackupHistory(assetId).then(setRows).catch(() => setRows([])) }, [assetId])
  if (rows === null) return <p className="hint">Yükleniyor…</p>
  if (rows.length === 0) return <p className="empty">Yedekleme geçmişi yok.</p>
  return (
    <table className="inner">
      <thead><tr><th>Tarih</th><th>Durum</th><th>Yöntem</th><th>Commit</th><th>Tetikleyen</th></tr></thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id}>
            <td>{new Date(r.triggered_at).toLocaleString('tr-TR')}</td>
            <td><span className={`badge ${r.status === 'SUCCESS' ? 'risk-ok' : 'risk-bad'}`}>
              {r.status}</span></td>
            <td>{r.method_used}</td>
            <td><code>{r.commit_hash ? r.commit_hash.slice(0, 10) : '—'}</code></td>
            <td>{r.triggered_by}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function Assets({ onShowAdvisories, prefill, onPrefillUsed }) {
  const [assets, setAssets] = useState([])
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)
  const [diffAsset, setDiffAsset] = useState(null)
  const [driftAsset, setDriftAsset] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [historyFor, setHistoryFor] = useState(null)

  // Ağ haritasından yönetilmeyen bir komşu "Envantere ekle" ile gelirse
  // formu ön dolgulu aç.
  useEffect(() => { if (prefill) setShowForm(true) }, [prefill])

  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  // Sunucu-taraflı arama+filtre (5.000+ cihazda doğru sonuç için).
  const load = () => getAssets({ q: query, status: statusFilter, limit: 500 })
    .then(setAssets).catch((e) => setError(e.message))
  useEffect(() => {
    const t = setTimeout(load, 250)  // debounce
    return () => clearTimeout(t)
  }, [query, statusFilter])

  const filtered = assets  // filtreleme artık sunucuda

  const backup = async (a) => {
    try { await triggerBackup(a.id); setMsg(`${a.hostname} için yedekleme kuyruğa alındı.`) }
    catch (e) { setError(e.message) }
  }

  const remove = async (a) => {
    if (!confirm(`${a.hostname} silinsin mi? Bağlı yedek geçmişi ve bulgular da silinir.`)) return
    try { await deleteAsset(a.id); load() } catch (e) { setError(e.message) }
  }

  const scanNeighbors = async (a) => {
    try { await collectTopology(a.id); setMsg(`${a.hostname} için komşu taraması kuyruğa alındı — Ağ Haritası'nda görünecek.`) }
    catch (e) { setError(e.message) }
  }

  const scanL2 = async (a) => {
    try { await collectL2(a.id); setMsg(`${a.hostname} için L2 envanteri (ARP+MAC) toplanıyor — Keşif → Keşfedilen Cihazlar'da görünecek.`) }
    catch (e) { setError(e.message) }
  }

  const baseline = async (a) => {
    if (!confirm(`${a.hostname} için mevcut config golden referans olarak alınsın mı?`)) return
    try { await setBaseline(a.id); setMsg(`${a.hostname} golden referansı ayarlandı.`); load() }
    catch (e) { setError(e.message) }
  }

  if (diffAsset) return <DiffView asset={diffAsset} onBack={() => setDiffAsset(null)} />
  if (driftAsset) return <DriftView asset={driftAsset} onBack={() => setDriftAsset(null)}
    onChanged={load} />

  return (
    <section>
      <div className="page-head">
        <h2>Cihaz Envanteri</h2>
        <div className="actions">
          {hasRole('operator') && !showForm &&
            <button onClick={() => setShowForm(true)}>+ Yeni Cihaz</button>}
          <button className="secondary" onClick={load}>Yenile</button>
        </div>
      </div>
      {showForm && <AssetForm key={prefill ? prefill.hostname : 'new'} initial={prefill}
        onCancel={() => { setShowForm(false); onPrefillUsed?.() }}
        onCreated={() => {
          setShowForm(false); onPrefillUsed?.()
          setMsg('Cihaz eklendi.'); load()
        }} />}
      {msg && <div className="info">{msg}</div>}
      {error && <div className="error">{error}</div>}
      <div className="toolbar">
        <input className="search" placeholder="Hostname, IP veya vendor ara…"
          value={query} onChange={(e) => setQuery(e.target.value)} />
        <div className="filter-chips">
          {[['all', 'Tümü'], ['up', 'Up'], ['down', 'Down'], ['risk', 'Riskli']].map(([k, l]) => (
            <button key={k} className={`chip ${statusFilter === k ? 'active' : ''}`}
              onClick={() => setStatusFilter(k)}>{l}</button>
          ))}
        </div>
        <span className="result-count">{filtered.length} / {assets.length} cihaz</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Hostname</th><th>IP</th><th>Durum</th><th>Drift</th><th>Vendor</th><th>Yöntem</th>
            <th>Risk</th><th>Son Yedek</th><th></th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((a) => (
            <>
              <tr key={a.id}>
                <td>{a.hostname}</td>
                <td>{a.ip_address}</td>
                <td>{a.is_reachable === null || a.is_reachable === undefined
                  ? <span className="badge sev-info">bilinmiyor</span>
                  : a.is_reachable
                    ? <span className="badge risk-ok">up</span>
                    : <span className="badge risk-bad">down</span>}</td>
                <td>{a.has_drift
                  ? <span className="badge risk-bad" title="Golden'dan sapma var">drift</span>
                  : <span className="badge risk-ok" title="Golden ile senkron">senkron</span>}</td>
                <td>{a.vendor}</td>
                <td>{a.backup_method}</td>
                <td><span className={`badge ${riskClass(a.risk_score)}`}>{a.risk_score}</span></td>
                <td>{a.last_successful_backup_at
                  ? new Date(a.last_successful_backup_at).toLocaleString('tr-TR') : '—'}</td>
                <td className="actions">
                  <button onClick={() => onShowAdvisories(a)}>Bulgular</button>
                  <button className="secondary" onClick={() => setDriftAsset(a)}>Drift</button>
                  <button className="secondary" onClick={() => setDiffAsset(a)}>Config</button>
                  <button className="secondary"
                    onClick={() => setHistoryFor(historyFor === a.id ? null : a.id)}>
                    Yedekler</button>
                  {hasRole('operator') &&
                    <button className="secondary" onClick={() => baseline(a)}>Baz Al</button>}
                  {hasRole('operator') && a.backup_method === 'ACTIVE_SSH' &&
                    <button onClick={() => backup(a)}>Yedekle</button>}
                  {hasRole('operator') &&
                    <button className="secondary" onClick={() => scanNeighbors(a)}>Komşuları Tara</button>}
                  {hasRole('operator') &&
                    <button className="secondary" onClick={() => scanL2(a)}>L2 Topla</button>}
                  {hasRole('admin') &&
                    <button className="danger" onClick={() => remove(a)}>Sil</button>}
                </td>
              </tr>
              {historyFor === a.id && (
                <tr key={`h-${a.id}`}><td colSpan="9"><BackupHistory assetId={a.id} /></td></tr>
              )}
            </>
          ))}
          {filtered.length === 0 && (
            <tr><td colSpan="9" className="empty">
              {assets.length === 0
                ? 'Henüz cihaz yok. "+ Yeni Cihaz" ile ekleyin (operator rolü gerekir).'
                : 'Filtreyle eşleşen cihaz yok.'}
            </td></tr>
          )}
        </tbody>
      </table>
    </section>
  )
}
