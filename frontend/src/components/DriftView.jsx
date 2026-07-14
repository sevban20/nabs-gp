import { useEffect, useState } from 'react'
import { getDrift, hasRole, setBaseline } from '../api.js'

export default function DriftView({ asset, onBack, onChanged }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [msg, setMsg] = useState(null)

  const load = () => getDrift(asset.id).then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [asset])

  const rebaseline = async () => {
    if (!confirm(`${asset.hostname} için MEVCUT config yeni golden referans olarak alınsın mı? `
      + 'Bu, mevcut sapmayı onaylanmış kabul eder.')) return
    try {
      await setBaseline(asset.id)
      setMsg('Golden referans güncellendi; cihaz artık senkron.')
      load(); onChanged?.()
    } catch (e) { setError(e.message) }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h2>Config Drift — {asset.hostname}</h2>
          {data?.baseline_set_at && <span className="hint">Golden baz:
            {' '}{new Date(data.baseline_set_at).toLocaleString('tr-TR')}
            {data.baseline_note ? ` · ${data.baseline_note}` : ''}</span>}
        </div>
        <div className="actions">
          {hasRole('operator') && data?.has_baseline &&
            <button onClick={rebaseline}>Mevcudu Golden Al</button>}
          <button className="secondary" onClick={onBack}>← Geri</button>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}

      {data && !data.has_baseline && (
        <div className="info">Bu cihaz için golden baseline tanımlı değil.
          Cihazlar listesinden "Baz Al" ile mevcut config'i referans olarak sabitleyin.</div>
      )}
      {data && data.has_baseline && data.in_sync && (
        <div className="drift-banner ok">✓ Senkron — mevcut config golden referansla birebir aynı.</div>
      )}
      {data && data.has_baseline && !data.in_sync && (
        <>
          <div className="drift-banner bad">⚠ Drift tespit edildi:
            {' '}{data.added} eklenen, {data.removed} silinen satır (golden'a göre).</div>
          <pre className="diff">{data.diff.split('\n').map((l, i) => (
            <span key={i} className={
              l.startsWith('+') && !l.startsWith('+++') ? 'line-add'
                : l.startsWith('-') && !l.startsWith('---') ? 'line-del' : ''
            }>{l}{'\n'}</span>
          ))}</pre>
        </>
      )}
    </section>
  )
}
