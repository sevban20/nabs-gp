import { useEffect, useState } from 'react'
import {
  generateRemediation, getAdvisories, hasRole, resolveAdvisory, silenceAdvisory,
} from '../api.js'

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

export default function Advisories({ asset }) {
  const [rows, setRows] = useState([])
  const [error, setError] = useState(null)

  const load = () =>
    getAdvisories(asset?.id)
      .then((r) => setRows(r.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])))
      .catch((e) => setError(e.message))
  useEffect(() => { load() }, [asset])

  const [msg, setMsg] = useState(null)

  const resolve = async (id) => {
    try { await resolveAdvisory(id); load() } catch (e) { setError(e.message) }
  }

  const silence = async (id) => {
    try { await silenceAdvisory(id); setMsg('Bulgu susturuldu; risk skoruna sayılmaz.'); load() }
    catch (e) { setError(e.message) }
  }

  const genRemediation = async (id) => {
    setError(null); setMsg('LLM düzeltme komutu üretiyor…')
    try {
      const res = await generateRemediation(id)
      setMsg(`Düzeltme #${res.remediation_action_id} oluşturuldu (${res.status}). ` +
        'Onay Akışı sekmesinden inceleyin.')
    } catch (e) { setMsg(null); setError(e.message) }
  }

  return (
    <section>
      <div className="section-head">
        <h2>Güvenlik Bulguları {asset ? `— ${asset.hostname}` : '(tümü)'}</h2>
        <button onClick={load}>Yenile</button>
      </div>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      {rows.map((r) => (
        <div key={r.id} className={`advisory sev-${r.severity.toLowerCase()}`}>
          <div className="advisory-head">
            <span className={`badge sev-${r.severity.toLowerCase()}`}>{r.severity}</span>
            <strong>{r.title}</strong>
            <code>{r.rule_id}</code>
            <span className="source">{r.finding_source}{r.is_silenced ? ' · susturuldu' : ''}</span>
            {hasRole('operator') && <span className="actions">
              <button onClick={() => resolve(r.id)}>Çözüldü</button>
              {!r.is_silenced &&
                <button className="secondary" onClick={() => silence(r.id)}>Sustur</button>}
              <button className="secondary" onClick={() => genRemediation(r.id)}>
                AI Düzeltme Üret</button>
            </span>}
          </div>
          <p>{r.description}</p>
          {r.remediation && <p className="remediation">Öneri: {r.remediation}</p>}
        </div>
      ))}
      {rows.length === 0 && <p className="empty">Açık bulgu yok.</p>}
    </section>
  )
}
