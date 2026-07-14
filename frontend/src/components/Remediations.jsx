import { useEffect, useState } from 'react'
import { createRemediation, getRemediations, hasRole, transitionRemediation } from '../api.js'

// Spec Section 8 state machine (client-side hints; server enforces).
const NEXT = {
  PENDING_APPROVAL: ['APPROVED', 'REJECTED'],
  APPROVED: ['STAGED'],
  STAGED: ['APPLIED', 'ROLLED_BACK'],
  APPLIED: ['ROLLED_BACK'],
}

export default function Remediations() {
  const [rows, setRows] = useState([])
  const [error, setError] = useState(null)

  const load = () => getRemediations().then(setRows).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const move = async (id, status) => {
    try { await transitionRemediation(id, status); load() }
    catch (e) { setError(e.message) }
  }

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ advisory_id: '', generated_commands: '', rollback_commands: '' })
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const submit = async (e) => {
    e.preventDefault(); setError(null)
    try {
      await createRemediation({
        advisory_id: Number(form.advisory_id),
        generated_commands: form.generated_commands,
        rollback_commands: form.rollback_commands || null,
      })
      setForm({ advisory_id: '', generated_commands: '', rollback_commands: '' })
      setShowForm(false); load()
    } catch (err) { setError(err.message) }
  }

  return (
    <section>
      <div className="section-head">
        <h2>Düzeltme Onay Akışı</h2>
        <div className="actions">
          {hasRole('operator') && !showForm &&
            <button onClick={() => setShowForm(true)}>+ Manuel Düzeltme</button>}
          <button className="secondary" onClick={load}>Yenile</button>
        </div>
      </div>
      {showForm && (
        <form className="panel-form" onSubmit={submit}>
          <h3>Manuel Düzeltme Talebi</h3>
          <div className="form-grid">
            <label>Advisory ID*<input required type="number" value={form.advisory_id}
              onChange={set('advisory_id')} /></label>
          </div>
          <label>Komutlar*<textarea required rows={3} style={{ width: '100%' }}
            value={form.generated_commands} onChange={set('generated_commands')} /></label>
          <label>Rollback komutları<textarea rows={2} style={{ width: '100%' }}
            value={form.rollback_commands} onChange={set('rollback_commands')} /></label>
          <div className="actions" style={{ marginTop: 8 }}>
            <button>Onaya Gönder</button>
            <button type="button" className="secondary" onClick={() => setShowForm(false)}>Vazgeç</button>
          </div>
        </form>
      )}
      <p className="hint">
        LLM/kural kaynaklı komutlar bir cihaza ancak insan onayı ve (CRITICAL/HIGH için)
        STAGED lab doğrulaması sonrası uygulanabilir. Onaylayan, talebi açan kişi olamaz.
      </p>
      {error && <div className="error">{error}</div>}
      {rows.map((r) => (
        <div key={r.id} className="remediation-card">
          <div className="advisory-head">
            <span className={`badge status-${r.status.toLowerCase()}`}>{r.status}</span>
            <span>#{r.id} · advisory {r.advisory_id}</span>
            <span className="source">talep: {r.requested_by || '—'}
              {r.approved_by ? ` · onay: ${r.approved_by}` : ''}</span>
          </div>
          <pre>{r.generated_commands}</pre>
          {r.rollback_commands && <details><summary>Rollback komutları</summary>
            <pre>{r.rollback_commands}</pre></details>}
          <div className="actions">
            {(NEXT[r.status] || []).map((s) => (
              <button key={s} onClick={() => move(r.id, s)}>{s}</button>
            ))}
          </div>
        </div>
      ))}
      {rows.length === 0 && <p className="empty">Bekleyen düzeltme aksiyonu yok.</p>}
    </section>
  )
}
