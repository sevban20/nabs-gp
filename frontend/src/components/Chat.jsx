import { useEffect, useState } from 'react'
import { chatWithNetwork, downloadRiskReport, getAiStatus } from '../api.js'

function StatusBadge({ status }) {
  if (!status) return <span className="ai-status muted">durum kontrol ediliyor…</span>
  if (!status.reachable)
    return <span className="ai-status bad">● Ollama erişilemez ({status.endpoint})</span>
  if (!status.model_ready)
    return <span className="ai-status warn">● Ollama bağlı — '{status.model}' modeli yüklü değil
      (ollama pull {status.model})</span>
  return <span className="ai-status ok">● LLM bağlı · model {status.model}</span>
}

export default function Chat() {
  const [question, setQuestion] = useState('')
  const [messages, setMessages] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [status, setStatus] = useState(null)

  useEffect(() => { getAiStatus().then(setStatus).catch(() => setStatus({ reachable: false })) }, [])

  const ask = async (e) => {
    e.preventDefault()
    const q = question.trim()
    if (!q) return
    setMessages((m) => [...m, { role: 'user', text: q }])
    setQuestion(''); setBusy(true); setError(null)
    try {
      const res = await chatWithNetwork(q)
      setMessages((m) => [...m, { role: 'ai', text: res.answer }])
    } catch (err) {
      // LLM erişilemezse (503) net bir sistem mesajı göster
      setMessages((m) => [...m, { role: 'ai', text: `⚠ ${err.message}` }])
    } finally { setBusy(false) }
  }

  return (
    <section>
      <div className="section-head">
        <h2>Chat-with-Network</h2>
        <button onClick={() => downloadRiskReport().catch((e) => setError(e.message))}>
          PDF Risk Raporu İndir
        </button>
      </div>
      <div className="ai-statusbar"><StatusBadge status={status} /></div>
      <p className="hint">Yanıtlar yerel LLM'den (Ollama) gelir; envanter, açık bulgular ve
        indekslenmiş benchmark bağlamı kullanılır. Ollama'yı ayrı çalıştırın
        (Mac: <code>ollama serve</code> · sunucu: docker-compose.ollama.yml).</p>
      {error && <div className="error">{error}</div>}
      <div className="chat-box">
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>{m.text}</div>
        ))}
        {busy && <div className="chat-msg ai">Düşünüyor…</div>}
        {messages.length === 0 &&
          <p className="empty">Örn: "En riskli 3 cihaz hangileri ve neden?"</p>}
      </div>
      <form onSubmit={ask} className="actions" style={{ gap: 8 }}>
        <input style={{ flex: 1 }} placeholder="Ağınız hakkında soru sorun…"
          value={question} onChange={(e) => setQuestion(e.target.value)} />
        <button disabled={busy || !question.trim()}>Gönder</button>
      </form>
    </section>
  )
}
