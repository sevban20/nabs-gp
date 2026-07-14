import { useEffect, useState } from 'react'
import {
  downloadTextFile, getConfigContent, getConfigDiff, getConfigHistory, summarizeChange,
} from '../api.js'

export default function DiffView({ asset, onBack }) {
  const [history, setHistory] = useState([])
  const [selected, setSelected] = useState([])
  const [diff, setDiff] = useState(null)
  const [content, setContent] = useState(null)  // {commit, text}
  const [summary, setSummary] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    getConfigHistory(asset.id).then(setHistory).catch((e) => setError(e.message))
  }, [asset])

  const toggle = (sha) => {
    setDiff(null)
    setSelected((cur) =>
      cur.includes(sha) ? cur.filter((s) => s !== sha) : [...cur, sha].slice(-2))
  }

  const view = async (commit) => {
    setDiff(null); setError(null)
    try {
      const res = await getConfigContent(asset.id, commit)
      setContent({ commit: res.commit, text: res.content })
    } catch (e) { setError(e.message) }
  }

  const download = async (commit) => {
    try {
      const res = await getConfigContent(asset.id, commit)
      const tag = commit ? commit.slice(0, 8) : 'latest'
      downloadTextFile(`${asset.hostname}_${tag}.conf`, res.content)
    } catch (e) { setError(e.message) }
  }

  const showDiff = async () => {
    setContent(null)
    try {
      const [a, b] = selected
      setDiff((await getConfigDiff(asset.id, a, b)).diff || '(fark yok)')
    } catch (e) { setError(e.message) }
  }

  const summarize = async () => {
    setSummary('LLM özetliyor…')
    try {
      const [a, b] = selected
      setSummary((await summarizeChange(asset.id, a, b)).summary)
    } catch (e) { setSummary(null); setError(e.message) }
  }

  return (
    <section>
      <div className="page-head">
        <h2>Konfigürasyon — {asset.hostname}</h2>
        <div className="actions">
          <button onClick={() => view(null)}>Son Config'i Görüntüle</button>
          <button className="secondary" onClick={() => download(null)}>Son Config'i İndir</button>
          <button className="secondary" onClick={onBack}>← Geri</button>
        </div>
      </div>
      <p className="hint">Cihaz arızalanıp değiştirildiğinde: son (veya istediğiniz tarihteki)
        config'i indirip yeni cihaza manuel yükleyin. Otomatik geri-yazma tasarım gereği kapalıdır.</p>
      {error && <div className="error">{error}</div>}

      <table>
        <thead><tr><th></th><th>Commit</th><th>Mesaj</th><th>Tarih</th><th></th></tr></thead>
        <tbody>
          {history.map((c) => (
            <tr key={c.commit}>
              <td><input type="checkbox" checked={selected.includes(c.commit)}
                onChange={() => toggle(c.commit)} /></td>
              <td><code>{c.commit.slice(0, 10)}</code></td>
              <td>{c.message}</td>
              <td>{new Date(c.date).toLocaleString('tr-TR')}</td>
              <td className="actions">
                <button className="secondary" onClick={() => view(c.commit)}>Görüntüle</button>
                <button className="secondary" onClick={() => download(c.commit)}>İndir</button>
              </td>
            </tr>
          ))}
          {history.length === 0 &&
            <tr><td colSpan="5" className="empty">Bu cihaz için henüz yedek yok.</td></tr>}
        </tbody>
      </table>

      <div className="actions">
        <button disabled={selected.length !== 2} onClick={showDiff}>
          Seçili iki commit'i karşılaştır
        </button>
        <button className="secondary" disabled={selected.length !== 2} onClick={summarize}>
          AI ile Özetle
        </button>
      </div>
      {summary && <div className="info">{summary}</div>}

      {content && (
        <div className="config-panel">
          <div className="card-head">
            <h3>Config içeriği {content.commit ? `· ${content.commit.slice(0, 10)}` : '· son'}</h3>
            <div className="actions">
              <button className="secondary" onClick={() => download(content.commit)}>İndir</button>
              <button className="link" onClick={() => setContent(null)}>kapat ✕</button>
            </div>
          </div>
          <pre className="config-text">{content.text}</pre>
        </div>
      )}

      {diff && <pre className="diff">{diff.split('\n').map((l, i) => (
        <span key={i} className={
          l.startsWith('+') && !l.startsWith('+++') ? 'line-add'
            : l.startsWith('-') && !l.startsWith('---') ? 'line-del' : ''
        }>{l}{'\n'}</span>
      ))}</pre>}
    </section>
  )
}
