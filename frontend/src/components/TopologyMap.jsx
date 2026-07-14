import { useEffect, useMemo, useState } from 'react'
import { getTopologyGraph } from '../api.js'

// Bağımlılıksız basit force-directed yerleşim. Düğüm sayısına göre iterasyon
// uyarlanır (uç cihazlarla düğüm sayısı çok artabilir).
function layout(nodes, edges, width, height) {
  const n = nodes.length
  const iterations = n > 200 ? 90 : n > 80 ? 150 : 220
  const pos = {}
  const R = Math.min(width, height) / 2.6
  nodes.forEach((nd, i) => {
    const ang = (i / Math.max(1, n)) * Math.PI * 2
    pos[nd.id] = {
      x: width / 2 + Math.cos(ang) * R * (0.5 + 0.5 * Math.random()),
      y: height / 2 + Math.sin(ang) * R * (0.5 + 0.5 * Math.random()),
      vx: 0, vy: 0, endpoint: nd.type === 'endpoint',
    }
  })
  const k = 90
  for (let it = 0; it < iterations; it++) {
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = pos[nodes[i].id], b = pos[nodes[j].id]
        let dx = a.x - b.x, dy = a.y - b.y
        let d = Math.hypot(dx, dy) || 0.01
        const rep = (k * k) / d / 12
        dx /= d; dy /= d
        a.vx += dx * rep; a.vy += dy * rep
        b.vx -= dx * rep; b.vy -= dy * rep
      }
    }
    edges.forEach((e) => {
      const a = pos[e.source], b = pos[e.target]
      if (!a || !b) return
      let dx = b.x - a.x, dy = b.y - a.y
      let d = Math.hypot(dx, dy) || 0.01
      // uç cihaz kenarları daha kısa (switch'ine yakın kümelensin)
      const ideal = e.kind === 'l2' ? k * 0.5 : k
      const att = (d - ideal) / 14
      dx /= d; dy /= d
      a.vx += dx * att; a.vy += dy * att
      b.vx -= dx * att; b.vy -= dy * att
    })
    nodes.forEach((nd) => {
      const p = pos[nd.id]
      p.vx += (width / 2 - p.x) * 0.002
      p.vy += (height / 2 - p.y) * 0.002
      p.x += Math.max(-8, Math.min(8, p.vx))
      p.y += Math.max(-8, Math.min(8, p.vy))
      p.vx *= 0.85; p.vy *= 0.85
      p.x = Math.max(24, Math.min(width - 24, p.x))
      p.y = Math.max(24, Math.min(height - 24, p.y))
    })
  }
  return pos
}

function nodeColor(n) {
  if (n.type === 'endpoint') return 'var(--accent-2)'
  if (!n.managed) return 'var(--faint)'
  if (n.risk_score == null) return 'var(--accent)'
  if (n.risk_score >= 80) return 'var(--ok)'
  if (n.risk_score >= 50) return 'var(--warn)'
  return 'var(--bad)'
}

export default function TopologyMap() {
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [showEndpoints, setShowEndpoints] = useState(false)
  const W = 860, H = 560

  const load = () => getTopologyGraph(showEndpoints)
    .then(setGraph).catch((e) => setError(e.message))
  useEffect(() => { load() }, [showEndpoints])

  const pos = useMemo(() => graph ? layout(graph.nodes, graph.edges, W, H) : {}, [graph])

  if (error) return <div className="error">{error}</div>
  if (!graph) return <div className="hint">Harita yükleniyor…</div>

  const devices = graph.nodes.filter((n) => n.type !== 'endpoint')
  const endpoints = graph.nodes.filter((n) => n.type === 'endpoint')
  const managed = devices.filter((n) => n.managed).length

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Ağ Haritası</h2>
          <span className="hint">{devices.length} cihaz, {endpoints.length} uç cihaz,
            {' '}{graph.edges.length} bağlantı · LLDP/CDP omurga + L2 (ARP/MAC) uç cihazlar</span>
        </div>
        <div className="actions">
          <label className="toggle">
            <input type="checkbox" checked={showEndpoints}
              onChange={(e) => setShowEndpoints(e.target.checked)} />
            Uç cihazları göster
          </label>
          <button className="secondary" onClick={load}>Yenile</button>
        </div>
      </div>

      {graph.edges.length === 0 && (
        <div className="info">Henüz topoloji verisi yok. Cihazlar sekmesinde "Komşuları Tara"
          (omurga) ve "L2 Topla" (uç cihazlar) çalıştırın.</div>
      )}

      <div className="map-wrap card">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: 'block' }}>
          {graph.edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target]
            if (!a || !b) return null
            const isL2 = e.kind === 'l2'
            return (
              <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={isL2 ? 'var(--border-soft)' : 'var(--border)'}
                strokeWidth={isL2 ? 1 : 1.5}
                strokeDasharray={isL2 ? '2 4' : e.protocol === 'LLDP' ? '4 3' : ''} />
            )
          })}
          {graph.nodes.map((n) => {
            const p = pos[n.id]
            if (!p) return null
            const isSel = selected?.id === n.id
            if (n.type === 'endpoint') {
              // uç cihaz: küçük eşkenar dörtgen
              return (
                <g key={n.id} transform={`translate(${p.x} ${p.y}) rotate(45)`}
                  style={{ cursor: 'pointer' }} onClick={() => setSelected(n)}>
                  <rect x="-5" y="-5" width="10" height="10" fill={nodeColor(n)}
                    stroke={isSel ? 'var(--text)' : 'var(--bg)'} strokeWidth={isSel ? 2 : 1}
                    opacity="0.85" />
                </g>
              )
            }
            return (
              <g key={n.id} transform={`translate(${p.x} ${p.y})`}
                style={{ cursor: 'pointer' }} onClick={() => setSelected(n)}>
                <circle r={n.managed ? 13 : 9} fill={nodeColor(n)}
                  stroke={isSel ? 'var(--text)' : 'var(--bg)'} strokeWidth={isSel ? 3 : 2}
                  opacity={n.managed ? 1 : 0.7} />
                {n.managed && n.is_reachable === false &&
                  <circle r="17" fill="none" stroke="var(--bad)" strokeWidth="1.5"
                    strokeDasharray="2 2" />}
                <text y={n.managed ? 27 : 22} textAnchor="middle" fontSize="11"
                  fill="var(--text)">{n.id}</text>
              </g>
            )
          })}
        </svg>
        <div className="map-legend">
          <span><i className="dot" style={{ background: 'var(--ok)' }} />Düşük risk</span>
          <span><i className="dot" style={{ background: 'var(--warn)' }} />Orta</span>
          <span><i className="dot" style={{ background: 'var(--bad)' }} />Yüksek risk</span>
          <span><i className="dot" style={{ background: 'var(--faint)' }} />Yönetilmeyen</span>
          <span><i className="dot" style={{ background: 'var(--accent-2)' }} />Uç cihaz</span>
          <span className="legend-note">— komşuluk · ┄ LLDP · ⋯ L2 · ◆ uç cihaz</span>
        </div>
      </div>

      <div className="map-summary hint">
        {managed} yönetilen cihaz · {devices.length - managed} yönetilmeyen komşu
        {endpoints.length > 0 && ` · ${endpoints.length} uç cihaz (ARP/MAC)`}.
      </div>

      {selected && (
        <div className="card node-detail">
          <div className="card-head">
            <h3>{selected.type === 'endpoint' ? (selected.label || selected.mac) : selected.id}</h3>
            <button className="link" onClick={() => setSelected(null)}>kapat ✕</button>
          </div>
          <div className="detail-grid">
            {selected.type === 'endpoint' ? (
              <>
                <div><span className="muted">Tip:</span> Uç cihaz (L2 keşif)</div>
                <div><span className="muted">MAC:</span> <code>{selected.mac}</code></div>
                <div><span className="muted">Üretici (OUI):</span> {selected.oui_vendor || 'unknown'}</div>
                {selected.ip_address && <div><span className="muted">IP:</span> {selected.ip_address}</div>}
                <div><span className="muted">Bağlı switch:</span>{' '}
                  {graph.edges.filter((e) => e.target === selected.id)
                    .map((e) => `${e.source}${e.local_interface ? ` (${e.local_interface})` : ''}`)
                    .join(', ') || '—'}</div>
              </>
            ) : (
              <>
                <div><span className="muted">Durum:</span> {selected.managed
                  ? 'Yönetilen (envanterde)' : 'Yönetilmeyen (yalnızca komşuluktan bilinir)'}</div>
                {selected.ip_address && <div><span className="muted">IP:</span> {selected.ip_address}</div>}
                {selected.vendor && <div><span className="muted">Vendor:</span> {selected.vendor}</div>}
                {selected.risk_score != null &&
                  <div><span className="muted">Risk:</span> {selected.risk_score}</div>}
                <div><span className="muted">Bağlantılar:</span>{' '}
                  {graph.edges.filter((e) => (e.source === selected.id || e.target === selected.id)
                    && e.kind !== 'l2')
                    .map((e) => e.source === selected.id ? e.target : e.source).join(', ') || '—'}</div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
