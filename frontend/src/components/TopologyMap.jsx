import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getTopologyGraph, hasRole } from '../api.js'

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
        const d = Math.hypot(dx, dy) || 0.01
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
      const d = Math.hypot(dx, dy) || 0.01
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

// LLDP 'System Description' metninden vendor tahmini — envantere eklerken
// formu ön doldurmak için. Tutmazsa kullanıcı listeden değiştirir.
function guessVendor(platform) {
  const p = (platform || '').toLowerCase()
  if (p.includes('fortiswitch')) return 'fortiswitch'
  if (p.includes('fortigate') || p.includes('fortios') || p.includes('fortinet')) return 'fortinet'
  if (p.includes('cisco') || p.includes('ios')) return 'cisco_ios'
  if (p.includes('huawei') || p.includes('vrp')) return 'huawei_vrp'
  if (p.includes('aruba') || p.includes('aos-cx')) return 'aruba_aoscx'
  if (p.includes('procurve') || p.includes('hp ')) return 'aruba_procurve'
  if (p.includes('juniper') || p.includes('junos')) return 'juniper_junos'
  if (p.includes('mikrotik') || p.includes('routeros')) return 'mikrotik'
  if (p.includes('pan-os') || p.includes('palo')) return 'paloalto'
  return 'cisco_ios'
}

const W = 860, H = 560

export default function TopologyMap({ onOnboard }) {
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [showEndpoints, setShowEndpoints] = useState(false)

  // Pan/zoom durumu: görünen alan (viewBox). Sürükleme ve tekerlek bunu değiştirir.
  const [vb, setVb] = useState({ x: 0, y: 0, w: W, h: H })
  const [positions, setPositions] = useState({})
  const svgRef = useRef(null)
  const dragRef = useRef(null)   // {mode:'pan'|'node', ...}

  const load = useCallback(() => getTopologyGraph(showEndpoints)
    .then(setGraph).catch((e) => setError(e.message)), [showEndpoints])
  useEffect(() => { load() }, [load])

  const initialPos = useMemo(
    () => (graph ? layout(graph.nodes, graph.edges, W, H) : {}), [graph])
  useEffect(() => { setPositions(initialPos) }, [initialPos])

  // Ekran koordinatını SVG koordinatına çevir (zoom/pan sonrası doğru olsun)
  const toSvg = (evt) => {
    const svg = svgRef.current
    if (!svg) return { x: 0, y: 0 }
    const pt = svg.createSVGPoint()
    pt.x = evt.clientX; pt.y = evt.clientY
    const ctm = svg.getScreenCTM()
    if (!ctm) return { x: 0, y: 0 }
    const p = pt.matrixTransform(ctm.inverse())
    return { x: p.x, y: p.y }
  }

  const onWheel = (e) => {
    e.preventDefault()
    const { x: cx, y: cy } = toSvg(e)
    const factor = e.deltaY > 0 ? 1.15 : 1 / 1.15
    setVb((v) => {
      const w = Math.max(120, Math.min(W * 4, v.w * factor))
      const h = w * (H / W)
      // imlecin altındaki nokta sabit kalsın
      return { x: cx - (cx - v.x) * (w / v.w), y: cy - (cy - v.y) * (h / v.h), w, h }
    })
  }

  const onPointerDown = (e, node) => {
    e.currentTarget.setPointerCapture?.(e.pointerId)
    const p = toSvg(e)
    dragRef.current = node
      ? { mode: 'node', id: node.id, dx: p.x - (positions[node.id]?.x ?? 0), dy: p.y - (positions[node.id]?.y ?? 0), moved: false }
      : { mode: 'pan', sx: e.clientX, sy: e.clientY, ox: vb.x, oy: vb.y }
  }

  const onPointerMove = (e) => {
    const d = dragRef.current
    if (!d) return
    if (d.mode === 'node') {
      const p = toSvg(e)
      d.moved = true
      setPositions((prev) => ({ ...prev, [d.id]: { ...prev[d.id], x: p.x - d.dx, y: p.y - d.dy } }))
    } else {
      const svg = svgRef.current
      const scale = vb.w / (svg?.clientWidth || W)
      setVb((v) => ({ ...v, x: d.ox - (e.clientX - d.sx) * scale, y: d.oy - (e.clientY - d.sy) * scale }))
    }
  }

  const onPointerUp = () => { dragRef.current = null }
  const resetView = () => { setVb({ x: 0, y: 0, w: W, h: H }); setPositions(initialPos) }

  if (error) return <div className="error">{error}</div>
  if (!graph) return <div className="hint">Harita yükleniyor…</div>

  const pos = positions
  const devices = graph.nodes.filter((n) => n.type !== 'endpoint')
  const endpoints = graph.nodes.filter((n) => n.type === 'endpoint')
  const managed = devices.filter((n) => n.managed).length
  const unmanaged = devices.filter((n) => !n.managed)

  // Seçili düğümün komşuluk kenarları, yön düzeltilmiş olarak
  const linksOf = (id) => graph.edges
    .filter((e) => e.kind !== 'l2' && (e.source === id || e.target === id))
    .map((e) => {
      const outgoing = e.source === id
      return {
        peer: outgoing ? e.target : e.source,
        localIf: outgoing ? e.local_interface : e.remote_interface,
        remoteIf: outgoing ? e.remote_interface : e.local_interface,
        protocol: e.protocol, platform: e.platform, remoteIp: e.remote_ip,
      }
    })

  const onboardPayload = (n) => {
    const l = linksOf(n.id)[0] || {}
    return { hostname: n.id, ip_address: n.ip_address || l.remoteIp || '',
             vendor: guessVendor(l.platform) }
  }

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
          <button className="secondary" onClick={resetView}>Görünümü sıfırla</button>
          <button className="secondary" onClick={load}>Yenile</button>
        </div>
      </div>

      {graph.edges.length === 0 && (
        <div className="info">Henüz topoloji verisi yok. Cihazlar sekmesinde "Komşuları Tara"
          (omurga) ve "L2 Topla" (uç cihazlar) çalıştırın.</div>
      )}

      <div className="map-wrap card">
        <svg ref={svgRef} viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`} width="100%"
          style={{ display: 'block', cursor: dragRef.current ? 'grabbing' : 'grab',
                   touchAction: 'none' }}
          onWheel={onWheel}
          onPointerDown={(e) => onPointerDown(e, null)}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={onPointerUp}>
          {/* arka plan: boşluğa tıklayınca seçim kalksın */}
          <rect x={vb.x} y={vb.y} width={vb.w} height={vb.h} fill="transparent"
            onClick={() => setSelected(null)} />
          {graph.edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target]
            if (!a || !b) return null
            const isL2 = e.kind === 'l2'
            const hot = selected && (e.source === selected.id || e.target === selected.id)
            return (
              <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={hot ? 'var(--accent)' : isL2 ? 'var(--border-soft)' : 'var(--border)'}
                strokeWidth={hot ? 2.5 : isL2 ? 1 : 1.5}
                strokeDasharray={isL2 ? '2 4' : e.protocol === 'LLDP' ? '4 3' : ''} />
            )
          })}
          {graph.nodes.map((n) => {
            const p = pos[n.id]
            if (!p) return null
            const isSel = selected?.id === n.id
            const pick = (ev) => { if (!dragRef.current?.moved) setSelected(n); ev.stopPropagation() }
            if (n.type === 'endpoint') {
              return (
                <g key={n.id} transform={`translate(${p.x} ${p.y}) rotate(45)`}
                  style={{ cursor: 'pointer' }}
                  onPointerDown={(e) => { e.stopPropagation(); onPointerDown(e, n) }}
                  onClick={pick}>
                  <rect x="-5" y="-5" width="10" height="10" fill={nodeColor(n)}
                    stroke={isSel ? 'var(--text)' : 'var(--bg)'} strokeWidth={isSel ? 2 : 1}
                    opacity="0.85" />
                </g>
              )
            }
            return (
              <g key={n.id} transform={`translate(${p.x} ${p.y})`}
                style={{ cursor: 'grab' }}
                onPointerDown={(e) => { e.stopPropagation(); onPointerDown(e, n) }}
                onClick={pick}>
                <circle r={n.managed ? 13 : 9} fill={nodeColor(n)}
                  stroke={isSel ? 'var(--text)' : 'var(--bg)'} strokeWidth={isSel ? 3 : 2}
                  opacity={n.managed ? 1 : 0.7} />
                {n.managed && n.is_reachable === false &&
                  <circle r="17" fill="none" stroke="var(--bad)" strokeWidth="1.5"
                    strokeDasharray="2 2" />}
                {!n.managed &&
                  <text y="4" textAnchor="middle" fontSize="11" fill="var(--bg)">+</text>}
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
          <span className="legend-note">— komşuluk · ┄ LLDP · ⋯ L2 · ◆ uç cihaz
            &nbsp;·&nbsp; sürükle: taşı · tekerlek: yakınlaştır</span>
        </div>
      </div>

      <div className="map-summary hint">
        {managed} yönetilen cihaz · {devices.length - managed} yönetilmeyen komşu
        {endpoints.length > 0 && ` · ${endpoints.length} uç cihaz (ARP/MAC)`}.
      </div>

      {unmanaged.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h3>Yönetilmeyen komşular ({unmanaged.length})</h3>
            <span className="hint">LLDP/CDP ile görüldü, envanterde yok</span>
          </div>
          <table className="table">
            <thead><tr>
              <th>Cihaz</th><th>IP</th><th>Platform</th><th>Görüldüğü yer</th><th></th>
            </tr></thead>
            <tbody>
              {unmanaged.map((n) => {
                const ls = linksOf(n.id)
                return (
                  <tr key={n.id}>
                    <td><b>{n.id}</b></td>
                    <td>{n.ip_address || ls[0]?.remoteIp || '—'}</td>
                    <td className="muted">{ls[0]?.platform || '—'}</td>
                    <td>{ls.map((l) => `${l.peer}${l.remoteIf ? ` (${l.remoteIf})` : ''}`).join(', ') || '—'}</td>
                    <td className="right">
                      <button className="link" onClick={() => setSelected(n)}>detay</button>
                      {hasRole('operator') && onOnboard &&
                        <button onClick={() => onOnboard(onboardPayload(n))}>+ Envantere ekle</button>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

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
              </>
            )}
          </div>

          {selected.type !== 'endpoint' && (
            <>
              <h4 className="sub">Komşuluklar</h4>
              {linksOf(selected.id).length === 0
                ? <div className="hint">Bu cihaz için komşuluk kaydı yok.</div>
                : (
                  <table className="table">
                    <thead><tr>
                      <th>Yerel port</th><th>Komşu</th><th>Uzak port</th>
                      <th>Protokol</th><th>Komşu IP</th><th>Platform</th>
                    </tr></thead>
                    <tbody>
                      {linksOf(selected.id).map((l, i) => (
                        <tr key={i}>
                          <td><code>{l.localIf || '—'}</code></td>
                          <td><b>{l.peer}</b></td>
                          <td><code>{l.remoteIf || '—'}</code></td>
                          <td>{l.protocol || '—'}</td>
                          <td>{l.remoteIp || '—'}</td>
                          <td className="muted">{l.platform || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              {!selected.managed && hasRole('operator') && onOnboard && (
                <div className="actions" style={{ marginTop: 12 }}>
                  <button onClick={() => onOnboard(onboardPayload(selected))}>
                    + Envantere ekle
                  </button>
                  <span className="hint">Form hostname, IP ve tahmini vendor ile açılır.</span>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
