// Bağımlılıksız SVG grafikler (donut + yatay bar). Enterprise panel hissi
// için hafif ve tema-uyumlu.

export function Donut({ segments, size = 140, thickness = 18, centerLabel, centerSub }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1
  const r = (size - thickness) / 2
  const c = 2 * Math.PI * r
  let offset = 0
  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none"
            stroke="var(--border-soft)" strokeWidth={thickness} />
          {segments.map((seg, i) => {
            const len = (seg.value / total) * c
            const el = (
              <circle key={i} cx={size / 2} cy={size / 2} r={r} fill="none"
                stroke={seg.color} strokeWidth={thickness}
                strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
                style={{ transition: 'stroke-dasharray .5s ease' }} />
            )
            offset += len
            return el
          })}
        </g>
        {centerLabel !== undefined && (
          <text x="50%" y="47%" textAnchor="middle" fontSize="26" fontWeight="700"
            fill="var(--text)">{centerLabel}</text>
        )}
        {centerSub && (
          <text x="50%" y="62%" textAnchor="middle" fontSize="11"
            fill="var(--muted)">{centerSub}</text>
        )}
      </svg>
      <div className="donut-legend">
        {segments.map((seg, i) => (
          <div key={i} className="legend-row">
            <span className="dot" style={{ background: seg.color }} />
            <span className="legend-label">{seg.label}</span>
            <span className="legend-value">{seg.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function BarList({ items, unit = '' }) {
  const max = Math.max(1, ...items.map((i) => i.value))
  return (
    <div className="barlist">
      {items.map((it, i) => (
        <div key={i} className="bar-row">
          <span className="bar-label">{it.label}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{
              width: `${(it.value / max) * 100}%`,
              background: it.color || 'var(--accent)',
            }} />
          </div>
          <span className="bar-value">{it.value}{unit}</span>
        </div>
      ))}
      {items.length === 0 && <p className="empty">Veri yok.</p>}
    </div>
  )
}
