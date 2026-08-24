import { useState } from 'react'
import { getRole, hasRole, setToken } from './api.js'
import Login from './components/Login.jsx'
import Overview from './components/Overview.jsx'
import Assets from './components/Assets.jsx'
import Advisories from './components/Advisories.jsx'
import Remediations from './components/Remediations.jsx'
import Discovery from './components/Discovery.jsx'
import TopologyMap from './components/TopologyMap.jsx'
import Jobs from './components/Jobs.jsx'
import Chat from './components/Chat.jsx'
import Admin from './components/Admin.jsx'
import Integrations from './components/Integrations.jsx'
import Settings from './components/Settings.jsx'

const NAV = [
  { id: 'overview', label: 'Genel Bakış', icon: '▦', group: 'İzleme' },
  { id: 'assets', label: 'Cihazlar', icon: '▤', group: 'İzleme' },
  { id: 'advisories', label: 'Güvenlik Bulguları', icon: '⚠', group: 'İzleme' },
  { id: 'discovery', label: 'Ağ Keşfi', icon: '◎', group: 'İşlemler' },
  { id: 'topology', label: 'Ağ Haritası', icon: '⧉', group: 'İzleme' },
  { id: 'remediations', label: 'Onay Akışı', icon: '✓', group: 'İşlemler' },
  { id: 'jobs', label: 'İşlem Geçmişi', icon: '≡', group: 'İşlemler' },
  { id: 'chat', label: 'AI Asistan', icon: '✦', group: 'İşlemler' },
  { id: 'admin', label: 'Yönetim', icon: '⚙', group: 'Sistem', role: 'operator' },
  { id: 'settings', label: 'Ayarlar', icon: '⚙', group: 'Sistem', role: 'admin' },
  { id: 'integrations', label: 'Entegrasyonlar & API', icon: '⧉', group: 'Sistem', role: 'admin' },
]

export default function App() {
  const [authed, setAuthed] = useState(false)
  const [view, setView] = useState('overview')
  const [selectedAsset, setSelectedAsset] = useState(null)
  // Haritadaki yönetilmeyen komşuyu envantere eklerken formu ön dolduran veri
  const [assetPrefill, setAssetPrefill] = useState(null)

  if (!authed) return <Login onLogin={() => { setAuthed(true); setView('overview') }} />

  const logout = () => { setToken(null); setAuthed(false) }
  const go = (id, asset = null) => { setView(id); setSelectedAsset(asset) }

  const visibleNav = NAV.filter((n) => !n.role || hasRole(n.role))
  const groups = [...new Set(visibleNav.map((n) => n.group))]
  const current = NAV.find((n) => n.id === view)

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo-mark">N</div>
          <div>
            <div className="brand-name">NABS-GP</div>
            <div className="brand-sub">Network Governance</div>
          </div>
        </div>
        <nav className="side-nav">
          {groups.map((g) => (
            <div key={g} className="nav-group">
              <div className="nav-group-title">{g}</div>
              {visibleNav.filter((n) => n.group === g).map((n) => (
                <button key={n.id} className={`nav-item ${view === n.id ? 'active' : ''}`}
                  onClick={() => go(n.id)}>
                  <span className="nav-icon">{n.icon}</span>{n.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <div className="user-chip">rol: <b>{getRole()}</b></div>
          <button className="secondary" onClick={logout}>Çıkış</button>
        </div>
      </aside>

      <div className="main-col">
        <header className="topbar">
          <div className="crumb"><span className="crumb-icon">{current?.icon}</span>{current?.label}</div>
        </header>
        <main className="content">
          {view === 'overview' && <Overview onNavigate={go} />}
          {view === 'assets' && <Assets onShowAdvisories={(a) => go('advisories', a)}
            prefill={assetPrefill} onPrefillUsed={() => setAssetPrefill(null)} />}
          {view === 'advisories' && <Advisories asset={selectedAsset} />}
          {view === 'discovery' && <Discovery />}
          {view === 'topology' && <TopologyMap
            onOnboard={(p) => { setAssetPrefill(p); setView('assets') }} />}
          {view === 'remediations' && <Remediations />}
          {view === 'jobs' && <Jobs />}
          {view === 'chat' && <Chat />}
          {view === 'admin' && <Admin />}
          {view === 'settings' && <Settings />}
          {view === 'integrations' && <Integrations />}
        </main>
      </div>
    </div>
  )
}
