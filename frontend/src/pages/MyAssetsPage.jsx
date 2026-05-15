import { useState, useEffect, useCallback } from 'react'
import { Plus, Search, Trash2, Bookmark, X, Server, Save, ToggleLeft, ToggleRight } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Criticality badge ─────────────────────────────────────────────
function CriticalityBadge({ score }) {
  const s = Number(score)
  let cls = 'bg-green-500/20 text-green-400 border-green-500/30'
  if (s >= 9) cls = 'bg-red-500/20 text-red-400 border-red-500/30'
  else if (s >= 7) cls = 'bg-orange-500/20 text-orange-400 border-orange-500/30'
  else if (s >= 4) cls = 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${cls}`}>
      {s}/10
    </span>
  )
}

// ── Add Asset Modal ───────────────────────────────────────────────
function AddAssetModal({ onClose, onSave }) {
  const [form, setForm] = useState({
    ip_address: '',
    hostname: '',
    mac_address: '',
    owner: '',
    device_type: 'unknown',
    criticality_score: 5,
    is_internet_facing: false,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.ip_address.trim()) { setError('IP address is required'); return }
    setSaving(true)
    setError(null)
    try {
      await onSave(form)
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to create asset')
    } finally {
      setSaving(false)
    }
  }

  const set = (field) => (e) => setForm(f => ({ ...f, [field]: e.target?.value ?? e }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Add Asset</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">IP Address *</label>
            <input
              type="text"
              value={form.ip_address}
              onChange={set('ip_address')}
              placeholder="192.168.1.10"
              className="input-field w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Hostname</label>
            <input
              type="text"
              value={form.hostname}
              onChange={set('hostname')}
              placeholder="workstation-01"
              className="input-field w-full text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">MAC Address</label>
            <input
              type="text"
              value={form.mac_address}
              onChange={set('mac_address')}
              placeholder="AA:BB:CC:DD:EE:FF"
              className="input-field w-full text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Owner</label>
            <input
              type="text"
              value={form.owner}
              onChange={set('owner')}
              placeholder="IT Dept / john.doe@company.com"
              className="input-field w-full text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Device Type</label>
            <select value={form.device_type} onChange={set('device_type')} className="input-field w-full text-sm">
              <option value="unknown">Unknown</option>
              <option value="server">Server</option>
              <option value="workstation">Workstation</option>
              <option value="network">Network Device</option>
              <option value="iot">IoT</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">
              Criticality Score: <span className="text-white font-medium">{form.criticality_score}</span>
            </label>
            <input
              type="range"
              min="1"
              max="10"
              value={form.criticality_score}
              onChange={(e) => setForm(f => ({ ...f, criticality_score: Number(e.target.value) }))}
              className="w-full accent-eagle-500"
            />
            <div className="flex justify-between text-xs text-dark-500 mt-0.5">
              <span>1 Low</span>
              <span>10 Critical</span>
            </div>
          </div>

          <div className="flex items-center justify-between py-2">
            <label className="text-sm text-dark-300">Internet Facing</label>
            <button
              type="button"
              onClick={() => setForm(f => ({ ...f, is_internet_facing: !f.is_internet_facing }))}
              className="text-dark-400 hover:text-white transition-colors"
            >
              {form.is_internet_facing
                ? <ToggleRight className="w-7 h-7 text-eagle-400" />
                : <ToggleLeft className="w-7 h-7" />
              }
            </button>
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-4 h-4" />}
              Add Asset
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Inline edit cell for owner / criticality ──────────────────────
function EditableCell({ value, type = 'text', onSave, readOnly }) {
  const [editing, setEditing] = useState(false)
  const [local, setLocal] = useState(value)

  if (readOnly || !editing) {
    return (
      <span
        onClick={() => !readOnly && setEditing(true)}
        className={`cursor-pointer text-sm ${readOnly ? '' : 'hover:text-white underline decoration-dotted decoration-dark-500'}`}
        title={readOnly ? '' : 'Click to edit'}
      >
        {value || <span className="text-dark-500">—</span>}
      </span>
    )
  }

  return (
    <div className="flex items-center gap-1">
      <input
        autoFocus
        type={type}
        value={local}
        onChange={(e) => setLocal(e.target.value)}
        className="input-field text-sm py-0.5 px-2 w-32"
        onKeyDown={(e) => {
          if (e.key === 'Enter') { onSave(local); setEditing(false) }
          if (e.key === 'Escape') { setLocal(value); setEditing(false) }
        }}
      />
      <button
        onClick={() => { onSave(local); setEditing(false) }}
        className="p-1 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors"
      >
        <Save className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function MyAssetsPage() {
  const { user } = useAuth()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [showAdd, setShowAdd] = useState(false)
  const [error, setError] = useState(null)

  const isReadOnly = user?.role === 'business_owner'
  const canDelete = ['ops_lead', 'superadmin'].includes(user?.role)

  const loadAssets = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = { source: 'manual' }
      if (search) params.search = search
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load assets')
    } finally {
      setLoading(false)
    }
  }, [search])

  useEffect(() => { loadAssets() }, [loadAssets])

  const handleAddAsset = async (form) => {
    await client.post('/assets', form)
    await loadAssets()
  }

  const handleUpdate = async (assetId, field, value) => {
    try {
      await client.patch(`/assets/${assetId}`, { [field]: value })
      setAssets(prev => prev.map(a => a.asset_id === assetId ? { ...a, [field]: value } : a))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Update failed')
    }
  }

  const handleBaseline = async (assetId) => {
    if (!confirm('Set current state as baseline? This will overwrite any existing baseline.')) return
    try {
      await client.post(`/assets/${assetId}/baseline`, { confirm: true })
      alert('Baseline set successfully.')
      await loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to set baseline')
    }
  }

  const handleDelete = async (assetId) => {
    if (!confirm('Delete this asset permanently?')) return
    try {
      await client.delete(`/assets/${assetId}`)
      setAssets(prev => prev.filter(a => a.asset_id !== assetId))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete asset')
    }
  }

  // Filter by search
  const filtered = search
    ? assets.filter(a =>
        a.ip_address?.includes(search) ||
        a.hostname?.toLowerCase().includes(search.toLowerCase())
      )
    : assets

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">My Assets</h1>
          <p className="text-dark-400 text-sm mt-1">Manually managed asset inventory</p>
        </div>
        {!isReadOnly && (
          <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Add Asset
          </button>
        )}
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
        <input
          type="text"
          placeholder="Search by IP or hostname..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field w-full pl-10 text-sm"
        />
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadAssets} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : filtered.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Device Type</th>
                <th>Owner</th>
                <th>Criticality</th>
                <th>Internet Facing</th>
                <th>Last Scanned</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => (
                <tr key={a.asset_id}>
                  <td className="font-mono text-sm text-accent-cyan">{a.ip_address}</td>
                  <td className="font-medium text-white">{a.hostname || '—'}</td>
                  <td>
                    <span className="text-xs text-dark-300 capitalize">{a.device_type}</span>
                  </td>
                  <td>
                    <EditableCell
                      value={a.owner}
                      readOnly={isReadOnly}
                      onSave={(v) => handleUpdate(a.asset_id, 'owner', v)}
                    />
                  </td>
                  <td>
                    {isReadOnly ? (
                      <CriticalityBadge score={a.criticality_score} />
                    ) : (
                      <div className="flex items-center gap-2">
                        <CriticalityBadge score={a.criticality_score} />
                        <input
                          type="range"
                          min="1"
                          max="10"
                          value={a.criticality_score}
                          onChange={(e) => handleUpdate(a.asset_id, 'criticality_score', Number(e.target.value))}
                          className="w-20 accent-eagle-500"
                        />
                      </div>
                    )}
                  </td>
                  <td>
                    {a.is_internet_facing
                      ? <span className="text-xs text-yellow-400 font-medium">Yes</span>
                      : <span className="text-xs text-dark-500">No</span>
                    }
                  </td>
                  <td className="text-dark-400 text-xs">
                    {a.last_scanned ? new Date(a.last_scanned).toLocaleString() : '—'}
                  </td>
                  <td>
                    <div className="flex items-center gap-1">
                      {!isReadOnly && (
                        <button
                          onClick={() => handleBaseline(a.asset_id)}
                          className={`p-1.5 rounded transition-colors ${a.baseline_state ? 'text-eagle-400 hover:bg-eagle-500/10' : 'text-dark-400 hover:bg-dark-700'}`}
                          title="Set Baseline"
                        >
                          <Bookmark className="w-4 h-4" />
                        </button>
                      )}
                      {canDelete && (
                        <button
                          onClick={() => handleDelete(a.asset_id)}
                          className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                          title="Delete Asset"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Server className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No manual assets found</p>
            <p className="text-sm mb-4">
              {search ? 'No assets match your search.' : 'Add assets manually to track them here.'}
            </p>
            {!isReadOnly && !search && (
              <button onClick={() => setShowAdd(true)} className="btn-primary">
                <Plus className="w-4 h-4 mr-2" />
                Add First Asset
              </button>
            )}
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAdd && (
        <AddAssetModal
          onClose={() => setShowAdd(false)}
          onSave={handleAddAsset}
        />
      )}
    </div>
  )
}
