import { useState, useEffect, useCallback } from 'react'
import { Plus, Search, Trash2, Bookmark, X, Server, Save, ToggleLeft, ToggleRight, Upload, Download, FileText, Building2 } from 'lucide-react'
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

// ── CSV Import Modal ──────────────────────────────────────────────
const TEMPLATE_HEADERS = [
  'ip_address', 'hostname', 'mac_address', 'owner',
  'device_type', 'criticality_score', 'is_internet_facing',
  'hardware_vendor', 'os_name', 'os_version', 'open_ports',
]
const TEMPLATE_SAMPLE = [
  ['192.168.1.1', 'router-01', 'AA:BB:CC:11:22:33', 'Network Team / netops@corp.com',
   'network', '9', 'true', 'Cisco', 'IOS XE', '16.9', '22/tcp 23/tcp 443/tcp'],
  ['192.168.1.10', 'server-01', 'AA:BB:CC:44:55:66', 'IT Dept / admin@corp.com',
   'server', '8', 'false', 'Dell', 'Ubuntu', '22.04', '22/tcp 80/tcp 443/tcp 3306/tcp'],
  ['192.168.1.50', 'workstation-01', '', 'HR Dept / alice@corp.com',
   'workstation', '4', 'false', 'HP', 'Windows', '11', '3389/tcp'],
]

function parseCSVLine(line) {
  const result = []
  let current = ''
  let inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++ }
      else { inQuotes = !inQuotes }
    } else if (ch === ',' && !inQuotes) {
      result.push(current.trim()); current = ''
    } else {
      current += ch
    }
  }
  result.push(current.trim())
  return result
}

function ImportModal({ onClose, onImport, tenantId }) {
  const [file, setFile] = useState(null)
  const [headers, setHeaders] = useState([])
  const [preview, setPreview] = useState([])
  const [importing, setImporting] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const downloadTemplate = () => {
    const escape = (v) => (v.includes(',') || v.includes(' ') ? `"${v}"` : v)
    const rows = [TEMPLATE_HEADERS, ...TEMPLATE_SAMPLE].map(r => r.map(escape).join(','))
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'assets_import_template.csv'
    document.body.appendChild(a); a.click()
    document.body.removeChild(a); URL.revokeObjectURL(url)
  }

  const handleFileChange = (e) => {
    const f = e.target.files?.[0]
    if (!f) return
    setFile(f); setResult(null); setError(null)
    const reader = new FileReader()
    reader.onload = (ev) => {
      const lines = ev.target.result.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
      if (lines.length < 2) { setError('File must have a header row and at least one data row'); return }
      const hdrs = parseCSVLine(lines[0]).map(h => h.toLowerCase().replace(/\s+/g, '_'))
      const rows = lines.slice(1, 6).map(line => {
        const cols = parseCSVLine(line)
        const row = {}
        hdrs.forEach((h, i) => { row[h] = cols[i] ?? '' })
        return row
      })
      setHeaders(hdrs); setPreview(rows)
    }
    reader.readAsText(f)
  }

  const handleImport = async () => {
    if (!file) return
    setImporting(true); setError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const url = tenantId ? `/assets/import?tenant_id=${tenantId}` : '/assets/import'
      const res = await client.post(url, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setResult(res.data)
      await onImport()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  const DISPLAY_COLS = ['ip_address', 'hostname', 'device_type', 'criticality_score', 'owner', 'os_name', 'open_ports']
  const visibleHeaders = headers.filter(h => DISPLAY_COLS.includes(h))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-3xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Import Assets via CSV</h2>
            <p className="text-xs text-dark-400 mt-0.5">
              {tenantId ? <span>Importing into <span className="text-eagle-400">selected tenant</span></span> : 'Bulk import assets with OS, port and criticality data'}
            </p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Template download */}
        <div className="flex items-center justify-between p-3 bg-dark-800/60 border border-dark-700/40 rounded-xl">
          <div className="flex items-center gap-3">
            <FileText className="w-5 h-5 text-eagle-400 flex-shrink-0" />
            <div>
              <p className="text-sm text-white font-medium">Download CSV Template</p>
              <p className="text-xs text-dark-400">Includes sample rows with all supported columns</p>
            </div>
          </div>
          <button onClick={downloadTemplate} className="btn-secondary text-sm flex items-center gap-2">
            <Download className="w-4 h-4" />
            Template
          </button>
        </div>

        {/* Supported columns hint */}
        <div className="p-3 bg-dark-800/40 rounded-xl border border-dark-700/30">
          <p className="text-xs text-dark-400 mb-1.5 font-medium">Supported columns</p>
          <div className="flex flex-wrap gap-1.5">
            {TEMPLATE_HEADERS.map(h => (
              <span key={h} className={`text-xs px-2 py-0.5 rounded font-mono ${h === 'ip_address' ? 'bg-eagle-500/20 text-eagle-400 border border-eagle-500/30' : 'bg-dark-700/60 text-dark-300'}`}>
                {h}{h === 'ip_address' && ' *'}
              </span>
            ))}
          </div>
          <p className="text-xs text-dark-500 mt-2">
            <span className="text-eagle-400">open_ports</span>: space or comma-separated (e.g. <code className="font-mono">22/tcp 80/tcp 443/tcp</code>)
          </p>
        </div>

        {/* File input */}
        <div>
          <label className="block text-xs text-dark-400 mb-2">Select CSV File</label>
          <input
            type="file"
            accept=".csv,text/csv"
            onChange={handleFileChange}
            className="block w-full text-sm text-dark-300
              file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0
              file:text-sm file:font-medium file:bg-eagle-500/20 file:text-eagle-400
              hover:file:bg-eagle-500/30 cursor-pointer"
          />
        </div>

        {/* Preview table */}
        {preview.length > 0 && !result && (
          <div>
            <p className="text-xs text-dark-400 mb-2">Preview — first {preview.length} row(s)</p>
            <div className="overflow-x-auto rounded-xl border border-dark-700/40">
              <table className="w-full text-xs">
                <thead className="bg-dark-800/80">
                  <tr>
                    {visibleHeaders.map(h => (
                      <th key={h} className="px-3 py-2 text-left text-dark-400 font-medium whitespace-nowrap">
                        {h.replace(/_/g, ' ')}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {preview.map((row, i) => (
                    <tr key={i} className="border-t border-dark-700/30">
                      {visibleHeaders.map(h => (
                        <td key={h} className="px-3 py-2 text-dark-300 max-w-[150px] truncate" title={row[h]}>
                          {row[h] || <span className="text-dark-600">—</span>}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>
        )}

        {/* Result */}
        {result && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-xl text-center">
                <p className="text-3xl font-bold text-green-400">{result.imported}</p>
                <p className="text-xs text-dark-400 mt-1">New assets created</p>
              </div>
              <div className="p-4 bg-eagle-500/10 border border-eagle-500/30 rounded-xl text-center">
                <p className="text-3xl font-bold text-eagle-400">{result.updated}</p>
                <p className="text-xs text-dark-400 mt-1">Existing assets updated</p>
              </div>
            </div>
            {result.errors?.length > 0 && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl">
                <p className="text-xs font-medium text-red-400 mb-2">{result.errors.length} row(s) skipped:</p>
                <div className="space-y-0.5 max-h-32 overflow-y-auto">
                  {result.errors.map((e, i) => (
                    <p key={i} className="text-xs text-dark-400 font-mono">{e}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Buttons */}
        <div className="flex gap-3 pt-1">
          <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">
            {result ? 'Done' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={handleImport}
              disabled={!file || importing}
              className="btn-primary flex-1 text-sm flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {importing
                ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                : <Upload className="w-4 h-4" />
              }
              {importing ? 'Importing…' : 'Import Assets'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function MyAssetsPage() {
  const { user } = useAuth()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [tenantFilter, setTenantFilter] = useState('')
  const [tenants, setTenants] = useState([])
  const [showAdd, setShowAdd] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [error, setError] = useState(null)

  const isReadOnly = user?.role === 'business_owner'
  const canDelete = ['ops_lead', 'superadmin'].includes(user?.role)

  // Fetch tenant list for superadmin filter
  useEffect(() => {
    if (user?.role === 'superadmin') {
      client.get('/tenants')
        .then(res => setTenants(res.data.tenants || []))
        .catch(() => {})
    }
  }, [user?.role])

  const loadAssets = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = { source: 'manual' }
      if (search) params.search = search
      if (tenantFilter) params.tenant_id = tenantFilter
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load assets')
    } finally {
      setLoading(false)
    }
  }, [search, tenantFilter])

  useEffect(() => { loadAssets() }, [loadAssets])

  const handleAddAsset = async (form) => {
    const payload = { ...form, source: 'manual', ...(tenantFilter ? { tenant_id: tenantFilter } : {}) }
    await client.post('/assets', payload)
    await loadAssets()
  }

  const handleImportDone = async () => {
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
        a.ipAddress?.includes(search) ||
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
          <div className="flex items-center gap-2">
            <button onClick={() => setShowImport(true)} className="btn-secondary flex items-center gap-2">
              <Upload className="w-4 h-4" />
              Import CSV
            </button>
            <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Add Asset
            </button>
          </div>
        )}
      </div>

      {/* Search + Tenant filter */}
      <div className="flex items-center gap-3 flex-wrap">
        {user?.role === 'superadmin' && tenants.length > 0 && (
          <div className="relative">
            <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400 pointer-events-none" />
            <select
              value={tenantFilter}
              onChange={(e) => setTenantFilter(e.target.value)}
              className="input-field pl-9 pr-8 text-sm appearance-none min-w-[180px]"
            >
              <option value="">All Tenants</option>
              {tenants.map((t) => (
                <option key={t.tenant_id} value={t.tenant_id}>{t.name}</option>
              ))}
            </select>
          </div>
        )}
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
          <input
            type="text"
            placeholder="Search by IP or hostname..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field w-full pl-10 text-sm"
          />
        </div>
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
                <tr key={a.assetId}>
                  <td className="font-mono text-sm text-accent-cyan">{a.ipAddress}</td>
                  <td className="font-medium text-white">{a.hostname || '—'}</td>
                  <td>
                    <span className="text-xs text-dark-300 capitalize">{a.deviceType}</span>
                  </td>
                  <td>
                    <EditableCell
                      value={a.owner}
                      readOnly={isReadOnly}
                      onSave={(v) => handleUpdate(a.assetId, 'owner', v)}
                    />
                  </td>
                  <td>
                    {isReadOnly ? (
                      <CriticalityBadge score={a.criticalityScore} />
                    ) : (
                      <div className="flex items-center gap-2">
                        <CriticalityBadge score={a.criticalityScore} />
                        <input
                          type="range"
                          min="1"
                          max="10"
                          value={a.criticalityScore}
                          onChange={(e) => handleUpdate(a.assetId, 'criticality_score', Number(e.target.value))}
                          className="w-20 accent-eagle-500"
                        />
                      </div>
                    )}
                  </td>
                  <td>
                    {a.isInternetFacing
                      ? <span className="text-xs text-yellow-400 font-medium">Yes</span>
                      : <span className="text-xs text-dark-500">No</span>
                    }
                  </td>
                  <td className="text-dark-400 text-xs">
                    {a.lastScanned ? new Date(a.lastScanned).toLocaleString() : '—'}
                  </td>
                  <td>
                    <div className="flex items-center gap-1">
                      {!isReadOnly && (
                        <button
                          onClick={() => handleBaseline(a.assetId)}
                          className={`p-1.5 rounded transition-colors ${a.baselineState ? 'text-eagle-400 hover:bg-eagle-500/10' : 'text-dark-400 hover:bg-dark-700'}`}
                          title="Set Baseline"
                        >
                          <Bookmark className="w-4 h-4" />
                        </button>
                      )}
                      {canDelete && (
                        <button
                          onClick={() => handleDelete(a.assetId)}
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

      {/* Import Modal */}
      {showImport && (
        <ImportModal
          onClose={() => setShowImport(false)}
          onImport={handleImportDone}
          tenantId={tenantFilter || undefined}
        />
      )}
    </div>
  )
}
