// Add / Edit / CSV-import modals for the Inventory page.
// Copied unchanged from MyAssetsPage.jsx, which keeps its own copies until the old
// pages are retired; after that this file is the single source.
import { useState, useEffect, useRef } from 'react'
import { Plus, X, Save, ToggleLeft, ToggleRight, Upload, Download, FileText } from 'lucide-react'
import client from '../../api/client'

// ── Add Asset Modal ───────────────────────────────────────────────
export function AddAssetModal({ onClose, onSave }) {
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

// ── Edit asset modal (owner, type, hostname, exposure) ────────────
export function EditAssetModal({ asset, onClose, onSave }) {
  const [form, setForm] = useState({
    owner: asset.owner ?? '',
    device_type: asset.deviceType ?? 'unknown',
    hostname: asset.hostname ?? '',
    is_internet_facing: !!asset.isInternetFacing,
  })
  const [updateBaseline, setUpdateBaseline] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  // Drift-tracked fields editable here that actually changed (owner is not tracked).
  const driftChanged =
    form.hostname !== (asset.hostname ?? '') ||
    form.device_type !== (asset.deviceType ?? 'unknown') ||
    form.is_internet_facing !== !!asset.isInternetFacing
  const showBaselineOption = driftChanged && !!asset.baselineState

  const set = (field) => (e) => setForm(f => ({ ...f, [field]: e.target?.value ?? e }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true); setError(null)
    try {
      await onSave({
        owner: form.owner,
        device_type: form.device_type,
        hostname: form.hostname,
        is_internet_facing: form.is_internet_facing,
        ...(showBaselineOption ? { update_baseline: updateBaseline } : {}),
      })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to save changes')
    } finally {
      setSaving(false)
    }
  }

  // Focus trap + Escape close — the Edit button is the single entry point.
  const modalRef = useRef(null)
  useEffect(() => {
    const el = modalRef.current
    if (!el) return
    const focusables = () => Array.from(
      el.querySelectorAll('button, input, select, textarea, [href], [tabindex]:not([tabindex="-1"])'),
    ).filter((n) => !n.disabled && n.offsetParent !== null)
    focusables()[0]?.focus()
    const onKey = (ev) => {
      if (ev.key === 'Escape') { ev.preventDefault(); onClose(); return }
      if (ev.key !== 'Tab') return
      const f = focusables()
      if (f.length === 0) return
      const first = f[0], last = f[f.length - 1]
      if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus() }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus() }
    }
    el.addEventListener('keydown', onKey)
    return () => el.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="edit-asset-title" className="glass-card w-full max-w-md p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <div>
            <h2 id="edit-asset-title" className="text-lg font-semibold text-white">Edit Asset</h2>
            <p className="font-mono text-xs text-accent-cyan mt-0.5">{asset.ipAddress}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="text-dark-400 hover:text-dark-100 transition-colors"><X className="w-5 h-5" /></button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Hostname</label>
            <input type="text" value={form.hostname} onChange={set('hostname')} placeholder="workstation-01" className="input-field w-full text-sm" />
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
            <label className="block text-xs text-dark-400 mb-1">Owner</label>
            <input type="text" value={form.owner} onChange={set('owner')} placeholder="IT Dept / john.doe@company.com" className="input-field w-full text-sm" />
          </div>
          <div className="flex items-center justify-between py-1">
            <label className="text-sm text-dark-300">Internet Facing</label>
            <button type="button" role="switch" aria-checked={form.is_internet_facing} aria-label="Internet facing"
              onClick={() => setForm(f => ({ ...f, is_internet_facing: !f.is_internet_facing }))}
              className="text-dark-400 hover:text-dark-100 transition-colors">
              {form.is_internet_facing ? <ToggleRight className="w-7 h-7 text-eagle-400" /> : <ToggleLeft className="w-7 h-7" />}
            </button>
          </div>

          {/* Read-only — criticality is changed only via Rescore, not inline here. */}
          <div className="rounded-lg border border-dark-700/70 bg-dark-900/40 px-3 py-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs text-dark-400">Criticality <span className="text-dark-400">(read-only)</span></span>
              <span className="text-sm font-semibold text-dark-100">{asset.criticalityScore}/10</span>
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-dark-300">
              Computed from device type, exposure and topology. Use <span className="text-dark-200">Rescore this asset</span> to refresh.
            </p>
          </div>

          {showBaselineOption && (
            <div className="rounded-lg border border-dark-700/70 bg-dark-900/30 p-3">
              <label className="flex items-start gap-2 text-xs text-dark-200 cursor-pointer">
                <input type="checkbox" checked={updateBaseline} onChange={(e) => setUpdateBaseline(e.target.checked)} className="mt-0.5 accent-eagle-500" />
                <span>Also update the baseline for the fields I changed</span>
              </label>
              <p className="mt-1.5 text-[11px] leading-relaxed text-dark-300">
                Unchecked, the next drift audit will flag this change as drift.
              </p>
            </div>
          )}

          <div className="flex gap-3 pt-1">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── CSV Import Modal ──────────────────────────────────────────────
const TEMPLATE_HEADERS = [
  'ip_address', 'hostname', 'mac_address', 'owner',
  'device_type', 'criticality_score', 'criticality_status', 'is_internet_facing',
  'hardware_vendor', 'os_name', 'os_version', 'open_ports',
]
const TEMPLATE_SAMPLE = [
  ['192.168.1.1', 'router-01', 'AA:BB:CC:11:22:33', 'Network Team / netops@corp.com',
   'network', '9', 'Critical', 'true', 'Cisco', 'IOS XE', '16.9', '22/tcp 23/tcp 443/tcp'],
  ['192.168.1.10', 'server-01', 'AA:BB:CC:44:55:66', 'IT Dept / admin@corp.com',
   'server', '8', 'High', 'false', 'Dell', 'Ubuntu', '22.04', '22/tcp 80/tcp 443/tcp 3306/tcp'],
  ['192.168.1.50', 'workstation-01', '', 'HR Dept / alice@corp.com',
   'workstation', '4', 'Medium', 'false', 'HP', 'Windows', '11', '3389/tcp'],
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

export function ImportModal({ onClose, onImport, tenantId }) {
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

  const DISPLAY_COLS = ['ip_address', 'hostname', 'device_type', 'criticality_score', 'criticality_status', 'owner', 'os_name', 'open_ports']
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
