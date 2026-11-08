// Install codes (workers/src/routes/enrolment.ts): one code for many computers. Intune, GPO,
// a script or a container installs the agent with it, and each computer registers an agent
// of its own (a connection code is one agent's: shared, every computer would be that agent).
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Check, Copy, KeyRound, Plus, X } from 'lucide-react'
import client from '../../api/client'
import { agentApiUrl, makeInstallCode } from '../../utils/connectionCode'
import { formatSeen } from '../../utils/time'

const STATE = {
  active: ['Active', 'text-green-400 border-green-500/30 bg-green-500/10'],
  expired: ['Expired', 'text-dark-400 border-dark-600/40'],
  revoked: ['Withdrawn', 'text-dark-400 border-dark-600/40'],
  used_up: ['Used up', 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'],
}

function Copyable({ text, label }) {
  const [copied, setCopied] = useState(false)
  return (
    <button type="button" title={label} aria-label={label} className="p-1.5 rounded text-dark-400 hover:text-eagle-400"
      onClick={async () => { try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch { /* select by hand */ } }}>
      {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

export default function InstallCodesCard({ enabled }) {
  const [tokens, setTokens] = useState(null)
  const [creating, setCreating] = useState(false)
  const [made, setMade] = useState(null)              // {code, kind, name} shown once
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!enabled) return
    try { setTokens((await client.get('/enrolment/tokens')).data.tokens) } catch { setTokens([]) }
  }, [enabled])
  useEffect(() => { load() }, [load])
  if (!enabled) return null

  const revoke = async (t) => {
    if (!confirm(`Withdraw the install code "${t.name}"?\n\nComputers that already registered with it keep working; new installs with it are refused.`)) return
    try { await client.delete(`/enrolment/tokens/${t.token_id}`); await load() } catch (err) {
      setError(err?.response?.data?.detail || 'Could not withdraw the install code')
    }
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
            <KeyRound className="w-4 h-4 text-accent-cyan" /> Install codes
          </h2>
          <p className="text-xs text-dark-400 mt-0.5 max-w-3xl">
            One code for many computers: deploy the agent with Intune, Group Policy or a script, and each computer
            registers as an agent of its own. (A connection code from Register agent is for one computer only.)
          </p>
        </div>
        <button onClick={() => { setCreating(true); setMade(null) }} className="btn-primary text-sm flex items-center gap-2">
          <Plus className="w-4 h-4" /> New install code
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}
      {creating && <NewCode onClose={() => setCreating(false)} onMade={(m) => { setMade(m); setCreating(false); load() }} />}
      {made && <MadeCode made={made} onClose={() => setMade(null)} />}

      {tokens && tokens.length > 0 && (
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead><tr><th>Name</th><th>For</th><th>Used</th><th>Expires</th><th>State</th><th /></tr></thead>
            <tbody>
              {tokens.map((t) => {
                const [label, cls] = STATE[t.state] ?? STATE.expired
                return (
                  <tr key={t.token_id}>
                    <td className="text-sm text-dark-100">{t.name}</td>
                    <td className="text-sm">{t.kind === 'network' ? 'Network agents' : 'Computers'}</td>
                    <td className="text-sm">{t.uses}{t.max_uses ? ` of ${t.max_uses}` : ''}
                      {t.last_used_at && <span className="block text-[11px] text-dark-500">last {formatSeen(t.last_used_at).text}</span>}
                    </td>
                    <td className="text-sm">{new Date(t.expires_at).toLocaleDateString()}</td>
                    <td><span className={`px-2 py-0.5 rounded-full border text-[11px] ${cls}`}>{label}</span></td>
                    <td>{t.state === 'active' && (
                      <button onClick={() => revoke(t)} className="text-xs text-dark-400 hover:text-red-400">Withdraw</button>
                    )}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {tokens && tokens.length === 0 && !made && <p className="text-sm text-dark-500">No install codes yet.</p>}
    </div>
  )
}

function NewCode({ onClose, onMade }) {
  const [name, setName] = useState('')
  const [kind, setKind] = useState('host')
  const [days, setDays] = useState(14)
  const [maxUses, setMaxUses] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      const { data } = await client.post('/enrolment/tokens', {
        name: name.trim(), kind, days: Number(days), max_uses: maxUses === '' ? null : Number(maxUses),
      })
      onMade({ ...data, code: makeInstallCode({ apiUrl: agentApiUrl(client.defaults.baseURL), token: data.token }) })
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not create the install code')
    } finally { setBusy(false) }
  }
  return (
    <form onSubmit={submit} className="rounded-lg border border-dark-700/60 p-4 space-y-3">
      <div className="grid sm:grid-cols-4 gap-3">
        <label className="text-xs text-dark-400 space-y-1 sm:col-span-2">Name
          <input className="input-field text-sm w-full" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100}
            placeholder="e.g. Finance laptops (Intune)" />
        </label>
        <label className="text-xs text-dark-400 space-y-1">For
          <select className="input-field text-sm w-full" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="host">Computers</option>
            <option value="network">Network agents</option>
          </select>
        </label>
        <label className="text-xs text-dark-400 space-y-1">Valid for (days)
          <input type="number" min={1} max={90} className="input-field text-sm w-full" value={days} onChange={(e) => setDays(e.target.value)} />
        </label>
        <label className="text-xs text-dark-400 space-y-1">At most (computers)
          <input type="number" min={1} className="input-field text-sm w-full" value={maxUses} onChange={(e) => setMaxUses(e.target.value)}
            placeholder="no limit" />
        </label>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      <div className="flex gap-2 justify-end">
        <button type="button" onClick={onClose} className="btn-secondary text-sm">Cancel</button>
        <button type="submit" disabled={busy || !name.trim()} className="btn-primary text-sm">{busy ? 'Creating…' : 'Create'}</button>
      </div>
    </form>
  )
}

function MadeCode({ made, onClose }) {
  const network = made.kind === 'network'
  const commands = network ? [
    ['Docker', `docker run -d --name eagleeye-network-agent --restart unless-stopped \\\n  -e EAGLEEYE_CONNECTION_CODE_FILE=/run/secrets/connection_code ... eagleeye-network-agent`],
    ['Linux service', 'sudo python3 -m eagleeye service enrol --kind network --connection-code-file code.txt'],
  ] : [
    ['Intune / script (silent)', `EagleEyeAgent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CONNECTIONCODE=${made.code}`],
    ['Group Policy (code in a file on a share)', 'EagleEyeAgent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CONNECTIONCODEFILE=\\\\server\\share\\eagleeye-code.txt'],
    ['Linux', 'sudo python3 -m eagleeye service enrol --connection-code-file code.txt'],
  ]
  return (
    <div className="rounded-lg border border-eagle-500/40 bg-eagle-500/5 p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm text-dark-100">
          Install code <span className="font-medium">{made.name}</span>: copy it now, it is not shown again.
          Anyone with it can register {network ? 'network agents' : 'computers'} in this tenant until it expires
          {made.max_uses ? ` or ${made.max_uses} have registered` : ''}: keep it like a password.
        </p>
        <button onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-4 h-4" /></button>
      </div>
      <div className="flex items-center gap-2 bg-dark-900/60 rounded-lg p-2">
        <code className="text-xs font-mono text-dark-100 break-all flex-1">{made.code}</code>
        <Copyable text={made.code} label="Copy install code" />
      </div>
      <div className="space-y-2">
        {commands.map(([title, cmd]) => (
          <div key={title}>
            <p className="text-[11px] uppercase tracking-wide text-dark-500">{title}</p>
            <div className="flex items-start gap-2">
              <code className="text-xs font-mono text-dark-300 break-all whitespace-pre-wrap flex-1">{cmd}</code>
              <Copyable text={cmd} label={`Copy the ${title} command`} />
            </div>
          </div>
        ))}
        <p className="text-[11px] text-dark-500">
          Exit code 10 from the installer means it installed but could not register (an expired or used-up code, or no
          connection to the server). Reinstalling keeps the agent a computer already has.
        </p>
      </div>
    </div>
  )
}
