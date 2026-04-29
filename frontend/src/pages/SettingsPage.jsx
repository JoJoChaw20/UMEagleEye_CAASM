import { useState, useEffect } from 'react'
import { Settings, Users, Shield, Clock, Key, Bell } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import client from '../api/client'

export default function SettingsPage() {
  const { user } = useAuth()
  const [mfaSetup, setMfaSetup] = useState(null)
  const [mfaCode, setMfaCode] = useState('')
  const [message, setMessage] = useState('')

  const setupMFA = async () => {
    try {
      const res = await client.post('/auth/mfa/setup')
      setMfaSetup(res.data)
    } catch (err) {
      setMessage(err.response?.data?.detail || 'MFA setup failed')
    }
  }

  const enableMFA = async () => {
    try {
      await client.post('/auth/mfa/enable', { username: user?.username, code: mfaCode })
      setMessage('✅ MFA enabled successfully!')
      setMfaSetup(null)
      setMfaCode('')
    } catch (err) {
      setMessage(err.response?.data?.detail || 'Invalid code')
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-2xl font-bold text-white">Settings</h1>

      {/* Profile */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Users className="w-5 h-5 text-eagle-400" />
          <h2 className="text-lg font-semibold text-white">Profile</h2>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-dark-400 mb-1">Username</p>
            <p className="text-white font-medium">{user?.username || '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Role</p>
            <p className="text-white font-medium">{user?.role?.replace('_', ' ') || '—'}</p>
          </div>
        </div>
      </div>

      {/* MFA */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-accent-green" />
          <h2 className="text-lg font-semibold text-white">Multi-Factor Authentication</h2>
        </div>
        {message && <p className="text-sm mb-3 text-accent-cyan">{message}</p>}

        {!mfaSetup ? (
          <button onClick={setupMFA} className="btn-primary">Setup TOTP MFA</button>
        ) : (
          <div className="space-y-4">
            <p className="text-dark-300 text-sm">Scan this QR code with your authenticator app:</p>
            <div className="bg-white p-4 rounded-lg inline-block">
              <img src={`data:image/png;base64,${mfaSetup.qr_code_base64}`} alt="TOTP QR" className="w-48 h-48" />
            </div>
            <p className="text-dark-400 text-xs font-mono">Secret: {mfaSetup.totp_secret}</p>
            <div className="flex gap-2 max-w-xs">
              <input type="text" value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="input-field flex-1 text-center font-mono tracking-widest" placeholder="000000" maxLength={6} />
              <button onClick={enableMFA} disabled={mfaCode.length !== 6} className="btn-primary">Verify</button>
            </div>
          </div>
        )}
      </div>

      {/* System config */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Clock className="w-5 h-5 text-accent-amber" />
          <h2 className="text-lg font-semibold text-white">Scan Configuration</h2>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-dark-400 mb-1">Discovery Cycle</p>
            <p className="text-white font-mono">15 minutes</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Default Subnet</p>
            <p className="text-white font-mono">172.18.0.0/24</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Scan Rate Limit</p>
            <p className="text-white font-mono">1000 pps</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">SLA Threshold</p>
            <p className="text-white font-mono">4 hours (Critical)</p>
          </div>
        </div>
      </div>

      {/* API Keys Status */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-5 h-5 text-accent-purple" />
          <h2 className="text-lg font-semibold text-white">Integration Status</h2>
        </div>
        <div className="space-y-2 text-sm">
          {[
            { name: 'Gemini AI', status: true },
            { name: 'AlienVault OTX', status: true },
            { name: 'Telegram Bot', status: true },
            { name: 'Google Cloud Storage', status: true },
            { name: 'MyCERT STIX/TAXII', status: false },
            { name: 'NVD API', status: false },
          ].map(api => (
            <div key={api.name} className="flex items-center justify-between py-1.5 border-b border-dark-800/50">
              <span className="text-dark-300">{api.name}</span>
              <span className={api.status ? 'text-accent-green text-xs' : 'text-dark-500 text-xs'}>
                {api.status ? '● Connected' : '○ Not configured'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
