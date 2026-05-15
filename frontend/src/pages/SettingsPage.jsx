import { useState } from 'react'
import { Settings, Users, Shield, Clock, Key, Eye, EyeOff, Lock } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import client from '../api/client'

export default function SettingsPage() {
  const { user } = useAuth()

  // MFA state
  const [mfaSetup, setMfaSetup] = useState(null)
  const [mfaCode, setMfaCode] = useState('')
  const [mfaMessage, setMfaMessage] = useState('')

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [pwMessage, setPwMessage] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwLoading, setPwLoading] = useState(false)

  const setupMFA = async () => {
    try {
      const res = await client.post('/auth/mfa/setup')
      setMfaSetup(res.data)
      setMfaMessage('')
    } catch (err) {
      setMfaMessage(err.response?.data?.detail || 'MFA setup failed')
    }
  }

  const enableMFA = async () => {
    try {
      await client.post('/auth/mfa/enable', { username: user?.username, code: mfaCode })
      setMfaMessage('MFA enabled successfully!')
      setMfaSetup(null)
      setMfaCode('')
    } catch (err) {
      setMfaMessage(err.response?.data?.detail || 'Invalid code')
    }
  }

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setPwError('')
    setPwMessage('')
    if (newPassword !== confirmPassword) {
      setPwError('New passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      setPwError('New password must be at least 8 characters')
      return
    }
    setPwLoading(true)
    try {
      await client.post('/auth/change-password', {
        current_password: currentPassword,
        new_password: newPassword,
      })
      setPwMessage('Password changed successfully!')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      setPwError(err.response?.data?.detail || 'Failed to change password')
    } finally {
      setPwLoading(false)
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
            <p className="text-dark-400 mb-1">Email</p>
            <p className="text-white font-medium">{user?.email || '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Role</p>
            <p className="text-white font-medium capitalize">{user?.role?.replace(/_/g, ' ') || '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Tenant</p>
            <p className="text-white font-medium font-mono text-xs">{user?.tenant_id?.slice(0, 16) || '—'}...</p>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-5 h-5 text-accent-cyan" />
          <h2 className="text-lg font-semibold text-white">Change Password</h2>
        </div>

        {pwMessage && (
          <div className="mb-4 p-3 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-sm">
            {pwMessage}
          </div>
        )}
        {pwError && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            {pwError}
          </div>
        )}

        <form onSubmit={handleChangePassword} className="space-y-4 max-w-sm">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Current Password</label>
            <div className="relative">
              <input
                type={showCurrent ? 'text' : 'password'}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="input-field w-full pr-10"
                placeholder="Enter current password"
                required
              />
              <button type="button" onClick={() => setShowCurrent(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200">
                {showCurrent ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">New Password</label>
            <div className="relative">
              <input
                type={showNew ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="input-field w-full pr-10"
                placeholder="Minimum 8 characters"
                required
              />
              <button type="button" onClick={() => setShowNew(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200">
                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input-field w-full"
              placeholder="Re-enter new password"
              required
            />
          </div>
          <button type="submit" disabled={pwLoading} className="btn-primary flex items-center gap-2">
            {pwLoading
              ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Lock className="w-4 h-4" />}
            {pwLoading ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      </div>

      {/* MFA */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-accent-green" />
          <h2 className="text-lg font-semibold text-white">Multi-Factor Authentication</h2>
        </div>
        {mfaMessage && (
          <p className={`text-sm mb-3 ${mfaMessage.includes('success') ? 'text-accent-green' : 'text-red-400'}`}>
            {mfaMessage}
          </p>
        )}

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
          <h2 className="text-lg font-semibold text-white">Platform Configuration</h2>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-dark-400 mb-1">Drift Audit Cycle</p>
            <p className="text-white font-mono">Every 15 minutes</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">SLA Monitor Cycle</p>
            <p className="text-white font-mono">Every 30 minutes</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">SLA Breach Threshold</p>
            <p className="text-white font-mono">72 hours</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">CTI Ingestion</p>
            <p className="text-white font-mono">Daily 6:00 AM MYT</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">NVD Update</p>
            <p className="text-white font-mono">Daily 7:00 AM MYT</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Posture Snapshot</p>
            <p className="text-white font-mono">Daily midnight MYT</p>
          </div>
        </div>
      </div>

      {/* Integration Status */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-5 h-5 text-accent-purple" />
          <h2 className="text-lg font-semibold text-white">Integrations</h2>
        </div>
        <div className="space-y-2 text-sm">
          {[
            { name: 'DeepSeek AI (via OpenRouter)', status: true, detail: 'Advisory generation' },
            { name: 'AlienVault OTX', status: true, detail: 'Threat intelligence feed' },
            { name: 'ThreatFox', status: true, detail: 'IoC feed' },
            { name: 'Telegram Bot', status: true, detail: 'ChatOps & SLA alerts' },
            { name: 'Cloudflare R2', status: true, detail: 'PDF report storage' },
            { name: 'NIST NVD', status: true, detail: 'CVE vulnerability database' },
          ].map(api => (
            <div key={api.name} className="flex items-center justify-between py-2 border-b border-dark-800/50">
              <div>
                <span className="text-dark-200">{api.name}</span>
                <span className="ml-2 text-dark-500 text-xs">{api.detail}</span>
              </div>
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
