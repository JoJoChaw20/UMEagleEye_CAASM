import { useState, useEffect, useCallback } from 'react'
import { Users, Shield, Clock, Eye, EyeOff, Lock, Check, LifeBuoy } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import client from '../api/client'
import { roleLabel } from '../utils/actions'
import { isMfaExemptUser, lostMfaAdvice, recoveryCodesLeftLabel } from '../utils/mfa'
import { FormAlert, errorText } from '../components/auth/AuthParts'
import StepUpDialog from '../components/auth/StepUpDialog'
import RecoveryCodes from '../components/auth/RecoveryCodes'

const passwordRequirements = [
  ['length', 'At least 12 characters'],
  ['lowercase', 'A lowercase letter'],
  ['uppercase', 'An uppercase letter'],
  ['number', 'A number'],
  ['special', 'A special character'],
  ['space', 'No spaces'],
]

const passwordChecks = (password) => ({
  length: password.length >= 12,
  lowercase: /[a-z]/.test(password),
  uppercase: /[A-Z]/.test(password),
  number: /[0-9]/.test(password),
  special: /[^A-Za-z0-9\s]/.test(password),
  space: !/\s/.test(password),
})

export default function SettingsPage() {
  const { user } = useAuth()

  // MFA state
  const [mfaStatus, setMfaStatus] = useState(null)      // { mfa_enabled, recovery_codes_left }
  const [mfaStatusError, setMfaStatusError] = useState('')
  const [askCodes, setAskCodes] = useState(false)
  const [newCodes, setNewCodes] = useState(null)

  const loadMfaStatus = useCallback(async () => {
    try {
      const res = await client.get('/auth/mfa/status')
      setMfaStatus(res.data)
      setMfaStatusError('')
    } catch (err) {
      setMfaStatusError(errorText(err, 'Could not load MFA status.'))
    }
  }, [])
  useEffect(() => { loadMfaStatus() }, [loadMfaStatus])

  const regenerateCodes = async (body) => {
    const res = await client.post('/auth/mfa/recovery-codes', body)
    setAskCodes(false)
    setNewCodes(res.data.recovery_codes)
  }

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [pwMessage, setPwMessage] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [passwordSet, setPasswordSet] = useState(false)
  const hasPassword = passwordSet || user?.hasPassword !== false
  const newPasswordChecks = passwordChecks(newPassword)
  const newPasswordIsStrong = Object.values(newPasswordChecks).every(Boolean)

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setPwError('')
    setPwMessage('')
    if (newPassword !== confirmPassword) {
      setPwError('New passwords do not match')
      return
    }
    if (!newPasswordIsStrong) {
      setPwError('Choose a stronger password that meets all the requirements below')
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

  const handleSetPassword = async (e) => {
    e.preventDefault()
    setPwError('')
    setPwMessage('')
    if (newPassword !== confirmPassword) {
      setPwError('New passwords do not match')
      return
    }
    if (!newPasswordIsStrong) {
      setPwError('Choose a stronger password that meets all the requirements below')
      return
    }
    setPwLoading(true)
    try {
      await client.post('/auth/set-password', { new_password: newPassword })
      setPasswordSet(true)
      setPwMessage('Password set successfully! You can now also sign in with your username and password.')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      setPwError(err.response?.data?.detail || 'Failed to set password')
    } finally {
      setPwLoading(false)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="page-title">Settings</h1>

      {/* Profile */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Users className="w-5 h-5 text-eagle-400" />
          <h2 className="text-lg font-semibold text-dark-50">Profile</h2>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-dark-400 mb-1">Username</p>
            <p className="text-dark-50 font-medium">{user?.username || '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Email</p>
            <p className="text-dark-50 font-medium">{user?.email || '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Role</p>
            <p className="text-dark-50 font-medium">{user?.role ? roleLabel(user.role) : '—'}</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Tenant</p>
            <p className="text-dark-50 font-medium">
              {user?.tenantName ?? (user?.role === 'superadmin' ? 'All Tenants' : '—')}
            </p>
          </div>
        </div>
      </div>

      {/* Password */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-5 h-5 text-accent-cyan" />
          <h2 className="text-lg font-semibold text-dark-50">{hasPassword ? 'Change Password' : 'Set Password'}</h2>
        </div>

        {!hasPassword && (
          <p className="mb-4 text-sm text-dark-400">
            Your account uses Google sign-in and does not have a password yet. Set one here if you also want username and password sign-in.
          </p>
        )}
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

        <form onSubmit={hasPassword ? handleChangePassword : handleSetPassword} className="space-y-4 max-w-sm">
          {hasPassword && (
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
          )}
          <div>
            <label className="block text-xs text-dark-400 mb-1">New Password</label>
            <div className="relative">
              <input
                type={showNew ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="input-field w-full pr-10"
                placeholder="Create a strong password"
                required
              />
              <button type="button" onClick={() => setShowNew(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200">
                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1">
              {passwordRequirements.map(([key, label]) => (
                <span key={key} className={`text-[11px] ${newPasswordChecks[key] ? 'text-green-400' : 'text-dark-500'}`}>
                  {newPasswordChecks[key] ? '✓' : '○'} {label}
                </span>
              ))}
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
            {pwLoading ? (hasPassword ? 'Changing...' : 'Setting...') : (hasPassword ? 'Change Password' : 'Set Password')}
          </button>
        </form>
      </div>

      {/* MFA */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-accent-green" />
          <h2 className="text-lg font-semibold text-dark-50">Multi-Factor Authentication</h2>
        </div>
        {isMfaExemptUser(user) && <p className="text-sm text-dark-400">MFA is not required for this account.</p>}
        {!isMfaExemptUser(user) && mfaStatusError && <FormAlert className="mb-3">{mfaStatusError}</FormAlert>}
        {!isMfaExemptUser(user) && !mfaStatus && !mfaStatusError && <p className="text-sm text-dark-400">Loading…</p>}
        {!isMfaExemptUser(user) && mfaStatus && (
          <div className="space-y-3">
            <p className="text-sm text-dark-50">
              <span className="font-medium">{mfaStatus.mfa_enabled ? 'MFA is on' : 'MFA is off'}</span>
              {mfaStatus.mfa_enabled && <span className="text-dark-400"> · {recoveryCodesLeftLabel(mfaStatus.recovery_codes_left)}</span>}
            </p>
            <p className="text-sm text-dark-400">
              Your authenticator app keeps working with no expiry. If you lose it or change phones:{' '}
              {lostMfaAdvice(user?.role)}
            </p>
            {mfaStatus.mfa_enabled && (
              <button type="button" onClick={() => setAskCodes(true)} className="btn-primary flex items-center gap-2">
                <LifeBuoy className="w-4 h-4" /> Get new recovery codes
              </button>
            )}
          </div>
        )}
      </div>

      {askCodes && (
        <StepUpDialog title="Get new recovery codes" idPrefix="codes" confirmLabel="Get new codes"
          onSubmit={regenerateCodes} onCancel={() => setAskCodes(false)}>
          Your current recovery codes stop working as soon as new ones are issued. Confirm it is you.
        </StepUpDialog>
      )}

      {newCodes && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center overflow-y-auto bg-dark-950/70 p-4">
          <div role="dialog" aria-modal="true" className="glass-card my-auto w-full max-w-md bg-dark-800 p-6">
            <RecoveryCodes codes={newCodes} title="Your new recovery codes"
              intro="Your old recovery codes no longer work. Each new code works once. They are shown only now."
              doneLabel="Done" DoneIcon={Check}
              onDone={() => { setNewCodes(null); loadMfaStatus() }} />
          </div>
        </div>
      )}

      {/* System config */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Clock className="w-5 h-5 text-accent-amber" />
          <h2 className="text-lg font-semibold text-dark-50">Platform Configuration</h2>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-dark-400 mb-1">Drift Audit Cycle</p>
            <p className="text-dark-50 font-mono">Every 15 minutes</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">SLA Monitor Cycle</p>
            <p className="text-dark-50 font-mono">Every 30 minutes</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">SLA Breach Threshold</p>
            <p className="text-dark-50 font-mono">72 hours</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">CTI Ingestion</p>
            <p className="text-dark-50 font-mono">Daily 6:00 AM MYT</p>
          </div>
          <div>
            <p className="text-dark-400 mb-1">Posture Snapshot</p>
            <p className="text-dark-50 font-mono">Daily midnight MYT</p>
          </div>
        </div>
      </div>
    </div>
  )
}
