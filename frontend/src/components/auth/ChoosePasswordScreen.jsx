import { useState } from 'react'
import { KeyRound, LogOut } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { isStrongPassword } from '../../utils/password.js'
import { FormAlert, Spin, errorText, useSingleFlight } from './AuthParts'
import PasswordChecklist from './PasswordChecklist'

/**
 * Shown instead of the app while the account still has the starting password its creator gave it
 * (/auth/me password_change_required): the server refuses everything outside /auth until it is replaced.
 */
export default function ChoosePasswordScreen() {
  const { user, refreshUser, logout } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, run] = useSingleFlight()

  const submit = (e) => {
    e.preventDefault()
    run(async () => {
      setError('')
      if (next !== confirm) { setError('The new passwords do not match.'); return false }
      if (!isStrongPassword(next)) { setError('Choose a password that meets every rule below.'); return false }
      if (next === current) { setError('Choose a password different from the one you were given.'); return false }
      try {
        await client.post('/auth/change-password', { current_password: current, new_password: next })
        await refreshUser()
        return true
      } catch (err) {
        setError(errorText(err, 'Could not change the password.'))
        return false
      }
    })
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-dark-950 p-4">
      <form onSubmit={submit} className="glass-card w-full max-w-md space-y-4 p-6">
        <div className="flex items-center gap-3">
          <KeyRound className="h-5 w-5 text-accent-cyan" />
          <h1 className="text-lg font-semibold text-dark-50">Choose your own password</h1>
        </div>
        <p className="text-sm text-dark-400">
          {user?.username ? <><span className="text-dark-200">{user.username}</span>, your</> : 'Your'} account was
          created with a starting password. Replace it with one only you know before you continue.
        </p>
        <div>
          <label htmlFor="choose-current" className="mb-1.5 block text-sm font-medium text-dark-200">Starting password</label>
          <input id="choose-current" type="password" value={current} onChange={(e) => setCurrent(e.target.value)}
            className="input-field w-full" autoComplete="current-password" required autoFocus />
        </div>
        <div>
          <label htmlFor="choose-new" className="mb-1.5 block text-sm font-medium text-dark-200">New password</label>
          <input id="choose-new" type="password" value={next} onChange={(e) => setNext(e.target.value)}
            className="input-field w-full" autoComplete="new-password" required />
          <PasswordChecklist password={next} />
        </div>
        <div>
          <label htmlFor="choose-confirm" className="mb-1.5 block text-sm font-medium text-dark-200">Confirm new password</label>
          <input id="choose-confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
            className="input-field w-full" autoComplete="new-password" required />
        </div>
        <FormAlert className="mt-0">{error}</FormAlert>
        <div className="flex items-center justify-between gap-3 pt-1">
          <button type="button" onClick={logout} className="btn-secondary flex items-center gap-2 text-sm">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
          <button type="submit" disabled={busy} className="btn-primary flex items-center gap-2">
            {busy ? <Spin /> : <KeyRound className="h-4 w-4" />} Save password
          </button>
        </div>
      </form>
    </div>
  )
}
