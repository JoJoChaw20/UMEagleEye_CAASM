import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import PasswordChecklist from '../auth/PasswordChecklist'

/**
 * A new account without an email: its username and the starting password to hand over. The person
 * must choose their own password at first sign-in and can connect Google later in Settings.
 */
export default function StartingPasswordFields({ idPrefix, username, onUsername, password, onPassword }) {
  const [show, setShow] = useState(false)
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor={`${idPrefix}-new-username`} className="mb-1 block text-xs text-dark-400">Username</label>
          <input id={`${idPrefix}-new-username`} type="text" value={username} onChange={(e) => onUsername(e.target.value)}
            placeholder="e.g. john_doe" className="input-field w-full text-sm" minLength={3} maxLength={100}
            autoComplete="off" required autoFocus />
        </div>
        <div>
          <label htmlFor={`${idPrefix}-new-password`} className="mb-1 block text-xs text-dark-400">Starting password</label>
          <div className="relative">
            <input id={`${idPrefix}-new-password`} type={show ? 'text' : 'password'} value={password}
              onChange={(e) => onPassword(e.target.value)} className="input-field w-full pr-10 text-sm"
              autoComplete="new-password" required />
            <button type="button" onClick={() => setShow((v) => !v)} aria-label={show ? 'Hide password' : 'Show password'}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200">
              {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>
      <PasswordChecklist password={password} />
      <p className="text-xs text-dark-500">
        No email needed. Give them the username and starting password: they choose their own password at first
        sign-in, and can connect their Google account in Settings to also sign in with Google.
      </p>
    </div>
  )
}
