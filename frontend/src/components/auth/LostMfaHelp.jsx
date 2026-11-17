import { useState } from 'react'
import { LifeBuoy, Send } from 'lucide-react'
import client from '../../api/client'
import { FormAlert, Spin, errorText, useSingleFlight } from './AuthParts'
import { lostMfaAdvice } from '../../utils/mfa'

/**
 * "Lost your authenticator?" help on the code screen. The role is not known before the code
 * check, so every case is listed. The Platform Superadmin form posts to break-glass request,
 * which always answers the same 202 text whether or not the details were right.
 */
export default function LostMfaHelp({ onUseRecoveryCode }) {
  const [formOpen, setFormOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [secret, setSecret] = useState('')
  const [result, setResult] = useState(null) // { tone, text }
  const [busy, run] = useSingleFlight()

  const send = (e) => {
    e.preventDefault()
    run(async () => {
      setResult(null)
      try {
        const res = await client.post('/auth/mfa/break-glass/request', {
          email: email.trim(), password, reset_secret: secret.trim(),
        })
        setResult({ tone: 'success', text: res.data?.detail || 'Request sent.' })
        setPassword('')
        setSecret('')
      } catch (err) {
        setResult({ tone: 'error', text: errorText(err, 'The request failed. Try again.') })
      }
    })
  }

  return (
    <section className="mt-4 rounded-md border border-dark-700 bg-dark-900 px-4 py-3.5 text-sm text-dark-300" aria-labelledby="lost-mfa-title">
      <h2 id="lost-mfa-title" className="flex items-center gap-2 font-medium text-dark-100">
        <LifeBuoy className="h-4 w-4 text-eagle-400" />Lost your authenticator?
      </h2>
      <p className="mt-2"><span className="font-medium text-dark-200">Tenant user:</span> use a recovery code. If you have none, ask your Tenant Superadmin to reset your MFA.</p>
      <button type="button" onClick={onUseRecoveryCode} className="mt-1 text-eagle-400 hover:text-eagle-300 hover:underline">
        Use a recovery code
      </button>
      <p className="mt-3"><span className="font-medium text-dark-200">Tenant Superadmin:</span> {lostMfaAdvice('tenant_superadmin')}</p>
      <p className="mt-3">
        <span className="font-medium text-dark-200">Platform Superadmin:</span> {lostMfaAdvice('superadmin')}{' '}
        {!formOpen && (
          <button type="button" onClick={() => setFormOpen(true)} className="text-eagle-400 hover:text-eagle-300 hover:underline">
            Lost all MFA methods
          </button>
        )}
      </p>

      {formOpen && (
        <form onSubmit={send} className="mt-3 space-y-3 border-t border-dark-700 pt-3">
          <p className="font-medium text-dark-100">Lost all MFA methods</p>
          <p className="text-xs text-dark-400">
            A confirmation email goes to your address. MFA is cleared 24 hours after you confirm, unless the cancel link is used.
          </p>
          <div>
            <label htmlFor="bg-email" className="mb-1 block text-xs font-medium text-dark-200">Email</label>
            <input id="bg-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              className="input-field w-full" autoComplete="email" required />
          </div>
          <div>
            <label htmlFor="bg-password" className="mb-1 block text-xs font-medium text-dark-200">Password</label>
            <input id="bg-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="input-field w-full" autoComplete="current-password" required />
          </div>
          <div>
            <label htmlFor="bg-secret" className="mb-1 block text-xs font-medium text-dark-200">Reset secret</label>
            <input id="bg-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)}
              className="input-field w-full font-mono" autoComplete="off" spellCheck={false} required />
          </div>
          <FormAlert tone={result?.tone} className="mt-0">{result?.text}</FormAlert>
          <button type="submit" disabled={busy} className="btn-secondary w-full">
            {busy ? <Spin /> : <Send className="h-4 w-4" />}Send the reset request
          </button>
        </form>
      )}
    </section>
  )
}
