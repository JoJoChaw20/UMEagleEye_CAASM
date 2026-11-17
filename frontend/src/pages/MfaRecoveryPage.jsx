import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ArrowLeft, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react'
import client from '../api/client'
import BrandLogo from '../components/ui/BrandLogo'
import { FormAlert, Spin, errorText, useSingleFlight } from '../components/auth/AuthParts'
import { readRecoveryLink } from '../utils/mfa.js'

/**
 * Public page for the links in the break-glass email: /mfa-recovery?confirm=… or ?cancel=….
 * Cancel is posted as soon as the page opens. Confirm waits for a click, so a mail scanner that
 * opens links cannot start the reset on its own.
 */
export default function MfaRecoveryPage() {
  const { search } = useLocation()
  const [link] = useState(() => readRecoveryLink(search))
  const [result, setResult] = useState(null) // { tone, text }
  const [busy, run] = useSingleFlight()
  const sent = useRef(false)

  const post = () => run(async () => {
    if (!link || sent.current) return true
    sent.current = true
    try {
      const res = await client.post(`/auth/mfa/break-glass/${link.action}`, { token: link.token })
      setResult({ tone: 'success', text: res.data?.detail || 'Done.' })
    } catch (err) {
      setResult({ tone: 'error', text: errorText(err, 'This link could not be used. Try again later.') })
      // A network failure may be retried; a refusal from the server is final.
      if (!err?.response) sent.current = false
    }
    return sent.current
  })

  useEffect(() => {
    if (link?.action === 'cancel') post()
    // once, on open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const Icon = !link ? ShieldX : link.action === 'cancel' ? ShieldCheck : ShieldAlert
  const title = !link ? 'This link is not complete' : link.action === 'cancel' ? 'Cancel the MFA reset' : 'Confirm the MFA reset'

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-dark-950 px-6 py-12 text-dark-100">
      <div className="w-full max-w-[420px]">
        <BrandLogo className="mb-8 h-12 w-auto" />
        <span className="flex h-10 w-10 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 text-eagle-400">
          <Icon className="h-5 w-5" />
        </span>
        <h1 className="mt-4 text-[26px] font-semibold leading-8 text-dark-50">{title}</h1>

        {!link && (
          <p className="mt-1.5 text-sm text-dark-400">Open the link from the email again, exactly as it was sent.</p>
        )}

        {link?.action === 'confirm' && !result && (
          <>
            <p className="mt-1.5 text-sm text-dark-400">
              Confirming starts a 24-hour wait. After it, MFA of the platform account is cleared at the next sign-in,
              and you set it up again. The cancel link in the same email stops it until then.
            </p>
            <p className="mt-3 text-sm text-dark-400">If you did not ask for this, do not confirm. Use the cancel link instead.</p>
            <button type="button" onClick={post} disabled={busy} className="btn-primary mt-6 w-full py-2.5" id="mfa-recovery-confirm">
              {busy ? <><Spin />Confirming…</> : 'Confirm the MFA reset'}
            </button>
          </>
        )}

        {link?.action === 'cancel' && !result && (
          <div className="mt-6 flex items-center gap-2.5 text-sm text-dark-400" role="status">
            <span className="h-5 w-5 animate-spin rounded-full border-2 border-eagle-500/30 border-t-eagle-500" />Cancelling…
          </div>
        )}

        <FormAlert tone={result?.tone}>{result?.text}</FormAlert>
        {result?.tone === 'error' && !sent.current && (
          <button type="button" onClick={post} disabled={busy} className="btn-secondary mt-3 w-full">Try again</button>
        )}

        <Link to="/login" className="btn-ghost mt-6 w-full">
          <ArrowLeft className="h-4 w-4" />Go to sign in
        </Link>
      </div>
    </div>
  )
}
