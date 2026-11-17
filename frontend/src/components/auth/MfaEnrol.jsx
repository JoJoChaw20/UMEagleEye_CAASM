import { useCallback, useEffect, useRef, useState } from 'react'
import { ArrowLeft, Check, Copy, RefreshCw, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { isMfaTokenExpired, SIGN_IN_TOOK_TOO_LONG } from '../../utils/mfa.js'
import { FormAlert, Spin, TotpField, errorText, useCopy, useSingleFlight } from './AuthParts'

const TWO_DEVICES = 'Scan this code on two devices: your phone and a backup device kept somewhere safe.'
const NO_PENDING = 'Start MFA set-up first'

/**
 * MFA set-up during sign-in (mfa_token stage 'enrol', valid 15 minutes).
 * enrol/start returns the pending secret when there is one, so after a new sign-in the QR the
 * phone already scanned still works. "Show a new QR code" asks for a fresh secret.
 * onFinished(data) gets { access_token, role, user_id, recovery_codes }.
 * onRestart(message) goes back to the password form (expired token, account already set up).
 */
export default function MfaEnrol({ mfaToken, onFinished, onRestart, onBack }) {
  const { startMfaEnrol, finishMfaEnrol } = useAuth()
  const [setup, setSetup] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [loadingQr, setLoadingQr] = useState(false)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, run] = useSingleFlight()
  const [copyState, copy] = useCopy()
  const codeRef = useRef(null)
  const started = useRef(false)

  // Errors that end this sign-in attempt; true when handled.
  const restartFor = useCallback((err) => {
    const response = err?.response
    if (isMfaTokenExpired(response)) { onRestart(SIGN_IN_TOOK_TOO_LONG); return true }
    if (response?.status === 409 || (response?.status === 401 && /deactivated/i.test(response?.data?.detail || ''))) {
      onRestart(response.data.detail)
      return true
    }
    return false
  }, [onRestart])

  const loadQr = useCallback(async (newSecret) => {
    setLoadingQr(true)
    setLoadError('')
    try {
      const data = await startMfaEnrol(mfaToken, newSecret)
      setSetup(data)
      setCode('')
      return true
    } catch (err) {
      if (!restartFor(err)) setLoadError(errorText(err, 'MFA set-up failed. Try again.'))
      return false
    } finally {
      setLoadingQr(false)
    }
  }, [mfaToken, startMfaEnrol, restartFor])

  // Once per mount: React's development double-mount would otherwise ask twice.
  useEffect(() => {
    if (started.current) return
    started.current = true
    loadQr(false)
  }, [loadQr])

  const showNewQr = () => run(async () => {
    setError('')
    setNotice('')
    if (await loadQr(true)) {
      setNotice('This is a new QR code. Delete the old UMEagleEye entry in your app, then scan this one.')
      codeRef.current?.focus()
    }
  })

  const submit = (value) => run(async () => {
    if (value.length !== 6) return false
    setError('')
    try {
      const data = await finishMfaEnrol(mfaToken, value)
      onFinished(data)
      return true
    } catch (err) {
      if (restartFor(err)) return false
      const message = errorText(err, 'MFA set-up failed. Try again.')
      setError(message)
      setCode('')
      // The pending secret is gone (an MFA reset ran meanwhile): fetch the QR again.
      if (message.startsWith(NO_PENDING)) await loadQr(false)
      requestAnimationFrame(() => codeRef.current?.focus())
      return false
    }
  })

  const header = (
    <>
      <span className="flex h-10 w-10 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 text-eagle-400">
        <ShieldCheck className="h-5 w-5" />
      </span>
      <h1 className="mt-4 text-[26px] font-semibold leading-8 text-dark-50">Set up two-factor sign-in</h1>
      <p className="mt-1.5 text-sm text-dark-400">
        Every account signs in with a code from an authenticator app, such as Google Authenticator or Microsoft Authenticator.
      </p>
    </>
  )

  const back = (
    <button type="button" onClick={onBack} className="btn-ghost mt-3 w-full">
      <ArrowLeft className="h-4 w-4" />Back to sign in
    </button>
  )

  if (!setup) {
    return (
      <>
        {header}
        {loadError ? (
          <>
            <FormAlert>{loadError}</FormAlert>
            <button type="button" onClick={() => loadQr(false)} disabled={loadingQr} className="btn-primary mt-4 w-full py-2.5">
              {loadingQr ? <Spin /> : <RefreshCw className="h-4 w-4" />}Try again
            </button>
          </>
        ) : (
          <div className="mt-8 flex items-center justify-center gap-2.5 text-sm text-dark-400" role="status">
            <span className="h-5 w-5 animate-spin rounded-full border-2 border-eagle-500/30 border-t-eagle-500" />Preparing your QR code…
          </div>
        )}
        {back}
      </>
    )
  }

  return (
    <>
      {header}

      <ol className="mt-6 space-y-5 text-sm text-dark-200">
        <li>
          <p className="font-medium text-dark-100">1. Scan this QR code with your authenticator app</p>
          {setup.two_devices && (
            <FormAlert tone="info" className="mt-2">{TWO_DEVICES}</FormAlert>
          )}
          <div className="mt-3 flex justify-center">
            <div className={`rounded-lg bg-white p-2.5 shadow ${loadingQr ? 'opacity-40' : ''}`}>
              <img src={`data:image/svg+xml;base64,${setup.qr_code_base64}`} alt="QR code for your authenticator app" className="block h-44 w-44" />
            </div>
          </div>
          <p className="mt-3 text-xs text-dark-400">Cannot scan? Enter this key in the app instead:</p>
          <div className="mt-1.5 flex items-center gap-2 rounded-md border border-dark-700 bg-dark-900 py-1.5 pl-3 pr-1.5">
            <code className="flex-1 select-all break-all font-mono text-xs text-eagle-300">{setup.totp_secret}</code>
            <button type="button" onClick={() => copy(setup.totp_secret)} className="btn-ghost px-2 py-1 text-xs" aria-label="Copy the key">
              {copyState === 'copied' ? <><Check className="h-3.5 w-3.5" />Copied</> : <><Copy className="h-3.5 w-3.5" />Copy</>}
            </button>
          </div>
          {copyState === 'failed' && <p className="mt-1.5 text-xs text-red-400">Copy did not work here. Select the key and copy it.</p>}
        </li>
        <li>
          <p className="font-medium text-dark-100">2. Enter the 6-digit code the app shows</p>
          <p className="mt-1 text-xs text-dark-400">Already scanned this QR code before? Its entry still works: enter the code it shows now.</p>
        </li>
      </ol>

      <FormAlert tone="success" className="mt-4">{notice}</FormAlert>
      <FormAlert className="mt-4">{error}</FormAlert>

      <form onSubmit={(e) => { e.preventDefault(); submit(code) }} className="mt-4 space-y-4">
        <TotpField id="mfa-enrol-code" value={code} onChange={setCode} onComplete={submit} busy={busy} inputRef={codeRef} />
        <button type="submit" disabled={busy || code.length !== 6} className="btn-primary w-full py-2.5" id="mfa-enrol-submit">
          {busy ? <><Spin />Checking…</> : 'Turn on MFA'}
        </button>
      </form>

      <div className="mt-4 border-t border-dark-700 pt-4">
        <button type="button" onClick={showNewQr} disabled={busy || loadingQr} className="btn-ghost w-full text-xs">
          <RefreshCw className="h-3.5 w-3.5" />Show a new QR code
        </button>
        <p className="mt-1 text-center text-xs text-dark-500">Only if the app's codes are not accepted. The old entry then stops working.</p>
      </div>
      {back}
    </>
  )
}
