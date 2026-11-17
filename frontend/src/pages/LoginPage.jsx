import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Eye, EyeOff, KeyRound, LogIn } from 'lucide-react'
import { useGoogleLogin } from '@react-oauth/google'
import { useAuth } from '../context/AuthContext'
import BrandLogo from '../components/ui/BrandLogo'
import CircuitField from '../components/ui/CircuitField'
import MfaEnrol from '../components/auth/MfaEnrol'
import RecoveryCodes from '../components/auth/RecoveryCodes'
import LostMfaHelp from '../components/auth/LostMfaHelp'
import { FormAlert, Spin, TotpField, errorText, useSingleFlight } from '../components/auth/AuthParts'
import {
  isMfaTokenExpired, isRecoveryCodeComplete, loginReasonMessage, normalizeRecoveryCode,
  SET_UP_MFA_TO_CONTINUE, SIGN_IN_TOOK_TOO_LONG,
} from '../utils/mfa.js'

// Sign-in always ends with MFA. Password or Google sign-in returns { mfa_token, stage }:
//   'verify' asks for the authenticator code (or a recovery code), then starts the session;
//   'enrol'  sets MFA up (MfaEnrol), shows the recovery codes once, then starts the session.
// The mfa_token lives in this component's state only, never in storage.
export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [stage, setStage] = useState('password') // password | verify | enrol | codes
  const [mfaToken, setMfaToken] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [lostOpen, setLostOpen] = useState(false)
  const [mfaCode, setMfaCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [enrolled, setEnrolled] = useState(null) // the enrol/finish answer, until the codes are saved
  // api/client.js sends a user here with ?reason=deactivated or ?reason=mfa_setup
  const [notice, setNotice] = useState(() => {
    const text = loginReasonMessage(new URLSearchParams(window.location.search).get('reason'))
    return text ? { tone: text === SET_UP_MFA_TO_CONTINUE ? 'info' : 'error', text } : null
  })
  const [busy, run] = useSingleFlight()
  const codeRef = useRef(null)
  const recoveryRef = useRef(null)

  const { login, loginWithGoogle, verifyMfa, startSession } = useAuth()
  const navigate = useNavigate()

  const showError = (text) => setNotice(text ? { tone: 'error', text } : null)

  // Back to the password form: the mfa_token and everything typed for it are dropped.
  const restart = useCallback((message, tone = 'error') => {
    setStage('password')
    setMfaToken('')
    setMfaCode('')
    setRecoveryCode('')
    setUseRecovery(false)
    setLostOpen(false)
    setEnrolled(null)
    setPassword('')
    setNotice(message ? { tone, text: message } : null)
  }, [])

  const beginMfa = (result) => {
    setMfaToken(result.mfa_token)
    setMfaCode('')
    setRecoveryCode('')
    setUseRecovery(false)
    setLostOpen(false)
    setPassword('')
    setStage(result.stage === 'enrol' ? 'enrol' : 'verify')
  }

  const googleLogin = useGoogleLogin({
    onSuccess: (tokenResponse) => handleGoogleLogin(tokenResponse.access_token),
    onError: () => showError('Google login failed'),
    prompt: 'select_account',
  })

  const handleLogin = (e) => {
    e.preventDefault()
    run(async () => {
      setNotice(null)
      try {
        beginMfa(await login(username, password))
      } catch (err) {
        showError(errorText(err, 'Login failed'))
      }
    })
  }

  const handleGoogleLogin = (credential) => run(async () => {
    setNotice(null)
    try {
      beginMfa(await loginWithGoogle(credential))
    } catch (err) {
      showError(errorText(err, 'Google login failed'))
    }
  })

  // One request at a time, and the code field is emptied after a refusal, so a code is never
  // sent twice (the server counts a replayed code as a failed attempt).
  const submitVerify = (answer) => run(async () => {
    setNotice(null)
    try {
      await verifyMfa(mfaToken, answer)
      navigate('/')
      return true
    } catch (err) {
      const response = err?.response
      // These end the attempt: back to the password form, which must stay usable (return false
      // so the single-flight guard unlocks).
      if (isMfaTokenExpired(response)) { restart(SIGN_IN_TOOK_TOO_LONG); return false }
      if (response?.status === 401 && /deactivated/i.test(response?.data?.detail || '')) {
        restart(response.data.detail)
        return false
      }
      showError(errorText(err, 'MFA verification failed'))
      if (answer.code) {
        setMfaCode('')
        requestAnimationFrame(() => codeRef.current?.focus())
      } else {
        // Keep a typed recovery code so a typo can be fixed
        requestAnimationFrame(() => recoveryRef.current?.select())
      }
      return false
    }
  })

  const submitCode = (code) => { if (code.length === 6) submitVerify({ code }) }

  const handleVerify = (e) => {
    e.preventDefault()
    if (useRecovery) {
      if (isRecoveryCodeComplete(recoveryCode)) submitVerify({ recovery_code: normalizeRecoveryCode(recoveryCode) })
    } else {
      submitCode(mfaCode)
    }
  }

  const switchToRecovery = (on) => {
    setUseRecovery(on)
    setLostOpen(false)
    setNotice(null)
    setMfaCode('')
    requestAnimationFrame(() => (on ? recoveryRef : codeRef).current?.focus())
  }

  const finishSignIn = () => {
    startSession(enrolled)
    setEnrolled(null)
    navigate('/')
  }

  return (
    <div className="flex min-h-screen bg-dark-950 text-dark-100">
      {/* Brand panel: navy in every theme, the logo's world */}
      <aside className="relative hidden w-[46%] max-w-[720px] flex-col overflow-hidden border-r border-rail-line bg-rail text-rail-text lg:flex">
        <CircuitField className="absolute inset-0 h-full w-full" />
        <div className="absolute inset-0 bg-[linear-gradient(90deg,rgb(var(--rail))_0%,rgb(var(--rail)/0.85)_45%,rgb(var(--rail)/0.2)_100%)]" />
        <div className="relative flex flex-1 flex-col justify-between p-12 xl:p-14">
          <BrandLogo tone="onDark" className="h-auto w-[300px] xl:w-[340px]" />
          <div className="max-w-md">
            <h2 className="text-[28px] font-semibold leading-tight text-on-brand">Cyber Asset Attack Surface Management</h2>
            <p className="mt-3 text-[15px] leading-relaxed text-rail-muted">
              Asset discovery, drift and threat-intel matching, CVE checks and AI remediation advisories for your organisation, in one place.
            </p>
          </div>
          <p className="text-xs text-rail-muted">University of Malaya · Faculty of Computer Science &amp; Information Technology</p>
        </div>
      </aside>

      {/* Sign-in */}
      <main className="flex flex-1 flex-col">
        <div className="flex items-center justify-between px-6 pt-6 lg:hidden">
          <BrandLogo className="h-12 w-auto" />
        </div>

        <div className="flex flex-1 items-center justify-center px-6 py-12">
          <div className="w-full max-w-[380px]">
            {stage === 'password' && (
              <>
                <h1 className="text-[26px] font-semibold leading-8 text-dark-50">Sign in</h1>
                <p className="mt-1.5 text-sm text-dark-400">Use your UMEagleEye account to open the dashboard.</p>

                <FormAlert tone={notice?.tone}>{notice?.text}</FormAlert>

                <form onSubmit={handleLogin} className="mt-6 space-y-4">
                  <div>
                    <label htmlFor="login-username" className="mb-1.5 block text-sm font-medium text-dark-200">Username</label>
                    <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                      className="input-field w-full py-2.5" placeholder="e.g. j.tan" autoComplete="username" required id="login-username" />
                  </div>
                  <div>
                    <label htmlFor="login-password" className="mb-1.5 block text-sm font-medium text-dark-200">Password</label>
                    <div className="relative">
                      <input type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)}
                        className="input-field w-full py-2.5 pr-11" placeholder="Your password" autoComplete="current-password" required id="login-password" />
                      <button type="button" onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword}
                        className="absolute right-1.5 top-1/2 flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded text-dark-400 transition-colors hover:text-dark-100">
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                  <button type="submit" disabled={busy} className="btn-primary w-full py-2.5" id="login-submit">
                    {busy ? <><Spin />Signing in…</> : <><LogIn className="h-4 w-4" />Sign in</>}
                  </button>
                </form>

                {import.meta.env.VITE_GOOGLE_CLIENT_ID && (
                  <>
                    <div className="my-5 flex items-center gap-3">
                      <div className="h-px flex-1 bg-dark-700" />
                      <span className="text-xs text-dark-500">or</span>
                      <div className="h-px flex-1 bg-dark-700" />
                    </div>
                    <button type="button" onClick={() => googleLogin()} disabled={busy}
                      className="flex w-full items-center justify-center gap-3 rounded-md border border-dark-700 bg-white px-4 py-2.5 text-sm font-medium text-[#1f1f1f] transition-colors hover:bg-[#f2f4f8] disabled:opacity-50">
                      <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                        <path fill="none" d="M0 0h48v48H0z"/>
                      </svg>
                      Sign in with Google
                    </button>
                  </>
                )}
              </>
            )}

            {stage === 'verify' && (
              <>
                <span className="flex h-10 w-10 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 text-eagle-400">
                  <KeyRound className="h-5 w-5" />
                </span>
                <h1 className="mt-4 text-[26px] font-semibold leading-8 text-dark-50">Two-factor check</h1>
                <p className="mt-1.5 text-sm text-dark-400">
                  {useRecovery
                    ? 'Enter one of the recovery codes you saved when you set up MFA. Each code works once.'
                    : 'Enter the 6-digit code from your authenticator app.'}
                </p>

                <FormAlert tone={notice?.tone}>{notice?.text}</FormAlert>

                <form onSubmit={handleVerify} className="mt-6 space-y-4">
                  {useRecovery ? (
                    <div>
                      <label htmlFor="mfa-recovery-code" className="mb-1.5 block text-sm font-medium text-dark-200">Recovery code</label>
                      <input ref={recoveryRef} id="mfa-recovery-code" type="text" value={recoveryCode} readOnly={busy}
                        onChange={(e) => setRecoveryCode(e.target.value.slice(0, 24))}
                        className="input-field w-full py-3 text-center font-mono text-lg uppercase tracking-[0.2em]"
                        placeholder="XXXXX-XXXXX" autoComplete="off" autoCapitalize="characters" autoCorrect="off" spellCheck={false} autoFocus />
                    </div>
                  ) : (
                    <TotpField id="mfa-code" value={mfaCode} onChange={setMfaCode} onComplete={submitCode} busy={busy} inputRef={codeRef} />
                  )}
                  <button type="submit" disabled={busy || (useRecovery ? !isRecoveryCodeComplete(recoveryCode) : mfaCode.length !== 6)}
                    className="btn-primary w-full py-2.5" id="mfa-submit">
                    {busy ? <><Spin />Verifying…</> : 'Verify and continue'}
                  </button>
                </form>

                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-sm">
                  <button type="button" onClick={() => switchToRecovery(!useRecovery)} className="text-eagle-400 hover:text-eagle-300 hover:underline">
                    {useRecovery ? 'Use your authenticator app' : 'Use a recovery code'}
                  </button>
                  <button type="button" onClick={() => setLostOpen((v) => !v)} aria-expanded={lostOpen}
                    className="text-dark-400 hover:text-dark-100 hover:underline">
                    Lost your authenticator?
                  </button>
                </div>
                {lostOpen && <LostMfaHelp onUseRecoveryCode={() => switchToRecovery(true)} />}

                <button type="button" onClick={() => restart('')} className="btn-ghost mt-4 w-full">
                  <ArrowLeft className="h-4 w-4" />Back to sign in
                </button>
              </>
            )}

            {stage === 'enrol' && (
              <MfaEnrol
                mfaToken={mfaToken}
                onFinished={(data) => { setEnrolled(data); setStage('codes') }}
                onRestart={restart}
                onBack={() => restart('')}
              />
            )}

            {stage === 'codes' && enrolled && (
              <RecoveryCodes codes={enrolled.recovery_codes || []} onDone={finishSignIn} />
            )}
          </div>
        </div>

        <p className="px-6 pb-6 text-center text-xs text-dark-500 lg:hidden">
          University of Malaya · Faculty of CS &amp; IT
        </p>
      </main>
    </div>
  )
}
