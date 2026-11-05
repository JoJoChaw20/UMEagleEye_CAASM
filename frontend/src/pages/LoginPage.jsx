import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowLeft, Eye, EyeOff, KeyRound, LogIn } from 'lucide-react'
import { useGoogleLogin } from '@react-oauth/google'
import { useAuth } from '../context/AuthContext'
import BrandLogo from '../components/ui/BrandLogo'
import CircuitField from '../components/ui/CircuitField'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [mfaRequired, setMfaRequired] = useState(() => sessionStorage.getItem('mfa_pending') === 'true')
  const [mfaUserId, setMfaUserId] = useState(() => sessionStorage.getItem('mfa_user_id') || '')
  const [mfaCode, setMfaCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const { login, verifyMFA, loginWithGoogle } = useAuth()
  const navigate = useNavigate()

  const googleLogin = useGoogleLogin({
    onSuccess: (tokenResponse) => handleGoogleLogin(tokenResponse.access_token),
    onError: () => setError('Google login failed'),
    prompt: 'select_account',
  })

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const result = await login(username, password)
      if (result.mfa_required) {
        sessionStorage.setItem('mfa_pending', 'true')
        sessionStorage.setItem('mfa_user_id', result.user_id)
        setMfaUserId(result.user_id)
        setMfaRequired(true)
      } else {
        navigate('/')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleLogin = async (credential) => {
    setError('')
    setLoading(true)
    try {
      const result = await loginWithGoogle(credential)
      if (result.mfa_required) {
        sessionStorage.setItem('mfa_pending', 'true')
        sessionStorage.setItem('mfa_user_id', result.user_id)
        setMfaUserId(result.user_id)
        setMfaRequired(true)
      } else {
        navigate('/')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Google login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleMFAVerify = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await verifyMFA(mfaUserId, mfaCode)
      sessionStorage.removeItem('mfa_pending')
      sessionStorage.removeItem('mfa_user_id')
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid MFA code')
    } finally {
      setLoading(false)
    }
  }

  const resetMfa = () => {
    sessionStorage.removeItem('mfa_pending')
    sessionStorage.removeItem('mfa_user_id')
    setMfaRequired(false)
    setMfaUserId('')
    setMfaCode('')
    setError('')
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
            {!mfaRequired ? (
              <>
                <h1 className="text-[26px] font-semibold leading-8 text-dark-50">Sign in</h1>
                <p className="mt-1.5 text-sm text-dark-400">Use your UMEagleEye account to open the dashboard.</p>

                {error && (
                  <div role="alert" className="mt-6 flex items-start gap-2.5 rounded-md border border-red-500/30 bg-red-500/[0.08] px-3.5 py-3 text-sm text-red-400">
                    <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />{error}
                  </div>
                )}

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
                  <button type="submit" disabled={loading} className="btn-primary w-full py-2.5" id="login-submit">
                    {loading ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />Signing in…</> : <><LogIn className="h-4 w-4" />Sign in</>}
                  </button>
                </form>

                {import.meta.env.VITE_GOOGLE_CLIENT_ID && (
                  <>
                    <div className="my-5 flex items-center gap-3">
                      <div className="h-px flex-1 bg-dark-700" />
                      <span className="text-xs text-dark-500">or</span>
                      <div className="h-px flex-1 bg-dark-700" />
                    </div>
                    <button type="button" onClick={() => googleLogin()} disabled={loading}
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
            ) : (
              <>
                <span className="flex h-10 w-10 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 text-eagle-400">
                  <KeyRound className="h-5 w-5" />
                </span>
                <h1 className="mt-4 text-[26px] font-semibold leading-8 text-dark-50">Two-factor check</h1>
                <p className="mt-1.5 text-sm text-dark-400">Enter the 6-digit code from your authenticator app.</p>

                {error && (
                  <div role="alert" className="mt-6 flex items-start gap-2.5 rounded-md border border-red-500/30 bg-red-500/[0.08] px-3.5 py-3 text-sm text-red-400">
                    <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />{error}
                  </div>
                )}

                <form onSubmit={handleMFAVerify} className="mt-6 space-y-4">
                  <div>
                    <label htmlFor="mfa-code" className="mb-1.5 block text-sm font-medium text-dark-200">Authentication code</label>
                    <input type="text" inputMode="numeric" autoComplete="one-time-code" value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="input-field w-full py-3 text-center font-mono text-2xl tracking-[0.5em]"
                      placeholder="000000" maxLength={6} required id="mfa-code" autoFocus />
                  </div>
                  <button type="submit" disabled={loading || mfaCode.length !== 6} className="btn-primary w-full py-2.5" id="mfa-submit">
                    {loading ? 'Verifying…' : 'Verify and continue'}
                  </button>
                  <button type="button" onClick={resetMfa} className="btn-ghost w-full">
                    <ArrowLeft className="h-4 w-4" />Back to sign in
                  </button>
                </form>
              </>
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
