import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, Lock } from 'lucide-react'
import { useGoogleLogin } from '@react-oauth/google'
import { useAuth } from '../context/AuthContext'

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

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-950 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-eagle-600/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-accent-cyan/5 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-dark-900/50 via-dark-950 to-dark-950" />
      </div>

      {/* Login card */}
      <div className="relative glass-card glow-border p-8 w-full max-w-md mx-4">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-eagle-500 to-accent-cyan rounded-2xl mb-4 shadow-[0_0_30px_rgba(51,147,255,0.3)]">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold gradient-text">UMEagleEye</h1>
          <p className="text-dark-400 text-sm mt-1">Cyber Asset Attack Surface Management</p>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg text-sm mb-4">
            {error}
          </div>
        )}

        {!mfaRequired ? (
          <>
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm text-dark-300 mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input-field w-full"
                placeholder="Enter your username"
                required
                id="login-username"
              />
            </div>
            <div>
              <label className="block text-sm text-dark-300 mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-field w-full pr-10"
                  placeholder="Enter your password"
                  required
                  id="login-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2"
              id="login-submit"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  Sign In
                </>
              )}
            </button>
          </form>

          {import.meta.env.VITE_GOOGLE_CLIENT_ID && (
            <>
              <div className="flex items-center gap-3 my-4">
                <div className="flex-1 h-px bg-dark-700" />
                <span className="text-dark-500 text-xs">or</span>
                <div className="flex-1 h-px bg-dark-700" />
              </div>
              <button
                type="button"
                onClick={() => googleLogin()}
                disabled={loading}
                className="w-full flex items-center justify-center gap-3 px-4 py-2.5 bg-white hover:bg-gray-100 text-gray-800 font-medium rounded-lg transition-colors"
              >
                <svg width="18" height="18" viewBox="0 0 48 48">
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
          <form onSubmit={handleMFAVerify} className="space-y-4">
            <p className="text-dark-300 text-sm text-center mb-4">
              Enter the 6-digit code from your authenticator app
            </p>
            <div>
              <label className="block text-sm text-dark-300 mb-1.5">MFA Code</label>
              <input
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="input-field w-full text-center text-2xl tracking-[0.5em] font-mono"
                placeholder="000000"
                maxLength={6}
                required
                id="mfa-code"
              />
            </div>
            <button
              type="submit"
              disabled={loading || mfaCode.length !== 6}
              className="btn-primary w-full"
              id="mfa-submit"
            >
              {loading ? 'Verifying...' : 'Verify MFA'}
            </button>
            <button
              type="button"
              onClick={() => {
                sessionStorage.removeItem('mfa_pending')
                sessionStorage.removeItem('mfa_user_id')
                setMfaRequired(false)
                setMfaUserId('')
                setMfaCode('')
              }}
              className="w-full text-sm text-dark-400 hover:text-dark-200 transition-colors"
            >
              ← Back to login
            </button>
          </form>
        )}

        <p className="text-center text-dark-500 text-xs mt-6">
          University of Malaya • Faculty of CS & IT
        </p>
      </div>
    </div>
  )
}
