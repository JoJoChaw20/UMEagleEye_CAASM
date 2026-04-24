import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Shield, Lock } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaCode, setMfaCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const { login, verifyMFA } = useAuth()
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const result = await login(username, password)
      if (result.mfa_required) {
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

  const handleMFAVerify = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await verifyMFA(username, mfaCode)
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
          </form>
        )}

        <p className="text-center text-dark-500 text-xs mt-6">
          University of Malaya • Faculty of CS & IT
        </p>
      </div>
    </div>
  )
}
