import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react'
import client from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(localStorage.getItem('access_token'))
  const [loading, setLoading] = useState(true)
  const [catalog, setCatalog] = useState(null)
  // pending until the catalog request settles; 'error' when it failed after retries
  const [catalogStatus, setCatalogStatus] = useState('pending')
  const [catalogTry, setCatalogTry] = useState(0)
  // Bumped on every sign-in so /auth/me runs again even if the token string is unchanged
  const [session, setSession] = useState(0)

  useEffect(() => {
    if (!token) { setLoading(false); return undefined }
    let cancelled = false
    setLoading(true)
    // Validate token by fetching user profile
    client.get('/auth/me')
      .then(res => {
        if (cancelled) return
        setUser(res.data)
        setLoading(false)
      })
      .catch(() => {
        if (cancelled) return
        logout()
        setLoading(false)
      })
    return () => { cancelled = true }
  }, [token, session])

  // The action catalog is fetched once per sign-in; it tells can() which actions are read-only.
  // Retried twice with a short backoff; retryCatalog() runs it again after a failure.
  useEffect(() => {
    if (!token) { setCatalog(null); setCatalogStatus('pending'); return undefined }
    let cancelled = false
    let timer = null
    setCatalogStatus('pending')
    const attempt = (n) => {
      client.get('/auth/actions')
        .then(res => { if (!cancelled) { setCatalog(res.data); setCatalogStatus('ok') } })
        .catch(() => {
          if (cancelled) return
          if (n < 2) timer = setTimeout(() => attempt(n + 1), n === 0 ? 500 : 1500)
          else { setCatalog(null); setCatalogStatus('error') }
        })
    }
    attempt(0)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [token, catalogTry])

  const retryCatalog = useCallback(() => setCatalogTry(n => n + 1), [])

  // Re-read the profile, e.g. after the user's grants changed. The user object is only
  // replaced when something changed, so pages that refetch on a new can() do not loop.
  const refreshUser = useCallback(async () => {
    const res = await client.get('/auth/me')
    setUser(prev => (prev && JSON.stringify(prev) === JSON.stringify(res.data) ? prev : res.data))
  }, [])

  // New grants appear and removed ones hide without a reload: re-read the profile when the
  // window regains focus (at most every 30s) and when the API refuses a call for a missing
  // action (at most every 10s; api/client.js raises the event).
  useEffect(() => {
    if (!token) return undefined
    let lastFocus = Date.now()
    let lastRefusal = 0
    const quietly = () => { refreshUser().catch(() => {}) }
    const onFocus = () => {
      if (Date.now() - lastFocus < 30_000) return
      lastFocus = Date.now()
      quietly()
    }
    const onRefusal = () => {
      if (Date.now() - lastRefusal < 10_000) return
      lastRefusal = Date.now()
      quietly()
    }
    window.addEventListener('focus', onFocus)
    window.addEventListener('auth:missing-action', onRefusal)
    return () => {
      window.removeEventListener('focus', onFocus)
      window.removeEventListener('auth:missing-action', onRefusal)
    }
  }, [token, refreshUser])

  // Mirrors the server decide(): platform superadmin read-only, tenant superadmin everything, others by grant.
  // Only the platform superadmin needs the catalog.
  const can = useCallback((key) => {
    if (!user) return false
    if (user.role === 'superadmin') return !!catalog?.actions?.find(a => a.key === key)?.read_only
    if (user.role === 'tenant_superadmin') return true
    return Array.isArray(user.actions) && user.actions.includes(key)
  }, [user, catalog])

  // False while a platform superadmin's catalog is still on its way
  const ready = !loading && (!user || user.role !== 'superadmin' || catalogStatus !== 'pending')
  const catalogError = catalogStatus === 'error'

  // Sign-in ends with an access_token only after the MFA step (/auth/mfa/verify or
  // /auth/mfa/enrol/finish). Those responses lack actions and tenantId, so the user is never
  // taken from them: loading goes up before the token changes and /auth/me alone fills the user.
  // Only role and user_id are kept in storage, never the recovery codes of an enrol response.
  const startSession = (data) => {
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('user', JSON.stringify({ role: data.role, user_id: data.user_id }))
    setLoading(true)
    setUser(null)
    setToken(data.access_token)
    setSession(n => n + 1)
  }

  // Password and Google sign-in answer { mfa_token, stage }: 'verify' asks for a code,
  // 'enrol' sets MFA up first. The mfa_token stays in LoginPage's memory only.
  const login = async (username, password) => {
    const res = await client.post('/auth/login', { username, password })
    return { mfa_token: res.data.mfa_token, stage: res.data.stage }
  }

  const loginWithGoogle = async (access_token) => {
    const res = await client.post('/auth/google', { access_token })
    return { mfa_token: res.data.mfa_token, stage: res.data.stage }
  }

  // answer: { code } or { recovery_code }. Starts the session on success.
  const verifyMfa = async (mfaToken, answer) => {
    const res = await client.post('/auth/mfa/verify', { mfa_token: mfaToken, ...answer })
    startSession(res.data)
    return res.data
  }

  // Reuses the pending secret (same QR) unless newSecret asks for a new one.
  const startMfaEnrol = async (mfaToken, newSecret = false) => {
    const body = newSecret ? { mfa_token: mfaToken, new_secret: true } : { mfa_token: mfaToken }
    const res = await client.post('/auth/mfa/enrol/start', body)
    return res.data
  }

  // Returns { access_token, role, user_id, recovery_codes } without starting the session:
  // the recovery codes are shown first, and startSession runs once the user saved them.
  const finishMfaEnrol = async (mfaToken, code) => {
    const res = await client.post('/auth/mfa/enrol/finish', { mfa_token: mfaToken, code })
    return res.data
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    setToken(null)
    setUser(null)
  }

  const value = useMemo(() => ({
    user, token, loading, ready, isPlatformSuperadmin: user?.role === 'superadmin',
    login, loginWithGoogle, verifyMfa, startMfaEnrol, finishMfaEnrol, startSession,
    logout, can, catalog, catalogError, retryCatalog, refreshUser,
  // the sign-in helpers and logout only call the API and set state, so they are safe to leave out
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [user, token, loading, ready, can, catalog, catalogError, retryCatalog, refreshUser])

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
