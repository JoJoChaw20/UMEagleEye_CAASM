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
  }, [token])

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

  // Re-read the profile, e.g. after the user's grants changed
  const refreshUser = useCallback(async () => {
    const res = await client.get('/auth/me')
    setUser(res.data)
  }, [])

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

  const login = async (username, password) => {
    const res = await client.post('/auth/login', { username, password })
    const data = res.data

    if (data.mfa_required) {
      return { mfa_required: true, user_id: data.user_id }
    }

    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('user', JSON.stringify(data))
    setToken(data.access_token)
    setUser(data)
    return data
  }

  const verifyMFA = async (userId, code) => {
    const res = await client.post('/auth/mfa/verify', { user_id: userId, code })
    const data = res.data
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('user', JSON.stringify(data))
    setToken(data.access_token)
    setUser(data)
    return data
  }

  const loginWithGoogle = async (access_token) => {
    const res = await client.post('/auth/google', { access_token })
    const data = res.data
    if (data.mfa_required) {
      return { mfa_required: true, user_id: data.user_id }
    }
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('user', JSON.stringify(data))
    setToken(data.access_token)
    setUser(data)
    return data
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    setToken(null)
    setUser(null)
  }

  const value = useMemo(() => ({
    user, token, loading, ready, login, verifyMFA, loginWithGoogle, logout, can, catalog, catalogError, retryCatalog, refreshUser,
  // login/verifyMFA/loginWithGoogle/logout only set state, so they are safe to leave out
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
