import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import client from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(localStorage.getItem('access_token'))
  const [loading, setLoading] = useState(true)
  const [catalog, setCatalog] = useState(null)

  useEffect(() => {
    if (token) {
      // Validate token by fetching user profile
      client.get('/auth/me')
        .then(res => {
          setUser(res.data)
          setLoading(false)
        })
        .catch(() => {
          logout()
          setLoading(false)
        })
    } else {
      setLoading(false)
    }
  }, [token])

  // The action catalog is fetched once per sign-in; it tells can() which actions are read-only
  useEffect(() => {
    if (!token) { setCatalog(null); return undefined }
    let cancelled = false
    client.get('/auth/actions')
      .then(res => { if (!cancelled) setCatalog(res.data) })
      .catch(() => { if (!cancelled) setCatalog(null) })
    return () => { cancelled = true }
  }, [token])

  // Re-read the profile, e.g. after the user's grants changed
  const refreshUser = useCallback(async () => {
    const res = await client.get('/auth/me')
    setUser(res.data)
  }, [])

  // Mirrors the server decide(): platform superadmin read-only, tenant superadmin everything, others by grant
  const can = (key) => {
    if (!user) return false
    if (user.role === 'superadmin') return !!catalog?.actions?.find(a => a.key === key)?.read_only
    if (user.role === 'tenant_superadmin') return true
    return Array.isArray(user.actions) && user.actions.includes(key)
  }

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

  return (
    <AuthContext.Provider value={{ user, token, loading, login, verifyMFA, loginWithGoogle, logout, can, catalog, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
