import { createContext, useContext, useState, useEffect } from 'react'
import client from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(localStorage.getItem('access_token'))
  const [loading, setLoading] = useState(true)

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

  const verifyMFA = async (username, code) => {
    const res = await client.post('/auth/mfa/verify', { username, code })
    const data = res.data
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('user', JSON.stringify(data))
    setToken(data.access_token)
    setUser(data)
    return data
  }

  const register = async (username, email, password, role) => {
    const res = await client.post('/auth/register', { username, email, password, role })
    return res.data
  }

  const loginWithGoogle = async (access_token) => {
    const res = await client.post('/auth/google', { access_token })
    const data = res.data
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
    <AuthContext.Provider value={{ user, token, loading, login, verifyMFA, register, loginWithGoogle, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
