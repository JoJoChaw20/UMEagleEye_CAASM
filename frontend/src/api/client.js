import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

const client = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

// JWT token interceptor
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor for 401 handling
client.interceptors.response.use(
  (response) => response,
  (error) => {
    const requestUrl = error.config?.url || ''
    const isAuthenticationAttempt = /^\/?auth\/(login|register|google|mfa\/verify)(?:\?|$)/.test(requestUrl)

    // A failed sign-in is expected to return 401. Keep it on the login form so
    // LoginPage can show the API's "Invalid credentials" message instead of
    // reloading the page and clearing the form.
    if (error.response?.status === 401 && !isAuthenticationAttempt) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
      // A user deactivated mid-session keeps the reason so the login page can say why
      const detail = String(error.response?.data?.detail || '')
      window.location.href = /deactivated/i.test(detail) ? '/login?reason=deactivated' : '/login'
    }
    // A refusal for a missing action means the grants may have changed since sign-in:
    // AuthContext re-reads the profile so the UI follows.
    if (error.response?.status === 403 && error.response?.data?.missing_action) {
      window.dispatchEvent(new CustomEvent('auth:missing-action', { detail: error.response.data.missing_action }))
    }
    return Promise.reject(error)
  }
)

export default client
