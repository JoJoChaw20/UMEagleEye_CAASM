import axios from 'axios'
import { isMfaSetupRequired, isSessionEnded } from '../utils/mfa.js'

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
    // Sign-in requests carry no session yet: their 401s (wrong password, wrong code, expired
    // mfa_token, deactivated) are shown on the login screens, never turned into a redirect.
    const isSignInAttempt = /^\/?auth\/(login|register|google|mfa\/verify|mfa\/enrol\/(start|finish)|mfa\/break-glass\/\w+)(?:\?|$)/.test(requestUrl)
    const status = error.response?.status
    const detail = String(error.response?.data?.detail || '')

    // Only a 401 that ends the session (missing or expired token, signed out everywhere,
    // deactivated) signs the user out. Any other 401, such as a wrong step-up password or MFA
    // code on /auth/mfa/recovery-codes or an MFA reset, stays with the screen that asked.
    if (!isSignInAttempt && isSessionEnded(status, detail)) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
      // A user deactivated mid-session keeps the reason so the login page can say why
      window.location.href = /deactivated/i.test(detail) ? '/login?reason=deactivated' : '/login'
    }
    // An account without MFA (a session from before MFA became mandatory) is refused
    // everywhere outside /auth: end the session and send it to sign in, which sets MFA up.
    if (isMfaSetupRequired(error.response)) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
      window.location.href = '/login?reason=mfa_setup'
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
