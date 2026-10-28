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
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default client
