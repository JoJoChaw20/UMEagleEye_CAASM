import { createContext, useContext, useEffect, useState } from 'react'

const ThemeContext = createContext(null)

const prefersDark = () => window.matchMedia('(prefers-color-scheme: dark)').matches

// theme: the user's choice ('dark' | 'light' | 'system'); resolved: what is on screen.
export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => localStorage.getItem('theme') || 'system')
  const [resolved, setResolved] = useState(() =>
    theme === 'system' ? (prefersDark() ? 'dark' : 'light') : theme)

  useEffect(() => {
    const root = document.documentElement
    const apply = () => {
      const next = theme === 'system' ? (prefersDark() ? 'dark' : 'light') : theme
      root.classList.toggle('light', next === 'light')
      setResolved(next)
    }
    apply()
    localStorage.setItem('theme', theme)
    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)')
      mq.addEventListener('change', apply)
      return () => mq.removeEventListener('change', apply)
    }
  }, [theme])

  return (
    <ThemeContext.Provider value={{ theme, resolved, setTheme: setThemeState }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
