import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { useAuth } from './AuthContext'

const sessionsKey = (uid) => `umeagleeye_chat_sessions_${uid}`
const activeKey   = (uid) => `umeagleeye_chat_active_${uid}`
export const MAX_MSG = 50

export function makeWelcome(username) {
  return {
    role: 'bot', type: 'text', ts: Date.now(),
    content: `Hello **${username ?? 'there'}**! I'm the UMEagleEye security assistant.\n\nSelect an advisory folder on the left to debug it, or use the quick buttons below.`,
  }
}

export function loadSessions(uid, username) {
  try {
    const raw = localStorage.getItem(sessionsKey(uid))
    if (raw) {
      const parsed = JSON.parse(raw)
      if (parsed && Object.keys(parsed).length > 0) return parsed
    }
  } catch {}
  return {
    general: {
      id: 'general', name: 'General', emoji: '💬',
      category: null, advisoryId: null,
      messages: [makeWelcome(username)], updatedAt: Date.now(),
    },
  }
}

export function saveSessions(uid, sessions) {
  try { localStorage.setItem(sessionsKey(uid), JSON.stringify(sessions)) } catch {}
}

export function loadActiveId(uid) {
  return localStorage.getItem(activeKey(uid)) ?? 'general'
}

export function saveActiveId(uid, id) {
  try { localStorage.setItem(activeKey(uid), id) } catch {}
}

const ChatbotContext = createContext(null)

export function ChatbotProvider({ children }) {
  const { user } = useAuth()
  const uid      = user?.userId ?? 'guest'
  const username = user?.username

  const [sessions, setSessions] = useState(() => loadSessions(uid, username))
  const [activeId, setActiveId] = useState(() => {
    const id = loadActiveId(uid)
    const s  = loadSessions(uid, username)
    return s[id] ? id : 'general'
  })
  // Tracks which session is currently streaming — persists across page navigation
  const [streamingSessionId, setStreamingSessionId] = useState(null)

  // Re-load from localStorage when the real user ID becomes available after auth resolves
  useEffect(() => {
    if (!user?.userId) return
    const stored = loadSessions(user.userId, user.username)
    setSessions(stored)
    const id = loadActiveId(user.userId)
    setActiveId(stored[id] ? id : 'general')
  }, [user?.userId]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { saveSessions(uid, sessions) }, [sessions, uid])
  useEffect(() => { saveActiveId(uid, activeId) }, [activeId, uid])

  // Stable updater — safe to capture in async streaming closures after page unmount
  const updateSession = useCallback((id, updater) => {
    setSessions(prev => {
      const s = prev[id]
      if (!s) return prev
      return { ...prev, [id]: { ...s, ...updater(s), updatedAt: Date.now() } }
    })
  }, [])

  return (
    <ChatbotContext.Provider value={{
      sessions, setSessions,
      activeId, setActiveId,
      updateSession,
      streamingSessionId, setStreamingSessionId,
    }}>
      {children}
    </ChatbotContext.Provider>
  )
}

export const useChatbot = () => useContext(ChatbotContext)
