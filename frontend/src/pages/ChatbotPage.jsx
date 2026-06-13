import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Bot, Send, User, Loader2, RotateCcw,
  Activity, Server, Bell, Shield, BarChart2, HelpCircle,
  CheckCircle2, ChevronDown, ChevronUp, Sparkles,
  Trash2, Plus, PanelLeft,
} from 'lucide-react'
import { useNavigate, useLocation } from 'react-router-dom'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import { useChatbot, makeWelcome, MAX_MSG } from '../context/ChatbotContext'
import { useTheme } from '../context/ThemeContext'

// ── Message bubble ────────────────────────────────────────────────
function Bubble({ msg, onSend, onOpenAdvisorySession, onSelectTenant, canDebugAI }) {
  const isBot = msg.role === 'bot'
  return (
    <div className={`flex gap-3 ${isBot ? '' : 'flex-row-reverse'}`}>
      <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${isBot ? 'bg-eagle-500/20 text-eagle-400' : 'bg-dark-700 text-dark-300'}`}>
        {isBot ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
      </div>
      <div className={`max-w-[78%] ${isBot ? '' : 'items-end flex flex-col'}`}>
        <div className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
          isBot
            ? 'bg-dark-800 border border-dark-700/50 text-dark-100 rounded-tl-sm'
            : 'bg-eagle-600/20 border border-eagle-500/30 text-dark-100 rounded-tr-sm'
        }`}>
          <BotContent msg={msg} onSend={onSend} onOpenAdvisorySession={onOpenAdvisorySession} onSelectTenant={onSelectTenant} canDebugAI={canDebugAI} />
        </div>
        <p className="text-[10px] text-dark-500 mt-1 px-1">
          {new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </p>
      </div>
    </div>
  )
}

// ── Inline markdown parser (bold + code — no dangerouslySetInnerHTML) ────
function parseInline(text, keyPrefix, isLight) {
  const codeClass = isLight
    ? 'inline-flex items-center bg-eagle-700/15 border border-eagle-700/60 text-eagle-800 px-1.5 py-0.5 rounded-md text-[11px] font-mono font-semibold mx-0.5 leading-none'
    : 'inline-flex items-center bg-eagle-500/25 border border-eagle-500/70 text-eagle-200 px-1.5 py-0.5 rounded-md text-[11px] font-mono font-semibold mx-0.5 leading-none'

  const segments = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  return segments.map((seg, i) => {
    if (seg.startsWith('**') && seg.endsWith('**')) {
      return (
        <strong key={`${keyPrefix}-b${i}`} className="text-white font-semibold">
          {seg.slice(2, -2)}
        </strong>
      )
    }
    if (seg.startsWith('`') && seg.endsWith('`')) {
      return (
        <code key={`${keyPrefix}-c${i}`} className={codeClass}>
          {seg.slice(1, -1)}
        </code>
      )
    }
    return seg ? <span key={`${keyPrefix}-t${i}`}>{seg}</span> : null
  }).filter(Boolean)
}

// Renders a full markdown text block: paragraphs, bullet lists, plain lines
function MarkdownBody({ text }) {
  const { theme } = useTheme()
  const isLight = theme === 'light' || (theme === 'system' && !window.matchMedia('(prefers-color-scheme: dark)').matches)
  if (!text) return null

  const paragraphs = text.split(/\n{2,}/)

  return (
    <div className="space-y-2 text-dark-100 leading-relaxed">
      {paragraphs.map((para, pi) => {
        const lines = para.split('\n').filter(l => l !== undefined)

        const isList = lines.every(l => /^\s*[-*]\s/.test(l) || l.trim() === '')
        if (isList) {
          return (
            <ul key={pi} className="space-y-1 pl-1">
              {lines.filter(l => l.trim()).map((l, li) => (
                <li key={li} className="flex gap-2 items-start">
                  <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-eagle-400/60 flex-shrink-0" />
                  <span>{parseInline(l.replace(/^\s*[-*]\s+/, ''), `${pi}-${li}`, isLight)}</span>
                </li>
              ))}
            </ul>
          )
        }

        if (lines.length === 1) {
          return (
            <p key={pi}>
              {parseInline(lines[0], String(pi), isLight)}
            </p>
          )
        }

        return (
          <div key={pi} className="space-y-0.5">
            {lines.map((line, li) => (
              <p key={li}>{parseInline(line, `${pi}-${li}`, isLight)}</p>
            ))}
          </div>
        )
      })}
    </div>
  )
}

// ── Renders structured bot responses ─────────────────────────────
function BotContent({ msg, onSend, onOpenAdvisorySession, onSelectTenant, canDebugAI }) {
  const { type, content, items, data } = msg

  if (type === 'tenant_select') {
    const msgTenants = msg.tenants || []
    return (
      <div>
        <p className="text-dark-200 mb-3">{content}</p>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSelectTenant?.(null, 'All Tenants', msg.command)}
            className="px-3 py-1.5 text-xs rounded-lg bg-dark-700 border border-dark-600 text-dark-300 hover:text-white hover:border-dark-400 transition-colors"
          >
            🌐 All Tenants
          </button>
          {msgTenants.map(t => (
            <button
              key={t.tenant_id}
              onClick={() => onSelectTenant?.(t.tenant_id, t.name, msg.command)}
              className="px-3 py-1.5 text-xs rounded-lg bg-eagle-500/10 border border-eagle-500/30 text-eagle-300 hover:bg-eagle-500/20 transition-colors"
            >
              {t.name}
            </button>
          ))}
        </div>
      </div>
    )
  }
  const navigate = useNavigate()
  const [expandedId, setExpandedId] = useState(null)

  if (type === 'stats' && items) {
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="grid grid-cols-2 gap-2">
          {items.map(({ label, value }) => (
            <div key={label} className="bg-dark-900/60 rounded-lg p-2 text-center">
              <p className="text-lg font-bold text-eagle-400">{value}</p>
              <p className="text-[10px] text-dark-300 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (type === 'posture' && data) {
    const color = data.score >= 70 ? 'text-green-400' : data.score >= 40 ? 'text-yellow-400' : 'text-red-400'
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="flex items-center gap-4 bg-dark-900/60 rounded-lg p-3">
          <div className="text-center">
            <p className={`text-3xl font-bold ${color}`}>{data.score}</p>
            <p className="text-[10px] text-dark-400">/ 100</p>
          </div>
          <div className="space-y-1 text-xs text-dark-300">
            <p>Total assets: <span className="text-white font-medium">{data.total}</span></p>
            <p>Critical assets: <span className="text-red-400 font-medium">{data.critical}</span></p>
            <p>Open critical events: <span className="text-yellow-400 font-medium">{data.openCrit}</span></p>
          </div>
        </div>
      </div>
    )
  }

  if (type === 'assets' && items) {
    const critColor = (s) => (s ?? 0) >= 8 ? 'text-red-400 bg-red-500/10 border-red-500/30' : (s ?? 0) >= 5 ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' : 'text-green-400 bg-green-500/10 border-green-500/30'
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-1">
          {items.length === 0 && <p className="text-dark-400 text-xs">No assets found.</p>}
          {items.map((a, i) => (
            <div key={i} className="flex items-center gap-2 bg-dark-900/60 rounded-lg px-3 py-2 text-xs">
              <span className="text-dark-500 w-4 text-right flex-shrink-0">{i + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="text-dark-100 font-medium truncate">{a.hostname || a.ipAddress}</p>
                {a.hostname && <p className="text-dark-500 font-mono">{a.ipAddress}</p>}
              </div>
              <span className="text-dark-400 capitalize flex-shrink-0">{a.deviceType}</span>
              <span className={`flex-shrink-0 font-bold px-1.5 py-0.5 rounded border text-[10px] ${critColor(a.criticalityScore)}`}>
                {a.criticalityScore ?? '—'}/10
              </span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (type === 'alerts' && items) {
    const sevCls = { critical: 'text-red-400 bg-red-500/10 border-red-500/30', high: 'text-orange-400 bg-orange-500/10 border-orange-500/30' }
    const getDetail = (e) => {
      const d = e.details ?? {}
      return d.cve_id || d.cve || d.package_name || d.action || d.description || '—'
    }
    const isCve = (detail) => /^CVE-\d{4}-\d+$/i.test(detail)
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-1">
          {items.length === 0 && <p className="text-dark-400 text-xs">No critical/high alerts.</p>}
          {items.map((e, i) => {
            const detail = getDetail(e)
            return (
              <div
                key={i}
                onClick={() => navigate('/alerts')}
                className="cursor-pointer bg-dark-900/60 hover:bg-dark-800/80 rounded-lg px-3 py-2 text-xs transition-colors border border-transparent hover:border-eagle-500/30"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-dark-100 font-medium capitalize">{e.eventType?.replace(/_/g, ' ')}</span>
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold capitalize ${sevCls[e.severity] ?? 'text-dark-400'}`}>{e.severity}</span>
                </div>
                <div className="flex items-center justify-between">
                  {isCve(detail) ? (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${detail}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={ev => ev.stopPropagation()}
                      className="font-mono text-eagle-400 hover:text-eagle-300 hover:underline"
                    >
                      {detail}
                    </a>
                  ) : (
                    <span className="font-mono text-dark-200 truncate max-w-[60%]">{detail}</span>
                  )}
                  <span className="text-dark-500">{e.hostname || e.ipAddress}</span>
                </div>
                <p className="text-dark-600 mt-0.5">{new Date(e.timestamp).toLocaleString()}</p>
              </div>
            )
          })}
        </div>
        <p className="text-dark-500 text-[10px] mt-2 text-center">Click any alert to view details in Alerts page →</p>
      </div>
    )
  }

  if (type === 'advisories' && items) {
    const statusCls = {
      open:         'text-red-400 bg-red-500/10 border-red-500/30',
      acknowledged: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
      in_progress:  'text-blue-400 bg-blue-500/10 border-blue-500/30',
    }
    const parseSteps = (raw = '') => {
      raw = raw.trim()
      if (raw.startsWith('{') && raw.endsWith('}'))
        return raw.slice(1, -1).split(/",\s*"/).map(s => s.replace(/^"+|"+$/g, '').trim()).filter(Boolean).map(s => s.replace(/^\d+\.\s*/, ''))
      return raw.split(/\n/).map(s => s.trim()).filter(Boolean).map(s => s.replace(/^\d+\.\s*/, ''))
    }
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-2">
          {items.length === 0 && <p className="text-dark-400 text-xs">No open advisories.</p>}
          {items.map((a) => {
            const shortId = a.advisoryId?.slice(0, 8)
            const isExpanded = expandedId === a.advisoryId
            const steps = parseSteps(a.recommendedAction)
            return (
              <div key={a.advisoryId} className="bg-dark-900/60 rounded-lg border border-dark-700/50 text-xs overflow-hidden">
                <button
                  onClick={() => setExpandedId(isExpanded ? null : a.advisoryId)}
                  className="w-full text-left px-3 py-2 flex items-start justify-between gap-2 hover:bg-dark-800/60 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold capitalize flex-shrink-0 ${statusCls[a.status] ?? 'text-dark-400 border-dark-600'}`}>
                        {a.status?.replace('_', ' ')}
                      </span>
                      <span className="text-dark-500 font-mono text-[10px] truncate">{shortId}...</span>
                      <span className="text-dark-600 text-[10px] flex-shrink-0 ml-auto">{new Date(a.createdAt).toLocaleDateString()}</span>
                    </div>
                    <p className="text-dark-300 leading-snug line-clamp-2">{a.summary}</p>
                  </div>
                  {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 mt-0.5" /> : <ChevronDown className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 mt-0.5" />}
                </button>

                {isExpanded && (
                  <div className="px-3 pb-3 border-t border-dark-700/50 pt-2 space-y-3">
                    <div>
                      <p className="text-dark-500 uppercase text-[10px] tracking-wider mb-1">Advisory ID</p>
                      <p className="text-dark-200 font-mono break-all leading-relaxed select-all">{a.advisoryId}</p>
                    </div>
                    <div>
                      <p className="text-dark-500 uppercase text-[10px] tracking-wider mb-1">Description</p>
                      <p className="text-dark-200 leading-relaxed whitespace-pre-wrap">{a.summary}</p>
                    </div>
                    <div>
                      <p className="text-dark-500 uppercase text-[10px] tracking-wider mb-1">Recommended Actions</p>
                      <div className="space-y-1.5">
                        {steps.length > 1 ? steps.map((step, i) => (
                          <div key={i} className="flex gap-2 items-start">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-eagle-500/20 text-eagle-400 text-[9px] font-bold flex items-center justify-center mt-0.5">{i + 1}</span>
                            <p className="text-dark-200 leading-relaxed">{step}</p>
                          </div>
                        )) : <p className="text-dark-200 leading-relaxed whitespace-pre-wrap">{a.recommendedAction}</p>}
                      </div>
                    </div>
                    {canDebugAI && (
                      <button
                        onClick={() => onOpenAdvisorySession?.(a)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-eagle-500/10 border border-eagle-500/30 text-eagle-400 hover:bg-eagle-500/20 transition-colors text-[11px] font-medium w-full justify-center"
                      >
                        <Sparkles className="w-3 h-3" />
                        Debug with AI
                      </button>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  if (type === 'fix' && data) {
    return (
      <div>
        <div className="flex items-center gap-2 mb-2">
          <CheckCircle2 className="w-4 h-4 text-green-400" />
          <p className="font-semibold text-green-400">Advisory Resolved</p>
        </div>
        <div className="bg-dark-900/60 rounded-lg px-3 py-2 text-xs space-y-1">
          <p className="text-dark-400 font-mono text-[10px]">{data.advisoryId?.slice(0, 8)}...</p>
          <p className="text-dark-100">{data.summary}</p>
        </div>
      </div>
    )
  }


  // AI / text — markdown renderer (no dangerouslySetInnerHTML)
  return <MarkdownBody text={content ?? ''} />
}

// Commands that require tenant selection for superadmin before querying
const DATA_COMMANDS = new Set(['status', 'assets', 'alerts', 'advisories', 'posture'])

// ── Quick-command pills ───────────────────────────────────────────
const QUICK = [
  { label: 'Status',      icon: Activity,   cmd: 'status',     roles: null },
  { label: 'Posture',     icon: BarChart2,  cmd: 'posture',    roles: null },
  { label: 'Assets',      icon: Server,     cmd: 'assets',     roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Alerts',      icon: Bell,       cmd: 'alerts',     roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Advisories',  icon: Shield,     cmd: 'advisories', roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Help',        icon: HelpCircle, cmd: 'help',       roles: null },
]

// ── Typing indicator ──────────────────────────────────────────────
function Typing() {
  return (
    <div className="flex gap-3">
      <div className="w-8 h-8 rounded-full bg-eagle-500/20 flex items-center justify-center flex-shrink-0">
        <Bot className="w-4 h-4 text-eagle-400" />
      </div>
      <div className="bg-dark-800 border border-dark-700/50 rounded-2xl rounded-tl-sm px-4 py-3 flex items-center gap-1">
        {[0, 1, 2].map(i => (
          <span key={i} className="w-1.5 h-1.5 bg-dark-400 rounded-full animate-bounce" style={{ animationDelay: `${i * 150}ms` }} />
        ))}
      </div>
    </div>
  )
}

// ── Session sidebar ───────────────────────────────────────────────
function SessionSidebar({ sessions, activeId, onSelect, onDelete, onNew }) {
  const sorted = Object.values(sessions).sort((a, b) => {
    if (a.id === 'general') return -1
    if (b.id === 'general') return 1
    return b.updatedAt - a.updatedAt
  })

  return (
    <div className="w-56 flex-shrink-0 flex flex-col gap-1 pr-3 border-r border-dark-700/50 overflow-y-auto">
      <div className="flex items-center justify-between px-2 pb-1 pt-0.5">
        <p className="text-[9px] font-semibold text-dark-500 tracking-widest uppercase">Sessions</p>
        <button
          onClick={onNew}
          className="p-0.5 text-dark-500 hover:text-eagle-400 transition-colors"
          title="New chat"
        >
          <Plus className="w-3.5 h-3.5" />
        </button>
      </div>
      {sorted.map(s => (
        <div key={s.id} className="group relative">
          <button
            onClick={() => onSelect(s.id)}
            className={`w-full text-left flex items-start gap-2 px-2 py-2 rounded-lg transition-all text-xs ${
              activeId === s.id
                ? 'bg-eagle-500/15 border border-eagle-500/30 text-white'
                : 'text-dark-400 hover:bg-dark-800/60 hover:text-dark-100 border border-transparent'
            }`}
          >
            <span className="text-base leading-none flex-shrink-0 mt-0.5">{s.emoji}</span>
            <div className="min-w-0 flex-1">
              <p className="font-medium truncate leading-tight">{s.name}</p>
              {s.category && <p className="text-dark-500 text-[10px] truncate mt-0.5">{s.category}</p>}
              <p className="text-dark-600 text-[10px] mt-0.5">{s.messages.length} msg{s.messages.length !== 1 ? 's' : ''}</p>
            </div>
          </button>
          {s.id !== 'general' && (
            <button
              onClick={() => onDelete(s.id)}
              className="absolute top-1.5 right-1.5 opacity-0 group-hover:opacity-100 p-0.5 text-dark-500 hover:text-accent-red transition-all"
              title="Delete session"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function ChatbotPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const canDebugAI   = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const location = useLocation()

  // Sessions and streaming state live in ChatbotContext (persists across page navigation)
  const { sessions, setSessions, activeId, setActiveId, updateSession, streamingSessionId, setStreamingSessionId } = useChatbot()

  const [input, setInput] = useState('')
  const [localLoading, setLocalLoading] = useState(false)
  const [tenants, setTenants] = useState([])
  const bottomRef = useRef(null)

  // Combine: local loading (commands) OR background streaming on this session
  const loading = localLoading || streamingSessionId === activeId

  const activeSession = sessions[activeId] ?? sessions.general

  // Fetch tenant list once for superadmin (used by tenant_select prompt)
  useEffect(() => {
    if (!isSuperadmin) return
    client.get('/tenants').then(res => setTenants(res.data.tenants || [])).catch(() => {})
  }, [isSuperadmin])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [activeId, sessions, loading])



  const send = useCallback(async (text) => {
    const trimmed = (text ?? input).trim()
    if (!trimmed || loading) return
    setInput('')

    const userMsg = { role: 'user', type: 'text', content: trimmed, ts: Date.now() }
    updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), userMsg] }))

    // Superadmin data commands → ask which tenant first instead of querying immediately
    if (isSuperadmin && DATA_COMMANDS.has(trimmed.toLowerCase())) {
      const botMsg = {
        role: 'bot', type: 'tenant_select', ts: Date.now(),
        content: 'Which tenant would you like to query?',
        tenants,
        command: trimmed,
      }
      updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), botMsg] }))
      return
    }

    setLocalLoading(true)

    try {
      const currentMsgs = sessions[activeId]?.messages ?? []
      const history = currentMsgs
        .filter(m => m.role === 'user' || (m.role === 'bot' && ['text', 'ai'].includes(m.type)))
        .slice(-6)
        .map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: (m.content ?? '').slice(0, 6000) }))

      // Detect AI-intent messages and stream the response token-by-token
      const NON_AI = /^(status|posture|assets?|alerts?|advisori|help|debug\s|fix[\s$])/i
      const isAI = !NON_AI.test(trimmed.trim())

      if (isAI) {
        const placeholderTs = Date.now() + 1
        const sessionIdAtSend = activeId  // capture so closure works after navigation
        updateSession(sessionIdAtSend, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), { role: 'bot', type: 'ai', content: '', ts: placeholderTs }] }))
        setStreamingSessionId(sessionIdAtSend)  // mark in context — survives page unmount
        setLocalLoading(false)  // release local spinner; streaming indicator takes over

        const apiBase = import.meta.env.VITE_API_URL || '/api/v1'
        const token = localStorage.getItem('access_token')
        const fetchRes = await fetch(`${apiBase}/chatbot`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify({ message: trimmed, history, stream: true }),
        })
        if (!fetchRes.ok) throw new Error(`HTTP ${fetchRes.status}`)

        const reader = fetchRes.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        let full = ''
        try {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            buf += decoder.decode(value, { stream: true })
            const lines = buf.split('\n')
            buf = lines.pop() ?? ''
            for (const line of lines) {
              if (!line.startsWith('data: ')) continue
              const chunk = line.slice(6).trim()
              if (chunk === '[DONE]') break
              try {
                const parsed = JSON.parse(chunk)
                if (parsed.error) throw new Error(parsed.error)
                if (parsed.token) {
                  full += parsed.token
                  // updateSession is from context — works even when ChatbotPage is unmounted
                  updateSession(sessionIdAtSend, s => {
                    const msgs = [...s.messages]
                    const idx = msgs.findIndex(m => m.ts === placeholderTs && m.role === 'bot')
                    if (idx !== -1) msgs[idx] = { ...msgs[idx], content: full }
                    return { messages: msgs }
                  })
                }
              } catch { /* skip malformed chunk */ }
            }
          }
        } finally {
          reader.releaseLock()
          setStreamingSessionId(null)  // clear background streaming flag
        }
        return  // skip outer finally setLocalLoading (already cleared above)
      } else {
        const res = await client.post('/chatbot', { message: trimmed, history })
        const { type, content, items, data } = res.data
        const botMsg = { role: 'bot', type, content, items, data, ts: Date.now() }
        updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), botMsg] }))
      }
    } catch (err) {
      setStreamingSessionId(null)
      const detail = err?.response?.data?.detail || err?.message || 'Failed to reach the assistant.'
      updateSession(activeId, s => ({ messages: [...s.messages, { role: 'bot', type: 'text', content: detail, ts: Date.now() }] }))
    } finally {
      setLocalLoading(false)
    }
  }, [input, loading, activeId, sessions, updateSession, isSuperadmin, tenants, setStreamingSessionId])

  // Called when superadmin picks a tenant from the tenant_select prompt
  const sendWithTenant = useCallback(async (tenantId, tenantName, command) => {
    if (loading) return
    const label = tenantName ?? 'All Tenants'
    const confirmMsg = { role: 'bot', type: 'text', content: `Querying **${label}**…`, ts: Date.now() }
    updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), confirmMsg] }))
    setLocalLoading(true)
    try {
      const body = { message: command, ...(tenantId ? { tenant_id: tenantId } : {}) }
      const res = await client.post('/chatbot', body)
      const { type, content, items, data } = res.data
      const botMsg = { role: 'bot', type, content, items, data, ts: Date.now() }
      updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), botMsg] }))
    } catch (err) {
      const detail = err?.response?.data?.detail || 'Failed to reach the assistant.'
      updateSession(activeId, s => ({ messages: [...s.messages, { role: 'bot', type: 'text', content: detail, ts: Date.now() }] }))
    } finally {
      setLocalLoading(false)
    }
  }, [loading, activeId, updateSession])

  // Called when user clicks "Debug with AI" on an advisory
  const openAdvisorySession = useCallback(async (advisory) => {
    const sessionId = `adv-${advisory.advisoryId}`

    // Switch to existing session if it already exists
    if (sessions[sessionId]) {
      setActiveId(sessionId)
      return
    }

    // Create session with placeholder name
    const placeholder = {
      id: sessionId,
      name: 'Loading…',
      emoji: '🔄',
      category: null,
      advisoryId: advisory.advisoryId,
      messages: [],
      updatedAt: Date.now(),
    }
    setSessions(prev => ({ ...prev, [sessionId]: placeholder }))
    setActiveId(sessionId)
    setLocalLoading(true)

    try {
      // AI categorize in parallel with first debug message
      const [catRes] = await Promise.allSettled([
        client.post('/chatbot/categorize', {
          summary: advisory.summary ?? '',
          recommendedAction: advisory.recommendedAction ?? '',
        }),
      ])

      const cat = catRes.status === 'fulfilled' ? catRes.value.data : { name: 'Security Advisory', category: 'Security', emoji: '🔴' }

      // Update session name from AI
      setSessions(prev => ({
        ...prev,
        [sessionId]: { ...prev[sessionId], name: cat.name, emoji: cat.emoji, category: cat.category },
      }))

      // Auto-send the debug command — stream so background generation survives navigation
      const prompt = `debug ${advisory.advisoryId}`
      const userMsg = { role: 'user', type: 'text', content: prompt, ts: Date.now() }
      const placeholderTs = Date.now() + 1
      setSessions(prev => ({
        ...prev,
        [sessionId]: {
          ...prev[sessionId],
          messages: [userMsg, { role: 'bot', type: 'ai', content: '', ts: placeholderTs }],
          updatedAt: Date.now(),
        },
      }))
      setStreamingSessionId(sessionId)
      setLocalLoading(false)

      const apiBase = import.meta.env.VITE_API_URL || '/api/v1'
      const token = localStorage.getItem('access_token')
      const fetchRes = await fetch(`${apiBase}/chatbot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ message: prompt, history: [], stream: true }),
      })
      if (!fetchRes.ok) throw new Error(`HTTP ${fetchRes.status}`)

      const reader = fetchRes.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      let full = ''
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            const chunk = line.slice(6).trim()
            if (chunk === '[DONE]') break
            try {
              const parsed = JSON.parse(chunk)
              if (parsed.token) {
                full += parsed.token
                // setSessions from context — continues working after navigation
                setSessions(prev => {
                  const s = prev[sessionId]
                  if (!s) return prev
                  const msgs = [...s.messages]
                  const idx = msgs.findIndex(m => m.ts === placeholderTs && m.role === 'bot')
                  if (idx !== -1) msgs[idx] = { ...msgs[idx], content: full }
                  return { ...prev, [sessionId]: { ...s, messages: msgs, updatedAt: Date.now() } }
                })
              }
            } catch { /* skip malformed chunk */ }
          }
        }
      } finally {
        reader.releaseLock()
        setStreamingSessionId(null)
      }
      return  // skip outer finally setLocalLoading
    } catch {
      setStreamingSessionId(null)
      setSessions(prev => ({
        ...prev,
        [sessionId]: {
          ...prev[sessionId],
          name: 'Advisory Session',
          emoji: '🔴',
          messages: [{ role: 'bot', type: 'text', content: 'Failed to load advisory debug. Please try again.', ts: Date.now() }],
        },
      }))
    } finally {
      setLocalLoading(false)
    }
  }, [sessions, setStreamingSessionId])

  // ── Auto-open advisory session when navigated from AdvisoriesPage ─
  useEffect(() => {
    const advisory = location.state?.advisory
    if (!advisory?.advisoryId) return
    openAdvisorySession(advisory)
    // Clear router state so re-renders don't re-trigger
    window.history.replaceState({}, '')
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const deleteSession = (id) => {
    if (id === 'general') return
    setSessions(prev => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    if (activeId === id) setActiveId('general')
  }

  const newSession = () => {
    const id = `session-${Date.now()}`
    const session = {
      id,
      name: 'New Chat',
      emoji: '💬',
      category: null,
      advisoryId: null,
      messages: [makeWelcome(user?.username)],
      updatedAt: Date.now(),
    }
    setSessions(prev => ({ ...prev, [id]: session }))
    setActiveId(id)
  }

  const clearSession = () => {
    if (activeId === 'general') {
      updateSession('general', () => ({ messages: [makeWelcome(user?.username)] }))
    } else {
      updateSession(activeId, s => ({ messages: [] }))
    }
  }

  const [sidebarOpen, setSidebarOpen] = useState(true)
  const visibleQuick = QUICK.filter(q => !q.roles || q.roles.includes(user?.role))
  const messages = activeSession.messages ?? []

  return (
    <div className="flex h-[calc(100vh-5rem)] gap-0">

      {/* ── Session sidebar ───────────────────────────── */}
      {sidebarOpen && (
        <SessionSidebar
          sessions={sessions}
          activeId={activeId}
          onSelect={setActiveId}
          onDelete={deleteSession}
          onNew={newSession}
        />
      )}

      {/* ── Chat panel ───────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 pl-4">

        {/* Header */}
        <div className="flex items-center justify-between mb-3 flex-shrink-0">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSidebarOpen(v => !v)}
              className="p-1.5 text-dark-400 hover:text-dark-100 hover:bg-dark-800 rounded-lg transition-all"
              title={sidebarOpen ? 'Hide sessions' : 'Show sessions'}
            >
              <PanelLeft className="w-4 h-4" />
            </button>
            <span className="text-xl">{activeSession.emoji}</span>
            <div>
              <h1 className="text-base font-bold text-white leading-tight">{activeSession.name}</h1>
              {activeSession.category && (
                <p className="text-[10px] text-dark-400">{activeSession.category}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={clearSession}
              className="btn-secondary flex items-center gap-1.5 text-xs px-3 py-1.5"
              title="Clear this session"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Clear
            </button>
          </div>
        </div>

        {/* Quick buttons — only in General session */}
        {activeId === 'general' && (
          <div className="flex flex-wrap gap-2 mb-3 flex-shrink-0">
            {visibleQuick.map(({ label, icon: Icon, cmd }) => (
              <button
                key={cmd}
                onClick={() => send(cmd)}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-dark-800/60 border border-dark-700/40 text-dark-300 hover:text-white hover:border-eagle-500/40 hover:bg-eagle-500/5 transition-all disabled:opacity-50"
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </button>
            ))}
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-y-auto glass-card p-4 space-y-4 min-h-0">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-dark-500 gap-2">
              <Sparkles className="w-8 h-8 opacity-30" />
              <p className="text-sm">Ask anything about this advisory</p>
            </div>
          )}
          {messages.map((msg, i) => (
            <Bubble key={i} msg={msg} onSend={send} onOpenAdvisorySession={openAdvisorySession} onSelectTenant={sendWithTenant} canDebugAI={canDebugAI} />
          ))}
          {loading && <Typing />}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className="mt-3 flex-shrink-0">
          <div className="flex gap-2 items-end bg-dark-800/60 border border-dark-700/40 rounded-xl p-2 focus-within:border-eagle-500/40 transition-colors">
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder={activeId === 'general' ? 'Ask a security question or type a command…' : 'Ask about this advisory…'}
              rows={1}
              disabled={loading}
              className="flex-1 bg-transparent text-sm text-dark-100 placeholder-dark-500 resize-none outline-none max-h-28 py-1 px-2 disabled:opacity-50"
              style={{ minHeight: '2rem' }}
            />
            <button
              onClick={() => send()}
              disabled={loading || !input.trim()}
              className="p-2 bg-eagle-600 hover:bg-eagle-500 disabled:bg-dark-700 disabled:text-dark-500 text-white rounded-lg transition-colors flex-shrink-0"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-[10px] text-dark-600 mt-1.5 text-center">Enter to send · Shift+Enter for new line</p>
        </div>
      </div>
    </div>
  )
}
