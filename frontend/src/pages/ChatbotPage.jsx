import { useState, useRef, useEffect } from 'react'
import {
  Bot, Send, User, Loader2, RotateCcw,
  Activity, Server, Bell, Shield, BarChart2, HelpCircle,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Message bubble ────────────────────────────────────────────────
function Bubble({ msg }) {
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
          <BotContent msg={msg} />
        </div>
        <p className="text-[10px] text-dark-500 mt-1 px-1">
          {new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </p>
      </div>
    </div>
  )
}

// ── Renders structured bot responses ─────────────────────────────
function BotContent({ msg }) {
  const { type, content, items, data } = msg

  if (type === 'stats' && items) {
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="grid grid-cols-3 gap-2">
          {items.map(({ label, value }) => (
            <div key={label} className="bg-dark-900/60 rounded-lg p-2 text-center">
              <p className="text-lg font-bold text-eagle-400">{value}</p>
              <p className="text-[10px] text-dark-400 mt-0.5">{label}</p>
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
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-1">
          {items.length === 0 && <p className="text-dark-400 text-xs">No assets found.</p>}
          {items.map((a, i) => (
            <div key={i} className="flex items-center justify-between bg-dark-900/60 rounded-lg px-3 py-1.5 text-xs">
              <span className="text-dark-200 font-mono">{a.hostname || a.ipAddress}</span>
              <span className="flex items-center gap-2">
                <span className="text-dark-400 capitalize">{a.deviceType}</span>
                <span className={`font-bold ${(a.criticalityScore ?? 0) >= 8 ? 'text-red-400' : (a.criticalityScore ?? 0) >= 5 ? 'text-yellow-400' : 'text-green-400'}`}>
                  {a.criticalityScore ?? '—'}
                </span>
              </span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (type === 'alerts' && items) {
    const sev = { critical: 'text-red-400', high: 'text-orange-400' }
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-1">
          {items.length === 0 && <p className="text-dark-400 text-xs">No critical/high alerts.</p>}
          {items.map((e, i) => (
            <div key={i} className="flex items-center justify-between bg-dark-900/60 rounded-lg px-3 py-1.5 text-xs">
              <span className="text-dark-200 capitalize">{e.eventType?.replace(/_/g, ' ')}</span>
              <span className={`font-bold capitalize ${sev[e.severity] ?? 'text-dark-400'}`}>{e.severity}</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (type === 'advisories' && items) {
    const statusColor = { open: 'text-red-400', acknowledged: 'text-yellow-400', in_progress: 'text-blue-400' }
    return (
      <div>
        <p className="font-semibold text-white mb-2">{content}</p>
        <div className="space-y-1">
          {items.length === 0 && <p className="text-dark-400 text-xs">No open advisories.</p>}
          {items.map((a, i) => (
            <div key={i} className="bg-dark-900/60 rounded-lg px-3 py-1.5 text-xs">
              <div className="flex items-center justify-between mb-0.5">
                <span className={`font-medium capitalize ${statusColor[a.status] ?? 'text-dark-400'}`}>{a.status?.replace('_', ' ')}</span>
                <span className="text-dark-500">{new Date(a.createdAt).toLocaleDateString()}</span>
              </div>
              <p className="text-dark-300 truncate">{a.summary}</p>
            </div>
          ))}
        </div>
      </div>
    )
  }

  // AI / text — render markdown-lite (bold, code, newlines)
  const html = (content ?? '')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="bg-dark-900 px-1 rounded text-accent-cyan text-[11px]">$1</code>')
    .replace(/\n/g, '<br/>')

  return <span dangerouslySetInnerHTML={{ __html: html }} />
}

// ── Quick-command pills ───────────────────────────────────────────
const QUICK = [
  { label: 'Status',      icon: Activity,  cmd: 'status',     roles: null },
  { label: 'Posture',     icon: BarChart2, cmd: 'posture',    roles: null },
  { label: 'Assets',      icon: Server,    cmd: 'assets',     roles: ['ops_lead','security_engineer','mssp_analyst','superadmin'] },
  { label: 'Alerts',      icon: Bell,      cmd: 'alerts',     roles: ['ops_lead','security_engineer','mssp_analyst','superadmin'] },
  { label: 'Advisories',  icon: Shield,    cmd: 'advisories', roles: ['ops_lead','security_engineer','mssp_analyst','superadmin'] },
  { label: 'Help',        icon: HelpCircle,cmd: 'help',       roles: null },
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

// ── Main page ─────────────────────────────────────────────────────
export default function ChatbotPage() {
  const { user } = useAuth()
  const [messages, setMessages] = useState([
    {
      role: 'bot',
      type: 'text',
      content: `Hello **${user?.username ?? 'there'}**! I'm the UMEagleEye security assistant.\n\nType a command or question below, or use the quick buttons to get started.`,
      ts: Date.now(),
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = async (text) => {
    const trimmed = (text ?? input).trim()
    if (!trimmed || loading) return
    setInput('')

    const userMsg = { role: 'user', type: 'text', content: trimmed, ts: Date.now() }
    setMessages(prev => [...prev, userMsg])
    setLoading(true)

    try {
      const res = await client.post('/chatbot', { message: trimmed })
      const { type, content, items, data } = res.data
      setMessages(prev => [...prev, { role: 'bot', type, content, items, data, ts: Date.now() }])
    } catch (err) {
      const detail = err?.response?.data?.detail || err?.response?.data?.content || 'Failed to reach the assistant.'
      setMessages(prev => [...prev, { role: 'bot', type: 'text', content: detail, ts: Date.now() }])
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  const clearChat = () => setMessages([{
    role: 'bot',
    type: 'text',
    content: `Chat cleared. How can I help you, **${user?.username ?? 'there'}**?`,
    ts: Date.now(),
  }])

  const visibleQuick = QUICK.filter(q => !q.roles || q.roles.includes(user?.role))

  return (
    <div className="flex flex-col h-[calc(100vh-5rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-eagle-500/10 rounded-xl border border-eagle-500/20">
            <Bot className="w-5 h-5 text-eagle-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Security Assistant</h1>
            <p className="text-xs text-dark-400">Powered by AI · Ask anything about your security posture</p>
          </div>
        </div>
        <button
          onClick={clearChat}
          className="btn-secondary flex items-center gap-2 text-sm"
          title="Clear chat"
        >
          <RotateCcw className="w-4 h-4" /> Clear
        </button>
      </div>

      {/* Quick buttons */}
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

      {/* Message area */}
      <div className="flex-1 overflow-y-auto glass-card p-4 space-y-4 min-h-0">
        {messages.map((msg, i) => <Bubble key={i} msg={msg} />)}
        {loading && <Typing />}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="mt-3 flex-shrink-0">
        <div className="flex gap-2 items-end bg-dark-800/60 border border-dark-700/40 rounded-xl p-2 focus-within:border-eagle-500/40 transition-colors">
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Ask a security question or type a command..."
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
  )
}
