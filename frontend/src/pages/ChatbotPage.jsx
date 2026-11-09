import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Bot, Send, User, Loader2, RotateCcw,
  Activity, Server, Bell, Shield, BarChart2, HelpCircle,
  CheckCircle2, Sparkles,
  Trash2, Plus, PanelLeft, MessageCircle, FileSearch, Wrench, XCircle,
} from 'lucide-react'
import { useLocation } from 'react-router-dom'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import { useChatbot, makeWelcome, MAX_MSG } from '../context/ChatbotContext'
import { useTheme } from '../context/ThemeContext'

// Sessions keep their stored emoji for compatibility, but the page draws icons:
// a speech bubble for chats, the Advisories icon for advisory debug sessions.
function SessionIcon({ session, className = 'h-4 w-4' }) {
  if (session?.name === 'Loading…') return <Loader2 className={`${className} animate-spin text-dark-400`} />
  if (session?.advisoryId) return <FileSearch className={`${className} text-eagle-400`} />
  return <MessageCircle className={`${className} text-dark-400`} />
}


// ── Message bubble ────────────────────────────────────────────────
function Bubble({ msg, onConfirm, canConfirm }) {
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
          <BotContent msg={msg} onConfirm={onConfirm} canConfirm={canConfirm} />
        </div>
        <p className="text-[11px] text-dark-500 mt-1 px-1">
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
        <strong key={`${keyPrefix}-b${i}`} className="text-dark-50 font-semibold">
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

// Renders the assistant's Markdown as chat-friendly blocks, without dangerouslySetInnerHTML:
// section titles, tables, numbered steps (numbers kept from the text, so a command box
// between steps does not restart them), bullet lists, command boxes with Copy, and notes.
// Horizontal rules are dropped. Tolerates blank lines between table rows and an unclosed fence.
function parseBlocks(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n')
  const blocks = []
  const isTableRow = (l) => /^\s*\|.*\|\s*$/.test(l)
  const isTableSep = (l) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l)
  const nextNonBlank = (j) => { while (j < lines.length && !lines[j].trim()) j++; return j }
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const t = line.trim()
    if (!t) { i++; continue }

    const fence = t.match(/^(`{3,}|~{3,})\s*([\w+-]*)/)
    if (fence) {
      const body = []
      i++
      // ends at the closing fence, or at a stray line of backticks (an unclosed fence)
      while (i < lines.length && !/^`+$/.test(lines[i].trim()) && !lines[i].trim().startsWith(fence[1].slice(0, 3))) { body.push(lines[i]); i++ }
      i++
      const code = body.filter(l => l.trim()).join('\n')
      if (code) blocks.push({ kind: 'code', lang: fence[2] || '', code })
      continue
    }
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(t)) { i++; continue }

    const heading = t.match(/^(#{1,6})\s+(.*)$/)
    if (heading) { blocks.push({ kind: 'heading', level: heading[1].length, text: heading[2].replace(/#+\s*$/, '') }); i++; continue }

    if (isTableRow(line)) {
      const rows = []
      while (i < lines.length) {
        if (isTableRow(lines[i])) {
          if (!isTableSep(lines[i])) rows.push(lines[i].trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim()))
          i++
        } else if (!lines[i].trim() && isTableRow(lines[nextNonBlank(i)] ?? '')) {
          i = nextNonBlank(i)
        } else break
      }
      if (rows.length) blocks.push({ kind: 'table', head: rows[0], rows: rows.slice(1) })
      continue
    }

    if (t.startsWith('>')) {
      const body = []
      while (i < lines.length && lines[i].trim().startsWith('>')) { body.push(lines[i].trim().replace(/^>\s?/, '')); i++ }
      blocks.push({ kind: 'note', text: body.join(' ') })
      continue
    }

    const num = t.match(/^(\d+)[.)]\s+(.*)$/)
    if (num) {
      const items = []
      while (i < lines.length) {
        const m = lines[i].trim().match(/^(\d+)[.)]\s+(.*)$/)
        if (m && !/^\s{2,}/.test(lines[i])) { items.push({ n: m[1], text: m[2], sub: [] }); i++; continue }
        const sub = lines[i].match(/^\s+[-*]\s+(.*)$/)
        if (sub && items.length) { items[items.length - 1].sub.push(sub[1]); i++; continue }
        break
      }
      blocks.push({ kind: 'steps', items })
      continue
    }

    if (/^[-*•]\s+/.test(t)) {
      const items = []
      while (i < lines.length && /^\s*[-*•]\s+/.test(lines[i])) {
        items.push({ text: lines[i].replace(/^\s*[-*•]\s+/, ''), indent: /^\s{2,}/.test(lines[i]) })
        i++
      }
      blocks.push({ kind: 'bullets', items })
      continue
    }

    const para = []
    while (i < lines.length && lines[i].trim() && !/^\s*(#{1,6}\s|[-*•]\s|\d+[.)]\s|>|\||`{3}|~{3})/.test(lines[i])) {
      para.push(lines[i].trim()); i++
    }
    if (para.length) blocks.push({ kind: 'para', text: para.join(' ') })
    else i++
  }
  return blocks
}

function CodeBox({ lang, code }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }).catch(() => {})
  }
  return (
    <div className="rounded-lg border border-dark-700/70 bg-dark-950/70 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1 border-b border-dark-700/60 text-[11px] text-dark-400">
        <span>{lang ? lang.replace(/^(ps1|pwsh)$/, 'powershell') : 'command'}</span>
        <button type="button" onClick={copy} className="hover:text-dark-100 transition-colors">{copied ? 'Copied' : 'Copy'}</button>
      </div>
      <pre className="px-3 py-2 text-xs font-mono text-dark-100 overflow-x-auto whitespace-pre"><code>{code}</code></pre>
    </div>
  )
}

function MarkdownBody({ text }) {
  const { theme } = useTheme()
  const isLight = theme === 'light' || (theme === 'system' && !window.matchMedia('(prefers-color-scheme: dark)').matches)
  if (!text) return null
  const inline = (s, k) => parseInline(s, k, isLight)
  const blocks = parseBlocks(text)

  return (
    <div className="space-y-3 text-dark-100 leading-relaxed">
      {blocks.map((b, bi) => {
        switch (b.kind) {
          case 'heading':
            return b.level <= 2
              ? <p key={bi} className="font-display text-[15px] font-semibold text-dark-50 pt-1">{inline(b.text.replace(/\*\*/g, ''), `h${bi}`)}</p>
              : <p key={bi} className="font-semibold text-dark-50 pt-0.5">{inline(b.text.replace(/\*\*/g, ''), `h${bi}`)}</p>
          case 'table':
            return (
              <div key={bi} className="overflow-x-auto rounded-lg border border-dark-700/70">
                <table className="w-full text-xs">
                  <thead className="bg-dark-900/80">
                    <tr>{b.head.map((h, hi) => (
                      <th key={hi} className="text-left font-medium text-dark-400 px-3 py-1.5 whitespace-nowrap">{inline(h.replace(/\*\*/g, ''), `th${bi}-${hi}`)}</th>
                    ))}</tr>
                  </thead>
                  <tbody>
                    {b.rows.map((r, ri) => (
                      <tr key={ri} className="border-t border-dark-700/50 align-top">
                        {b.head.map((_, ci) => (
                          <td key={ci} className={`px-3 py-1.5 ${ci === 0 ? 'text-dark-300 whitespace-nowrap' : 'text-dark-100'}`}>{inline(r[ci] ?? '', `td${bi}-${ri}-${ci}`)}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          case 'code':
            return <CodeBox key={bi} lang={b.lang} code={b.code} />
          case 'note':
            return (
              <div key={bi} className="rounded-lg border border-accent-amber/30 bg-accent-amber/10 px-3 py-2 text-dark-100">
                {inline(b.text.replace(/^⚠️\s*/, ''), `n${bi}`)}
              </div>
            )
          case 'steps':
            return (
              <ol key={bi} className="space-y-2">
                {b.items.map((it, ii) => (
                  <li key={ii} className="flex gap-2.5 items-start">
                    <span className="mt-0.5 flex h-5 min-w-5 px-1 items-center justify-center rounded-md bg-eagle-500/15 text-eagle-400 text-[11px] font-semibold">{it.n}</span>
                    <div className="flex-1 space-y-1">
                      <p>{inline(it.text, `s${bi}-${ii}`)}</p>
                      {it.sub.length > 0 && (
                        <ul className="space-y-0.5 pl-1">
                          {it.sub.map((s, si) => (
                            <li key={si} className="flex gap-2 items-start text-dark-200">
                              <span className="mt-2 w-1 h-1 rounded-full bg-dark-400 flex-shrink-0" />
                              <span>{inline(s, `s${bi}-${ii}-${si}`)}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )
          case 'bullets':
            return (
              <ul key={bi} className="space-y-1 pl-1">
                {b.items.map((it, ii) => (
                  <li key={ii} className={`flex gap-2 items-start ${it.indent ? 'pl-5 text-dark-200' : ''}`}>
                    <span className="mt-2 w-1.5 h-1.5 rounded-full bg-eagle-400/60 flex-shrink-0" />
                    <span>{inline(it.text, `b${bi}-${ii}`)}</span>
                  </li>
                ))}
              </ul>
            )
          default:
            return <p key={bi}>{inline(b.text, `p${bi}`)}</p>
        }
      })}
    </div>
  )
}

// ── Renders a bot message ─────────────────────────────────────────
// Everything the server sends is shown as plain text (React escapes it), never as HTML.
function BotContent({ msg, onConfirm, canConfirm }) {
  const { content, error, tools, proposals, sources } = msg
  return (
    <div className="space-y-2">
      {tools?.length > 0 && <ToolSteps tools={tools} />}
      <MarkdownBody text={content ?? ''} />
      {error && (
        <div role="alert" className="rounded-lg border border-accent-red/40 bg-accent-red/10 px-3 py-2 text-xs text-dark-100">{error}</div>
      )}
      {(proposals ?? []).map((p) => (
        <ProposalCard key={p.confirm_token ?? p.advisory_id} proposal={p} onConfirm={onConfirm} canConfirm={canConfirm} />
      ))}
      {sources?.length > 0 && <Sources sources={sources} />}
    </div>
  )
}

// The records the answer is built from: title and type, as plain text.
function Sources({ sources }) {
  return (
    <div className="pt-1" aria-label="Sources">
      <p className="text-[11px] uppercase tracking-wider text-dark-500 mb-1">Sources</p>
      <ul className="flex flex-wrap gap-1.5">
        {sources.map((s, i) => (
          <li key={`${s.key ?? s.ref ?? i}-${i}`} className="inline-flex max-w-full items-center gap-1 rounded-md border border-dark-700/60 bg-dark-900/50 px-1.5 py-0.5 text-[11px] text-dark-300">
            <span className="truncate">{String(s.title ?? s.key ?? '')}</span>
            {s.type && <span className="text-dark-500 flex-shrink-0">· {String(s.type)}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

// The lookups the assistant made for this answer
function ToolSteps({ tools }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-dark-400" aria-label="Data the assistant looked up">
      <Wrench className="w-3.5 h-3.5" aria-hidden="true" />
      {tools.map((t, i) => (
        <span key={`${t.name}-${i}`} className="inline-flex items-center gap-1 rounded-md border border-dark-700/60 bg-dark-900/50 px-1.5 py-0.5">
          {t.status === 'running'
            ? <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
            : t.ok === false
              ? <XCircle className="w-3 h-3 text-accent-red" aria-hidden="true" />
              : <CheckCircle2 className="w-3 h-3 text-accent-green" aria-hidden="true" />}
          {t.title}
        </span>
      ))}
    </div>
  )
}

// A change the assistant proposed. Only the Confirm click makes it: it calls
// POST /chatbot/confirm, which checks the person, role and company again and audits it.
// Cancel only hides the card; the token expires on its own.
function ProposalCard({ proposal, onConfirm, canConfirm }) {
  const [state, setState] = useState('idle') // idle | pending | done | dismissed
  const busy = useRef(false)
  if (proposal.type !== 'resolve_advisory') return null
  if (state === 'dismissed') return <p className="text-xs text-dark-500">Proposal dismissed. Nothing was changed.</p>
  if (state === 'done') return null
  const confirm = async () => {
    if (busy.current) return
    busy.current = true
    setState('pending')
    await onConfirm(proposal.confirm_token)
    setState('done') // the result is shown in the chat
  }
  return (
    <div className="rounded-lg border border-eagle-500/30 bg-eagle-500/5 px-3 py-2.5 text-xs space-y-2">
      <p className="text-dark-100 font-medium">Resolve advisory <code className="font-mono">{String(proposal.advisory_id ?? '').slice(0, 8)}</code>?</p>
      {proposal.summary && <p className="text-dark-300">{proposal.summary}</p>}
      {proposal.reason && <p className="text-dark-400">Advisory: {proposal.reason}</p>}
      {canConfirm ? (
        <div className="flex items-center gap-2">
          <button type="button" disabled={state === 'pending'} onClick={confirm} className="btn-primary !py-1 !px-3 text-xs">
            {state === 'pending' ? 'Resolving…' : 'Confirm'}
          </button>
          <button type="button" disabled={state === 'pending'} onClick={() => setState('dismissed')} className="btn-secondary !py-1 !px-3 text-xs">
            Cancel
          </button>
        </div>
      ) : (
        <p className="text-dark-400">Only tenant admins can resolve advisories.</p>
      )}
    </div>
  )
}

// ── Quick buttons: ordinary questions, answered from the knowledge graph ──
const QUICK = [
  { label: 'Status',      icon: Activity,   q: 'What is the overall security status of my environment?', roles: null },
  { label: 'Posture',     icon: BarChart2,  q: 'What is my security posture score and what drives it?', roles: null },
  { label: 'Assets',      icon: Server,     q: 'Which of my assets are the most critical?', roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Alerts',      icon: Bell,       q: 'Which critical and high severity alerts are open?', roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Advisories',  icon: Shield,     q: 'Which advisories are still open?', roles: ['tenant_superadmin', 'tenant_admin', 'superadmin'] },
  { label: 'Fix first',   icon: HelpCircle, q: 'What should I fix first?', roles: null },
]

// Reads the answer stream (server-sent events). Calls onUpdate with everything received so far.
// Events: token, tool, sources, proposal, error.
async function readChatStream(res, onUpdate) {
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  const state = { content: '', error: null, tools: [], proposals: [], sources: [] }
  let buf = ''
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
        let parsed
        try { parsed = JSON.parse(chunk) } catch { continue /* skip malformed chunk */ }
        if (typeof parsed.error === 'string') state.error = state.error ? `${state.error} ${parsed.error}` : parsed.error
        if (typeof parsed.token === 'string') state.content += parsed.token
        if (parsed.tool) {
          // one chip per call: "running" is replaced by its "done"
          const last = state.tools.findLastIndex(t => t.name === parsed.tool.name && t.status === 'running')
          if (parsed.tool.status === 'done' && last !== -1) state.tools[last] = parsed.tool
          else state.tools.push(parsed.tool)
        }
        if (Array.isArray(parsed.sources)) state.sources = parsed.sources
        if (parsed.proposal) state.proposals.push(parsed.proposal)
        if (!(parsed.error || parsed.token || parsed.tool || parsed.sources || parsed.proposal)) continue
        onUpdate({ content: state.content, error: state.error, tools: [...state.tools], proposals: [...state.proposals], sources: [...state.sources] })
      }
    }
  } finally {
    reader.releaseLock()
  }
}

// What a failed request says to the person (429 is the per-minute question limit)
async function failureText(res) {
  if (res.status === 429) return 'You have asked a lot of questions in the last minute. Wait a moment, then try again.'
  try {
    const body = await res.json()
    if (typeof body?.content === 'string' && body.content) return body.content
    if (typeof body?.error === 'string' && body.error) return body.error
  } catch { /* not JSON */ }
  return `The assistant could not answer (HTTP ${res.status}). Please try again.`
}

// ── Typing indicator ──────────────────────────────────────────────
function Typing() {
  return (
    <div className="flex gap-3">
      <div className="w-8 h-8 rounded-full bg-eagle-500/20 flex items-center justify-center flex-shrink-0">
        <Bot className="w-4 h-4 text-eagle-400" />
      </div>
      <div className="bg-dark-800 border border-dark-700/50 rounded-2xl rounded-tl-sm px-4 py-3.5 flex items-center" role="status" aria-label="Assistant is typing">
        <span className="trace-loader w-12" />
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
        <p className="text-[11px] font-semibold text-dark-500 tracking-widest uppercase">Sessions</p>
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
                ? 'bg-eagle-500/15 border border-eagle-500/30 text-dark-50'
                : 'text-dark-400 hover:bg-dark-800/60 hover:text-dark-100 border border-transparent'
            }`}
          >
            <span className="mt-0.5 flex-shrink-0"><SessionIcon session={s} className="h-3.5 w-3.5" /></span>
            <div className="min-w-0 flex-1">
              <p className="font-medium truncate leading-tight">{s.name}</p>
              {s.category && <p className="text-dark-500 text-[11px] truncate mt-0.5">{s.category}</p>}
              <p className="text-dark-600 text-[11px] mt-0.5">{s.messages.length} msg{s.messages.length !== 1 ? 's' : ''}</p>
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
  const [pickedTenant, setPickedTenant] = useState('')
  const [tenants, setTenants] = useState([])
  const bottomRef = useRef(null)

  // Background streaming on this session (kept in context, so it survives navigation)
  const loading = streamingSessionId === activeId

  const activeSession = sessions[activeId] ?? sessions.general

  // Fetch tenant list once for superadmin (used by tenant_select prompt)
  useEffect(() => {
    if (!isSuperadmin) return
    client.get('/tenants').then(res => setTenants(res.data.tenants || [])).catch(() => {})
  }, [isSuperadmin])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [activeId, sessions, loading])



  // Asks one question and streams the answer into the session. Used by the input box, the
  // quick buttons and the advisory sessions, so background generation survives navigation.
  const streamAnswer = useCallback(async (sessionId, message, history, tenantId) => {
    const placeholderTs = Date.now() + 1
    const patchBot = (patch) => setSessions(prev => {
      const s = prev[sessionId]
      if (!s) return prev
      const msgs = [...s.messages]
      const idx = msgs.findIndex(m => m.ts === placeholderTs && m.role === 'bot')
      if (idx !== -1) msgs[idx] = { ...msgs[idx], ...patch }
      return { ...prev, [sessionId]: { ...s, messages: msgs, updatedAt: Date.now() } }
    })
    setSessions(prev => {
      const s = prev[sessionId]
      if (!s) return prev
      return { ...prev, [sessionId]: { ...s, messages: [...s.messages.slice(-MAX_MSG + 1), { role: 'bot', type: 'ai', content: '', ts: placeholderTs }], updatedAt: Date.now() } }
    })
    setStreamingSessionId(sessionId)
    try {
      const apiBase = import.meta.env.VITE_API_URL || '/api/v1'
      const token = localStorage.getItem('access_token')
      const res = await fetch(`${apiBase}/chatbot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ message, history, stream: true, ...(tenantId ? { tenant_id: tenantId } : {}) }),
      })
      if (!res.ok) { patchBot({ error: await failureText(res) }); return }
      await readChatStream(res, patchBot)
    } catch {
      patchBot({ error: 'Could not reach the assistant. Please try again.' })
    } finally {
      setStreamingSessionId(null)
    }
  }, [setSessions, setStreamingSessionId])

  const send = useCallback(async (text) => {
    const trimmed = (text ?? input).trim()
    if (!trimmed || loading) return
    setInput('')
    const userMsg = { role: 'user', type: 'text', content: trimmed, ts: Date.now() }
    updateSession(activeId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), userMsg] }))
    const history = (sessions[activeId]?.messages ?? [])
      .filter(m => (m.role === 'user' || m.role === 'bot') && m.content && !m.error)
      .slice(-6)
      .map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: m.content.slice(0, 6000) }))
    await streamAnswer(activeId, trimmed, history, isSuperadmin ? pickedTenant : null)
  }, [input, loading, activeId, sessions, updateSession, streamAnswer, isSuperadmin, pickedTenant])

  // The Confirm button: the server re-checks the person, role and company, then closes the advisory.
  const confirmProposal = useCallback(async (token) => {
    const sessionId = activeId
    const say = (content, error) => updateSession(sessionId, s => ({ messages: [...s.messages.slice(-MAX_MSG + 1), { role: 'bot', type: 'text', content, error, ts: Date.now() }] }))
    try {
      const res = await client.post('/chatbot/confirm', { token })
      say(`Advisory \`${String(res.data.advisory_id).slice(0, 8)}\` marked as **resolved**.`)
    } catch (err) {
      say('', err?.response?.data?.error || 'Could not confirm. Please try again.')
    }
  }, [activeId, updateSession])

  // Called when the user clicks "Debug with AI" on an advisory: an ordinary question about it
  const openAdvisorySession = useCallback(async (advisory) => {
    const sessionId = `adv-${advisory.advisoryId}`
    if (sessions[sessionId]) { setActiveId(sessionId); return }

    setSessions(prev => ({
      ...prev,
      [sessionId]: { id: sessionId, name: 'Loading…', emoji: '🔄', category: null, advisoryId: advisory.advisoryId, messages: [], updatedAt: Date.now() },
    }))
    setActiveId(sessionId)

    let cat = { name: 'Security Advisory', category: 'Security', emoji: '🔴' }
    try {
      const res = await client.post('/chatbot/categorize', {
        summary: advisory.summary ?? '',
        recommendedAction: advisory.recommendedAction ?? '',
      })
      cat = res.data
    } catch { /* keep the default name */ }
    const prompt = `Explain advisory ${advisory.advisoryId}: why was it raised, and how do I fix it?`
    setSessions(prev => ({
      ...prev,
      [sessionId]: {
        ...prev[sessionId], name: cat.name, emoji: cat.emoji, category: cat.category,
        messages: [{ role: 'user', type: 'text', content: prompt, ts: Date.now() }],
        updatedAt: Date.now(),
      },
    }))
    await streamAnswer(sessionId, prompt, [], null)
  }, [sessions, setSessions, setActiveId, streamAnswer])

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
    <div className="flex h-[calc(100dvh-6rem)] gap-0 lg:h-[calc(100dvh-7rem)]">

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
            <span className="flex h-8 w-8 items-center justify-center rounded-md border border-dark-700 bg-dark-900"><SessionIcon session={activeSession} /></span>
            <div>
              <h1 className="text-base font-bold text-dark-50 leading-tight">{activeSession.name}</h1>
              {activeSession.category && (
                <p className="text-[11px] text-dark-400">{activeSession.category}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isSuperadmin && (
              <select
                value={pickedTenant}
                onChange={e => setPickedTenant(e.target.value)}
                aria-label="Company to ask about"
                className="bg-dark-800 border border-dark-700/60 rounded-lg text-xs text-dark-200 px-2 py-1.5 max-w-[12rem]"
              >
                <option value="">Pick a company</option>
                {tenants.map(t => <option key={t.tenant_id} value={t.tenant_id}>{t.name}</option>)}
              </select>
            )}
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
            {visibleQuick.map(({ label, icon: Icon, q }) => (
              <button
                key={label}
                onClick={() => send(q)}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-dark-800/60 border border-dark-700/40 text-dark-300 hover:text-dark-50 hover:border-eagle-500/40 hover:bg-eagle-500/5 transition-all disabled:opacity-50"
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
            <Bubble key={i} msg={msg} onConfirm={confirmProposal} canConfirm={canDebugAI} />
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
              placeholder={activeId === 'general' ? 'Ask about your assets, alerts, advisories or the system…' : 'Ask about this advisory…'}
              rows={1}
              disabled={loading}
              className="flex-1 bg-transparent text-sm text-dark-100 placeholder-dark-500 resize-none outline-none max-h-28 py-1 px-2 disabled:opacity-50"
              style={{ minHeight: '2rem' }}
            />
            <button
              onClick={() => send()}
              disabled={loading || !input.trim()}
              className="p-2 bg-eagle-600 hover:bg-eagle-500 disabled:bg-dark-700 disabled:text-dark-500 text-on-brand rounded-lg transition-colors flex-shrink-0"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-[11px] text-dark-600 mt-1.5 text-center">Enter to send · Shift+Enter for new line</p>
        </div>
      </div>
    </div>
  )
}
