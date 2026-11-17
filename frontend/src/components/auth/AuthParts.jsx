import { useCallback, useRef, useState } from 'react'
import { AlertCircle, CheckCircle2, Info } from 'lucide-react'
import { cleanTotpInput } from '../../utils/mfa.js'

// Small pieces shared by the sign-in screens (LoginPage, MfaEnrol, RecoveryCodes, LostMfaHelp,
// MfaRecoveryPage). They keep the login page's look: input-field, btn-*, the red alert box.

const ALERT_TONES = {
  error: { box: 'border-red-500/30 bg-red-500/[0.08] text-red-400', Icon: AlertCircle },
  info: { box: 'border-eagle-500/30 bg-eagle-500/[0.08] text-eagle-300', Icon: Info },
  success: { box: 'border-emerald-500/30 bg-emerald-500/[0.08] text-emerald-400', Icon: CheckCircle2 },
}

export function FormAlert({ children, tone = 'error', className = 'mt-6' }) {
  if (!children) return null
  const { box, Icon } = ALERT_TONES[tone] ?? ALERT_TONES.error
  return (
    <div role={tone === 'error' ? 'alert' : 'status'} className={`${className} flex items-start gap-2.5 rounded-md border px-3.5 py-3 text-sm ${box}`}>
      <Icon className="mt-0.5 h-4 w-4 flex-shrink-0" /><span>{children}</span>
    </div>
  )
}

export function Spin() {
  // currentColor, so it shows on primary (white text) and secondary (dark text) buttons alike
  return <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent opacity-80" aria-hidden="true" />
}

/**
 * One request at a time. A second submit while one is in flight is dropped, because the server
 * counts a replayed code as a failed attempt. When the task returns true (the session started),
 * the guard stays locked so nothing is sent again before the page changes.
 */
export function useSingleFlight() {
  const flying = useRef(false)
  const [busy, setBusy] = useState(false)
  const run = useCallback(async (task) => {
    if (flying.current) return undefined
    flying.current = true
    setBusy(true)
    let done = false
    try {
      const result = await task()
      done = result === true
      return result
    } finally {
      if (!done) {
        flying.current = false
        setBusy(false)
      }
    }
  }, [])
  return [busy, run]
}

/** The message for a failed request: the server's own text, or a plain network note. */
export function errorText(err, fallback) {
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  if (err && !err.response) return 'Could not reach the server. Check your connection and try again.'
  return fallback
}

/**
 * The 6-digit authenticator code. onComplete(code) runs once when the field becomes full by
 * typing, pasting or autofill; editing an already full field does not resend it.
 * readOnly while busy (not disabled) keeps the focus in the field for the next try.
 */
export function TotpField({ id, value, onChange, onComplete, busy, inputRef, label = 'Authentication code' }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-dark-200">{label}</label>
      <input
        ref={inputRef} id={id} type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]*"
        value={value} readOnly={busy} autoFocus maxLength={6} placeholder="000000" spellCheck={false}
        onChange={(e) => {
          const next = cleanTotpInput(e.target.value)
          const wasFull = value.length === 6
          onChange(next)
          if (next.length === 6 && !wasFull && onComplete) onComplete(next)
        }}
        className="input-field w-full py-3 text-center font-mono text-2xl tracking-[0.5em]"
      />
    </div>
  )
}

/** Copies text; falls back to a hidden textarea where the Clipboard API is not allowed. */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const area = document.createElement('textarea')
      area.value = text
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(area)
      return ok
    } catch {
      return false
    }
  }
}

/** "Copied" feedback for a copy button: [label state, copy(text)]. */
export function useCopy() {
  const [state, setState] = useState('idle') // idle | copied | failed
  const timer = useRef(null)
  const copy = useCallback(async (text) => {
    const ok = await copyText(text)
    setState(ok ? 'copied' : 'failed')
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState('idle'), 2000)
  }, [])
  return [state, copy]
}
