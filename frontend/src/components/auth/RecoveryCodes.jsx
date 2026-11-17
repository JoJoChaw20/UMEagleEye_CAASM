import { useEffect, useState } from 'react'
import { Check, Copy, Download, LifeBuoy, LogIn } from 'lucide-react'
import { formatRecoveryCodes } from '../../utils/mfa.js'
import { useCopy } from './AuthParts'

const FILE_NAME = 'umeagleeye-recovery-codes.txt'

/**
 * The 10 recovery codes, shown once after MFA set-up. onDone (which starts the session) is only
 * reachable after "I have saved these codes" is ticked. Until then, closing or reloading the tab
 * asks first, because the codes cannot be shown again.
 */
export default function RecoveryCodes({ codes, onDone }) {
  const [saved, setSaved] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const [copyState, copy] = useCopy()
  const text = formatRecoveryCodes(codes)

  useEffect(() => {
    if (saved) return undefined
    const warn = (e) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [saved])

  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = FILE_NAME
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const finish = () => {
    if (!saved || leaving) return
    setLeaving(true)
    onDone()
  }

  return (
    <>
      <span className="flex h-10 w-10 items-center justify-center rounded-md border border-eagle-500/30 bg-eagle-500/10 text-eagle-400">
        <LifeBuoy className="h-5 w-5" />
      </span>
      <h1 className="mt-4 text-[26px] font-semibold leading-8 text-dark-50">Save your recovery codes</h1>
      <p className="mt-1.5 text-sm text-dark-400">
        MFA is set up. If you lose your authenticator app, sign in with one of these codes instead.
        Each code works once. They are shown only now.
      </p>

      <ol className="mt-6 grid grid-cols-2 gap-x-4 gap-y-2 rounded-md border border-dark-700 bg-dark-900 px-4 py-3.5 font-mono text-sm text-dark-100" aria-label="Recovery codes">
        {codes.map((code) => <li key={code} className="tabular-nums tracking-wide">{code}</li>)}
      </ol>

      <div className="mt-3 flex gap-2">
        <button type="button" onClick={() => copy(text)} className="btn-secondary flex-1">
          {copyState === 'copied' ? <><Check className="h-4 w-4" />Copied</> : <><Copy className="h-4 w-4" />Copy</>}
        </button>
        <button type="button" onClick={download} className="btn-secondary flex-1">
          <Download className="h-4 w-4" />Download .txt
        </button>
      </div>
      {copyState === 'failed' && <p className="mt-2 text-xs text-red-400">Copy did not work here. Use Download .txt, or select the codes and copy them.</p>}

      <label className="mt-6 flex cursor-pointer items-start gap-2.5 text-sm text-dark-200">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)}
          className="mt-0.5 h-4 w-4 flex-shrink-0 accent-eagle-500" id="recovery-saved" />
        I have saved these codes
      </label>

      <button type="button" onClick={finish} disabled={!saved || leaving} className="btn-primary mt-4 w-full py-2.5" id="recovery-continue">
        <LogIn className="h-4 w-4" />Continue to the dashboard
      </button>
    </>
  )
}
