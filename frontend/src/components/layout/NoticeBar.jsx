import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Info, X } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { canDismiss, checklistItems, noticeLink, visibleNotices } from '../../utils/notices'
import OwnerChecklist from '../ownership/OwnerChecklist'

const REFRESH_MS = 60_000

// In-app notices above the page: tenant-wide ones (expire) and the caller's own (dismissable).
// Any failure, or nothing to show (e.g. the Platform Superadmin has no tenant), renders nothing.
export default function NoticeBar() {
  const { token } = useAuth()
  const [notices, setNotices] = useState([])
  const [busyId, setBusyId] = useState(null)
  const [dismissError, setDismissError] = useState('')
  const last = useRef(0)

  const load = useCallback(async () => {
    last.current = Date.now()
    try {
      const res = await client.get('/notices')
      setNotices(visibleNotices(res.data))
    } catch { /* keep what is shown; never break the layout */ }
  }, [])

  useEffect(() => {
    if (!token) return undefined
    load()
    const onFocus = () => { if (Date.now() - last.current >= REFRESH_MS) load() }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [token, load])

  const dismiss = async (id) => {
    setBusyId(id)
    setDismissError('')
    try {
      await client.post(`/notices/${id}/dismiss`)
      setNotices((cur) => cur.filter((n) => n.notice_id !== id))
    } catch (err) {
      if (err?.response?.status === 404) setNotices((cur) => cur.filter((n) => n.notice_id !== id))
      else setDismissError('Could not dismiss the notice. Try again.')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div role="status" aria-live="polite" className={notices.length ? 'space-y-2 px-4 pt-4 lg:px-6' : undefined}>
      {notices.map((n) => n.kind === 'owner_checklist' && canDismiss(n) && checklistItems(n).length ? (
        <OwnerChecklist key={n.notice_id} notice={n} busy={busyId === n.notice_id} onDone={() => dismiss(n.notice_id)} />
      ) : (
        <div key={n.notice_id} className="flex items-start gap-3 rounded-lg border border-eagle-500/30 bg-eagle-500/5 p-3 text-sm text-dark-100">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-accent-cyan" aria-hidden="true" />
          <p className="min-w-0 flex-1 break-words">
            {n.body}
            {noticeLink(n) && (
              <> <Link to={noticeLink(n)} className="whitespace-nowrap text-eagle-400 underline-offset-2 hover:underline">Open ownership</Link></>
            )}
          </p>
          {canDismiss(n) && (
            <button type="button" onClick={() => dismiss(n.notice_id)} disabled={busyId === n.notice_id}
              aria-label="Dismiss notice" className="shrink-0 rounded p-0.5 text-dark-400 hover:text-dark-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-eagle-500">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      ))}
      {dismissError && <p className="text-xs text-red-400">{dismissError}</p>}
    </div>
  )
}
