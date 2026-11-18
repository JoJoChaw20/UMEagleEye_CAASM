import { useState } from 'react'
import { ConfirmDialog } from '../common/PageParts'
import { useAuth } from '../../context/AuthContext'
import { isMfaExemptUser, needsPasswordForStepUp, stepUpBody, stepUpReady } from '../../utils/mfa.js'
import { FormAlert, errorText, useSingleFlight } from './AuthParts'
import StepUpFields from './StepUpFields'

/**
 * A ConfirmDialog that asks for password + code. onSubmit(body) gets { password?, code } and
 * returns a promise; a thrown request error is shown inside the dialog (the server's text, e.g. a
 * wrong password or code) and the dialog stays open. children sit above the fields. isReady
 * (optional) replaces the default stepUpReady check, for a dialog with an extra field (delete user).
 */
export default function StepUpDialog({ title, children, confirmLabel, danger, idPrefix, onSubmit, onCancel, isReady }) {
  const { user } = useAuth()
  const hasPassword = needsPasswordForStepUp(user)
  const mfaExempt = isMfaExemptUser(user)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, run] = useSingleFlight()
  const ready = (isReady || stepUpReady)({ hasPassword, password, code, mfaExempt })

  const submit = () => run(async () => {
    if (!ready) return false
    setError('')
    try {
      await onSubmit(stepUpBody({ hasPassword, password, code, mfaExempt }))
    } catch (err) {
      setError(errorText(err, 'That did not work. Try again.'))
      setCode('')
      return false
    }
    return false
  })

  return (
    <ConfirmDialog title={title} confirmLabel={busy ? 'Working…' : confirmLabel} danger={danger}
      confirmDisabled={busy || !ready} onConfirm={submit} onCancel={() => { if (!busy) onCancel() }}>
      {children}
      <StepUpFields idPrefix={idPrefix} hasPassword={hasPassword} password={password} onPassword={setPassword}
        code={code} onCode={setCode} mfaExempt={mfaExempt} busy={busy} onSubmit={submit} />
      <FormAlert className="mt-3">{error}</FormAlert>
    </ConfirmDialog>
  )
}
