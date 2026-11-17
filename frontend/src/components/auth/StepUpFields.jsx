import { cleanTotpInput } from '../../utils/mfa.js'
import { TotpField } from './AuthParts'

/**
 * Step-up confirmation fields: the caller's password (left out when the account has none, such as
 * Google-only) and the current 6-digit authenticator code. Used for new recovery codes, MFA reset,
 * and any later action that asks the same (body from stepUpBody in utils/mfa.js).
 */
export default function StepUpFields({ idPrefix = 'stepup', hasPassword, password, onPassword, code, onCode, busy, onSubmit }) {
  return (
    <div className="mt-4 space-y-3" onKeyDown={(e) => { if (e.key === 'Enter' && onSubmit) { e.preventDefault(); onSubmit() } }}>
      {hasPassword && (
        <div>
          <label htmlFor={`${idPrefix}-password`} className="mb-1.5 block text-sm font-medium text-dark-200">Your password</label>
          <input id={`${idPrefix}-password`} type="password" autoComplete="current-password" value={password}
            readOnly={busy} onChange={(e) => onPassword(e.target.value)} className="input-field w-full" />
        </div>
      )}
      <TotpField id={`${idPrefix}-code`} value={code} onChange={(v) => onCode(cleanTotpInput(v))} busy={busy} />
    </div>
  )
}
