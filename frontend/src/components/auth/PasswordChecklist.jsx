import { passwordChecks, passwordRequirements } from '../../utils/password.js'

/** The password rules, each ticked once the typed password meets it. */
export default function PasswordChecklist({ password }) {
  const checks = passwordChecks(password)
  return (
    <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1">
      {passwordRequirements.map(([key, label]) => (
        <span key={key} className={`text-[11px] ${checks[key] ? 'text-green-400' : 'text-dark-500'}`}>
          {checks[key] ? '✓' : '○'} {label}
        </span>
      ))}
    </div>
  )
}
