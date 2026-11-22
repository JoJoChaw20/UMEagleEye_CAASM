// Password rules shown while typing; they mirror the server's (workers/src/lib/passwordRules.ts).
// Tested with node --test (password.test.js).

export const passwordRequirements = [
  ['length', 'At least 12 characters'],
  ['lowercase', 'A lowercase letter'],
  ['uppercase', 'An uppercase letter'],
  ['number', 'A number'],
  ['special', 'A special character'],
  ['space', 'No spaces'],
]

export const passwordChecks = (password) => ({
  length: password.length >= 12,
  lowercase: /[a-z]/.test(password),
  uppercase: /[A-Z]/.test(password),
  number: /[0-9]/.test(password),
  special: /[^A-Za-z0-9\s]/.test(password),
  space: !/\s/.test(password),
})

export const isStrongPassword = (password) => Object.values(passwordChecks(password)).every(Boolean)

/**
 * The body of POST /tenants/:id/users/invite. 'email': the person signs in with Google using it.
 * 'password': a username and a starting password, no email; they choose their own at first sign-in.
 */
export function inviteBody(mode, { email = '', username = '', password = '', ...rest }) {
  const name = username.trim() || undefined
  if (mode === 'password') return { username: name, password, ...rest }
  return { email: email.trim(), username: name, ...rest }
}

/** The confirmation after an invite: who was created or added, and how they sign in. */
export function inviteDoneText(mode, d, as = '') {
  if (d.action !== 'created') return `${d.username} added to this tenant${as}.`
  if (mode === 'password') {
    return `Created ${d.username}${as}. Give them the username and starting password: they choose their own password at first sign-in, and can connect Google in Settings.`
  }
  return `Invited ${d.email}${as}. They sign in with Google using this email.`
}
