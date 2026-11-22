// Password strength rules for every password a person chooses or is given: change-password, set-password
// and the starting password of an account created without an email (POST /tenants/:tenantId/users/invite).
import { z } from 'zod'

export const passwordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/[a-z]/, 'Password must contain a lowercase letter')
  .regex(/[A-Z]/, 'Password must contain an uppercase letter')
  .regex(/[0-9]/, 'Password must contain a number')
  .regex(/[^A-Za-z0-9\s]/, 'Password must contain a special character')
  .refine((password) => !/\s/.test(password), 'Password must not contain spaces')

export type InviteCredentials =
  | { ok: true; email: string; username: string | undefined; password: null }
  | { ok: true; email: null; username: string; password: string }
  | { ok: false; detail: string }

/**
 * An invite names the person either by email (they sign in with Google using it) or by a username and a
 * starting password (no email; they choose their own password at first sign-in and may connect Google later).
 */
export function inviteCredentials(body: { email?: string; username?: string; password?: string }): InviteCredentials {
  const email = body.email?.trim() || undefined
  const username = body.username?.trim() || undefined
  if (email && body.password) return { ok: false, detail: 'Give an email or a starting password, not both.' }
  if (email) {
    if (!z.string().email().safeParse(email).success) return { ok: false, detail: 'Enter a valid email address.' }
    return { ok: true, email, username, password: null }
  }
  if (!body.password) return { ok: false, detail: 'Give an email, or a username and a starting password.' }
  if (!username) return { ok: false, detail: 'A username is needed when there is no email.' }
  if (username.length < 3 || username.length > 100) return { ok: false, detail: 'The username must be 3 to 100 characters.' }
  const strong = passwordSchema.safeParse(body.password)
  if (!strong.success) return { ok: false, detail: strong.error.issues[0]?.message ?? 'Choose a stronger password.' }
  return { ok: true, email: null, username, password: body.password }
}
