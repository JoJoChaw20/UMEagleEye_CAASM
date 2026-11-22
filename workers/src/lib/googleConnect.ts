// Connecting a Google account to the signed-in account (POST /auth/google/connect): the rules,
// pure so they are tested without a database (googleConnect.test.ts).

export type ConnectRefusal = { detail: string; status: 403 | 409 }

/**
 * Whether account `me` may take Google account `google`. `byGoogleId` and `byEmail` are the accounts
 * (if any) that already hold that Google ID or that address. On success the account gets the Google ID
 * and Google's address becomes its email, so Google sign-in finds it either way.
 */
export function connectRefusal(
  me: { userId: string; googleId: string | null },
  google: { email_verified?: boolean },
  byGoogleId: { userId: string } | null | undefined,
  byEmail: { userId: string } | null | undefined,
): ConnectRefusal | null {
  if (me.googleId) return { detail: 'A Google account is already connected to this account.', status: 409 }
  // Unverified: anyone can put any address on a Google account, so it proves nothing.
  if (google.email_verified !== true) {
    return { detail: 'Google has not verified the email address of that Google account, so it cannot be connected.', status: 403 }
  }
  if (byGoogleId && byGoogleId.userId !== me.userId) {
    return { detail: 'That Google account is already connected to another EagleEye account.', status: 409 }
  }
  if (byEmail && byEmail.userId !== me.userId) {
    return { detail: 'That email address belongs to another EagleEye account.', status: 409 }
  }
  return null
}
