// The only way the app sends email. Without the EMAIL binding and the MAIL_FROM var it logs and
// returns { sent: false }; it never throws into a request.
import type { Env } from '../types'

// `to` is null for an account that has no email yet (users.email): nothing is sent.
export interface MailMessage { to: string | null | undefined; subject: string; text: string }

/** Whether sendMail would really send (the EMAIL binding and MAIL_FROM are both set). */
export function mailConfigured(env: Env): boolean {
  return !!env.EMAIL && !!env.MAIL_FROM
}

export async function sendMail(env: Env, msg: MailMessage): Promise<{ sent: boolean }> {
  if (!mailConfigured(env)) {
    console.log(`mail not sent (email is not configured): "${msg.subject}"`)
    return { sent: false }
  }
  if (!msg.to) {
    console.log(`mail not sent (the account has no email): "${msg.subject}"`)
    return { sent: false }
  }
  try {
    await env.EMAIL!.send({
      to: msg.to, from: { email: env.MAIL_FROM!, name: 'UMEagleEye' }, subject: msg.subject, text: msg.text,
    })
    return { sent: true }
  } catch (err) {
    console.error('mail send failed:', err)
    return { sent: false }
  }
}
