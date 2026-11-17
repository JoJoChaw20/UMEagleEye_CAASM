// The only way the app sends email. Without the EMAIL binding and the MAIL_FROM var it logs and
// returns { sent: false }; it never throws into a request.
import type { Env } from '../types'

export interface MailMessage { to: string; subject: string; text: string }

export async function sendMail(env: Env, msg: MailMessage): Promise<{ sent: boolean }> {
  if (!env.EMAIL || !env.MAIL_FROM) {
    console.log(`mail not sent (email is not configured): "${msg.subject}"`)
    return { sent: false }
  }
  try {
    await env.EMAIL.send({
      to: msg.to, from: { email: env.MAIL_FROM, name: 'UMEagleEye' }, subject: msg.subject, text: msg.text,
    })
    return { sent: true }
  } catch (err) {
    console.error('mail send failed:', err)
    return { sent: false }
  }
}
