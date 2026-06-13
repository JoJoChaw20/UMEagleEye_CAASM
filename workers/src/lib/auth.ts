import { SignJWT, jwtVerify } from 'jose'
import type { JWTPayload } from '../types'

// ── Password hashing (PBKDF2 via Web Crypto) ─────────────────────
export async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    key, 256
  )
  const saltB64 = btoa(String.fromCharCode(...salt))
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(bits)))
  return `${saltB64}:${hashB64}`
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltB64, hashB64] = stored.split(':')
  if (!saltB64 || !hashB64) return false
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0))
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    key, 256
  )
  return btoa(String.fromCharCode(...new Uint8Array(bits))) === hashB64
}

// ── JWT ───────────────────────────────────────────────────────────
function secretKey(secret: string) {
  return new TextEncoder().encode(secret)
}

export async function createToken(
  payload: Omit<JWTPayload, 'iat' | 'exp'>,
  secret: string,
  expiresInMinutes = 60
): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInMinutes}m`)
    .sign(secretKey(secret))
}

export async function verifyToken(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey(secret))
    return payload as unknown as JWTPayload
  } catch {
    return null
  }
}

// ── Google ID token verification ─────────────────────────────────
export async function verifyGoogleToken(
  credential: string,
  clientId: string
): Promise<{ sub: string; email: string; name?: string } | null> {
  try {
    // Fetch Google's public keys
    const keysRes = await fetch('https://www.googleapis.com/oauth2/v3/certs')
    if (!keysRes.ok) return null
    const { keys } = await keysRes.json() as { keys: JsonWebKey[] }

    // Decode header to find kid
    const [headerB64] = credential.split('.')
    if (!headerB64) return null
    const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))) as { kid?: string }

    const jwk = keys.find((k) => (k as JsonWebKey & { kid?: string }).kid === header.kid) ?? keys[0]
    if (!jwk) return null

    const publicKey = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    )
    const { payload } = await jwtVerify(credential, publicKey, { audience: clientId })
    const p = payload as Record<string, unknown>
    return { sub: p['sub'] as string, email: p['email'] as string, name: p['name'] as string | undefined }
  } catch {
    return null
  }
}

// ── TOTP (otplib) ─────────────────────────────────────────────────
import { authenticator } from 'otplib'

export function generateTotpSecret(): string {
  return authenticator.generateSecret()
}

export function verifyTotp(secret: string, token: string): boolean {
  return authenticator.verify({ token, secret })
}

export async function generateTotpQR(secret: string, username: string): Promise<string> {
  const otpauthUrl = authenticator.keyuri(username, 'UMEagleEye', secret)
  const QRCode = await import('qrcode')

  // Use module matrix → filled <rect> SVG (no canvas, universally scannable)
  const qrData = QRCode.create(otpauthUrl, { errorCorrectionLevel: 'M' })
  const modules = qrData.modules
  const size    = modules.size
  const cell    = 4
  const margin  = 4
  const total   = (size + margin * 2) * cell

  let rects = ''
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules.get(r, c)) {
        const x = (c + margin) * cell
        const y = (r + margin) * cell
        rects += `<rect x="${x}" y="${y}" width="${cell}" height="${cell}" fill="#000"/>`
      }
    }
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}"><rect width="${total}" height="${total}" fill="#fff"/>${rects}</svg>`
  return btoa(svg)
}

// ── Crypto helpers ────────────────────────────────────────────────
export function generateApiKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
