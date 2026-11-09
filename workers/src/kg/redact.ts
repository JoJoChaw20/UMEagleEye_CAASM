/**
 * kg/redact.ts — the last check before text enters the knowledge graph. Extraction already
 * reads only allowlisted columns; this catches a secret that was pasted into an allowed field
 * (a scan's failure reason, an analyst's note, a line of source code).
 */
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  // scheme://user:password@host, any scheme (postgres, mysql, https, ...)
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s/@]+@/i,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
  // A quoted literal assigned to a secret-sounding name; `apiKey = env.X` is not a secret.
  /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{12,}["']/i,
  // The same unquoted: needs a digit, so prose such as "password: required" and references pass.
  /\b(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)["']?\s*[:=]\s*["']?(?!(?:env|process|config|settings)\.|\$)(?=[^\s"',;]*\d)[^\s"',;]{10,}/i,
  // A key or code of our own format (64 hex) after its name. A bare hash is not matched: SHA-256 IOCs are normal.
  /\b(?:api[_ -]?key|access[_ -]?key|token|secret|(?:install|connection)[_ -]?code|enrol(?:l)?ment[_ -]?token)["']?\s*[:=]?\s*["']?[0-9a-f]{32,}\b/i,
]

export function containsSecret(text: string): boolean {
  return SECRET_PATTERNS.some(p => p.test(text))
}
