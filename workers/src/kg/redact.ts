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
  /\bpostgres(?:ql)?(?:\+\w+)?:\/\/[^\s:/@]+:[^\s/@]+@/i,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  // A quoted literal assigned to a secret-sounding name; `apiKey = env.X` is not a secret.
  /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{12,}["']/i,
]

export function containsSecret(text: string): boolean {
  return SECRET_PATTERNS.some(p => p.test(text))
}
