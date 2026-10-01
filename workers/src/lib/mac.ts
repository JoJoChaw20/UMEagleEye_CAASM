/**
 * Normalize a MAC address to canonical lowercase colon-separated form.
 *
 * Accepts 12 hex digits either bare ("aabbccddeeff") or separated by ':', '-',
 * or '.' in any grouping — e.g. "AA:BB:CC:DD:EE:FF", "14-13-33-C3-F6-03",
 * "aabb.ccdd.eeff". All of these normalize to "aa:bb:cc:dd:ee:ff".
 *
 * Returns null for anything that is not exactly 12 hex digits once the allowed
 * separators are stripped: empty / whitespace-only, wrong length, non-hex
 * characters, disallowed separators, or a non-string input.
 */
export function normalizeMac(input: unknown): string | null {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (trimmed === '') return null
  // Reject any character that is not a hex digit or an allowed separator.
  if (!/^[0-9a-fA-F:.\-]+$/.test(trimmed)) return null
  const hex = trimmed.replace(/[:.\-]/g, '').toLowerCase()
  if (!/^[0-9a-f]{12}$/.test(hex)) return null
  return hex.match(/.{2}/g)!.join(':')
}
