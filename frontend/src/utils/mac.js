// Shared frontend MAC helpers (mirrors workers/src/lib/mac.ts normalizeMac and the
// locally-administered bit used by the identity resolver). Pure, no dependencies.
// Previously these lived file-local in DiscoveryPage; promoted here for reuse.

// Normalize to canonical lowercase colon form, or null if not 12 hex digits.
export function normalizeMac(input) {
  if (typeof input !== 'string') return null
  const t = input.trim()
  if (!t || !/^[0-9a-fA-F:.\-]+$/.test(t)) return null
  const hex = t.replace(/[:.\-]/g, '').toLowerCase()
  if (!/^[0-9a-f]{12}$/.test(hex)) return null
  return hex.match(/.{2}/g).join(':')
}

// A usable (global or local, non-garbage) MAC in canonical form, else null.
export function usableMac(input) {
  return normalizeMac(input)
}

// True when the U/L bit (0x02 of the first octet) is set — i.e. a locally
// administered / randomized MAC (common on privacy-enabled phones and laptops).
export function isLocallyAdministeredMac(input) {
  const m = normalizeMac(input)
  if (!m) return false
  return (parseInt(m.slice(0, 2), 16) & 0x02) !== 0
}
