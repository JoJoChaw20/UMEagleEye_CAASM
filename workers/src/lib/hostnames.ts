/**
 * Which hostname an asset keeps when a scan reports one.
 *
 * Stored names are fill-only, so a name typed by an analyst is never overwritten by
 * a scan. That also froze default names: an Oppo phone that announced itself over
 * mDNS as "Android" kept that name even after its DHCP request said "OPPO-A31". A
 * generic name (a platform default nobody chose) is now replaced by the first
 * specific name a scan reports; a specific name is still never replaced.
 *
 * Learning the real name is classification, not drift: the caller moves an
 * automatic baseline that still holds the generic name, so no "hostname changed"
 * alert is raised for it.
 */

const GENERIC_NAME_PATTERNS: RegExp[] = [
  /^android(-\d{1,2})?$/,                                           // Android's mDNS default; -2 after a name clash
  /^android-[0-9a-f]{6,}$/,                                           // android-83f59958ba7e18a1
  /^localhost(\.localdomain)?$/,
  /^(iphone|ipad|macbook(-pro|-air)?)(-\d{1,2})?$/,               // Apple defaults; -2 after a name clash
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,   // UUID-style
]

/** True for a platform default that says nothing about which device it is. */
export function isGenericHostname(name: string | null | undefined): boolean {
  if (typeof name !== 'string') return false
  const v = name.trim().toLowerCase().replace(/\.local$/, '')
  return v !== '' && GENERIC_NAME_PATTERNS.some(re => re.test(v))
}

/** The hostname to store: fill-only, except that a generic stored name gives way to a
 *  specific one from the scan. */
export function pickHostname(stored: string | null | undefined, incoming: string | null | undefined): string | null {
  const have = stored?.trim() ? stored : null
  const got = incoming?.trim() ? incoming : null
  if (!have) return got
  if (got && isGenericHostname(have) && !isGenericHostname(got)) return got
  return have
}
