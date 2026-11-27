// What a feed indicator is used for (workers/src/services/threatIntel.ts indicatorUseSql), in words.
export const USE_META = {
  agents:    { label: 'Checked by agents', short: 'Agents', cls: 'bg-eagle-600/15 text-eagle-300 border-eagle-500/40',
    help: 'On the agents\' list: matched on each computer against its DNS lookups, connections and running programs, and against device addresses and names.' },
  assets:    { label: 'Checked against assets', short: 'Assets', cls: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
    help: 'Matched against scan, inventory and SBOM data: CVE IDs, watched software, and URLs on a named host (against device names).' },
  reference: { label: 'Reference only', short: 'Reference', cls: 'bg-dark-700/60 text-dark-400 border-dark-600',
    help: 'Kept for look-ups and context; never raises an alert.' },
}

export const REASON_LABEL = {
  expired: 'expired: from an older MyCERT advisory (an IP matches for 30 days from the advisory, a domain or URL 90); a feed\'s expired values are deleted',
  retired: 'from a feed no longer used',
  safe_list: 'on a safe list (CDN, top site, private range...)',
  not_for_detection: 'marked by its source as not for detection',
  no_data: 'nothing here can see this type (emails)',
}
