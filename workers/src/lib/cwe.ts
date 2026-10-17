// CWE names from src/data/cwe.json (built by scripts/cwe/build-cwe.mjs from MITRE's CWE list).
import data from '../data/cwe.json'

const CWE = data as unknown as { version: string; names: Record<string, string> }

// NVD's placeholders for CVEs it has not classified
const NVD_PLACEHOLDERS: Record<string, string> = {
  'NVD-CWE-Other': 'Other (NVD: no specific CWE fits)',
  'NVD-CWE-noinfo': 'Not enough information (NVD)',
}

/** [{ id: 'CWE-787', name: 'Out-of-bounds Write' }] for the ids on an alert; unknown ids keep a null name. */
export function cweList(ids: unknown): Array<{ id: string; name: string | null }> {
  if (!Array.isArray(ids)) return []
  const out = new Map<string, string | null>()
  for (const raw of ids) {
    const id = String(raw).trim()
    if (!id || out.has(id)) continue
    out.set(id, NVD_PLACEHOLDERS[id] ?? CWE.names[id.replace(/^CWE-/i, '')] ?? null)
  }
  return [...out].map(([id, name]) => ({ id, name }))
}
