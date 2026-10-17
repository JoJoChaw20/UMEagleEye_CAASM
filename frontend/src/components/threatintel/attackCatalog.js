// MITRE ATT&CK catalogue (GET /cti/attack), loaded once per page load.
import { useEffect, useState } from 'react'
import client from '../../api/client'

let pending = null

export function loadAttackCatalog() {
  if (!pending) {
    pending = client.get('/cti/attack').then((r) => {
      const d = r.data
      return {
        ...d,
        techniques: d.techniques.map(([id, name, tactics]) => ({ id, name, tactics })),
        softwareById: Object.fromEntries(d.software.map(([id, name, count]) => [id, { id, name, count }])),
      }
    }).catch((err) => { pending = null; throw err })
  }
  return pending
}

export function useAttackCatalog() {
  const [cat, setCat] = useState(null)
  useEffect(() => {
    let live = true
    loadAttackCatalog().then((c) => live && setCat(c)).catch(() => {})
    return () => { live = false }
  }, [])
  return cat
}

// Same as workers/src/lib/attack.ts normName/resolveSoftware
const norm = (s) => (s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '')
export function softwareFor(cat, family) {
  const id = cat?.names?.[norm(family)]
  return id ? cat.softwareById[id] ?? null : null
}

export const techniqueUrl = (id) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
export const softwareUrl = (id) => `https://attack.mitre.org/software/${id}/`
