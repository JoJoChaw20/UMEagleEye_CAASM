// How sure a feed is about an indicator, turned into how loudly a match is raised. ThreatFox gives
// each IOC a confidence level 0-100 (stored 0-1); CISA KEV is certain (1). A weak entry still alerts,
// but as something to review rather than a possible compromise to investigate at once.
//
//   confidence    sighting (R7, a contact)    match on an asset (R5, a listing)
//   75% or more   critical                    high
//   50 to 74%     high                        medium
//   below 50%     medium                      low
// With no confidence recorded, the entry is treated as 75% (as before this rule, every feed entry
// was rated as sure).

export const SURE = 0.75
export const LIKELY = 0.5

/** 3 sure, 2 likely, 1 weak. */
export function confidenceLevel(confidence: number | string | null | undefined): 1 | 2 | 3 {
  const c = confidence == null || confidence === '' ? SURE : Number(confidence)
  if (!Number.isFinite(c) || c >= SURE) return 3
  return c >= LIKELY ? 2 : 1
}

/** The same as SQL, for a cti_indicators row aliased `c`. */
export const CONFIDENCE_LEVEL_SQL = `(CASE WHEN c.confidence_score IS NULL OR c.confidence_score >= ${SURE} THEN 3 WHEN c.confidence_score >= ${LIKELY} THEN 2 ELSE 1 END)`
