// Pure view helpers for structured advisories (see AdvisoryBody).
export const REGENERATE_HINT = 'Regenerate to get structured steps and automation labels.'
export const NOT_ON_TEXT = 'Automatic fixing is not switched on yet.'

const TONES = {
  'Auto-fixable': { tone: 'green', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' },
  'Partly auto-fixable': { tone: 'amber', className: 'border-amber-500/30 bg-amber-500/10 text-amber-400' },
  'Guided fix': { tone: 'blue', className: 'border-sky-500/30 bg-sky-500/10 text-sky-400' },
  'Needs outside support': { tone: 'red', className: 'border-red-500/30 bg-red-500/10 text-red-400' },
}
const NEUTRAL = { tone: 'neutral', className: 'border-dark-600 bg-dark-900 text-dark-300' }

export function labelTone(label) {
  return Object.hasOwn(TONES, label) ? TONES[label] : NEUTRAL
}

const KINDS = {
  auto: { text: 'Automatic', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' },
  manual: { text: 'Manual', className: 'border-sky-500/30 bg-sky-500/10 text-sky-400' },
  external: { text: 'Outside support', className: 'border-red-500/30 bg-red-500/10 text-red-400' },
}

export function kindBadge(kind) {
  return Object.hasOwn(KINDS, kind) ? KINDS[kind] : KINDS.manual
}

export const RISK_STYLE = {
  low: 'border-dark-600 bg-dark-900 text-dark-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
  high: 'border-red-500/30 bg-red-500/10 text-red-400',
}

// Structured view when the advisory has content with steps; otherwise the text view.
export function advisoryDisplay(advisory) {
  const a = advisory ?? {}
  const content = a.content
  if (content && Array.isArray(content.steps) && content.steps.length > 0) {
    return { mode: 'structured', content, automation: a.automation ?? null }
  }
  return { mode: 'text', text: a.recommendedAction ?? a.recommended_action ?? '', hint: REGENERATE_HINT }
}

const ACTION_LABELS = {
  'pkg.upgrade': 'Upgrade a package',
  'os.updates.apply': 'Install Windows updates',
  'service.stop_disable': 'Stop and disable a service',
  'firewall.block_port': 'Block an inbound port',
  'app.uninstall': 'Uninstall an application',
  'check.version': 'Check a package version',
  'check.port': 'Check a port',
  'check.service': 'Check a service',
}

// Plain-words description of a planned automatic action; null when there is nothing to say.
export function plannedActionText(action) {
  if (!action || !Object.hasOwn(ACTION_LABELS, action.key)) return null
  const vals = Object.values(action.params ?? {}).map(String).filter(Boolean)
  return `Planned automatic action: ${ACTION_LABELS[action.key]}${vals.length ? ` (${vals.join(', ')})` : ''}`
}
