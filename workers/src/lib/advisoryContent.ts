/**
 * advisoryContent.ts - PURE. Turns an advisory draft into structured content: each step gets a
 * kind (auto/manual/external), a risk and, when the rules allow, a catalog action. Only this
 * mapper decides kind, action key and parameters; the model's text is never executed.
 */
import { safeToken, type AdvisoryDraft, type AdvisoryFacts } from './advisoryKit'
import {
  REMEDIATION_ACTIONS, PACKAGE_MANAGER_FOR, isProtectedPort, isProtectedService, type RemediationActionKey,
} from './remediationCatalog'

export type AdvisoryStep = {
  id: string; text: string; kind: 'auto' | 'manual' | 'external'
  action?: { key: RemediationActionKey; params: Record<string, string | number> }
  risk: 'low' | 'medium' | 'high'; needs_reboot?: boolean; expert_note?: string; reason?: string
}

export type AdvisoryContent = {
  summary: string; why_now: string | null; steps: AdvisoryStep[]; verify: string | null; rollback: string | null
  confidence: AdvisoryDraft['confidence']; sources: AdvisoryFacts['sources']; basis: string; version: 1
}

export type DeviceInfo = { hasAgent: boolean; isNetworkDevice: boolean; remediationEnabled: boolean; capabilities: string[] }

type Action = NonNullable<AdvisoryStep['action']>
type Draftish = { text: string; expert_note?: string; action?: Action }

const NO_AGENT = 'This device has no EagleEye agent.'
const NETWORK_DEVICE = 'Network devices are changed by an engineer or the vendor.'
const NOT_ON = 'Automatic fixing is not switched on yet.'

// Literal, case-insensitive containment. Never builds a RegExp from the text.
const has = (text: string, needle: string) => text.toLowerCase().includes(needle.toLowerCase())

/** True when `port` appears in the text as a whole number (not inside 18080 or 80800). */
function namesPort(text: string, port: number): boolean {
  const s = String(port)
  let i = text.indexOf(s)
  while (i >= 0) {
    const before = text[i - 1]; const after = text[i + s.length]
    if (!(before && /\d/.test(before)) && !(after && /\d/.test(after))) return true
    i = text.indexOf(s, i + 1)
  }
  return false
}

/** The one automatic action the facts allow, with the rule that attaches it to a step. */
function planAction(facts: AdvisoryFacts): { action: Action; matches: (t: string) => boolean; prepend: string } | null {
  const c = facts.cve
  if (c) {
    const manager = PACKAGE_MANAGER_FOR[(c.packageType ?? '').toLowerCase()]
    const pkg = safeToken(c.pkg); const version = safeToken(c.group?.fixTo)
    if (!manager || !pkg || !version) return null
    return {
      action: { key: 'pkg.upgrade', params: { manager, package: pkg, version } },
      matches: t => has(t, pkg) && has(t, version),
      prepend: `Upgrade ${pkg} to ${version}.`,
    }
  }
  const o = facts.other ?? {}
  if (facts.eventType === 'os_patch_missing') {
    const kb = safeToken(o.kb)
    if (!kb) return null
    return {
      action: { key: 'os.updates.apply', params: { scope: 'kb', kb } },
      matches: t => has(t, kb),
      prepend: `Install Windows update ${kb}.`,
    }
  }
  if (facts.eventType === 'port_opened') {
    const raw = String(o.port ?? '').trim()
    if (!/^\d{1,5}$/.test(raw)) return null
    const port = Number(raw)
    if (port < 1 || port > 65535 || isProtectedPort(port)) return null
    const proto = String(o.protocol ?? 'tcp').trim().toLowerCase() || 'tcp'
    if (proto !== 'tcp' && proto !== 'udp') return null
    // the service on that port (alert detail, or the scan's "service product version" text) must not be protected
    const words = [o.service, ...String(o.service_on_port ?? '').split(/\s+/)]
    if (words.some(w => w != null && w !== '' && isProtectedService(w))) return null
    return {
      action: { key: 'firewall.block_port', params: { port, protocol: proto, direction: 'inbound' } },
      matches: t => namesPort(t, port) && /close|block|firewall/i.test(t),
      prepend: `Block inbound port ${port}/${proto} at the firewall.`,
    }
  }
  return null
}

export function mapSteps(
  facts: AdvisoryFacts, steps: Array<{ text: string; expert_note?: string }>, device: DeviceInfo,
): AdvisoryStep[] {
  const list: Draftish[] = steps.map(s => ({ text: s.text, expert_note: s.expert_note }))
  const plan = planAction(facts)
  if (plan) {
    const hit = list.find(s => plan.matches(s.text))
    if (hit) hit.action = plan.action
    else list.unshift({ text: plan.prepend, action: plan.action })
  }
  return list.map((s, i): AdvisoryStep => {
    const step: AdvisoryStep = { id: `s${i + 1}`, text: s.text, kind: 'manual', risk: 'low' }
    if (s.expert_note) step.expert_note = s.expert_note
    if (s.action) {
      if (!device.hasAgent) { step.kind = 'external'; step.reason = NO_AGENT }
      else if (device.isNetworkDevice) { step.kind = 'external'; step.reason = NETWORK_DEVICE }
      else {
        const def = REMEDIATION_ACTIONS[s.action.key]
        step.kind = 'auto'; step.action = s.action; step.risk = def.risk
        if (def.needsReboot) step.needs_reboot = true
        return step
      }
    }
    if (/reboot|uninstall/i.test(s.text)) step.risk = 'medium'
    return step
  })
}

export function automationLabel(steps: AdvisoryStep[], device: DeviceInfo): {
  label: 'Auto-fixable' | 'Partly auto-fixable' | 'Guided fix' | 'Needs outside support'; available: boolean; reason: string
} {
  const real = steps.filter(s => !s.action?.key.startsWith('check.'))
  const autos = real.filter(s => s.kind === 'auto')
  const external = real.find(s => s.kind === 'external')
  const available = device.remediationEnabled && autos.every(s => !!s.action && device.capabilities.includes(s.action.key))
  if (external) return { label: 'Needs outside support', available: false, reason: external.reason ?? NO_AGENT }
  if (autos.length === 0) return { label: 'Guided fix', available: false, reason: 'Follow the steps by hand.' }
  const label = autos.length === real.length ? 'Auto-fixable' : 'Partly auto-fixable'
  return { label, available, reason: available ? 'EagleEye can apply the automatic steps.' : NOT_ON }
}

export function buildContent(
  draft: AdvisoryDraft & { stepNotes?: string[] }, facts: AdvisoryFacts, basis: string, device: DeviceInfo,
): AdvisoryContent {
  return {
    summary: draft.summary,
    why_now: draft.whyNow,
    steps: mapSteps(facts, draft.steps.map((text, i) => ({ text, expert_note: draft.stepNotes?.[i] || undefined })), device),
    verify: draft.verify,
    rollback: draft.rollback,
    confidence: draft.confidence,
    sources: facts.sources,
    basis,
    version: 1,
  }
}
