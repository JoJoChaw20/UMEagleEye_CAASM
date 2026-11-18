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
  /** external only because of the device (no agent / network device); the validated action is kept so the label can follow the device */
  device_blocked?: boolean
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

const WORD = /[A-Za-z0-9_+-]/
const NEGATION = /\b(do not|don't|dont|never|avoid)\b/i

/** Index of `token` in `text` as a whole token (literal, case-insensitive, no RegExp from input), or -1.
 *  Before: not [A-Za-z0-9._+-]. After: not [A-Za-z0-9_+-], and a "." must not lead into more alphanumerics
 *  (so "1.0" does not match "1.0.2" but does match "to 1.0."). */
function tokenAt(text: string, token: string): number {
  const t = text.toLowerCase(); const n = token.toLowerCase()
  if (!n) return -1
  let i = t.indexOf(n)
  while (i >= 0) {
    const before = t[i - 1]; const after = t[i + n.length]; const after2 = t[i + n.length + 1]
    const okBefore = !before || !(WORD.test(before) || before === '.')
    const okAfter = !after || (!WORD.test(after) && !(after === '.' && !!after2 && /[A-Za-z0-9]/.test(after2)))
    if (okBefore && okAfter) return i
    i = t.indexOf(n, i + 1)
  }
  return -1
}
const negatedBefore = (text: string, idx: number) => NEGATION.test(text.slice(0, idx))

/** Whole-number port in the text (not inside 18080 or 80800). */
function portAt(text: string, port: number): number {
  const s = String(port)
  let i = text.indexOf(s)
  while (i >= 0) {
    const before = text[i - 1]; const after = text[i + s.length]
    if (!(before && /\d/.test(before)) && !(after && /\d/.test(after))) return i
    i = text.indexOf(s, i + 1)
  }
  return -1
}

// nmap names and Windows/Unix aliases of protected services, used only for the port check
const PROTECTED_SERVICE_ALIASES = new Set([
  'ssh', 'ms-wbt-server', 'rdp', 'domain', 'dns', 'ldap', 'ldaps', 'kerberos', 'kerberos-sec', 'dhcp', 'dhcps',
  'bootps', 'microsoft-ds', 'netbios-ssn', 'msrpc', 'winrm', 'wsman',
])
const isProtectedServiceName = (w: unknown) =>
  isProtectedService(w) || PROTECTED_SERVICE_ALIASES.has(String(w ?? '').trim().toLowerCase())

type Plan = { action: Action; /** index of the match in the step text, -1 for none */ at: (t: string) => number; verb: RegExp; prepend: string }

/** The one automatic action the facts allow, with the rule that attaches it to a step. */
function planAction(facts: AdvisoryFacts): Plan | null {
  const c = facts.cve
  if (c) {
    const type = (c.packageType ?? '').toLowerCase()
    const manager = Object.hasOwn(PACKAGE_MANAGER_FOR, type) ? PACKAGE_MANAGER_FOR[type] : undefined
    const pkg = safeToken(c.pkg); const version = safeToken(c.group?.fixTo)
    if (typeof manager !== 'string' || !pkg || !version) return null
    if (pkg.toLowerCase().includes('eagleeye')) return null   // never self-upgrade the agent mid-run
    return {
      action: { key: 'pkg.upgrade', params: { manager, package: pkg, version } },
      at: t => (tokenAt(t, version) >= 0 ? tokenAt(t, pkg) : -1), verb: /upgrade|update|patch|install/i,
      prepend: `Upgrade ${pkg} to ${version}.`,
    }
  }
  const o = facts.other ?? {}
  if (facts.eventType === 'os_patch_missing') {
    const kb = safeToken(o.kb)
    if (!kb) return null
    return {
      action: { key: 'os.updates.apply', params: { scope: 'kb', kb } },
      at: t => tokenAt(t, kb), verb: /install|update|patch|apply/i,
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
    const words = [...String(o.service ?? '').split(/\s+/), ...String(o.service_on_port ?? '').split(/\s+/)]
    if (words.some(w => w != null && w !== '' && isProtectedServiceName(w))) return null
    return {
      action: { key: 'firewall.block_port', params: { port, protocol: proto, direction: 'inbound' } },
      at: t => (/close|block|firewall/i.test(t) ? portAt(t, port) : -1), verb: /close|block|firewall/i,
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
    const ok = list.filter(s => { const i = plan.at(s.text); return i >= 0 && !negatedBefore(s.text, i) })
    const hit = ok.find(s => plan.verb.test(s.text)) ?? ok[0]
    if (hit) hit.action = plan.action
    else list.unshift({ text: plan.prepend, action: plan.action })
  }
  return list.map((s, i): AdvisoryStep => {
    const step: AdvisoryStep = { id: `s${i + 1}`, text: s.text, kind: 'manual', risk: 'low' }
    if (s.expert_note) step.expert_note = s.expert_note
    if (s.action) {
      if (!device.hasAgent) { step.kind = 'external'; step.reason = NO_AGENT; step.action = s.action; step.device_blocked = true }
      else if (device.isNetworkDevice) { step.kind = 'external'; step.reason = NETWORK_DEVICE; step.action = s.action; step.device_blocked = true }
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
  if (external) {
    // the mapper always sets a reason on external steps; the text below only covers hand-built steps
    return { label: 'Needs outside support', available: false, reason: external.reason || 'This step is handled outside EagleEye.' }
  }
  if (autos.length === 0) return { label: 'Guided fix', available: false, reason: 'Follow the steps by hand.' }
  const label = autos.length === real.length ? 'Auto-fixable' : 'Partly auto-fixable'
  return { label, available, reason: available ? 'EagleEye can apply the automatic steps.' : NOT_ON }
}

/** API view of stored content: the automation label is recomputed from the device as it is now.
 *  Steps that were auto or device-blocked follow the current device (no agent or network device ->
 *  external, otherwise auto); all other steps keep their stored kind. */
export function advisoryView(row: { content: AdvisoryContent | null }, device: DeviceInfo): {
  content: AdvisoryContent | null; automation: ReturnType<typeof automationLabel> | null
} {
  const content = row.content ?? null
  if (!content || !Array.isArray(content.steps)) return { content, automation: null }
  const steps = content.steps.map((s): AdvisoryStep => {
    if (!s.action || !(s.kind === 'auto' || s.device_blocked)) return s
    const { reason: _drop, device_blocked: _db, ...rest } = s
    if (!device.hasAgent) return { ...rest, kind: 'external', reason: NO_AGENT, device_blocked: true }
    if (device.isNetworkDevice) return { ...rest, kind: 'external', reason: NETWORK_DEVICE, device_blocked: true }
    return { ...rest, kind: 'auto' }
  })
  return { content: { ...content, steps }, automation: automationLabel(steps, device) }
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
