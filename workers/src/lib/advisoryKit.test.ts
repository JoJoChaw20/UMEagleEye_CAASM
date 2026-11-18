import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseAiDraft, parseAiDraftWithReason, ruleBasedDraft, type AdvisoryDraft, type AdvisoryFacts } from './advisoryKit'
import { buildContent } from './advisoryContent'
import { unsafeRecommendations } from '../kg/safety'

const fallback: AdvisoryDraft = {
  summary: 'fallback summary', steps: ['fallback step'], whyNow: 'now', verify: 'v', rollback: null,
  confidence: { level: 'Medium', reason: 'r' },
}
const ai = (steps: unknown[]) => JSON.stringify({ summary: 'A real summary here.', steps, why_now: 'soon', verify: 'check', rollback: 'undo' })

function facts(o: Partial<AdvisoryFacts> = {}): AdvisoryFacts {
  return {
    eventType: 'port_opened', severity: 'high',
    asset: { label: 'h1', type: 'server', os: null, owner: null, criticality: null, internetFacing: false, windows: false, ports: [] },
    neighbours: { total: 0, critical: 0 }, other: { port: '8080', protocol: 'tcp' },
    urgency: { level: 'planned', window: 'soon', reasons: [] },
    commands: { upgrade: [], verify: null, rollback: null }, sources: [], ...o,
  }
}

test('parseAiDraft accepts object steps with expert notes', () => {
  const d = parseAiDraft(ai([{ text: 'Do one thing.', expert_note: 'It changes X and can break Y.' }, { text: 'Second step.' }]), fallback)!
  assert.deepEqual(d.steps, ['Do one thing.', 'Second step.'])
  assert.deepEqual(d.stepNotes, ['It changes X and can break Y.', ''])
})

test('expert note with a URL is stripped of it, an unknown CVE drops the note, backticks are removed, the draft stays', () => {
  const d = parseAiDraft(ai([
    { text: 'Step one.', expert_note: 'See https://evil.example/x for details' },
    { text: 'Step two.', expert_note: 'Fixes CVE-2099-0001 completely' },
    { text: 'Step three.', expert_note: 'Use `rm -rf` here' },
  ]), fallback)!
  assert.ok(d)
  assert.equal(d.stepNotes[0], 'See for details')
  assert.equal(d.stepNotes[1], '')
  assert.ok(!/CVE-2099/.test(d.stepNotes.join(' ')))
  assert.ok(!/https?:/.test(d.stepNotes.join(' ')))
  assert.ok(!d.stepNotes[2].includes('`'))
})

test('expert note is capped at 280 characters', () => {
  const d = parseAiDraft(ai([{ text: 'Step.', expert_note: 'word '.repeat(100) }]), fallback)!
  assert.ok(d.stepNotes[0].length <= 280)
})

test('string steps still parse', () => {
  const d = parseAiDraft(ai(['1. First step.', 'Second step.']), fallback)!
  assert.deepEqual(d.steps, ['First step.', 'Second step.'])
  assert.deepEqual(d.stepNotes, ['', ''])
})

test('a bad step is dropped as before and keeps notes aligned', () => {
  const d = parseAiDraft(ai([{ text: '', expert_note: 'orphan note' }, { text: 'Good step.', expert_note: 'good note' }]), fallback)!
  assert.deepEqual(d.steps, ['Good step.'])
  assert.deepEqual(d.stepNotes, ['good note'])
})

test('content is built for the rule-based fallback', () => {
  const f = facts()
  const draft = ruleBasedDraft(f)
  const c = buildContent(draft, f, 'Rule-based (no AI)', { hasAgent: true, isNetworkDevice: false, remediationEnabled: false, capabilities: [] })
  assert.equal(c.version, 1)
  assert.ok(c.steps.length >= draft.steps.length)
  for (const s of c.steps) { assert.equal(typeof s.text, 'string'); assert.ok(s.kind) }
})

test('M3: an object step whose text is not a string is dropped', () => {
  const d = parseAiDraft(JSON.stringify({ summary: 'Sum text.', steps: [{ text: 123 }, { text: ['a'] }, { text: 'Real step.' }] }), fallback)!
  assert.deepEqual(d.steps, ['Real step.'])
})

test('parseAiDraftWithReason reports why a reply is not used', () => {
  const good = ai([{ text: 'Do one thing.', expert_note: 'Because X.' }, { text: 'Second step.' }])
  assert.equal(parseAiDraftWithReason(good, fallback).reason, 'ok')
  assert.ok(parseAiDraftWithReason(good, fallback).draft)
  const cut = good.slice(0, good.indexOf('Second step.') + 4)
  assert.deepEqual(parseAiDraftWithReason(cut, fallback), { draft: null, reason: 'not_json' })
  assert.equal(parseAiDraftWithReason('{}', fallback).reason, 'no_summary_or_steps')
  const bad = JSON.stringify({ summary: 'About CVE-2099-0001 here.', steps: ['Patch it.'] })
  assert.deepEqual(parseAiDraftWithReason(bad, fallback, ['CVE-2024-1111']), { draft: null, reason: 'unknown_cve' })
})

test('the rule-based advisory (the fallback for an unsafe AI draft) passes the same safety check for every alert type', () => {
  const asset = (internetFacing: boolean) => ({ label: 'h1', type: 'server', os: null, owner: null, criticality: null, internetFacing, windows: false, ports: [] })
  const cve = (fixTo: string | null) => ({
    id: 'CVE-2024-0001', pkg: 'openssl', packageType: 'deb', installed: '1.0', cvss: 9, epss: 0.5, kev: true, threatIntel: false,
    tiTitles: [], cwe: [], description: null, group: { openCves: 1, kevCves: 1, fixTo, fixedCount: fixTo ? 1 : 0, noFixCount: fixTo ? 0 : 1 },
  })
  const all: AdvisoryFacts[] = []
  for (const internetFacing of [false, true]) {
    for (const eventType of ['port_opened', 'new_device', 'cti_match', 'version_downgrade', 'exposure', 'os_patch_missing']) all.push(facts({ eventType, asset: asset(internetFacing) }))
    for (const fixTo of ['1.1', null]) all.push(facts({ eventType: 'cve_detected', asset: asset(internetFacing), cve: cve(fixTo) }))
  }
  for (const f of all) {
    const d = ruleBasedDraft(f)
    for (const text of [d.summary, ...d.steps, d.whyNow, d.verify, d.rollback]) {
      if (text) assert.deepEqual(unsafeRecommendations(text), [], `${f.eventType} internet=${f.asset.internetFacing}: ${text}`)
    }
  }
})

test('an AI draft that recommends anything unsafe is not used (the rule-based advisory is)', () => {
  const unsafeDraft = (o: Record<string, unknown>) => JSON.stringify({ summary: 'A real summary here.', steps: ['Patch the package.'], why_now: 'soon', verify: 'check', rollback: 'undo', ...o })
  const cases: Array<[string, Record<string, unknown>]> = [
    ['step', { steps: ['Patch the package.', 'Disable the firewall while testing the upgrade.'] }],
    ['step object', { steps: [{ text: 'Allow inbound 3389 from any address so the vendor can connect.' }] }],
    ['expert note', { steps: [{ text: 'Patch the package.', expert_note: 'If the service fails to read its key, chmod 777 the directory.' }] }],
    ['summary', { summary: 'Turn off Windows Defender, then patch the package.' }],
    ['why now', { why_now: 'Open port 3389 to the internet so the vendor can help.' }],
    ['verify', { verify: 'Run curl -k https://host to skip the certificate error.' }],
    ['rollback', { rollback: 'If it fails, run setenforce 0 and retry.' }],
    // a warning in one step never covers the next step
    ['next step', { steps: ['Never use telnet', 'Allow 3389 from anywhere'] }],
  ]
  for (const [where, o] of cases) {
    const r = parseAiDraftWithReason(unsafeDraft(o), fallback)
    assert.equal(r.draft, null, where)
    assert.equal(r.reason, 'unsafe', where)
  }
  // safe advice and a description of the finding are kept
  const safe = unsafeDraft({
    summary: 'RDP on win-01 is open to the internet.',
    steps: ['Allow 3389 only from the admin network, not from anywhere.', { text: 'Restrict inbound 3389 in Windows Defender Firewall.', expert_note: 'Never disable the firewall to test; keep a console session open.' }],
  })
  assert.equal(parseAiDraftWithReason(safe, fallback).reason, 'ok')
})
