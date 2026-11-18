import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseAiDraft, parseAiDraftWithReason, ruleBasedDraft, type AdvisoryDraft, type AdvisoryFacts } from './advisoryKit'
import { buildContent } from './advisoryContent'

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
