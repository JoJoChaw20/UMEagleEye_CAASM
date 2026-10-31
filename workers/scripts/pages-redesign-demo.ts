/**
 * pages-redesign-demo.ts — the pure parts behind the redesigned Threat Intel, SBOM and
 * Discovery pages: the next feed run and the feed-health record (routes/cti.ts,
 * services/cti.ts), each computer's SBOM state (lib/sbomCoverage.ts), the network and
 * kind of each Discovery record and the network cards (lib/discoveryNetworks.ts), and the
 * asset each Discovery host became (lib/scanLog.ts). PURE (no DB).
 * Run: npx esbuild scripts/pages-redesign-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.pages-redesign-demo.cjs && node .pages-redesign-demo.cjs
 */
import { nextIngestAt } from '../src/routes/cti'
import { BATCH_SIZE, describeError, feedRecord, nextCtiStep, planIngestRecord, planUpsertChunks } from '../src/services/cti'
import { computerState } from '../src/lib/sbomCoverage'
import { buildNetworks, ipInCidr, isCidr, networkOf, passiveNetworkOf, scanKind, type NetworkRecord } from '../src/lib/discoveryNetworks'
import { resolveHostAssets, type HostAssetCandidate } from '../src/lib/scanLog'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

console.log('\n── threat intel: next nightly run (22:00 UTC = 06:00 MYT) ──')
check('before 22:00 UTC: today', nextIngestAt(new Date('2026-10-31T10:00:00Z')).toISOString(), '2026-10-31T22:00:00.000Z')
check('exactly 22:00: tomorrow', nextIngestAt(new Date('2026-10-31T22:00:00Z')).toISOString(), '2026-11-01T22:00:00.000Z')
check('after 22:00 on the last day of a month: next month', nextIngestAt(new Date('2026-10-31T23:30:00Z')).toISOString(), '2026-11-01T22:00:00.000Z')

console.log('\n── threat intel: feed-health record ──')
{
  const run = (ok: Record<string, boolean>) =>
    Object.fromEntries(Object.entries(ok).map(([k, v]) => [k, { ok: v, count: v ? 10 : 0 }]))
  const first = planIngestRecord(null, run({ 'AlienVault OTX': true, ThreatFox: false }), new Date('2026-10-30T22:00:00Z'))
  check('a loaded feed: last_ok_at is this run', first.feeds['AlienVault OTX']!.last_ok_at, '2026-10-30T22:00:00.000Z')
  check('a feed that never loaded: last_ok_at null', first.feeds['ThreatFox']!.last_ok_at, null)
  const second = planIngestRecord(first, run({ 'AlienVault OTX': false, ThreatFox: true }), new Date('2026-10-31T22:00:00Z'))
  check('a feed that failed this time keeps when it last loaded', second.feeds['AlienVault OTX'], { ok: false, count: 0, last_ok_at: '2026-10-30T22:00:00.000Z' })
  check('run time recorded', second.at, '2026-10-31T22:00:00.000Z')
  // one feed per queue job: recording one feed keeps the others
  const third = planIngestRecord(second, run({ 'CISA KEV': true }), new Date('2026-11-01T22:00:00Z'))
  check('one feed recorded: the other feeds stay as they were', [Object.keys(third.feeds).sort(), third.feeds['ThreatFox']], [['AlienVault OTX', 'CISA KEV', 'ThreatFox'], second.feeds['ThreatFox']])
}

console.log('\n── threat intel: one feed per queue job ──')
check('steps in order, then done', [nextCtiStep('kev'), nextCtiStep('threatfox'), nextCtiStep('otx'), nextCtiStep('finish')], ['threatfox', 'otx', 'finish', null])
check('the JSON record sent to Postgres', feedRecord({ source: 'ThreatFox', indicatorType: 'ip', value: '1.2.3.4', confidenceScore: '0.75', malwareFamily: 'Vidar', lastSeen: new Date('2026-10-31T05:00:00Z') } as never),
  { source: 'ThreatFox', indicator_type: 'ip', value: '1.2.3.4', warning: null, confidence_score: '0.75', malware_family: 'Vidar', attack_software: null, attack_techniques: null, last_seen: '2026-10-31T05:00:00.000Z' })

console.log('\n── threat intel: feed upserts fit the free plan\'s 50 requests per run ──')
{
  const tf = Array.from({ length: 17117 }, (_, i) => ({ value: `10.0.${Math.floor(i / 256)}.${i % 256}` }))
  check('the 31 Oct ThreatFox pull (17,117 rows): 5 statements, not 172', planUpsertChunks(tf).length, 5)
  check('9 parameters per row stay under Postgres\' 65,535', BATCH_SIZE * 9 < 65535, true)
  const otx = [{ value: 'evil.example', n: 1 }, { value: 'a.example', n: 2 }, { value: 'evil.example', n: 3 }]
  check('a value twice in one pull: one row, the last one wins', planUpsertChunks(otx), [[{ value: 'evil.example', n: 3 }, { value: 'a.example', n: 2 }]])
  check('no rows: no statements', planUpsertChunks([]), [])
  const long = [{ value: 'https://x.example/' + 'a'.repeat(600) }, { value: 'ok.example' }]
  check('a value longer than the 512-character column is left out (it failed the whole statement)', planUpsertChunks(long), [[{ value: 'ok.example' }]])
  const pgErr = Object.assign(new Error('deadlock detected'), { code: '40P01', detail: 'Process 1 waits for ShareLock on transaction 2' })
  check('a database error is logged with its text and code', describeError(pgErr), 'deadlock detected | code 40P01 | Process 1 waits for ShareLock on transaction 2')
  check('not an Error', describeError('boom'), 'boom')
}

console.log('\n── SBOM: computer state ──')
{
  const now = new Date('2026-10-31T12:00:00Z')
  check('no SBOM, no job', computerState({ generatedAt: null, job: null }, now), 'none')
  check('SBOM 6 h old', computerState({ generatedAt: '2026-10-31T06:00:00Z', job: null }, now), 'ok')
  check('SBOM 3 days old', computerState({ generatedAt: '2026-10-28T12:00:00Z', job: null }, now), 'stale')
  check('job running wins over a stale SBOM', computerState({ generatedAt: '2026-10-28T12:00:00Z', job: { status: 'running', startedAt: '2026-10-31T11:58:00Z' } }, now), 'running')
  check('job queued', computerState({ generatedAt: null, job: { status: 'pending', startedAt: null } }, now), 'queued')
  check('failed after the SBOM: failed', computerState({ generatedAt: '2026-10-30T12:00:00Z', job: { status: 'failed', startedAt: '2026-10-31T10:00:00Z' } }, now), 'failed')
  check('failed before the current SBOM: the SBOM counts', computerState({ generatedAt: '2026-10-31T11:00:00Z', job: { status: 'failed', startedAt: '2026-10-31T09:00:00Z' } }, now), 'ok')
  check('failed and no SBOM at all', computerState({ generatedAt: null, job: { status: 'failed', startedAt: '2026-10-31T10:00:00Z' } }, now), 'failed')
  check('cancelled job: the SBOM counts', computerState({ generatedAt: '2026-10-31T11:00:00Z', job: { status: 'cancelled', startedAt: '2026-10-31T11:30:00Z' } }, now), 'ok')
}

console.log('\n── Discovery: kind and network of a record ──')
{
  const lab = { subnet: '192.168.0.0/24', lan_subnet: '192.168.0.0/24', gateway_ip: '192.168.0.1' }
  const passive = { scanType: 'passive', subnet: 'arp-discovery', networkInfo: lab }
  const oldPassive = { scanType: 'passive', subnet: 'arp-discovery', networkInfo: { subnet: '192.168.100.0/24', gateway_ip: '192.168.100.1' } }
  const investigation = { scanType: 'active', subnet: '192.168.0.57', networkInfo: { ...lab, subnet: '192.168.0.57', trigger: 'new_device', event_id: 'e1' } }
  const fullScan = { scanType: 'active', subnet: '192.168.100.0/24', networkInfo: { subnet: '192.168.100.0/24', lan_subnet: '192.168.100.0/24', gateway_ip: '192.168.100.1' } }
  const otherRange = { scanType: 'active', subnet: '10.0.5.0/24', networkInfo: { subnet: '10.0.5.0/24', lan_subnet: '192.168.100.0/24', gateway_ip: '192.168.100.1' } }
  const hostScan = { scanType: 'active', subnet: '192.168.0.20', networkInfo: null }
  const slash32 = { scanType: 'active', subnet: '192.168.0.20/32', networkInfo: null }
  check('kinds', [passive, investigation, fullScan, hostScan, slash32].map(scanKind), ['passive', 'investigation', 'network', 'host', 'host'])
  check('passive: the LAN the agent listened on', networkOf(passive), { subnet: '192.168.0.0/24', gateway: '192.168.0.1' })
  check('passive from an agent before 2.2.4 (subnet only)', networkOf(oldPassive), { subnet: '192.168.100.0/24', gateway: '192.168.100.1' })
  check('new-device check: the agent\'s LAN, not the one IP', networkOf(investigation), { subnet: '192.168.0.0/24', gateway: '192.168.0.1' })
  check('full scan of its own LAN keeps the gateway', networkOf(fullScan), { subnet: '192.168.100.0/24', gateway: '192.168.100.1' })
  check('full scan of another range: that range, no gateway', networkOf(otherRange), { subnet: '10.0.5.0/24', gateway: null })
  check('single-host scan with no network block: unknown', networkOf(hostScan), null)
  check('fold key: lan_subnet first, then subnet, null without', [passiveNetworkOf(lab), passiveNetworkOf({ subnet: '10.0.0.0/8' }), passiveNetworkOf(null)], ['192.168.0.0/24', '10.0.0.0/8', null])
  check('isCidr rejects junk', [isCidr('192.168.0.0/24'), isCidr('arp-discovery'), isCidr('300.1.1.0/24'), isCidr('10.0.0.0/33')], [true, false, false, false])
  check('ipInCidr', [ipInCidr('192.168.0.57', '192.168.0.0/24'), ipInCidr('192.168.1.5', '192.168.0.0/24'), ipInCidr('10.9.8.7', '0.0.0.0/0'), ipInCidr('x', '10.0.0.0/8')], [true, false, true, false])
}

console.log('\n── Discovery: network cards ──')
{
  const lab = { subnet: '192.168.0.0/24', lan_subnet: '192.168.0.0/24', gateway_ip: '192.168.0.1' }
  const home = { subnet: '192.168.100.0/24', lan_subnet: '192.168.100.0/24', gateway_ip: '192.168.100.1' }
  const rec = (o: Partial<NetworkRecord> & { scanId: string }): NetworkRecord => ({
    agentId: 'A', scanType: 'passive', subnet: 'arp-discovery', networkInfo: lab, status: 'completed',
    hostsDiscovered: 0, startedAt: '2026-10-30T09:00:00Z', completedAt: '2026-10-30T09:00:00Z', ...o,
  })
  const records = [
    rec({ scanId: 'p1', startedAt: '2026-10-29T18:15:00Z', completedAt: '2026-10-29T19:10:00Z' }),
    rec({ scanId: 'p2', startedAt: '2026-10-30T10:00:00Z', completedAt: '2026-10-30T11:27:00Z' }),
    rec({ scanId: 'i1', scanType: 'active', subnet: '192.168.0.57', networkInfo: { ...lab, subnet: '192.168.0.57', trigger: 'new_device' }, hostsDiscovered: 1 }),
    rec({ scanId: 'h1', agentId: 'B', networkInfo: home, startedAt: '2026-10-30T13:19:00Z', completedAt: '2026-10-30T14:00:00Z' }),
    rec({ scanId: 'f1', agentId: 'B', scanType: 'active', subnet: '192.168.100.0/24', networkInfo: home, hostsDiscovered: 7, startedAt: '2026-10-25T02:00:00Z', completedAt: '2026-10-25T02:05:00Z' }),
    rec({ scanId: 'f2', agentId: 'B', scanType: 'active', subnet: '192.168.100.0/24', networkInfo: home, status: 'failed', startedAt: '2026-10-28T02:00:00Z', completedAt: '2026-10-28T02:01:00Z' }),
    rec({ scanId: 'x1', scanType: 'active', subnet: '192.168.0.20', networkInfo: null }),
  ]
  const ips = new Map([['p2', ['192.168.0.6', '192.168.0.57', '192.168.0.1']], ['i1', ['192.168.0.57']], ['h1', ['192.168.100.71', '8.8.8.8']]])
  const nets = buildNetworks(records, ips, ['192.168.0.57', '192.168.0.94', '192.168.100.204', '10.1.1.1'])
  check('one card per network, most recent first', nets.map(n => n.subnet), ['192.168.100.0/24', '192.168.0.0/24'])
  const labCard = nets.find(n => n.subnet === '192.168.0.0/24')!
  const homeCard = nets.find(n => n.subnet === '192.168.100.0/24')!
  check('lab: heard passively until Friday 11:27', labCard.last_heard_at, '2026-10-30T11:27:00.000Z')
  check('lab: the latest passive record', labCard.last_heard_scan_id, 'p2')
  check('lab: never had a full scan (the new-device check does not count)', labCard.last_full_scan, null)
  check('lab: distinct hosts in 24 h', labCard.hosts_24h, 3)
  check('lab: open new-device alerts in range', labCard.new_devices, 2)
  check('lab: gateway', labCard.gateway, '192.168.0.1')
  check('home: last COMPLETED full scan (the failed one is skipped)', homeCard.last_full_scan, { scan_id: 'f1', at: '2026-10-25T02:05:00.000Z', hosts: 7 })
  check('home: an IP outside the range is not counted', homeCard.hosts_24h, 1)
  check('home: the agent that was there last', homeCard.latest_agent_id, 'B')
  check('records with no known network are left out', nets.length, 2)
}

console.log('\n── Discovery: the asset each host became ──')
{
  const cands: HostAssetCandidate[] = [
    { assetId: 'pc', hostname: 'JOJO-PC', inMyAssets: true, ips: ['192.168.0.6', '192.168.100.71'], currentIps: ['192.168.100.71'], macs: ['14:13:33:c3:f6:03'] },
    { assetId: 'phone-old', hostname: null, inMyAssets: false, ips: ['192.168.0.57'], currentIps: [], macs: ['aa:aa:aa:aa:aa:01'] },
    { assetId: 'phone-new', hostname: 'iPhone', inMyAssets: false, ips: ['192.168.0.57'], currentIps: ['192.168.0.57'], macs: ['aa:aa:aa:aa:aa:02'] },
  ]
  const hosts = [
    { ip: '192.168.0.6', mac: '14-13-33-C3-F6-03' },     // any MAC spelling
    { ip: '192.168.0.57', mac: 'aa:aa:aa:aa:aa:01' },    // the device that used to hold it
    { ip: '192.168.0.57' },                              // no MAC: the one holding the IP now
    { ip: '192.168.0.6', mac: 'bb:bb:bb:bb:bb:bb' },     // same IP, another device
    { ip: '10.0.0.9' },
    { hostname: 'no-ip' },
  ]
  check('resolved', resolveHostAssets(hosts, cands).map(c => c?.assetId ?? null), ['pc', 'phone-old', 'phone-new', null, null, null])
  check('not an array: nothing', resolveHostAssets(null, cands), [])
}

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
