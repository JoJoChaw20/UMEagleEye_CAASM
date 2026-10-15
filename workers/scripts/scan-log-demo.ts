/**
 * scan-log-demo.ts — Discovery log housekeeping (lib/scanLog.ts): passive uploads
 * folded into one record per agent per hour, and a deleted asset's entries leaving the
 * log. PURE (no DB).
 * Run: npx esbuild scripts/scan-log-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.scan-log-demo.cjs && node .scan-log-demo.cjs
 */
import { mergePassiveHosts, planScanLogPurge, type ScanLogRow } from '../src/lib/scanLog'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const LOOP = '02:00:4c:4f:4f:50'          // KM-TEST loopback: the same on every PC
const PC_WIFI = '14:13:33:c3:f6:03'

console.log('\n── passive uploads fold into one record ──')
{
  const first = [{ ip: '192.168.100.186', mac: '0e:18:7c:8f:fd:91', hostname: null },
    { ip: '192.168.100.1', mac: 'd4:d5:1b:5f:ac:7c', hostname: null }]
  const second = [{ ip: '192.168.100.186', mac: '0E-18-7C-8F-FD-91', hostname: 'Jojos-iPad' },
    { ip: '192.168.100.182', mac: '06:00:59:e5:9a:c6', hostname: null }]
  const merged = mergePassiveHosts(first, second)
  check('same IP and MAC (any spelling): one entry, newer data', merged.filter(h => h['ip'] === '192.168.100.186').map(h => h['hostname']), ['Jojos-iPad'])
  check('new hosts appended, first-heard order kept', merged.map(h => h['ip']), ['192.168.100.186', '192.168.100.1', '192.168.100.182'])
  const dhcp = mergePassiveHosts(merged, [{ ip: '192.168.100.1', mac: 'aa:bb:cc:00:11:22', hostname: null }])
  check('same IP, another MAC (DHCP reuse): both kept', dhcp.filter(h => h['ip'] === '192.168.100.1').length, 2)
  check('no open record: just the upload', mergePassiveHosts(null, second).length, 2)
  check('stored record is not changed in place', first.length, 2)
}

console.log('\n── deleting an asset removes its Discovery entries ──')
{
  const rows: ScanLogRow[] = [
    // A passive record that only ever heard the loopback host: emptied -> deleted.
    { scanId: 'p1', status: 'completed', rawResults: [{ ip: '142.19.0.1', mac: LOOP }] },
    // An active /24 scan with 3 hosts: only that entry goes.
    { scanId: 'a1', status: 'completed', rawResults: [
      { ip: '142.19.0.1', mac: '02-00-4C-4F-4F-50' }, { ip: '192.168.100.71', mac: PC_WIFI }, { ip: '192.168.100.1', mac: 'd4:d5:1b:5f:ac:7c' }] },
    // Another PC's loopback: same MAC, different IP -> kept.
    { scanId: 'p2', status: 'completed', rawResults: [{ ip: '142.20.0.1', mac: LOOP }] },
    // The same IP later given to another device (different MAC) -> kept.
    { scanId: 'p3', status: 'completed', rawResults: [{ ip: '142.19.0.1', mac: 'aa:bb:cc:00:11:22' }] },
    // An entry without a MAC at the asset's IP (remote host seen by Nmap) -> the asset's.
    { scanId: 'a2', status: 'completed', rawResults: [{ ip: '142.19.0.1' }, { ip: '192.168.100.1', mac: 'd4:d5:1b:5f:ac:7c' }] },
    // A scan still running is left alone.
    { scanId: 'r1', status: 'running', rawResults: [{ ip: '142.19.0.1', mac: LOOP }] },
    // A scan that genuinely found nothing is history, not touched.
    { scanId: 'e1', status: 'completed', rawResults: [] },
  ]
  const plan = planScanLogPurge(rows, { ips: ['142.19.0.1'], macs: [LOOP.toUpperCase(), null] })
  check('emptied record deleted', plan.deletes, ['p1'])
  check('shared records keep the other hosts, count updated',
    plan.updates.map(u => [u.scanId, u.hostsDiscovered, u.rawResults.map(h => h['ip'])]),
    [['a1', 2, ['192.168.100.71', '192.168.100.1']], ['a2', 1, ['192.168.100.1']]])
  check('entries removed', plan.entriesRemoved, 3)
  check('other PC with the same loopback MAC, another device on the same IP, running and empty scans untouched',
    ['p2', 'p3', 'r1', 'e1'].filter(id => plan.deletes.includes(id) || plan.updates.some(u => u.scanId === id)), [])
  check('an asset with no addresses removes nothing', planScanLogPurge(rows, { ips: [], macs: [LOOP] }), { updates: [], deletes: [], entriesRemoved: 0 })
}

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
