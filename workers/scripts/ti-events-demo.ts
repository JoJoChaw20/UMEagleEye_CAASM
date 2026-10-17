/**
 * ti-events-demo.ts — threat-intel event helpers: parsing pasted IOCs (lib/iocParse.ts),
 * the warninglist (lib/warninglist.ts) and which tenants an event change refreshes
 * (services/threatIntel.ts scopeForEvent). PURE (no DB).
 * Run: npx esbuild scripts/ti-events-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.ti-events-demo.cjs && node .ti-events-demo.cjs
 */
import { detectType, normalise, parseIocs, refang } from '../src/lib/iocParse'
import { warninglistOf } from '../src/lib/warninglist'
import { scopeForEvent } from '../src/services/threatIntel'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// ── refanging and type detection ──
check('refang hxxp and [.]', refang('hxxp://evil[.]example[.]my/login'), 'http://evil.example.my/login')
check('refang [@] and (dot)', refang('attacker[@]mail(dot)ru'), 'attacker@mail.ru')
check('detect IPv4', detectType('203.0.113.5'), 'ip')
check('detect IPv6', detectType('2001:db8::1'), 'ip')
check('detect CVE (any case)', detectType('cve-2024-3400'), 'cve')
check('detect SHA-256', detectType('a'.repeat(64)), 'hash')
check('detect MD5', detectType('d41d8cd98f00b204e9800998ecf8427e'), 'hash')
check('detect URL', detectType('https://evil.example.my/x'), 'url')
check('detect email', detectType('ops@evil.example.my'), 'email')
check('detect domain', detectType('evil-site.example.my'), 'domain')
check('a plain word is not an IOC', detectType('hello'), null)
check('999.1.1.1 is neither an IP nor a domain', detectType('999.1.1.1'), null)

// ── normalising ──
check('CVE upper-cased', normalise('cve', 'cve-2024-3400'), 'CVE-2024-3400')
check('domain lower-cased, trailing dot dropped', normalise('domain', 'Evil.Example.MY.'), 'evil.example.my')
check('hash lower-cased', normalise('hash', 'D41D8CD98F00B204E9800998ECF8427E'), 'd41d8cd98f00b204e9800998ecf8427e')
check('URL host lower-cased', normalise('url', 'HTTPS://EVIL.Example.my/Path'), 'https://evil.example.my/Path')
check('forced type that does not fit is refused', normalise('ip', 'evil.example.my'), null)

// ── parsing a pasted block ──
const pasted = `
  203.0.113[.]5
  hxxps://phish[.]example[.]my/login
  CVE-2024-3400, cve-2024-3400
  not-an-ioc!
  d41d8cd98f00b204e9800998ecf8427e
`
const { parsed, rejected } = parseIocs(pasted)
check('pasted block: values, types, duplicates dropped', parsed, [
  { type: 'ip', value: '203.0.113.5' },
  { type: 'url', value: 'https://phish.example.my/login' },
  { type: 'cve', value: 'CVE-2024-3400' },
  { type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e' },
])
check('pasted block: the junk is reported', rejected.map(r => r.input), ['not-an-ioc!'])
check('forced type rejects what does not fit', parseIocs('1.2.3.4 evil.example.my', 'ip').rejected.map(r => r.input), ['evil.example.my'])

// ── software watchlist entries (never auto-detected; one per line) ──
check('software: names with spaces, one per line', parseIocs('MOVEit Transfer\nlog4j-core@2.14.1\n@babel/core@7.1.0', 'software').parsed,
  [{ type: 'software', value: 'MOVEit Transfer' }, { type: 'software', value: 'log4j-core@2.14.1' }, { type: 'software', value: '@babel/core@7.1.0' }])
check('software is not guessed from plain text', detectType('MOVEit'), null)
check('software: two @versions refused', normalise('software', 'a@1@2'), null)

// ── warninglist ──
check('Google DNS', warninglistOf('ip', '8.8.8.8'), 'public-dns')
check('private range', warninglistOf('ip', '192.168.1.10'), 'special-ip')
check('documentation range', warninglistOf('ip', '203.0.113.5'), 'special-ip')
check('CGNAT range', warninglistOf('ip', '100.64.3.4'), 'special-ip')
check('public IP is fine', warninglistOf('ip', '45.33.32.156'), null)
check('microsoft.com subdomain', warninglistOf('domain', 'login.microsoft.com'), 'well-known-domain')
check('lookalike is NOT listed', warninglistOf('domain', 'microsoft.com.evil.my'), null)
check('URL on a cloud host', warninglistOf('url', 'https://bucket.s3.amazonaws.com/x'), 'well-known-domain')
check('email at a well-known domain', warninglistOf('email', 'someone@outlook.com'), 'well-known-domain')
check('CVEs and hashes are never listed', [warninglistOf('cve', 'CVE-2024-3400'), warninglistOf('hash', 'a'.repeat(64))], [null, null])

// ── which alerts an event change refreshes ──
check('private event: its tenant only', scopeForEvent({ tenantId: 't1', distribution: 'organisation' }), { tenantId: 't1' })
check('shared event: every tenant', scopeForEvent({ tenantId: 't1', distribution: 'all_tenants' }), { all: true })
check('platform event: every tenant', scopeForEvent({ tenantId: null, distribution: 'platform' }), { all: true })
check('made private from shared: every tenant (to clear others)', scopeForEvent({ tenantId: 't1', distribution: 'organisation' }, 'all_tenants'), { all: true })

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
