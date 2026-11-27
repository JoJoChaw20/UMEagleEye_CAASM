import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PgDialect } from 'drizzle-orm/pg-core'
import {
  exploitedEvidence, iocOf, mycertEventTitle, mycertRecords, mycertThreatLevel, parseMycertAdvisory, parseMycertRss, parseMytDate,
} from './mycert'
import { warninglistOf } from './warninglist'
import { EXPLOITED_SQL, freshSql } from '../services/threatIntel'
import { HARVEST_EVERY_MS, HARVEST_STALE_MS, MYCERT_RSS_URL, harvestUrls, shouldHarvest, trimAdvisoryPage } from './mycert'
import { maybeHarvestMycert, mycertSourceOf, rememberKnownMycert } from '../services/mycert'

// Pages laid out as MyCERT's are (title, date / kind / keywords, numbered sections), with made-up content.
function page(title: string, meta: { date?: string; kind?: string; tags?: string }, body: string): string {
  return `<html><body><div class="post-title"><h6 style="margin:0">${title}</h6></div>
    <ul class="meta"><li><i class="fas fa-calendar-alt"></i>&nbsp;&nbsp;${meta.date ?? '11 Nov 2026'}</li>
    <li><i class="fas fa-file"></i>&nbsp;&nbsp;${meta.kind ?? 'Advisory'}</li>
    <li><i class="fa fa-tag"></i>&nbsp;&nbsp;${meta.tags ?? ''}</li></ul>
    <div class="post-cont" style="color:black;">${body}</div>
    <!-- start blog right--><div class="side-bar"><a href="/portal/advisory?id=MA-782.042020">MA-782.042020</a></div></body></html>`
}
const p = (s: string) => `<p><strong>${s}</strong></p>`
const row = (...cells: string[]) => `<tr>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`
const CONTACT = '<p>For further enquiries, please contact MyCERT through the following channels:</p><p>E-mail: cyber999[at]cybersecurity.my</p>'

test('RSS: the advisory number, the link with &amp; undone, the date in Malaysia time', () => {
  const xml = `<rss><channel><title>MyCERT Advisory RSS Feed</title>
    <item><title>MA-1506.112026: MyCERT Advisory - Actively Exploited Outlook Zero-Day (CVE-2026-124194)</title>
      <description><![CDATA[Published date: 11 November 2026, 9:33 pm]]></description>
      <link>https://www.mycert.org.my/portal/details?menu=431f&amp;id=f68f</link></item>
    <item><title>Not an advisory</title><link>x</link></item></channel></rss>`
  const items = parseMycertRss(xml)
  assert.equal(items.length, 1)
  assert.equal(items[0]!.id, 'MA-1506.112026')
  assert.equal(items[0]!.link, 'https://www.mycert.org.my/portal/details?menu=431f&id=f68f')
  assert.equal(items[0]!.publishedAt?.toISOString(), '2026-11-11T13:33:00.000Z')   // 9:33 pm MYT
  assert.equal(parseMytDate('11 Nov 2026')?.toISOString(), '2026-11-10T16:00:00.000Z')
  assert.equal(parseMytDate('1 January 2026, 12:05 am')?.toISOString(), '2025-12-31T16:05:00.000Z')
  assert.equal(parseMytDate('soon'), null)
})

test('a page: number, kind, headline, date, keywords, rating, summary, products; References and the contact block left out', () => {
  const html = page('MA-1506.112026: MyCERT Advisory - Actively Exploited Outlook Zero-Day (CVE-2026-124194)',
    { tags: 'microsoft, outlook, cve-2026-124194, active exploitation' },
    p('1.0 Introduction') + '<p>Microsoft released an update for a flaw in Outlook that it says is being actively exploited. The flaw is tracked as CVE-2026-124194.</p>'
    + '<p>MyCERT rates this HIGH and advises users to patch.</p>'
    + p('4.0 Affected Products') + `<table>${row('Product', 'Affected', 'Action')}${row('Office LTSC 2021 (Outlook)', 'Affected versions', 'Apply the update')}</table>`
    + '<p>Confirm the KB for each build.</p>' + CONTACT
    + p('6.0 References') + '<p>Related: CVE-2025-00001 (an older Outlook flaw)</p>')
  const a = parseMycertAdvisory(html)!
  assert.equal(a.id, 'MA-1506.112026')
  assert.equal(a.number, 1506)
  assert.equal(a.kind, 'advisory')
  assert.equal(a.headline, 'Actively Exploited Outlook Zero-Day (CVE-2026-124194)')
  assert.equal(a.publishedAt?.toISOString(), '2026-11-10T16:00:00.000Z')
  assert.deepEqual(a.tags, ['microsoft', 'outlook', 'cve-2026-124194', 'active exploitation'])
  assert.equal(a.rating, 'high')
  assert.deepEqual(a.cves, ['CVE-2026-124194'])                  // not the one only in References
  assert.deepEqual(a.exploitedCves, ['CVE-2026-124194'])
  assert.deepEqual(a.products, ['Office LTSC 2021 (Outlook)'])
  assert.match(a.summary, /^Microsoft released an update/)
  assert.deepEqual(a.iocs, [])                                   // MyCERT's own address is no indicator
  assert.equal(mycertThreatLevel(a), 'high')
  assert.equal(mycertEventTitle(a), 'MyCERT MA-1506: Actively Exploited Outlook Zero-Day (CVE-2026-124194)')
  assert.equal(parseMycertAdvisory('<html>Page not found</html>'), null)
})

test('exploited: said of the CVE, or in the sentence before it; not a proof of concept, not negated', () => {
  const cves = ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0004']
  // the next sentence of the same paragraph names them
  assert.deepEqual(Object.keys(exploitedEvidence(
    ['CISA warned of the active exploitation of several flaws. The flaws, tracked as CVE-2026-0001 and CVE-2026-0002, allow code execution.'], 'X', cves)),
  ['CVE-2026-0001', 'CVE-2026-0002'])
  // a public exploit after "no in-the-wild exploitation" is not exploitation
  assert.deepEqual(exploitedEvidence(
    ['No in-the-wild exploitation has been reported. However, a public proof-of-concept for CVE-2026-0003 is available.'], 'X', cves), {})
  // a bare "KEV" saying it is not listed
  assert.deepEqual(exploitedEvidence(['CISA KEV: CVE-2026-0004 is not listed in the Known Exploited Vulnerabilities catalog.'], 'X', cves), {})
  assert.deepEqual(Object.keys(exploitedEvidence(['CVE-2026-0004 was added to the CISA KEV catalog on 10 November.'], 'X', cves)), ['CVE-2026-0004'])
  assert.deepEqual(exploitedEvidence(['If exploited, CVE-2026-0001 could be exploited remotely.'], 'X', cves), {})
  // the title: its own CVEs, or the advisory's only one
  assert.deepEqual(Object.keys(exploitedEvidence([], 'Actively Exploited Flaw in X (CVE-2026-0002)', cves)), ['CVE-2026-0002'])
  assert.deepEqual(Object.keys(exploitedEvidence([], 'SharePoint Hardening After New Exploitations', ['CVE-2026-0009'])), ['CVE-2026-0009'])
  assert.deepEqual(exploitedEvidence([], 'SharePoint Hardening After New Exploitations', cves), {})
})

test('an older advisory naming its CVE only in References: that CVE, exploited when the reference is its KEV entry', () => {
  const a = parseMycertAdvisory(page('MA-1475.072026: MyCERT Advisory - Oracle E-Business Suite Improper Privilege Management Vulnerability', {},
    p('1.0 Introduction') + '<p>Oracle has released a security update.</p>'
    + p('5.0 References') + '<p>https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-46817</p>'
    + '<p>https://nvd.nist.gov/vuln/detail/CVE-2026-46817</p>'))!
  assert.deepEqual(a.cves, ['CVE-2026-46817'])
  assert.deepEqual(a.exploitedCves, ['CVE-2026-46817'])
  assert.match(a.exploitedEvidence['CVE-2026-46817']!, /Known Exploited Vulnerabilities/)
})

test('indicators: defanged network values, hashes in the IOC section, a row\'s first cell, reference-only rows', () => {
  const sha = 'a'.repeat(64)
  const a = parseMycertAdvisory(page('MA-1508.112026: MyCERT Advisory - Infostealer Malware', { kind: 'Alert' },
    p('2.0 Overview') + `<p>The lure loads ethers.js from cdn.jsdelivr[.]net and sends logs to 1.2.3.4; sample ${'b'.repeat(64)}.</p>`
    + p('4.0 Indicators of Compromise') + p('4.1 File hashes (SHA-256)') + `<table>${row('SHA-256', 'Source')}${row(sha, 'Gen')}</table>`
    + p('4.2 Domains') + `<table>${row('Domain', 'Source', 'Status')}${row('24hocst[.]help (2538)', 'EtherHiding', 'Live, resolves to 159.223.150[.]218')}`
    + `${row('evil[.]example/path/x.jpg', 'Download server', 'Live')}</table>`
    + p('4.3 IP addresses') + `<table>${row('IP', 'Status')}${row('159.223.150[.]218', 'Live. Do not blocklist without collateral review')}`
    + `${row('62.90.129[.]xxx', 'masked')}${row('8.8.8[.]8', 'Context only')}</table>`
    + p('4.4 Other') + `<table>${row('Contract', '0x999941b74F6bbc921D5174A5b29911562cd2D7CF', 'Ethereum')}</table>` + CONTACT))!
  assert.equal(a.kind, 'alert')
  const byValue = new Map(a.iocs.map((i) => [i.value, i]))
  assert.equal(byValue.get(sha)?.type, 'hash')
  assert.ok(!byValue.has('b'.repeat(64)))                       // a hash outside the IOC section
  assert.ok(!byValue.has('1.2.3.4'))                            // not defanged
  assert.equal(byValue.get('cdn.jsdelivr.net')?.toIds, true)    // defanged in the text: kept (the warninglist may still apply)
  assert.equal(byValue.get('24hocst.help')?.type, 'domain')     // the port in brackets is not part of it
  assert.equal(byValue.get('evil.example')?.type, 'domain')     // a host with a path: the host
  const ip = byValue.get('159.223.150.218')!
  assert.equal(ip.toIds, false)                                 // its own row says not to block it
  assert.match(ip.comment!, /Do not blocklist/)
  assert.equal(byValue.get('8.8.8.8')?.toIds, false)            // "context only"
  assert.ok(![...byValue.keys()].some((v) => v.includes('xxx') || v.includes('cybersecurity.my') || v.startsWith('0x')))
  assert.equal(iocOf('hxxps://bad[.]example/a', false)?.type, 'url')
  assert.equal(iocOf('user[at]bad[.]example', false)?.type, 'email')
  assert.equal(iocOf('example.com', false), null)
})

test('records: one platform event, CVE and indicator attributes, warninglists, the advisory\'s own link', () => {
  const a = parseMycertAdvisory(page('MA-1513.112026: MyCERT Advisory - Fake STR Portal Captures Telegram Login Codes', { tags: 'STR, phishing' },
    p('1.0 Introduction') + '<p>STR is paid only through the official portal bantuantunai.hasil[.]gov[.]my. The fake one is str-rahmah[.]site.</p>'
    + '<p>Users were lured with T1566.002 links; attackers used CVE-2026-0001 which is actively exploited.</p>'))!
  const { event, attributes } = mycertRecords(a, new Date('2026-11-22T07:24:00Z'))
  assert.equal(event.externalId, 'MA-1513.112026')
  assert.equal(event.title, 'MyCERT MA-1513: Fake STR Portal Captures Telegram Login Codes')
  assert.deepEqual(event.tags, ['MyCERT', 'Advisory', 'STR', 'phishing'])
  assert.deepEqual(event.attackTechniques, ['T1566.002'])
  assert.deepEqual(event.exploitedCves, ['CVE-2026-0001'])
  assert.equal(event.threatLevel, 'high')
  assert.equal(event.publishedAt.toISOString(), '2026-11-22T07:24:00.000Z')   // the feed's time wins over the page's day
  assert.equal(event.sourceMeta.url, 'https://www.mycert.org.my/portal/advisory?id=MA-1513.112026')
  assert.match(event.description, /Source: MyCERT MA-1513\.112026/)
  const byValue = new Map(attributes.map((r) => [r.value, r]))
  assert.match(byValue.get('CVE-2026-0001')!.comment!, /^Exploited in the wild, per MyCERT/)
  // the genuine government portal the scam imitates never alerts
  assert.equal(byValue.get('bantuantunai.hasil.gov.my')?.warning, 'my-official-domain')
  assert.equal(byValue.get('str-rahmah.site')?.warning, null)
})

test('Malaysian official domains are on the warninglist; a URL on one keeps its path and is not', () => {
  assert.equal(warninglistOf('domain', 'www.moh.gov.my'), 'my-official-domain')
  assert.equal(warninglistOf('domain', 'um.edu.my'), 'my-official-domain')
  assert.equal(warninglistOf('email', 'help@jpn.gov.my'), 'my-official-domain')
  assert.equal(warninglistOf('domain', 'gov-my.online'), null)
  assert.equal(warninglistOf('domain', 'bantuan.my'), null)
  assert.equal(warninglistOf('url', 'https://hacked.gov.my/shell.php'), null)
})

const render = (q: ReturnType<typeof freshSql>) => new PgDialect().sqlToQuery(q).sql

test('matching: MyCERT\'s exploited CVEs rank as KEV; its addresses age from the advisory date; analysts\' do not', () => {
  const ex = render(EXPLOITED_SQL)
  assert.match(ex, /c\.ti_event_id IS NULL AND c\.source = \$1/)
  assert.match(ex, /te\.status = 'published' AND te\.distribution = 'platform' AND c\.value = ANY\(te\.exploited_cves\)/)
  const fresh = render(freshSql('c'))
  assert.match(fresh, /\(c\.ti_event_id IS NOT NULL AND c\.source <> 'MyCERT'\) OR \(c\.source NOT IN \('AlienVault OTX', 'URLhaus', 'Feodo Tracker'\)/)
})

test('migration 0048 only adds the event columns and their unique index', () => {
  const text = readFileSync(join(process.cwd(), 'drizzle/0048_mycert_advisories.sql'), 'utf8')
  const code = text.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')
  for (const col of ['"origin" varchar\\(20\\)', '"external_id" varchar\\(40\\)', '"exploited_cves" text\\[\\]', '"source_meta" jsonb']) {
    assert.match(code, new RegExp(`ALTER TABLE "ti_events" ADD COLUMN ${col};`))
  }
  assert.match(code, /CREATE UNIQUE INDEX IF NOT EXISTS "idx_ti_events_origin" ON "ti_events" USING btree \("origin","external_id"\) WHERE "ti_events"\."origin" IS NOT NULL;/)
  assert.doesNotMatch(code, /\b(UPDATE|DELETE|TRUNCATE|DROP)\b/i)
})

// ── Harvest: MyCERT is fetched during a request from Malaysia, read by the nightly step from KV ──
test('harvest: only for a request from Malaysia or Singapore, at most every few hours unless forced', () => {
  const now = Date.UTC(2026, 10, 27, 12)
  assert.equal(shouldHarvest('MY', null, now), true)
  assert.equal(shouldHarvest('sg', now - HARVEST_EVERY_MS, now), true)
  assert.equal(shouldHarvest('MY', now - 60_000, now), false)
  assert.equal(shouldHarvest('MY', now - 60_000, now, true), true)
  assert.equal(shouldHarvest('US', null, now, true), false)       // MyCERT would refuse it anyway
  assert.equal(shouldHarvest(undefined, null, now), false)
})

test('harvest: the feed\'s advisories not stored yet, oldest first; a page trimmed to what the parser reads', () => {
  const item = (n: number) => ({ id: `MA-${n}.112026`, title: '', link: `https://x/${n}`, publishedAt: null })
  const items = [item(1515), item(1514), item(1513), item(1512)]                    // newest first, as the feed lists them
  assert.deepEqual(harvestUrls(items, new Set(['MA-1512.112026'])), ['https://x/1513', 'https://x/1514', 'https://x/1515'])
  assert.deepEqual(harvestUrls(items, new Set(), 2), ['https://x/1512', 'https://x/1513'])
  const html = page('MA-1506.112026: MyCERT Advisory - X', {}, p('1.0 Introduction') + '<p>Body.</p>')
  const trimmed = trimAdvisoryPage(`<html><head><script>big()</script></head>${html}`)
  assert.ok(trimmed.length < html.length && trimmed.startsWith('<h6'))
  assert.ok(!trimmed.includes('side-bar'))
  assert.equal(parseMycertAdvisory(trimmed)?.id, 'MA-1506.112026')
})

function memoryKv() {
  const m = new Map<string, string>()
  return {
    m,
    async get(k: string, type?: string) { const v = m.get(k) ?? null; return v !== null && type === 'json' ? JSON.parse(v) : v },
    async put(k: string, v: string) { m.set(k, v) },
    async delete(k: string) { m.delete(k) },
  } as unknown as KVNamespace & { m: Map<string, string> }
}

test('harvest end to end: a request from Malaysia fetches the feed and new pages; the nightly reader uses them, then says when it went stale', async () => {
  const kv = memoryKv()
  const rss = `<rss><channel><item><title>MA-1516.112026: MyCERT Advisory - New</title><description>Published date: 27 November 2026, 9:00 am</description><link>https://www.mycert.org.my/portal/details?id=a</link></item>
    <item><title>MA-1515.112026: MyCERT Advisory - Old</title><link>https://www.mycert.org.my/portal/details?id=b</link></item></channel></rss>`
  const fetched: string[] = []
  const mycert = async (url: string) => {
    fetched.push(url)
    if (url === MYCERT_RSS_URL) return rss
    return page('MA-1516.112026: MyCERT Advisory - New', {}, p('1.0 Introduction') + '<p>Body.</p>')
  }
  const now = Date.UTC(2026, 10, 27, 4)
  await rememberKnownMycert(kv, ['MA-1515.112026'])
  assert.equal(await maybeHarvestMycert(kv, 'US', { now, fetchText: mycert, force: true }), false)
  assert.equal(fetched.length, 0)
  assert.equal(await maybeHarvestMycert(kv, 'MY', { now, fetchText: mycert, force: true }), true)
  assert.deepEqual(fetched, [MYCERT_RSS_URL, 'https://www.mycert.org.my/portal/details?id=a'])   // not the stored MA-1515
  assert.equal(kv.m.has('mycert:harvest_lock'), false)
  // the nightly step reads the harvest, without asking MyCERT
  const read = mycertSourceOf(kv, now + 3600_000)
  assert.equal(await read(MYCERT_RSS_URL), rss)
  assert.match(await read('https://www.mycert.org.my/portal/details?id=a'), /^<h6/)
  // two days on, the harvest is not used: the error says when MyCERT was last fetched
  const stale = mycertSourceOf(kv, now + HARVEST_STALE_MS + 1)
  const original = globalThis.fetch
  globalThis.fetch = (async () => new Response('Just a moment...', { status: 403, headers: { 'cf-mitigated': 'challenge' } })) as typeof fetch
  try {
    await assert.rejects(stale(MYCERT_RSS_URL), /answers only requests from Malaysia or Singapore; its pages were last fetched during one 48 hour\(s\) ago.*cf-mitigated=challenge/)
  } finally {
    globalThis.fetch = original
  }
})
