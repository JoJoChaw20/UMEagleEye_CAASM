import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CDN_CIDRS, warninglistOf } from './warninglist'

test('addresses: public DNS, special-use, shared CDN edges; anything else is not listed', () => {
  assert.equal(warninglistOf('ip', '8.8.8.8'), 'public-dns')
  assert.equal(warninglistOf('ip', '192.168.1.10'), 'special-ip')
  assert.equal(warninglistOf('ip', '104.16.0.1'), 'cdn')        // Cloudflare 104.16.0.0/13
  assert.equal(warninglistOf('ip', '151.101.1.140'), 'cdn')     // Fastly 151.101.0.0/16
  assert.equal(warninglistOf('ip', '45.33.32.156'), null)
  assert.equal(warninglistOf('url', 'http://104.16.0.1/payload.exe'), 'cdn')
  assert.ok(CDN_CIDRS.length > 200)
})

test('domains: platforms by suffix, top sites by exact name only', () => {
  assert.equal(warninglistOf('domain', 'cdn.googleusercontent.com'), 'well-known-domain')
  assert.equal(warninglistOf('domain', 'wikipedia.org'), 'top-domain')
  assert.equal(warninglistOf('domain', 'www.wikipedia.org'), 'top-domain')
  assert.equal(warninglistOf('domain', 'wikipedia.org.'), 'top-domain')
  // a subdomain of a popular site can be the attacker's own; a URL on it can be a bad page
  assert.equal(warninglistOf('domain', 'evil-login.wikipedia.org'), null)
  assert.equal(warninglistOf('url', 'https://wikipedia.org/some/page'), null)
  assert.equal(warninglistOf('domain', 'ue-sight-unregistered-test.com'), null)
})
