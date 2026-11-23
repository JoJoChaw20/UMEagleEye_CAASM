import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildTime, cleanBuildReport, cleanManifest, updateState, type PackageManifest } from './agentUpdate'

const OLD = '0.1.0+20261123T050648Z.91bc695'
const NEW = '0.1.0+20261124T010203Z.abc1234'
const manifest = (over: Partial<PackageManifest> = {}): PackageManifest => ({
  format: 1, kind: 'windows', file: 'EagleEyeAgent-Setup-0.1.0.exe', build: NEW, sha256: 'a'.repeat(64), size: 1000,
  key: 'umeagleeye-2026-11', signature: 'c2ln', ...over,
})

test('build stamps: time read, junk refused', () => {
  assert.equal(buildTime(OLD), '20261123T050648Z')
  assert.equal(buildTime('dev'), null)
  assert.equal(buildTime('0.1.0'), null)
  assert.deepEqual(cleanBuildReport({ build: OLD, install: 'windows' }), { build: OLD, install: 'windows' })
  assert.deepEqual(cleanBuildReport({ build: 'dev', install: null }), { build: 'dev', install: null })
  assert.deepEqual(cleanBuildReport({ build: '<script>', install: 'msi' }), { build: null, install: null })
})

test('a manifest is used only beside its own package', () => {
  const pkg = { filename: 'EagleEyeAgent-Setup-0.1.0.exe', size: 1000 }
  assert.ok(cleanManifest(manifest(), pkg))
  assert.equal(cleanManifest(manifest(), { ...pkg, size: 999 }), null)          // a newer upload, an old manifest
  assert.equal(cleanManifest(manifest({ file: 'other.exe' }), pkg), null)
  assert.equal(cleanManifest(manifest({ build: 'dev' }), pkg), null)
  assert.equal(cleanManifest({ ...manifest(), format: 2 }, pkg), null)
  assert.equal(cleanManifest('nope', pkg), null)
})

test('update state per agent', () => {
  const published = { windows: manifest(), source: null }
  const host = (build: string | null, install: 'windows' | 'source' | null) => ({ kind: 'host', build, install })
  assert.deepEqual(updateState(host(OLD, 'windows'), published), { state: 'available', build: OLD, latest: NEW })
  assert.deepEqual(updateState(host(NEW, 'windows'), published), { state: 'current', build: NEW })
  assert.equal(updateState(host(OLD, 'source'), published).state, 'current')       // nothing published for Linux
  assert.match((updateState(host(null, null), published) as { reason: string }).reason, /reinstall it once/)
  assert.match((updateState(host('dev', null), published) as { reason: string }).reason, /by hand/)
  assert.equal(updateState({ kind: 'network', build: OLD, install: 'source' }, published).state, 'manual')
})
