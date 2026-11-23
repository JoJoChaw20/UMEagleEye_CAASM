/**
 * Agent updates from the dashboard — PURE. The agent's own side is agent-gui/eagleeye/update.
 *
 * Every published package (R2 agent-installer/, routes/agents.ts) comes with a manifest signed on
 * the build machine with the project's Ed25519 key: kind, file, build, size, SHA-256. The server
 * only forwards it: the AGENT checks the signature, so a server or storage break-in cannot push
 * a program to the agents. Here: which build an agent runs, which package fits it, and whether
 * it is out of date.
 *
 *   build    0.1.0+<UTC time>.<commit> for a packaged build; "dev" for a copy run from source
 *   install  "windows" (the installer) | "source" (Linux, /opt/eagleeye-agent-*) | null: updated
 *            by hand (macOS, the network agent's container, a development copy)
 */

export type InstallKind = 'windows' | 'source'
export const INSTALL_KINDS: InstallKind[] = ['windows', 'source']
const BUILD_RE = /^\d+\.\d+\.\d+\+(\d{8}T\d{6}Z)(?:\.[0-9a-f]{4,40})?$/

export interface PackageManifest {
  format: 1
  kind: InstallKind
  file: string
  build: string
  sha256: string
  size: number
  key: string
  signature: string
}

/** The sortable build time inside a stamp, or null (a development copy, or junk). */
export function buildTime(build: unknown): string | null {
  return typeof build === 'string' ? BUILD_RE.exec(build)?.[1] ?? null : null
}

/** What a heartbeat said about the agent's build and install, kept only when well-formed. */
export function cleanBuildReport(raw: { build?: unknown; install?: unknown }): { build: string | null; install: InstallKind | null } {
  const build = typeof raw.build === 'string' && (raw.build === 'dev' || buildTime(raw.build)) && raw.build.length <= 80 ? raw.build : null
  const install = INSTALL_KINDS.includes(raw.install as InstallKind) ? raw.install as InstallKind : null
  return { build, install }
}

/** A manifest file as published, if it is well-formed and belongs to the package next to it
 *  (same file name and size): an old manifest left beside a newer upload is not used. */
export function cleanManifest(raw: unknown, pkg: { filename: string; size: number }): PackageManifest | null {
  if (!raw || typeof raw !== 'object') return null
  const m = raw as Record<string, unknown>
  if (m.format !== 1 || !INSTALL_KINDS.includes(m.kind as InstallKind)) return null
  if (m.file !== pkg.filename || m.size !== pkg.size || !buildTime(m.build)) return null
  if (typeof m.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(m.sha256)) return null
  if (typeof m.key !== 'string' || typeof m.signature !== 'string' || m.signature.length > 200) return null
  return { format: 1, kind: m.kind as InstallKind, file: m.file as string, build: m.build as string,
    sha256: m.sha256, size: m.size as number, key: m.key, signature: m.signature }
}

export type UpdateState =
  | { state: 'current'; build: string }
  | { state: 'available'; build: string; latest: string }
  | { state: 'manual'; reason: string }        // updated by hand: reinstall, or a kind the channel does not cover

/** Whether this agent can be updated from the dashboard, and to what. */
export function updateState(agent: { kind: string | null; build: string | null; install: InstallKind | null },
  published: Partial<Record<InstallKind, PackageManifest | null>>): UpdateState {
  if (agent.kind !== 'host') return { state: 'manual', reason: 'Network agents and phones are updated by reinstalling them' }
  if (!agent.build) return { state: 'manual', reason: 'This agent is older than dashboard updates: reinstall it once' }
  if (agent.build === 'dev' || !agent.install) {
    return { state: 'manual', reason: 'Installed by hand (a development copy or macOS): update it the same way' }
  }
  const latest = published[agent.install]
  const mine = buildTime(agent.build)
  if (!latest || !mine) return { state: 'current', build: agent.build }
  return buildTime(latest.build)! > mine ? { state: 'available', build: agent.build, latest: latest.build } : { state: 'current', build: agent.build }
}

/** Pending update jobs expire after this; a running one fails if the new build never checks in. */
export const UPDATE_PICKUP_HOURS = 2
export const UPDATE_FINISH_MINUTES = 45
